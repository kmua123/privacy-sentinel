// Package guardcore embeds one Mihomo forwarding engine behind an Android
// VpnService. The host application owns the TUN and every admission decision.
package guardcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
)

// Callbacks are called from forwarding goroutines, never the Android UI thread.
// Permit must be fast. A false result closes/drops the current attempt; user
// interaction happens asynchronously and the originating application retries.
type Callbacks interface {
	Protect(fd int64) bool
	ResolveUid(protocol int32, source, destination string) int64
	Permit(uid int64, protocol int32, source, destination string) bool
	Event(message string)
}

var lifecycle sync.Mutex
var running *engine
var errDenied = errors.New("connection requires approval or is blocked")

type engine struct {
	callbacks         Callbacks
	active            atomic.Bool
	listener          *sing_tun.Listener
	connections       sync.Map
	sessionMu         sync.Mutex
	generation        atomic.Uint64
	home              interface{ HomeStatus() string }
	homePrepareFailed bool
	proxies           map[string]C.Proxy
	delayGates        map[string]chan struct{}
	diagnostics       *networkDiagnosticsState
}

// Start duplicates tunFD. The host keeps ownership of its ParcelFileDescriptor;
// the native listener exclusively owns its duplicate.
func Start(tunFD int64, configYAML, stateDirectory string, callbacks Callbacks) error {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	if running != nil {
		return errors.New("network core is already running")
	}
	if callbacks == nil || tunFD < 0 || stateDirectory == "" {
		return errors.New("missing network core parameters")
	}
	if err := os.MkdirAll(stateDirectory, 0700); err != nil {
		return errors.New("cannot create private core state")
	}
	C.SetHomeDir(stateDirectory)
	config, err := executor.ParseWithBytes([]byte(configYAML))
	if err != nil {
		return fmt.Errorf("invalid network configuration: %w", err)
	}
	// The APK controls every ingress. Imported configuration cannot open a
	// second listener or an unauthenticated control port beside the guard.
	config.General.Port = 0
	config.General.SocksPort = 0
	config.General.MixedPort = 0
	config.General.RedirPort = 0
	config.General.TProxyPort = 0
	config.General.Tun.Enable = false
	config.General.TuicServer.Enable = false
	config.General.ShadowSocksConfig = ""
	config.General.VmessConfig = ""
	config.Listeners = nil
	config.Tunnels = nil
	config.NTP.Enable = false
	config.DNS.Listen = ""
	config.General.GeoAutoUpdate = false
	config.General.FindProcessMode = process.FindProcessOff

	e := &engine{callbacks: callbacks, proxies: config.Proxies, diagnostics: newNetworkDiagnostics()}
	e.active.Store(true)
	beginTrafficSession()
	dialer.DefaultSocketHook = e.protect
	sing_tun.SetIngressGuard(e)
	statistic.SetLeaveObserver(e.usageClosed)
	executor.ApplyConfig(config, true)
	fd, err := duplicateTUN(int(tunFD))
	if err != nil {
		e.active.Store(false)
		e.diagnostics.stop()
		endTrafficSession()
		executor.Shutdown()
		closeProxies()
		return errors.New("could not duplicate Android TUN descriptor")
	}
	options := guardedTunOptions(fd, config.General.IPv6)
	listener, err := sing_tun.New(options, tunnel.Tunnel)
	if err != nil {
		e.active.Store(false)
		e.diagnostics.stop()
		endTrafficSession()
		executor.Shutdown()
		closeProxies()
		return fmt.Errorf("could not start guarded TUN: %w", err)
	}
	e.listener = listener
	running = e
	e.diagnostics.startLogObserver()
	currentNetworkDiagnostics.Store(e.diagnostics)
	// An explicitly enabled private overlay needs its public node identity
	// before the controller can authorize it. Prepare only its control plane;
	// application flows still enter through the guarded TUN above.
	for _, proxy := range config.Proxies {
		if proxy.Type() != C.ZeroTier {
			continue
		}
		if status, ok := proxy.Adapter().(interface{ HomeStatus() string }); ok {
			e.home = status
		}
		if preparer, ok := proxy.Adapter().(interface{ PrepareIdentity() error }); ok {
			callbacks.Event(`{"type":"home_preparing"}`)
			if err := preparer.PrepareIdentity(); err != nil {
				e.homePrepareFailed = true
				// These are local control-plane initialization errors only. No
				// subscription configuration or node secret is included.
				message, _ := json.Marshal(map[string]string{
					"type": "home_error", "message": err.Error(),
				})
				callbacks.Event(string(message))
			} else {
				callbacks.Event(`{"type":"home_ready"}`)
			}
		}
	}
	return nil
}

// Match the host's advertised TUN address family. The Java VPN still captures
// both default routes; omitting an IPv6 source address does not allow bypass.
func guardedTunOptions(fd int, ipv6 bool) LC.Tun {
	options := LC.Tun{
		FileDescriptor:        fd,
		Stack:                 C.TunGvisor,
		MTU:                   1400,
		Inet4Address:          []netip.Prefix{netip.MustParsePrefix("10.99.0.1/30")},
		DNSHijack:             []string{"0.0.0.0:53", "[::]:53"},
		DisableICMPForwarding: true,
		UDPTimeout:            60,
	}
	if ipv6 {
		options.Inet6Address = []netip.Prefix{netip.MustParsePrefix("fd99:7072:6976::1/126")}
	}
	return options
}

// HomeStatus returns bounded, shareable diagnostics for the configured home
// overlay. It contains no private identity, keys, physical peer endpoints or
// raw log messages. Call it off the Android UI thread alongside Start/Stop.
func HomeStatus() string {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	if running != nil && running.home != nil {
		status := running.home.HomeStatus()
		if running.homePrepareFailed {
			var value map[string]any
			if json.Unmarshal([]byte(status), &value) == nil && value["initialized"] == false {
				value["state"] = "initialization-error"
				data, _ := json.Marshal(value)
				return string(data)
			}
		}
		return status
	}
	state := "stopped"
	if running != nil {
		state = "disabled"
	}
	data, _ := json.Marshal(map[string]any{
		"state": state, "initialized": false, "nodeId": "", "networkStatus": state,
		"stackReady": false, "assignedIps": []string{}, "managedRoutes": []string{},
		"knownPeers": 0, "peersWithActivePath": 0, "activePeerPaths": 0,
	})
	return string(data)
}

// ValidateConfig parses a generated configuration without opening a TUN or
// dialing any proxy. Parsed adapters are closed to release allocated resources.
func ValidateConfig(configYAML string) error {
	config, err := executor.ParseWithBytes([]byte(configYAML))
	if err != nil {
		return err
	}
	for _, proxy := range config.Proxies {
		_ = proxy.Close()
	}
	return nil
}

func Stop() {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	e := running
	if e == nil {
		return
	}
	running = nil
	e.active.Store(false)
	e.diagnostics.stop()
	endTrafficSession()
	if e.listener != nil {
		_ = e.listener.Close()
	}
	e.closeConnections()
	executor.Shutdown()
	closeProxies()
	statistic.SetLeaveObserver(nil)
	// Keep a refusing socket hook and guard installed until the next Start.
	// A leftover resolver/adapter goroutine must never escape after Stop.
}

// CloseConnections invalidates active TCP and UDP sessions after a policy
// change or temporary grant expiry. It does not change the TUN or local rules.
func CloseConnections() {
	lifecycle.Lock()
	e := running
	lifecycle.Unlock()
	if e != nil {
		e.closeConnections()
	}
}

func (e *engine) closeConnections() {
	e.sessionMu.Lock()
	defer e.sessionMu.Unlock()
	e.generation.Add(1)
	e.connections.Range(func(key, value any) bool {
		_ = value.(interface{ Close() error }).Close()
		return true
	})
	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		_ = tracker.Close()
		return true
	})
	resolver.ResetConnection()
}

func closeProxies() {
	for _, proxy := range tunnel.Proxies() {
		_ = proxy.Close()
	}
}

func (e *engine) protect(_ string, _ string, conn syscall.RawConn) error {
	if !e.active.Load() {
		return errors.New("network core is stopped")
	}
	protected := false
	err := conn.Control(func(fd uintptr) {
		protected = e.callbacks.Protect(int64(fd))
	})
	if err != nil {
		e.diagnostics.recordProtectFailure()
		return err
	}
	if !protected {
		e.diagnostics.recordProtectFailure()
		return errors.New("Android refused socket protection")
	}
	return nil
}

func (e *engine) admit(ctx context.Context, protocol int32, metadata M.Metadata) (context.Context, int64, error) {
	if !e.active.Load() {
		return ctx, -1, errDenied
	}
	source := metadata.Source.String()
	destination := metadata.Destination.String()
	generation := e.generation.Load()
	uid := e.resolveUID(protocol, source, destination)
	allowed := e.permit(uid, protocol, source, destination) && e.active.Load() && e.generation.Load() == generation
	e.diagnostics.recordAdmission(uid, protocol, metadata.Destination, allowed)
	if !allowed {
		return ctx, uid, errDenied
	}
	ctx = sing.WithAdditions(ctx, inbound.Addition(func(value *C.Metadata) {
		if uid >= 0 {
			value.Uid = uint32(uid)
		}
	}))
	return ctx, uid, nil
}

func (e *engine) resolveUID(protocol int32, source, destination string) int64 {
	started := time.Now()
	uid := e.callbacks.ResolveUid(protocol, source, destination)
	e.diagnostics.recordCallback(false, time.Since(started))
	return uid
}

func (e *engine) permit(uid int64, protocol int32, source, destination string) bool {
	started := time.Now()
	allowed := e.callbacks.Permit(uid, protocol, source, destination)
	e.diagnostics.recordCallback(true, time.Since(started))
	return allowed
}

func (e *engine) TCP(ctx context.Context, conn net.Conn, metadata M.Metadata) (context.Context, net.Conn, error) {
	generation := e.generation.Load()
	ctx, uid, err := e.admit(ctx, 6, metadata)
	if err != nil {
		_ = conn.Close()
		return ctx, conn, err
	}
	tracked := &guardedConn{
		conn: conn, owner: e, uid: uid, generation: generation,
		source: metadata.Source.String(), destination: metadata.Destination.String(),
	}
	e.sessionMu.Lock()
	defer e.sessionMu.Unlock()
	if e.generation.Load() != generation || !e.active.Load() {
		_ = conn.Close()
		return ctx, conn, errDenied
	}
	e.connections.Store(tracked, tracked)
	return ctx, tracked, nil
}

func (e *engine) Packet(ctx context.Context, _ netip.AddrPort, metadata M.Metadata) (context.Context, error) {
	ctx, _, err := e.admit(ctx, 17, metadata)
	return ctx, err
}

func (e *engine) PacketConnection(ctx context.Context, conn network.PacketConn, metadata M.Metadata) (context.Context, network.PacketConn, error) {
	generation := e.generation.Load()
	ctx, _, err := e.admit(ctx, 17, metadata)
	if err != nil {
		_ = conn.Close()
		return ctx, conn, err
	}
	tracked := &guardedPacketConn{PacketConn: conn, owner: e, metadata: metadata, ctx: ctx}
	e.sessionMu.Lock()
	defer e.sessionMu.Unlock()
	if e.generation.Load() != generation || !e.active.Load() {
		_ = conn.Close()
		return ctx, conn, errDenied
	}
	e.connections.Store(tracked, tracked)
	return ctx, tracked, nil
}

type guardedConn struct {
	// Keep the underlying connection private. In particular, exposing Upstream,
	// ReaderFrom or WriterTo would allow a copy fast path to skip Read/Write.
	conn                net.Conn
	owner               *engine
	uid                 int64
	source, destination string
	generation          uint64
	closed              atomic.Bool
}

func (c *guardedConn) permitted() bool {
	if c.closed.Load() || !c.owner.active.Load() || c.owner.generation.Load() != c.generation {
		return false
	}
	// The original socket may have disappeared from Android's owner table by
	// now. Retain its admitted UID rather than resolving it again or falling
	// back to a different identity on an established flow.
	return c.owner.permit(c.uid, 6, c.source, c.destination) &&
		!c.closed.Load() && c.owner.active.Load() && c.owner.generation.Load() == c.generation
}

func (c *guardedConn) Read(p []byte) (int, error) {
	if !c.permitted() {
		_ = c.Close()
		return 0, errDenied
	}
	n, err := c.conn.Read(p)
	// A read can block across the expiry of a temporary grant while Android
	// is idle. Do not release those upload bytes to a proxy after expiry.
	if !c.permitted() {
		clear(p[:n])
		_ = c.Close()
		return 0, errDenied
	}
	return n, err
}

func (c *guardedConn) Write(p []byte) (int, error) {
	if !c.permitted() {
		_ = c.Close()
		return 0, errDenied
	}
	return c.conn.Write(p)
}

func (c *guardedConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	c.owner.connections.Delete(c)
	return c.conn.Close()
}

func (c *guardedConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *guardedConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *guardedConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *guardedConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *guardedConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

type guardedPacketConn struct {
	network.PacketConn
	owner    *engine
	metadata M.Metadata
	ctx      context.Context
}

func (c *guardedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, err := c.PacketConn.ReadPacket(buffer)
	if err != nil {
		return destination, err
	}
	metadata := c.metadata
	metadata.Destination = destination
	if _, _, err = c.owner.admit(c.ctx, 17, metadata); err != nil {
		_ = c.Close()
		return destination, err
	}
	return destination, nil
}

func (c *guardedPacketConn) Close() error {
	c.owner.connections.Delete(c)
	return c.PacketConn.Close()
}

func (e *engine) usageClosed(info *statistic.TrackerInfo) {
	protocol := 6
	if info.Metadata.NetWork == C.UDP {
		protocol = 17
	}
	destination := info.Metadata.RemoteAddress()
	if info.Metadata.RawDstAddr != nil {
		destination = info.Metadata.RawDstAddr.String()
	}
	message, _ := json.Marshal(map[string]any{
		"type": "usage", "uid": info.Metadata.Uid,
		"protocol": protocol, "destination": destination,
		"sent": info.UploadTotal.Load(), "received": info.DownloadTotal.Load(),
	})
	e.callbacks.Event(string(message))
}
