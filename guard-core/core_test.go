package guardcore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/tunnel/statistic"
	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
)

type testCallbacks struct {
	allowed             atomic.Bool
	protected           bool
	uid                 int64
	protocol            int32
	source, destination string
	wait, release       chan struct{}
	events              []string
}

func (c *testCallbacks) Protect(int64) bool { return c.protected }
func (c *testCallbacks) ResolveUid(protocol int32, source, destination string) int64 {
	c.protocol, c.source, c.destination = protocol, source, destination
	return c.uid
}
func (c *testCallbacks) Permit(int64, int32, string, string) bool {
	if c.wait != nil {
		close(c.wait)
		<-c.release
	}
	return c.allowed.Load()
}
func (c *testCallbacks) Event(event string) { c.events = append(c.events, event) }

func fixture(callbacks *testCallbacks) *engine {
	e := &engine{callbacks: callbacks}
	e.active.Store(true)
	return e
}

func addresses(destination string) M.Metadata {
	return M.Metadata{
		Source:      M.ParseSocksaddr("10.99.0.1:41234"),
		Destination: M.ParseSocksaddr(destination),
	}
}

func TestDisabledICMPDoesNotPretendRemoteHostsAreReachable(t *testing.T) {
	handler := &sing_tun.ListenerHandler{DisableICMPForwarding: true}
	for _, address := range []string{"10.0.0.1", "10.147.17.1", "1.1.1.1", "fd00::1", "2606:4700:4700::1111"} {
		t.Run(address, func(t *testing.T) {
			// No route writer or network dialer is supplied. The disabled path
			// must terminate before any direct/raw ICMP socket can be opened.
			action, err := handler.PrepareConnection(network.NetworkICMP,
				M.ParseSocksaddr("10.99.0.1:0"),
				M.SocksaddrFrom(netip.MustParseAddr(address), 0), nil, time.Millisecond)
			if action != nil || !errors.Is(err, tun.ErrDrop) {
				t.Fatalf("disabled ICMP must drop, got action=%v err=%v", action, err)
			}
		})
	}

	// Preserve the upstream's local-interface behavior when forwarding is
	// deliberately enabled by a different embedding application.
	local := &sing_tun.ListenerHandler{Inet4Address: []netip.Prefix{netip.MustParsePrefix("10.99.0.1/30")}}
	action, err := local.PrepareConnection(network.NetworkICMP, M.ParseSocksaddr("10.99.0.1:0"),
		M.ParseSocksaddr("10.99.0.2:0"), nil, time.Millisecond)
	if action != nil || err != nil {
		t.Fatalf("upstream local-interface handling changed: action=%v err=%v", action, err)
	}
}

// A nil ordinary ListenerHandler and panicking packet initializer make this
// fail if a denied request reaches DNS handling or any normal routing path.
func TestDeniedIngressPrecedesDNSAndEveryOutbound(t *testing.T) {
	for _, state := range []string{"pending", "denied"} {
		for _, destination := range []string{
			"10.99.0.2:53", "[fd99:7072:6976::2]:53",
			"1.1.1.1:443", "8.8.8.8:443", "10.147.17.1:80",
		} {
			t.Run(state+"/"+destination, func(t *testing.T) {
				e := fixture(&testCallbacks{uid: 10087})
				sing_tun.SetIngressGuard(e)
				defer sing_tun.SetIngressGuard(nil)
				h := &sing_tun.ListenerHandler{DnsAddrPorts: []netip.AddrPort{
					netip.MustParseAddrPort("0.0.0.0:53"),
					netip.MustParseAddrPort("[::]:53"),
				}}
				conn := &testConn{}
				if err := h.NewConnection(context.Background(), conn, addresses(destination)); !errors.Is(err, errDenied) {
					t.Fatalf("TCP rejection = %v", err)
				}
				if !conn.closed.Load() {
					t.Fatal("denied TCP remains open")
				}
				h.NewPacket(context.Background(), netip.MustParseAddrPort("10.99.0.1:41234"),
					buf.As([]byte{0, 1, 2}), addresses(destination),
					func(network.PacketConn) network.PacketWriter { panic("denied UDP reached upstream writer") })
				packets := &testPacketConn{}
				if err := h.NewPacketConnection(context.Background(), packets, addresses(destination)); !errors.Is(err, errDenied) {
					t.Fatalf("UDP session rejection = %v", err)
				}
				if !packets.closed.Load() {
					t.Fatal("denied UDP session remains open")
				}
			})
		}
	}
}

func TestAllowedConnectionPreservesOriginalOwnerAndRevokes(t *testing.T) {
	callbacks := &testCallbacks{uid: 10087}
	callbacks.allowed.Store(true)
	e := fixture(callbacks)
	raw := &testConn{}
	ctx, tracked, err := e.TCP(context.Background(), raw, addresses("10.147.17.1:80"))
	if err != nil {
		t.Fatal(err)
	}
	metadata := &C.Metadata{}
	inbound.ApplyAdditions(metadata, sing.AdditionsFromContext(ctx)...)
	if metadata.Uid != 10087 || callbacks.protocol != 6 || callbacks.source != "10.99.0.1:41234" || callbacks.destination != "10.147.17.1:80" {
		t.Fatalf("original flow ownership not preserved: %+v / %+v", metadata, callbacks)
	}
	e.closeConnections()
	if !raw.closed.Load() {
		t.Fatal("revoked TCP remains open")
	}
	_ = tracked.Close()
}

func TestEstablishedTCPExpiryRejectsUploadAndDownloadWithoutAlarm(t *testing.T) {
	for _, direction := range []string{"upload", "download"} {
		t.Run(direction, func(t *testing.T) {
			callbacks := &testCallbacks{uid: 10087}
			callbacks.allowed.Store(true)
			e := fixture(callbacks)
			raw := &flowTestConn{}
			_, conn, err := e.TCP(context.Background(), raw, addresses("10.147.17.1:443"))
			if err != nil {
				t.Fatal(err)
			}
			// Simulate elapsed-time expiry without running an Android alarm or
			// calling closeConnections: the established flow must recheck policy.
			callbacks.allowed.Store(false)
			var n int
			if direction == "upload" {
				n, err = conn.Read(make([]byte, 32))
			} else {
				n, err = conn.Write([]byte("private data"))
			}
			if n != 0 || !errors.Is(err, errDenied) {
				t.Fatalf("expired flow returned (%d, %v)", n, err)
			}
			if raw.reads != 0 || raw.writes != 0 || !raw.closed.Load() {
				t.Fatalf("expired flow reached underlying I/O: reads=%d writes=%d closed=%v",
					raw.reads, raw.writes, raw.closed.Load())
			}
		})
	}
}

func TestTCPReadCrossingExpiryDoesNotReleaseUploadBytes(t *testing.T) {
	callbacks := &testCallbacks{uid: 10087}
	callbacks.allowed.Store(true)
	e := fixture(callbacks)
	raw := &flowTestConn{afterRead: func() { callbacks.allowed.Store(false) }}
	_, conn, err := e.TCP(context.Background(), raw, addresses("1.1.1.1:443"))
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 32)
	n, err := conn.Read(payload)
	if n != 0 || !errors.Is(err, errDenied) || raw.reads != 1 || !raw.closed.Load() {
		t.Fatalf("read crossing expiry returned (%d, %v), reads=%d closed=%v", n, err, raw.reads, raw.closed.Load())
	}
	for _, value := range payload {
		if value != 0 {
			t.Fatal("upload bytes remained visible after denied read")
		}
	}
}

func TestTCPRechecksRetainedOwnerAndCannotExposeCopyBypasses(t *testing.T) {
	callbacks := &ownerTrackingCallbacks{testCallbacks: testCallbacks{uid: 10087}}
	callbacks.allowed.Store(true)
	e := &engine{callbacks: callbacks}
	e.active.Store(true)
	raw := &flowTestConn{}
	_, conn, err := e.TCP(context.Background(), raw, addresses("1.1.1.1:443"))
	if err != nil {
		t.Fatal(err)
	}
	// An established socket can leave Android's owner lookup table. A later
	// recheck must still use the original admitted application's identity.
	callbacks.uid = -1
	if n, err := conn.Read(make([]byte, 32)); n == 0 || err != nil {
		t.Fatalf("allowed read returned (%d, %v)", n, err)
	}
	if n, err := conn.Write([]byte("reply")); n != 5 || err != nil {
		t.Fatalf("allowed write returned (%d, %v)", n, err)
	}
	if callbacks.resolutions.Load() != 1 || callbacks.permittedUID.Load() != 10087 {
		t.Fatalf("flow identity changed: resolutions=%d uid=%d", callbacks.resolutions.Load(), callbacks.permittedUID.Load())
	}
	if _, ok := conn.(io.ReaderFrom); ok {
		t.Fatal("ReaderFrom bypasses guarded writes")
	}
	if _, ok := conn.(io.WriterTo); ok {
		t.Fatal("WriterTo bypasses guarded reads")
	}
	if _, ok := conn.(interface{ Upstream() any }); ok {
		t.Fatal("Upstream exposes unguarded connection")
	}
	if _, ok := conn.(syscall.Conn); ok {
		t.Fatal("SyscallConn exposes unguarded descriptor")
	}
	e.active.Store(false)
	if n, err := conn.Write([]byte("after stop")); n != 0 || !errors.Is(err, errDenied) || raw.writes != 1 {
		t.Fatalf("stopped engine write returned (%d, %v), writes=%d", n, err, raw.writes)
	}
}

type ownerTrackingCallbacks struct {
	testCallbacks
	resolutions  atomic.Int32
	permittedUID atomic.Int64
}

func (c *ownerTrackingCallbacks) ResolveUid(protocol int32, source, destination string) int64 {
	c.resolutions.Add(1)
	return c.testCallbacks.ResolveUid(protocol, source, destination)
}

func (c *ownerTrackingCallbacks) Permit(uid int64, protocol int32, source, destination string) bool {
	c.permittedUID.Store(uid)
	return c.testCallbacks.Permit(uid, protocol, source, destination)
}

type flowTestConn struct {
	testConn
	reads, writes int
	afterRead     func()
}

func (c *flowTestConn) Read(p []byte) (int, error) {
	c.reads++
	n := copy(p, "private data")
	if c.afterRead != nil {
		c.afterRead()
	}
	return n, nil
}

func (c *flowTestConn) Write(p []byte) (int, error) {
	c.writes++
	return len(p), nil
}

func (*flowTestConn) ReadFrom(io.Reader) (int64, error)     { panic("unguarded ReadFrom") }
func (*flowTestConn) WriteTo(io.Writer) (int64, error)      { panic("unguarded WriteTo") }
func (*flowTestConn) Upstream() any                         { panic("unguarded Upstream") }
func (*flowTestConn) SyscallConn() (syscall.RawConn, error) { panic("unguarded SyscallConn") }

func TestRevocationRacingNewAdmissionFailsClosed(t *testing.T) {
	callbacks := &testCallbacks{uid: 10087, wait: make(chan struct{}), release: make(chan struct{})}
	callbacks.allowed.Store(true)
	e := fixture(callbacks)
	raw := &testConn{}
	done := make(chan error)
	go func() {
		_, _, err := e.TCP(context.Background(), raw, addresses("1.1.1.1:443"))
		done <- err
	}()
	<-callbacks.wait
	e.closeConnections()
	close(callbacks.release)
	if err := <-done; !errors.Is(err, errDenied) {
		t.Fatalf("racing admission escaped: %v", err)
	}
	if !raw.closed.Load() {
		t.Fatal("racing TCP remains open")
	}
}

func TestDatagramSessionRechecksEachDestination(t *testing.T) {
	callbacks := &testCallbacks{uid: 10087}
	callbacks.allowed.Store(true)
	e := fixture(callbacks)
	raw := &testPacketConn{destination: M.ParseSocksaddr("10.147.17.1:53")}
	_, conn, err := e.PacketConnection(context.Background(), raw, addresses("1.1.1.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	callbacks.allowed.Store(false)
	_, err = conn.ReadPacket(buf.New())
	if !errors.Is(err, errDenied) || !raw.closed.Load() {
		t.Fatalf("revoked UDP packet escaped: %v", err)
	}
	if callbacks.destination != "10.147.17.1:53" {
		t.Fatal("UDP destination switch skipped admission")
	}
}

func TestSocketProtectionRefusalAndStoppedEngineFailClosed(t *testing.T) {
	e := fixture(&testCallbacks{uid: 10087})
	if err := e.protect("tcp", "1.1.1.1:443", testRawConn{}); err == nil {
		t.Fatal("protect refusal ignored")
	}
	e.active.Store(false)
	if err := e.protect("udp", "1.1.1.1:53", testRawConn{}); err == nil {
		t.Fatal("stopped socket allowed")
	}
	if _, _, err := e.admit(context.Background(), 6, addresses("1.1.1.1:443")); !errors.Is(err, errDenied) {
		t.Fatal("stopped ingress allowed")
	}
}

func TestShortConnectionAccountingSettlesOnce(t *testing.T) {
	callbacks := &testCallbacks{}
	e := fixture(callbacks)
	statistic.SetLeaveObserver(e.usageClosed)
	defer statistic.SetLeaveObserver(nil)
	manager := &statistic.Manager{}
	tracker := &testTracker{info: &statistic.TrackerInfo{Metadata: &C.Metadata{
		Uid: 10087, NetWork: C.TCP, RawDstAddr: &net.TCPAddr{IP: net.ParseIP("10.147.17.1"), Port: 80},
	}}}
	tracker.info.UploadTotal.Store(123)
	tracker.info.DownloadTotal.Store(456)
	manager.Join(tracker)
	manager.Leave(tracker)
	manager.Leave(tracker)
	if len(callbacks.events) != 1 {
		t.Fatalf("short connection reported %d times", len(callbacks.events))
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(callbacks.events[0]), &event); err != nil {
		t.Fatal(err)
	}
	if event["sent"] != float64(123) || event["received"] != float64(456) || event["destination"] != "10.147.17.1:80" {
		t.Fatalf("incorrect settled event: %v", event)
	}
}

func TestZeroTierPreparationCreatesPublicIdentityWithoutApplicationFlow(t *testing.T) {
	previousHome, previousHook := C.Path.HomeDir(), dialer.DefaultSocketHook
	directory := t.TempDir()
	C.SetHomeDir(directory)
	// Identity creation must work even when physical network access fails.
	dialer.DefaultSocketHook = func(string, string, syscall.RawConn) error { return errors.New("fixture rejects physical sockets") }
	defer func() {
		C.SetHomeDir(previousHome)
		dialer.DefaultSocketHook = previousHook
	}()
	config, err := executor.ParseWithBytes([]byte("proxies:\n  - name: test-home\n    type: zerotier\n    network: 0123456789abcdef\n    state-dir: zerotier/home\n    udp: true\nrules:\n  - MATCH,REJECT\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, proxy := range config.Proxies {
		defer proxy.Close()
	}
	preparer, ok := config.Proxies["test-home"].Adapter().(interface{ PrepareIdentity() error })
	if !ok {
		t.Fatal("configured ZeroTier adapter does not expose identity preparation")
	}
	statusProvider, ok := config.Proxies["test-home"].Adapter().(interface{ HomeStatus() string })
	if !ok {
		t.Fatal("configured ZeroTier adapter does not forward public status")
	}
	lifecycle.Lock()
	previousEngine := running
	running = &engine{home: statusProvider}
	lifecycle.Unlock()
	defer func() {
		lifecycle.Lock()
		running = previousEngine
		lifecycle.Unlock()
	}()
	before := decodeHomeStatus(t, HomeStatus())
	if before["initialized"] != false || before["state"] != "initializing" {
		t.Fatalf("unexpected uninitialized state: %v", before)
	}
	if before["tcpFallbackMode"] != "auto" {
		t.Fatalf("default fallback mode missing from public status: %v", before)
	}
	if err := preparer.PrepareIdentity(); err != nil {
		t.Fatal(err)
	}
	public, err := os.ReadFile(filepath.Join(directory, "zerotier", "home", "identity.public"))
	if err != nil {
		t.Fatal(err)
	}
	if len(public) < 11 || public[10] != ':' {
		t.Fatal("prepared public identity does not contain a node address")
	}
	statusText := HomeStatus()
	status := decodeHomeStatus(t, statusText)
	if status["nodeId"] != string(public[:10]) || status["initialized"] != true ||
		status["state"] != "config-pending" || status["networkStatus"] != "requesting-configuration" ||
		status["stackReady"] != false || len(status["assignedIps"].([]any)) != 0 {
		t.Fatalf("incorrect pending-controller status: %v", status)
	}
	secret, err := os.ReadFile(filepath.Join(directory, "zerotier", "home", "identity.secret"))
	if err != nil {
		t.Fatal(err)
	}
	secretParts := strings.Split(string(secret), ":")
	if len(secretParts) != 4 || strings.Contains(statusText, secretParts[3]) ||
		strings.Contains(statusText, directory) || strings.Contains(statusText, "identity.secret") {
		t.Fatal("public status exposes secret material or a private state path")
	}
	allowedFields := map[string]bool{
		"state": true, "initialized": true, "nodeId": true, "networkStatus": true,
		"stackReady": true, "assignedIps": true, "managedRoutes": true,
		"knownPeers": true, "peersWithActivePath": true, "activePeerPaths": true,
		"tcpFallbackMode": true,
	}
	for name := range status {
		if !allowedFields[name] {
			t.Fatalf("unexpected public diagnostic field %q", name)
		}
	}
	concurrentStatus := make(chan error, 1)
	go func() {
		for index := 0; index < 100; index++ {
			var snapshot map[string]any
			if err := json.Unmarshal([]byte(HomeStatus()), &snapshot); err != nil {
				concurrentStatus <- err
				return
			}
		}
		concurrentStatus <- nil
	}()
	if err := config.Proxies["test-home"].Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-concurrentStatus; err != nil {
		t.Fatalf("status query racing overlay shutdown failed: %v", err)
	}
	closed := decodeHomeStatus(t, HomeStatus())
	if closed["state"] != "closed" || closed["initialized"] != false || closed["stackReady"] != false {
		t.Fatalf("closed overlay status remains ready: %v", closed)
	}
}

func TestHomeStatusReportsConfiguredFallbackModeWithoutPhysicalEndpoints(t *testing.T) {
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	defer C.SetHomeDir(previousHome)
	for _, mode := range []string{"auto", "force", "disable"} {
		t.Run(mode, func(t *testing.T) {
			config, err := executor.ParseWithBytes([]byte("proxies:\n  - name: test-home\n    type: zerotier\n    network: 0123456789abcdef\n    state-dir: zerotier/test-" + mode + "\n    tcp-fallback-mode: " + mode + "\nrules:\n  - MATCH,REJECT\n"))
			if err != nil {
				t.Fatal(err)
			}
			for _, proxy := range config.Proxies {
				defer proxy.Close()
			}
			provider := config.Proxies["test-home"].Adapter().(interface{ HomeStatus() string })
			text := provider.HomeStatus()
			status := decodeHomeStatus(t, text)
			if status["tcpFallbackMode"] != mode || status["initialized"] != false {
				t.Fatalf("configured mode must not imply a connected relay: %v", status)
			}
			if strings.Contains(text, "204.80.128.1") || strings.Contains(text, "tcpRelayConnected") {
				t.Fatal("public status leaked endpoint or fabricated unsupported connection state")
			}
		})
	}
}

func TestHomeStatusReadyMeansLocalConfigurationNotReachability(t *testing.T) {
	previousHome, previousHook := C.Path.HomeDir(), dialer.DefaultSocketHook
	C.SetHomeDir(t.TempDir())
	dialer.DefaultSocketHook = func(string, string, syscall.RawConn) error { return errors.New("fixture rejects physical sockets") }
	defer func() {
		C.SetHomeDir(previousHome)
		dialer.DefaultSocketHook = previousHook
	}()
	// Ad-hoc networks produce their own valid controllerless configuration.
	// This checks actual accepted addresses and stack readiness while every
	// physical socket is refused, without requiring a live private controller.
	config, err := executor.ParseWithBytes([]byte("proxies:\n  - name: test-home\n    type: zerotier\n    network: ff00160050000000\n    state-dir: zerotier/home\n    ip-stack: {mode: gvisor}\n    udp: true\nrules:\n  - MATCH,REJECT\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, proxy := range config.Proxies {
		defer proxy.Close()
	}
	adapter := config.Proxies["test-home"].Adapter()
	if err := adapter.(interface{ PrepareIdentity() error }).PrepareIdentity(); err != nil {
		t.Fatal(err)
	}
	provider := adapter.(interface{ HomeStatus() string })
	deadline := time.Now().Add(3 * time.Second)
	var status map[string]any
	for {
		status = decodeHomeStatus(t, provider.HomeStatus())
		if status["state"] == "ready" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ad-hoc configuration did not become ready: %v", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if status["networkStatus"] != "ok" || status["stackReady"] != true ||
		len(status["assignedIps"].([]any)) == 0 {
		t.Fatalf("ready overlay has no applied managed address: %v", status)
	}
	for _, address := range status["assignedIps"].([]any) {
		if _, err := netip.ParsePrefix(address.(string)); err != nil {
			t.Fatal("public diagnostic address is not a valid managed prefix")
		}
	}
}

func decodeHomeStatus(t *testing.T, value string) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(value), &decoded); err != nil {
		t.Fatalf("invalid public HomeStatus JSON: %v", err)
	}
	return decoded
}

type testTracker struct{ info *statistic.TrackerInfo }

func (*testTracker) ID() string                     { return "short-connection" }
func (*testTracker) Close() error                   { return nil }
func (t *testTracker) Info() *statistic.TrackerInfo { return t.info }
func (*testTracker) Chains() C.Chain                { return nil }
func (*testTracker) ProviderChains() C.Chain        { return nil }
func (*testTracker) AppendToChains(C.ProxyAdapter)  {}
func (*testTracker) RemoteDestination() string      { return "10.147.17.1:80" }

type testConn struct{ closed atomic.Bool }

func (*testConn) Read([]byte) (int, error)         { panic("unexpected upstream read") }
func (*testConn) Write([]byte) (int, error)        { panic("unexpected upstream write") }
func (c *testConn) Close() error                   { c.closed.Store(true); return nil }
func (*testConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*testConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*testConn) SetDeadline(time.Time) error      { return nil }
func (*testConn) SetReadDeadline(time.Time) error  { return nil }
func (*testConn) SetWriteDeadline(time.Time) error { return nil }

type testPacketConn struct {
	closed      atomic.Bool
	destination M.Socksaddr
}

func (c *testPacketConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	if !c.destination.IsValid() {
		panic("denied UDP reached upstream reader")
	}
	return c.destination, nil
}
func (*testPacketConn) WritePacket(*buf.Buffer, M.Socksaddr) error {
	panic("unexpected upstream packet write")
}
func (c *testPacketConn) Close() error                   { c.closed.Store(true); return nil }
func (*testPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*testPacketConn) SetDeadline(time.Time) error      { return nil }
func (*testPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*testPacketConn) SetWriteDeadline(time.Time) error { return nil }

type testRawConn struct{}

func (testRawConn) Control(f func(uintptr)) error  { f(42); return nil }
func (testRawConn) Read(func(uintptr) bool) error  { return syscall.EINVAL }
func (testRawConn) Write(func(uintptr) bool) error { return syscall.EINVAL }
