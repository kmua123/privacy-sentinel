package guardcore

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/observable"
	corelog "github.com/metacubex/mihomo/log"
	M "github.com/metacubex/sing/common/metadata"
)

const maxUnknownUIDSamples = 24

var currentNetworkDiagnostics atomic.Pointer[networkDiagnosticsState]
var lastNetworkDiagnosticsSession atomic.Int64

type logDiagnosticCounts struct {
	TCP         int64 `json:"tcp"`
	UDP         int64 `json:"udp"`
	DNS         int64 `json:"dns"`
	Timeout     int64 `json:"timeout"`
	Unreachable int64 `json:"unreachable"`
	Refused     int64 `json:"refused"`
	TLS         int64 `json:"tls"`
	Other       int64 `json:"other"`
}

// These count fixed resolver debug events, not all client questions. A cached
// response or a dropped best-effort event may not appear here.
type dnsQueryDiagnosticCounts struct {
	A     int64 `json:"a"`
	AAAA  int64 `json:"aaaa"`
	HTTPS int64 `json:"https"`
	SVCB  int64 `json:"svcb"`
	Other int64 `json:"other"`
}

type unknownUIDSample struct {
	UID         int64  `json:"uid"`
	Protocol    int32  `json:"protocol"`
	Destination string `json:"destination"`
	Reason      string `json:"reason"`
	Count       int64  `json:"count"`
	Time        int64  `json:"time"`
}

type networkDiagnosticsSnapshot struct {
	Running           bool                     `json:"running"`
	Session           int64                    `json:"session"`
	UIDLookups        int64                    `json:"uidLookups"`
	UnknownUID        int64                    `json:"unknownUid"`
	AllowedTCP        int64                    `json:"allowedTcp"`
	AllowedUDP        int64                    `json:"allowedUdp"`
	DeniedTCP         int64                    `json:"deniedTcp"`
	DeniedUDP         int64                    `json:"deniedUdp"`
	ProtectFailures   int64                    `json:"protectFailures"`
	LogEvents         int64                    `json:"logEvents"`
	LogEventsMayDrop  bool                     `json:"logEventsMayDrop"`
	LogCategories     logDiagnosticCounts      `json:"logCategories"`
	DNSLogFailures    int64                    `json:"dnsLogFailures"`
	DNSQueryTypes     dnsQueryDiagnosticCounts `json:"dnsQueryTypes"`
	UnknownUIDSamples []unknownUIDSample       `json:"unknownUidSamples"`
	ResolveUIDCalls   int64                    `json:"resolveUidCalls"`
	ResolveUIDTotalMS int64                    `json:"resolveUidTotalMs"`
	ResolveUIDMaxMS   int64                    `json:"resolveUidMaxMs"`
	ResolveUIDSlow    int64                    `json:"resolveUidSlowCalls"`
	PermitCalls       int64                    `json:"permitCalls"`
	PermitTotalMS     int64                    `json:"permitTotalMs"`
	PermitMaxMS       int64                    `json:"permitMaxMs"`
	PermitSlow        int64                    `json:"permitSlowCalls"`
	SlowThresholdMS   int64                    `json:"slowCallbackThresholdMs"`
}

// Diagnostic state is session-local and never participates in an authorization
// decision. Counters count checks (UDP may be checked per packet), not completed
// connections or proof a remote server responded.
type networkDiagnosticsState struct {
	session         int64
	running         atomic.Bool
	uidLookups      atomic.Int64
	unknownUID      atomic.Int64
	allowedTCP      atomic.Int64
	allowedUDP      atomic.Int64
	deniedTCP       atomic.Int64
	deniedUDP       atomic.Int64
	protectFailures atomic.Int64
	logEvents       atomic.Int64
	logTCP          atomic.Int64
	logUDP          atomic.Int64
	logDNS          atomic.Int64
	logTimeout      atomic.Int64
	logUnreachable  atomic.Int64
	logRefused      atomic.Int64
	logTLS          atomic.Int64
	logOther        atomic.Int64
	dnsLogFailures  atomic.Int64
	dnsQueryA       atomic.Int64
	dnsQueryAAAA    atomic.Int64
	dnsQueryHTTPS   atomic.Int64
	dnsQuerySVCB    atomic.Int64
	dnsQueryOther   atomic.Int64
	resolveUIDCalls atomic.Int64
	resolveUIDNanos atomic.Int64
	resolveUIDMax   atomic.Int64
	resolveUIDSlow  atomic.Int64
	permitCalls     atomic.Int64
	permitNanos     atomic.Int64
	permitMax       atomic.Int64
	permitSlow      atomic.Int64

	samplesMu sync.Mutex
	samples   []unknownUIDSample

	observerMu   sync.Mutex
	subscription observable.Subscription[corelog.Event]
	observerDone chan struct{}
	stopped      bool
}

func newNetworkDiagnostics() *networkDiagnosticsState {
	var session int64
	for {
		previous := lastNetworkDiagnosticsSession.Load()
		session = max(time.Now().UnixMilli(), previous+1)
		if lastNetworkDiagnosticsSession.CompareAndSwap(previous, session) {
			break
		}
	}
	d := &networkDiagnosticsState{session: session, samples: []unknownUIDSample{}}
	d.running.Store(true)
	return d
}

func (d *networkDiagnosticsState) recordAdmission(uid int64, protocol int32, destination M.Socksaddr, allowed bool) {
	if d == nil || !d.running.Load() {
		return
	}
	d.uidLookups.Add(1)
	if protocol == 6 {
		if allowed {
			d.allowedTCP.Add(1)
		} else {
			d.deniedTCP.Add(1)
		}
	} else if protocol == 17 {
		if allowed {
			d.allowedUDP.Add(1)
		} else {
			d.deniedUDP.Add(1)
		}
	}
	if uid >= 0 {
		return
	}
	d.unknownUID.Add(1)
	// TUN packets have literal IP destinations. Never retain a hostname from
	// an adapter/test metadata object, let alone a URL or raw log message.
	address := ""
	if destination.Addr.IsValid() {
		address = net.JoinHostPort(destination.Addr.Unmap().String(), strconv.Itoa(int(destination.Port)))
	}
	now := time.Now().UnixMilli()
	d.samplesMu.Lock()
	defer d.samplesMu.Unlock()
	if !d.running.Load() {
		return
	}
	for index := range d.samples {
		item := &d.samples[index]
		if item.UID == uid && item.Protocol == protocol && item.Destination == address {
			item.Count++
			item.Time = now
			return
		}
	}
	if len(d.samples) == maxUnknownUIDSamples {
		copy(d.samples, d.samples[1:])
		d.samples = d.samples[:maxUnknownUIDSamples-1]
	}
	d.samples = append(d.samples, unknownUIDSample{UID: uid, Protocol: protocol,
		Destination: address, Reason: "unknown_uid", Count: 1, Time: now})
}

func (d *networkDiagnosticsState) recordProtectFailure() {
	if d != nil && d.running.Load() {
		d.protectFailures.Add(1)
	}
}

func (d *networkDiagnosticsState) recordCallback(permit bool, elapsed time.Duration) {
	if d == nil || !d.running.Load() {
		return
	}
	calls, total, highest, slow := &d.resolveUIDCalls, &d.resolveUIDNanos, &d.resolveUIDMax, &d.resolveUIDSlow
	if permit {
		calls, total, highest, slow = &d.permitCalls, &d.permitNanos, &d.permitMax, &d.permitSlow
	}
	calls.Add(1)
	total.Add(int64(elapsed))
	for {
		previous := highest.Load()
		if int64(elapsed) <= previous || highest.CompareAndSwap(previous, int64(elapsed)) {
			break
		}
	}
	if elapsed >= 50*time.Millisecond {
		slow.Add(1)
	}
}

// Only fixed classification counters survive this call. Payloads can contain
// hostnames, subscription URLs and secrets and are intentionally never retained.
func (d *networkDiagnosticsState) observeLog(event corelog.Event) {
	if d == nil || !d.running.Load() {
		return
	}
	value := strings.ToLower(event.Payload)
	if event.LogLevel == corelog.DEBUG {
		if strings.HasPrefix(value, "[dns] resolve ") {
			// Format is pinned in mihomo/dns/util.go. Extract only the fixed
			// type token preceding " from "; never keep the queried name or
			// the upstream URL, which may include credentials.
			if before, _, ok := strings.Cut(value, " from "); ok {
				fields := strings.Fields(before)
				if len(fields) >= 4 {
					switch fields[len(fields)-1] {
					case "a":
						d.dnsQueryA.Add(1)
					case "aaaa":
						d.dnsQueryAAAA.Add(1)
					case "https":
						d.dnsQueryHTTPS.Add(1)
					case "svcb":
						d.dnsQuerySVCB.Add(1)
					default:
						d.dnsQueryOther.Add(1)
					}
				}
			}
			return
		}
		// Ordinary TUN DNS exchange failures are DEBUG, not WARNING. Only
		// this fixed failure prefix is selected from other debug events.
		if !strings.HasPrefix(value, "[dns server] exchange ") || !strings.Contains(value, " failed:") {
			return
		}
		d.dnsLogFailures.Add(1)
	} else if event.LogLevel != corelog.WARNING && event.LogLevel != corelog.ERROR {
		return
	}
	d.logEvents.Add(1)
	matched := false
	count := func(condition bool, counter *atomic.Int64) {
		if condition {
			counter.Add(1)
			matched = true
		}
	}
	count(strings.Contains(value, "[tcp]") || strings.Contains(value, "dial tcp"), &d.logTCP)
	count(strings.Contains(value, "[udp]") || strings.Contains(value, "dial udp"), &d.logUDP)
	count(strings.Contains(value, "dns") || strings.Contains(value, "lookup") || strings.Contains(value, "resolve"), &d.logDNS)
	count(strings.Contains(value, "timeout") || strings.Contains(value, "timed out") || strings.Contains(value, "deadline exceeded"), &d.logTimeout)
	count(strings.Contains(value, "unreachable") || strings.Contains(value, "no route to host") || strings.Contains(value, "cannot assign requested address"), &d.logUnreachable)
	count(strings.Contains(value, "refused"), &d.logRefused)
	count(strings.Contains(value, "tls") || strings.Contains(value, "x509") || strings.Contains(value, "certificate"), &d.logTLS)
	if !matched {
		d.logOther.Add(1)
	}
}

func (d *networkDiagnosticsState) startLogObserver() {
	if d == nil {
		return
	}
	d.observerMu.Lock()
	defer d.observerMu.Unlock()
	if d.stopped || d.subscription != nil {
		return
	}
	// This diagnostic alone uses a nonblocking bounded subscription. A burst
	// can drop log events, but cannot stall upstream forwarding/log writers.
	subscription := corelog.SubscribeNonBlocking()
	if subscription == nil {
		return
	}
	d.subscription = subscription
	d.observerDone = make(chan struct{})
	done := d.observerDone
	go func() {
		defer close(done)
		for event := range subscription {
			d.observeLog(event)
		}
	}()
}

func (d *networkDiagnosticsState) stop() {
	if d == nil {
		return
	}
	d.running.Store(false)
	d.observerMu.Lock()
	d.stopped = true
	subscription := d.subscription
	d.subscription = nil
	d.observerMu.Unlock()
	if subscription != nil {
		// UnSubscribe closes the bounded channel. The consumer drains/returns
		// asynchronously; Stop never waits for work while holding lifecycle.
		corelog.UnSubscribe(subscription)
	}
}

func (d *networkDiagnosticsState) snapshot() networkDiagnosticsSnapshot {
	value := networkDiagnosticsSnapshot{LogEventsMayDrop: true, UnknownUIDSamples: []unknownUIDSample{}, SlowThresholdMS: 50}
	if d == nil {
		return value
	}
	value.Running = d.running.Load()
	value.Session = d.session
	value.UIDLookups = d.uidLookups.Load()
	value.UnknownUID = d.unknownUID.Load()
	value.AllowedTCP = d.allowedTCP.Load()
	value.AllowedUDP = d.allowedUDP.Load()
	value.DeniedTCP = d.deniedTCP.Load()
	value.DeniedUDP = d.deniedUDP.Load()
	value.ProtectFailures = d.protectFailures.Load()
	value.LogEvents = d.logEvents.Load()
	value.DNSLogFailures = d.dnsLogFailures.Load()
	value.DNSQueryTypes = dnsQueryDiagnosticCounts{A: d.dnsQueryA.Load(), AAAA: d.dnsQueryAAAA.Load(),
		HTTPS: d.dnsQueryHTTPS.Load(), SVCB: d.dnsQuerySVCB.Load(), Other: d.dnsQueryOther.Load()}
	value.ResolveUIDCalls = d.resolveUIDCalls.Load()
	value.ResolveUIDTotalMS = d.resolveUIDNanos.Load() / int64(time.Millisecond)
	value.ResolveUIDMaxMS = d.resolveUIDMax.Load() / int64(time.Millisecond)
	value.ResolveUIDSlow = d.resolveUIDSlow.Load()
	value.PermitCalls = d.permitCalls.Load()
	value.PermitTotalMS = d.permitNanos.Load() / int64(time.Millisecond)
	value.PermitMaxMS = d.permitMax.Load() / int64(time.Millisecond)
	value.PermitSlow = d.permitSlow.Load()
	value.LogCategories = logDiagnosticCounts{
		TCP: d.logTCP.Load(), UDP: d.logUDP.Load(), DNS: d.logDNS.Load(), Timeout: d.logTimeout.Load(),
		Unreachable: d.logUnreachable.Load(), Refused: d.logRefused.Load(), TLS: d.logTLS.Load(), Other: d.logOther.Load(),
	}
	d.samplesMu.Lock()
	value.UnknownUIDSamples = append(value.UnknownUIDSamples, d.samples...)
	d.samplesMu.Unlock()
	return value
}

// NetworkDiagnostics returns local, bounded troubleshooting counters. It never
// contains raw log payloads, DNS names, URLs, packet contents or credentials.
// Unknown-UID samples contain only the literal IP/port from an admitted TUN
// packet; they remain untrusted/unattributed and never relax its policy.
// A stopped core retains one latest session for review; a new Start resets it.
func NetworkDiagnostics() string {
	data, _ := json.Marshal(currentNetworkDiagnostics.Load().snapshot())
	return string(data)
}
