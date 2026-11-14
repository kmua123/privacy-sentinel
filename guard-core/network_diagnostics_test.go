package guardcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/observable"
	corelog "github.com/metacubex/mihomo/log"
	M "github.com/metacubex/sing/common/metadata"
)

func diagnosticObject(t *testing.T, d *networkDiagnosticsState) map[string]any {
	t.Helper()
	data, err := json.Marshal(d.snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func diagnosticNumber(t *testing.T, object map[string]any, key string) int64 {
	t.Helper()
	value, ok := object[key].(float64)
	if !ok {
		t.Fatalf("missing numeric diagnostic field %q: %#v", key, object[key])
	}
	return int64(value)
}

func TestNetworkDiagnosticsClassifiesWithoutRetainingLogPayloads(t *testing.T) {
	d := newNetworkDiagnostics()
	defer d.stop()
	d.observeLog(corelog.Event{LogLevel: corelog.INFO, Payload: "ignored informational event"})
	for _, payload := range []string{
		"[TCP] dial DIRECT failed: DNS lookup https://private.example.invalid/path?token=diagnostic-secret failed with i/o timeout",
		"[UDP] network is unreachable",
		"TLS handshake failed for https://name:private-password@private.example.invalid",
		"connect: connection refused",
		"provider configuration failed",
	} {
		d.observeLog(corelog.Event{LogLevel: corelog.WARNING, Payload: payload})
	}
	value := diagnosticObject(t, d)
	if diagnosticNumber(t, value, "logEvents") != 5 {
		t.Fatalf("info must be ignored and five warnings counted: %+v", value)
	}
	categories, ok := value["logCategories"].(map[string]any)
	if !ok {
		t.Fatal("log categories are not an object")
	}
	for _, category := range []string{"tcp", "udp", "dns", "timeout", "unreachable", "refused", "tls", "other"} {
		if diagnosticNumber(t, categories, category) != 1 {
			t.Errorf("category %s = %v, want 1", category, categories[category])
		}
	}
	if value["logEventsMayDrop"] != true {
		t.Fatal("best-effort log observation must be declared")
	}
	encoded, _ := json.Marshal(value)
	for _, forbidden := range []string{"diagnostic-secret", "private-password", "private.example.invalid", "https://", "configuration failed", "dial DIRECT"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Errorf("raw warning content escaped diagnostics: %q", forbidden)
		}
	}
}

func TestNetworkDiagnosticsCountsSelectedDNSDebugEventsPrivately(t *testing.T) {
	d := newNetworkDiagnostics()
	defer d.stop()
	for _, qtype := range []string{"A", "AAAA", "HTTPS", "SVCB", "TXT"} {
		d.observeLog(corelog.Event{LogLevel: corelog.DEBUG,
			Payload: "[DNS] resolve token-diagnostic.example.invalid " + qtype + " from https://username:password@resolver.invalid/dns-query?key=hidden-secret"})
	}
	// Other debug lines and incomplete query lines are not mistaken for a
	// resolver attempt, even when they happen to mention DNS or a type name.
	d.observeLog(corelog.Event{LogLevel: corelog.DEBUG, Payload: "[DNS] cache hit token-diagnostic.example.invalid --> AAAA"})
	d.observeLog(corelog.Event{LogLevel: corelog.DEBUG, Payload: "[DNS] resolve from malformed"})
	d.observeLog(corelog.Event{LogLevel: corelog.DEBUG,
		Payload: "[DNS Server] Exchange ;token-diagnostic.example.invalid.\tIN\tHTTPS failed: DNS lookup https://resolver.invalid?key=hidden-secret i/o timeout"})
	value := diagnosticObject(t, d)
	if diagnosticNumber(t, value, "dnsLogFailures") != 1 || diagnosticNumber(t, value, "logEvents") != 1 {
		t.Fatalf("selected DEBUG DNS failure was missed: %+v", value)
	}
	types := value["dnsQueryTypes"].(map[string]any)
	for _, name := range []string{"a", "aaaa", "https", "svcb", "other"} {
		if diagnosticNumber(t, types, name) != 1 {
			t.Errorf("type %s = %v, want one resolver log", name, types[name])
		}
	}
	categories := value["logCategories"].(map[string]any)
	if diagnosticNumber(t, categories, "dns") != 1 || diagnosticNumber(t, categories, "timeout") != 1 {
		t.Fatalf("DEBUG DNS failure categories missing: %+v", categories)
	}
	encoded, _ := json.Marshal(value)
	for _, forbidden := range []string{"token-diagnostic", "resolver.invalid", "username", "password", "hidden-secret", "https://"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Errorf("DNS debug content escaped snapshot: %q", forbidden)
		}
	}
}

func TestGuardedTunAddressesMatchConfiguredIPv6(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		options := guardedTunOptions(123, ipv6)
		if len(options.Inet4Address) != 1 || options.Inet4Address[0].String() != "10.99.0.1/30" {
			t.Fatal("IPv4 support changed while configuring IPv6")
		}
		if ipv6 {
			if len(options.Inet6Address) != 1 || options.Inet6Address[0].String() != "fd99:7072:6976::1/126" {
				t.Fatal("IPv6-enabled host lost its corresponding native address")
			}
		} else if len(options.Inet6Address) != 0 {
			t.Fatal("IPv4-only configuration still advertises a native IPv6 address")
		}
		if len(options.DNSHijack) != 2 || options.DNSHijack[1] != "[::]:53" || !options.DisableICMPForwarding {
			t.Fatal("family configuration changed DNS admission or restored synthetic ICMP")
		}
	}
}

type delayedDiagnosticCallbacks struct {
	base *testCallbacks
}

type diagnosticIOConn struct{ testConn }

func (c *diagnosticIOConn) Read([]byte) (int, error)        { return 0, io.EOF }
func (c *diagnosticIOConn) Write(value []byte) (int, error) { return len(value), nil }

func (c *delayedDiagnosticCallbacks) Protect(fd int64) bool { return c.base.Protect(fd) }
func (c *delayedDiagnosticCallbacks) ResolveUid(protocol int32, source, destination string) int64 {
	time.Sleep(55 * time.Millisecond)
	return c.base.ResolveUid(protocol, source, destination)
}
func (c *delayedDiagnosticCallbacks) Permit(uid int64, protocol int32, source, destination string) bool {
	time.Sleep(55 * time.Millisecond)
	return c.base.Permit(uid, protocol, source, destination)
}
func (c *delayedDiagnosticCallbacks) Event(value string) { c.base.Event(value) }

func TestNetworkDiagnosticsMeasuresCallbacksIncludingEstablishedTCPChecks(t *testing.T) {
	base := &testCallbacks{uid: 10087}
	base.allowed.Store(true)
	d := newNetworkDiagnostics()
	defer d.stop()
	e := &engine{callbacks: &delayedDiagnosticCallbacks{base: base}, diagnostics: d}
	e.active.Store(true)
	_, conn, err := e.TCP(context.Background(), &diagnosticIOConn{}, addresses("192.0.2.9:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Read(make([]byte, 1))
	if _, err = conn.Write([]byte("permitted fixture")); err != nil {
		t.Fatal(err)
	}
	value := diagnosticObject(t, d)
	if diagnosticNumber(t, value, "resolveUidCalls") != 1 || diagnosticNumber(t, value, "resolveUidSlowCalls") != 1 {
		t.Fatalf("owner callback measurement missing: %+v", value)
	}
	if diagnosticNumber(t, value, "permitCalls") != 4 || diagnosticNumber(t, value, "permitSlowCalls") != 4 {
		t.Fatalf("established TCP checks were omitted from callback measurements: %+v", value)
	}
	if diagnosticNumber(t, value, "permitTotalMs") < 200 || diagnosticNumber(t, value, "permitMaxMs") < 50 || diagnosticNumber(t, value, "resolveUidMaxMs") < 50 {
		t.Fatalf("slow callback latency was not retained: %+v", value)
	}
	if diagnosticNumber(t, value, "allowedTcp") != 1 {
		t.Fatal("callback observations must not multiply initial ingress counts")
	}
}

func TestNetworkDiagnosticsBoundsAndDeduplicatesUnknownUIDSamples(t *testing.T) {
	d := newNetworkDiagnostics()
	defer d.stop()
	for index := 1; index <= 35; index++ {
		d.recordAdmission(-1, 17, M.ParseSocksaddr(fmt.Sprintf("192.0.2.%d:443", index)), false)
	}
	d.recordAdmission(-1, 17, M.ParseSocksaddr("192.0.2.35:443"), false)
	d.recordAdmission(-1, 17, M.ParseSocksaddr("192.0.2.35:443"), false)
	value := diagnosticObject(t, d)
	samples := value["unknownUidSamples"].([]any)
	if len(samples) != 24 {
		t.Fatalf("unknown UID sample storage grew to %d", len(samples))
	}
	duplicateFound := false
	for _, entry := range samples {
		sample := entry.(map[string]any)
		address := sample["destination"].(string)
		if _, err := netip.ParseAddrPort(address); err != nil {
			t.Fatalf("sample is not a literal IP and port: %q", address)
		}
		if sample["reason"] != "unknown_uid" || diagnosticNumber(t, sample, "uid") != -1 {
			t.Fatalf("invalid sample attribution: %+v", sample)
		}
		if diagnosticNumber(t, sample, "time") <= 0 {
			t.Fatal("sample is missing its observation time")
		}
		if address == "192.0.2.35:443" {
			duplicateFound = diagnosticNumber(t, sample, "count") == 3
		}
	}
	if !duplicateFound {
		t.Fatal("repeated unknown UDP ownership was not deduplicated and counted")
	}
	d.recordAdmission(10087, 17, M.ParseSocksaddr("198.51.100.1:443"), false)
	value = diagnosticObject(t, d)
	if len(value["unknownUidSamples"].([]any)) != 24 || diagnosticNumber(t, value, "unknownUid") != 37 || diagnosticNumber(t, value, "deniedUdp") != 38 {
		t.Fatalf("known policy denial polluted unknown samples or counters: %+v", value)
	}
}

func TestNetworkDiagnosticsSamplesDoNotRetainHostnames(t *testing.T) {
	d := newNetworkDiagnostics()
	defer d.stop()
	d.recordAdmission(-1, 6, M.ParseSocksaddr("private-token.example.invalid:443"), false)
	d.recordAdmission(-1, 6, M.ParseSocksaddr("[2001:db8::17]:8443"), false)
	value := diagnosticObject(t, d)
	encoded, _ := json.Marshal(value)
	if strings.Contains(string(encoded), "private-token") || strings.Contains(string(encoded), "example.invalid") {
		t.Fatal("hostname was retained in an unknown-UID sample")
	}
	seenIPv6 := false
	for _, entry := range value["unknownUidSamples"].([]any) {
		sample := entry.(map[string]any)
		destination := sample["destination"].(string)
		if destination == "" {
			continue
		}
		parsed, err := netip.ParseAddrPort(destination)
		if err != nil {
			t.Fatalf("non-literal destination: %q", destination)
		}
		seenIPv6 = seenIPv6 || parsed.Addr().Is6()
	}
	if !seenIPv6 {
		t.Fatal("IPv6 literal sample was lost")
	}
}

func TestNetworkDiagnosticsDoesNotChangeAdmissionOrProtection(t *testing.T) {
	callbacks := &testCallbacks{uid: -1}
	e := fixture(callbacks)
	d := newNetworkDiagnostics()
	e.diagnostics = d
	defer d.stop()
	raw := &testConn{}
	if _, _, err := e.TCP(context.Background(), raw, addresses("192.0.2.1:443")); !errors.Is(err, errDenied) || !raw.closed.Load() {
		t.Fatalf("diagnostic observation changed unknown UID rejection: err=%v closed=%v", err, raw.closed.Load())
	}
	value := diagnosticObject(t, d)
	if diagnosticNumber(t, value, "uidLookups") != 1 || diagnosticNumber(t, value, "unknownUid") != 1 || diagnosticNumber(t, value, "deniedTcp") != 1 {
		t.Fatalf("denied TCP was not observed: %+v", value)
	}
	callbacks.uid = 10087
	callbacks.allowed.Store(true)
	_, accepted, err := e.TCP(context.Background(), &testConn{}, addresses("192.0.2.2:443"))
	if err != nil {
		t.Fatalf("observation blocked a permitted TCP flow: %v", err)
	}
	defer accepted.Close()
	callbacks.allowed.Store(false)
	if _, err := accepted.Write([]byte("must remain blocked after revocation")); !errors.Is(err, errDenied) {
		t.Fatalf("diagnostics bypassed revocation: %v", err)
	}
	value = diagnosticObject(t, d)
	if diagnosticNumber(t, value, "allowedTcp") != 1 {
		t.Fatal("permitted initial admission was not observed")
	}
	if err := e.protect("tcp", "192.0.2.2:443", testRawConn{}); err == nil {
		t.Fatal("socket protection failure was ignored")
	}
	value = diagnosticObject(t, d)
	if diagnosticNumber(t, value, "protectFailures") != 1 {
		t.Fatal("failed protection was not counted")
	}
	callbacks.protected = true
	if err := e.protect("tcp", "192.0.2.2:443", testRawConn{}); err != nil {
		t.Fatalf("diagnostics rejected successful protection: %v", err)
	}
	if diagnosticNumber(t, diagnosticObject(t, d), "protectFailures") != 1 {
		t.Fatal("successful protection was counted as failed")
	}
}

func TestNetworkDiagnosticsConcurrentSnapshotsAreBounded(t *testing.T) {
	d := newNetworkDiagnostics()
	defer d.stop()
	var writers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		writers.Add(1)
		go func(worker int) {
			defer writers.Done()
			for index := 0; index < 500; index++ {
				uid := int64(10087)
				allowed := worker%2 == 0
				if !allowed {
					uid = -1
				}
				d.recordAdmission(uid, 17, M.ParseSocksaddr(fmt.Sprintf("192.0.2.%d:443", index%60+1)), allowed)
			}
		}(worker)
	}
	done := make(chan struct{})
	go func() { writers.Wait(); close(done) }()
	for {
		value := diagnosticObject(t, d)
		if len(value["unknownUidSamples"].([]any)) > 24 {
			t.Fatal("concurrent snapshot exceeded the bound")
		}
		select {
		case <-done:
			value = diagnosticObject(t, d)
			if diagnosticNumber(t, value, "uidLookups") != 4000 || diagnosticNumber(t, value, "allowedUdp") != 2000 || diagnosticNumber(t, value, "deniedUdp") != 2000 {
				t.Fatalf("concurrent observation lost counters: %+v", value)
			}
			return
		default:
		}
	}
}

func TestNetworkDiagnosticsObserverStopsAndDoesNotRestart(t *testing.T) {
	d := newNetworkDiagnostics()
	d.startLogObserver()
	defer d.stop()
	corelog.Warnln("[TCP] connection refused: diagnostic lifecycle fixture")
	deadline := time.Now().Add(time.Second)
	for diagnosticNumber(t, diagnosticObject(t, d), "logEvents") == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if diagnosticNumber(t, diagnosticObject(t, d), "logEvents") == 0 {
		t.Fatal("active diagnostics observer did not receive an actual warning")
	}
	d.stop()
	value := diagnosticObject(t, d)
	before := diagnosticNumber(t, value, "logEvents")
	if value["running"] != false {
		t.Fatal("stopped diagnostics are presented as running")
	}
	d.startLogObserver()
	corelog.Warnln("[UDP] stopped diagnostic fixture")
	time.Sleep(20 * time.Millisecond)
	if diagnosticNumber(t, diagnosticObject(t, d), "logEvents") != before {
		t.Fatal("stopped diagnostics observer counted later warnings or restarted")
	}
}

func TestNetworkDiagnosticsSessionAndSnapshotDoNotWaitForCoreLock(t *testing.T) {
	first := newNetworkDiagnostics()
	defer first.stop()
	second := newNetworkDiagnostics()
	defer second.stop()
	if diagnosticNumber(t, diagnosticObject(t, second), "session") <= diagnosticNumber(t, diagnosticObject(t, first), "session") {
		t.Fatal("core diagnostics session did not advance")
	}
	previous := currentNetworkDiagnostics.Swap(second)
	defer currentNetworkDiagnostics.Store(previous)
	lifecycle.Lock()
	defer lifecycle.Unlock()
	result := make(chan string, 1)
	go func() { result <- NetworkDiagnostics() }()
	select {
	case value := <-result:
		if !json.Valid([]byte(value)) {
			t.Fatal("network diagnostics JSON is invalid")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("diagnostic snapshot waited for a potentially slow core lifecycle operation")
	}
}

func TestNetworkDiagnosticsLogSubscriptionDoesNotBackpressurePublishers(t *testing.T) {
	input := make(chan int)
	source := observable.NewObservable[int](input)
	sub, err := source.SubscribeNonBlocking()
	if err != nil {
		t.Fatal(err)
	}
	defer source.UnSubscribe(sub)
	done := make(chan struct{})
	go func() {
		for index := 0; index < 1000; index++ {
			input <- index
		}
		close(input)
		close(done)
	}()
	// Deliberately never receive from sub. Its bounded queue must drop rather
	// than hold the observable mutex and stall forwarding goroutines that log.
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("diagnostic log listener backpressured its publisher")
	}
}
