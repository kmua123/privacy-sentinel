package guardcore

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
)

func TestProxyDelayRequiresActualHTTP204ThroughConfiguredSOCKS(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodHead {
			t.Errorf("URL test used %s instead of HEAD", r.Method)
		}
		time.Sleep(25 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	fixture := newDelaySOCKS(t, server.Listener.Addr().String(), false)
	installDelayEngine(t, fixture.proxy)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := decodeDelayResult(t, proxyDelayAtURL(ctx, fixture.proxy.Name(), server.URL))
	if !result.OK || result.DelayMS < 20 || result.ErrorCode != "" {
		t.Fatalf("real proxy/HTTP delay did not succeed: %+v", result)
	}
	if fixture.connects.Load() != 1 || requests.Load() != 1 {
		t.Fatalf("test bypassed SOCKS or did not reach HTTP: connects=%d requests=%d", fixture.connects.Load(), requests.Load())
	}
}

func TestProxyDelayRejectsReachableWrongHTTPStatus(t *testing.T) {
	for _, code := range []int{http.StatusOK, http.StatusFound} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if code == http.StatusFound {
					w.Header().Set("Location", "https://example.invalid/private-diagnostic-value")
				}
				w.WriteHeader(code)
			}))
			defer server.Close()
			fixture := newDelaySOCKS(t, server.Listener.Addr().String(), false)
			installDelayEngine(t, fixture.proxy)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result := decodeDelayResult(t, proxyDelayAtURL(ctx, fixture.proxy.Name(), server.URL))
			if result.OK || result.DelayMS != 0 || result.ErrorCode != "unexpected_status" || requests.Load() != 1 {
				t.Fatalf("wrong status must not become a positive timing or redirect fetch: %+v requests=%d", result, requests.Load())
			}
		})
	}
}

func TestProxyDelayDoesNotSkipTLSCertificateVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("self-signed HTTPS fixture unexpectedly passed certificate verification")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	fixture := newDelaySOCKS(t, server.Listener.Addr().String(), false)
	installDelayEngine(t, fixture.proxy)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := decodeDelayResult(t, proxyDelayAtURL(ctx, fixture.proxy.Name(), server.URL))
	if result.OK || result.DelayMS != 0 || result.ErrorCode != "test_failed" {
		t.Fatalf("untrusted certificate must fail the real TLS URL test: %+v", result)
	}
}

func TestProxyDelayTimeoutAndLifecycleAreBounded(t *testing.T) {
	entered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	fixture := newDelaySOCKS(t, server.Listener.Addr().String(), false)
	e := installDelayEngine(t, fixture.proxy)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	resultChannel := make(chan string, 1)
	go func() { resultChannel <- proxyDelayAtURL(ctx, fixture.proxy.Name(), server.URL) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("test request never reached HTTP through SOCKS")
	}
	if !lifecycle.TryLock() {
		t.Fatal("network URL test held the core lifecycle lock while blocking")
	}
	lifecycle.Unlock()
	select {
	case encoded := <-resultChannel:
		result := decodeDelayResult(t, encoded)
		if result.OK || result.DelayMS != 0 || result.ErrorCode != "timeout" {
			t.Fatalf("deadline did not fail predictably: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("URL test ignored context deadline")
	}
	// A queue behind an existing test also consumes only the same deadline.
	gate := e.delayGates[fixture.proxy.Name()]
	gate <- struct{}{}
	queuedContext, queuedCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer queuedCancel()
	queued := decodeDelayResult(t, proxyDelayAtURL(queuedContext, fixture.proxy.Name(), server.URL))
	<-gate
	if queued.ErrorCode != "timeout" || fixture.connects.Load() != 1 {
		t.Fatalf("queued test escaped its deadline or started another request: %+v", queued)
	}
}

func TestProxyDelayFailedProxyStoppedCoreAndSafeErrors(t *testing.T) {
	fixture := newDelaySOCKS(t, "127.0.0.1:1", true)
	e := installDelayEngine(t, fixture.proxy)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	encoded := proxyDelayAtURL(ctx, fixture.proxy.Name(), "http://127.0.0.1:1/secret-test-query")
	failed := decodeDelayResult(t, encoded)
	if failed.OK || failed.DelayMS != 0 || failed.ErrorCode != "test_failed" || fixture.connects.Load() != 1 {
		t.Fatalf("SOCKS CONNECT rejection became a success: %+v", failed)
	}
	missing := decodeDelayResult(t, TestProxyDelay("nonexistent-secret-node-label", 1000))
	if missing.ErrorCode != "node_not_found" {
		t.Fatalf("missing node was not diagnosed: %+v", missing)
	}
	e.active.Store(false)
	stopped := decodeDelayResult(t, TestProxyDelay(fixture.proxy.Name(), 1000))
	if stopped.ErrorCode != "core_stopped" || stopped.OK {
		t.Fatalf("inactive core still allowed a proxy test: %+v", stopped)
	}
	for _, value := range []string{encoded, TestProxyDelay(fixture.proxy.Name(), 1000), TestProxyDelay("nonexistent-secret-node-label", 1000)} {
		var fields map[string]any
		if json.Unmarshal([]byte(value), &fields) != nil || len(fields) != 3 {
			t.Fatalf("diagnostic contains unexpected/raw fields: %s", value)
		}
		for _, key := range []string{"ok", "delayMs", "errorCode"} {
			if _, ok := fields[key]; !ok {
				t.Fatalf("missing result field %s", key)
			}
		}
	}
}

func installDelayEngine(t *testing.T, proxy C.Proxy) *engine {
	t.Helper()
	previousHook := dialer.DefaultSocketHook
	previousUnifiedDelay := adapter.UnifiedDelay.Load()
	adapter.UnifiedDelay.Store(false)
	e := fixture(&testCallbacks{protected: true})
	e.proxies = map[string]C.Proxy{proxy.Name(): proxy}
	lifecycle.Lock()
	previousEngine := running
	running = e
	lifecycle.Unlock()
	dialer.DefaultSocketHook = e.protect
	t.Cleanup(func() {
		e.active.Store(false)
		lifecycle.Lock()
		running = previousEngine
		lifecycle.Unlock()
		dialer.DefaultSocketHook = previousHook
		adapter.UnifiedDelay.Store(previousUnifiedDelay)
		_ = proxy.Close()
	})
	return e
}

func decodeDelayResult(t *testing.T, encoded string) proxyDelayResult {
	t.Helper()
	var result proxyDelayResult
	if err := json.Unmarshal([]byte(encoded), &result); err != nil {
		t.Fatalf("invalid proxy diagnostic JSON: %v", err)
	}
	return result
}

type delaySOCKSFixture struct {
	proxy    C.Proxy
	connects atomic.Int64
}

// Only the one ephemeral loopback HTTP endpoint is accepted. This fixture is
// intentionally not a general-purpose SOCKS proxy and cannot reach the Internet.
func newDelaySOCKS(t *testing.T, allowedAddress string, reject bool) *delaySOCKSFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	result := &delaySOCKSFixture{}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go result.serve(connection, allowedAddress, reject)
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	proxy, err := adapter.ParseProxy(map[string]any{
		"name": "private-node-label-for-delay-test", "type": "socks5",
		"server": "127.0.0.1", "port": port, "udp": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	result.proxy = proxy
	return result
}

func (fixture *delaySOCKSFixture) serve(connection net.Conn, allowedAddress string, reject bool) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	var greeting [2]byte
	if _, err := io.ReadFull(connection, greeting[:]); err != nil || greeting[0] != 5 {
		return
	}
	methods := make([]byte, greeting[1])
	if _, err := io.ReadFull(connection, methods); err != nil {
		return
	}
	if _, err := connection.Write([]byte{5, 0}); err != nil {
		return
	}
	var request [4]byte
	if _, err := io.ReadFull(connection, request[:]); err != nil || request[0] != 5 || request[1] != 1 {
		return
	}
	var host string
	switch request[3] {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(connection, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(connection, length[:]); err != nil {
			return
		}
		name := make([]byte, length[0])
		if _, err := io.ReadFull(connection, name); err != nil {
			return
		}
		host = string(name)
	default:
		return
	}
	var port [2]byte
	if _, err := io.ReadFull(connection, port[:]); err != nil {
		return
	}
	fixture.connects.Add(1)
	address := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:]))))
	if reject || address != allowedAddress {
		_, _ = connection.Write([]byte{5, 2, 0, 1, 127, 0, 0, 1, 0, 0})
		return
	}
	upstream, err := net.DialTimeout("tcp", allowedAddress, time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	if _, err := connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	done := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(upstream, connection)
		_ = upstream.Close()
		done <- struct{}{}
	}()
	_, _ = io.Copy(connection, upstream)
	_ = connection.Close()
	<-done
}
