package guardcore

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/metacubex/mihomo/common/utils"
)

const proxyDelayTestURL = "https://www.gstatic.com/generate_204"

type proxyDelayResult struct {
	OK        bool   `json:"ok"`
	DelayMS   int64  `json:"delayMs"`
	ErrorCode string `json:"errorCode"`
}

// TestProxyDelay performs Mihomo's actual HTTP URL test through the named
// configured node. This is application-level connection/TLS/HTTP latency, not
// ICMP RTT, a bandwidth measurement or proof that every destination is usable.
// The target is fixed here; Android cannot turn this diagnostic into an
// arbitrary-URL fetch. Standard TLS verification remains enabled.
func TestProxyDelay(name string, timeoutMillis int64) string {
	timeoutMillis = min(10_000, max(1_000, timeoutMillis))
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMillis)*time.Millisecond)
	defer cancel()
	return proxyDelayAtURL(ctx, name, proxyDelayTestURL)
}

// A separate private URL parameter permits loopback integration fixtures. It
// is intentionally unexported and therefore absent from the gomobile API.
func proxyDelayAtURL(ctx context.Context, name, testURL string) string {
	// A concurrent core restart can hold lifecycle during initialization. Bound
	// that wait too, rather than consuming an unbounded UI worker interval.
	for !lifecycle.TryLock() {
		select {
		case <-ctx.Done():
			return encodeProxyDelay(0, "timeout")
		case <-time.After(5 * time.Millisecond):
		}
	}
	e := running
	if e == nil || !e.active.Load() {
		lifecycle.Unlock()
		return encodeProxyDelay(0, "core_stopped")
	}
	proxy := e.proxies[name]
	if proxy == nil {
		lifecycle.Unlock()
		return encodeProxyDelay(0, "node_not_found")
	}
	if e.delayGates == nil {
		e.delayGates = make(map[string]chan struct{})
	}
	gate := e.delayGates[name]
	if gate == nil {
		gate = make(chan struct{}, 1)
		e.delayGates[name] = gate
	}
	lifecycle.Unlock()

	// URLTest exposes expected-status success through per-URL state, so two
	// simultaneous tests of one proxy must not overwrite each other's result.
	// Waiting for the per-node slot is included in the caller's deadline.
	select {
	case gate <- struct{}{}:
		defer func() { <-gate }()
	case <-ctx.Done():
		return encodeProxyDelay(0, "timeout")
	}
	if !e.active.Load() {
		return encodeProxyDelay(0, "core_stopped")
	}

	expected := utils.IntRanges[uint16]{utils.NewRange[uint16](204, 204)}
	delay, err := proxy.URLTest(ctx, testURL, expected)
	if !e.active.Load() {
		return encodeProxyDelay(0, "core_stopped")
	}
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		return encodeProxyDelay(0, "timeout")
	}
	if err != nil {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return encodeProxyDelay(0, "timeout")
		}
		return encodeProxyDelay(0, "test_failed")
	}
	// Mihomo returns a nonzero timing and nil error for a received HTTP response
	// even if expectedStatus failed. Its per-URL health flag is authoritative.
	if !proxy.AliveForTestUrl(testURL) {
		return encodeProxyDelay(0, "unexpected_status")
	}
	if delay == 0 {
		return encodeProxyDelay(0, "test_failed")
	}
	return encodeProxyDelay(int64(delay), "")
}

func encodeProxyDelay(delay int64, code string) string {
	value, _ := json.Marshal(proxyDelayResult{OK: code == "", DelayMS: delay, ErrorCode: code})
	return string(value)
}
