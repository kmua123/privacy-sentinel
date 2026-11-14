package guardcore

import (
	"crypto/sha256"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/metacubex/mihomo/component/dialer"
	CFG "github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"
)

// These YAML files are rendered by the APK's actual ClashProfile.coreYaml(),
// not a separate hand-written interpretation of the intended routing policy.
// The binary MRS fixtures are the exact signed-APK assets and retain upstream
// source provenance, hashes and licensing alongside them.
func TestActualGeneratedSmartSplitAndBundledRules(t *testing.T) {
	previousHome, previousHook := C.Path.HomeDir(), dialer.DefaultSocketHook
	previousRules, previousProviders := tunnel.Rules(), tunnel.RuleProviders()
	directory := t.TempDir()
	C.SetHomeDir(directory)
	var physicalSockets atomic.Int64
	dialer.DefaultSocketHook = func(string, string, syscall.RawConn) error {
		physicalSockets.Add(1)
		return errors.New("integration fixture forbids physical sockets")
	}
	t.Cleanup(func() {
		tunnel.UpdateRules(previousRules, nil, previousProviders)
		C.SetHomeDir(previousHome)
		dialer.DefaultSocketHook = previousHook
		if physicalSockets.Load() != 0 {
			t.Errorf("local parsing/classification attempted %d physical sockets", physicalSockets.Load())
		}
	})
	if err := os.MkdirAll(filepath.Join(directory, "rules"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cn-domain.mrs", "cn-ip.mrs"} {
		data, err := os.ReadFile(filepath.Join("testdata", "smart-split", "rules", name))
		if err != nil {
			t.Fatal(err)
		}
		// When the Android sibling is present, fail on accidental divergence
		// between the self-contained native fixture and what the APK bundles.
		asset, err := os.ReadFile(filepath.Join("..", "netguard", "app", "src", "main", "assets", "rules", name))
		if err == nil && sha256.Sum256(asset) != sha256.Sum256(data) {
			t.Fatalf("native MRS fixture differs from actual APK asset %s", name)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "rules", name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("split", func(t *testing.T) {
		config := parseGeneratedProfile(t, "split.yaml")
		if len(config.RuleProviders) != 2 {
			t.Fatalf("expected both packaged rule providers: %v", config.RuleProviders)
		}
		for name, provider := range config.RuleProviders {
			if provider.VehicleType() != P.File {
				t.Fatalf("rule provider %s must stay local, got %s", name, provider.VehicleType())
			}
			if err := provider.Initial(); err != nil {
				t.Fatalf("cannot decode actual bundled %s MRS: %v", name, err)
			}
			if provider.Count() == 0 {
				t.Fatalf("bundled rule provider %s silently loaded empty", name)
			}
			t.Logf("decoded %s: %d rules", name, provider.Count())
		}
		tunnel.UpdateRules(config.Rules, config.SubRules, config.RuleProviders)
		cases := []struct{ domain, ip, expected string }{
			{"qq.com", "8.8.8.8", "DIRECT"},
			{"weixin.qq.com", "8.8.8.8", "DIRECT"},
			{"douyin.com", "8.8.8.8", "DIRECT"},
			{"", "223.5.5.5", "DIRECT"},
			{"", "114.114.114.114", "DIRECT"},
			{"", "10.147.17.1", "隐私哨兵-回家"},
			{"", "10.0.0.190", "隐私哨兵-回家"},
			// A domestic domain must not override an explicit home-network IP.
			{"qq.com", "10.0.0.190", "隐私哨兵-回家"},
			{"example.com", "8.8.8.8", "测试#&节点"},
			{"", "8.8.8.8", "测试#&节点"},
		}
		for _, sample := range cases {
			metadata := &C.Metadata{Host: sample.domain, DstIP: netip.MustParseAddr(sample.ip), DstPort: 443, NetWork: C.TCP}
			if got := classifyGenerated(t, config, metadata); got != sample.expected {
				t.Errorf("domain=%q ip=%s: got %q, want %q", sample.domain, sample.ip, got, sample.expected)
			}
		}
		if len(config.DNS.NameServerPolicy) != 1 || config.DNS.NameServerPolicy[0].Matcher == nil {
			t.Fatalf("domestic DNS rule-set policy did not parse: %+v", config.DNS.NameServerPolicy)
		}
		policy := config.DNS.NameServerPolicy[0]
		for _, name := range []string{"qq.com", "weixin.qq.com", "douyin.com"} {
			if !policy.Matcher.MatchDomain(name) {
				t.Errorf("domestic DNS provider does not match %s", name)
			}
		}
		if policy.Matcher.MatchDomain("example.com") || len(policy.NameServers) != 1 || policy.NameServers[0].ProxyName != "DIRECT" {
			t.Fatalf("domestic DNS policy changed scope or exit: %+v", policy)
		}
		if len(config.DNS.NameServer) != 1 || config.DNS.NameServer[0].ProxyName != "隐私哨兵-代理" ||
			len(config.DNS.NameServer[0].Params) != 0 || !strings.Contains(config.DNS.NameServer[0].Addr, "cloudflare-dns.com") {
			t.Fatalf("foreign DNS exit was misparsed from special-character node name: %+v", config.DNS.NameServer)
		}
		group := config.Proxies["隐私哨兵-代理"]
		if group == nil || group.Unwrap(&C.Metadata{}, false).Name() != "测试#&节点" {
			t.Fatal("foreign DNS alias does not select the actual configured node")
		}
		if len(config.DNS.ProxyServerNameserver) != 1 || config.DNS.ProxyServerNameserver[0].ProxyName != "DIRECT" {
			t.Fatal("proxy-node bootstrap DNS must not recurse through the proxy")
		}
	})

	t.Run("home-exit", func(t *testing.T) {
		config := parseGeneratedProfile(t, "home-exit.yaml")
		tunnel.UpdateRules(config.Rules, config.SubRules, config.RuleProviders)
		if len(config.RuleProviders) != 0 || len(config.DNS.NameServerPolicy) != 0 {
			t.Fatal("home-exit unexpectedly installed domestic direct bypass rules")
		}
		if config.General.IPv6 || config.DNS.IPv6 {
			t.Fatal("IPv4-only home exit still advertises IPv6 destinations")
		}
		for _, sample := range []struct{ domain, ip string }{{"qq.com", "223.5.5.5"}, {"example.com", "8.8.8.8"}, {"", "10.0.0.190"}} {
			metadata := &C.Metadata{Host: sample.domain, DstIP: netip.MustParseAddr(sample.ip), DstPort: 443, NetWork: C.TCP}
			if got := classifyGenerated(t, config, metadata); got != "隐私哨兵-回家" {
				t.Errorf("home-exit domain=%q ip=%s escaped to %q", sample.domain, sample.ip, got)
			}
		}
		if len(config.DNS.NameServer) != 2 || config.DNS.NameServer[0].Net != "" || config.DNS.NameServer[1].Net != "tcp" {
			t.Fatalf("home DNS must offer both UDP and TCP transports: %+v", config.DNS.NameServer)
		}
		for _, server := range config.DNS.NameServer {
			if server.Addr != "10.147.17.1:53" || server.ProxyName != "隐私哨兵-回家" {
				t.Fatalf("home DNS escaped the home tunnel: %+v", server)
			}
		}
	})
}

func parseGeneratedProfile(t *testing.T, name string) *CFG.Config {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "smart-split", name))
	if err != nil {
		t.Fatal(err)
	}
	config, err := executor.ParseWithBytes(data)
	if err != nil {
		t.Fatalf("actual Java-generated profile %s cannot parse in native core: %v", name, err)
	}
	t.Cleanup(func() {
		for _, provider := range config.RuleProviders {
			if closer, ok := provider.(interface{ Close() error }); ok {
				_ = closer.Close()
			}
		}
		for _, proxy := range config.Proxies {
			_ = proxy.Close()
		}
	})
	return config
}

func classifyGenerated(t *testing.T, config *CFG.Config, metadata *C.Metadata) string {
	t.Helper()
	helper := C.RuleMatchHelper{ResolveIP: func() { t.Fatal("numeric fixture classification unexpectedly tried DNS") }}
	for _, rule := range config.Rules {
		if matched, adapter := rule.Match(metadata, helper); matched {
			return adapter
		}
	}
	t.Fatal("generated profile had no terminal matching rule")
	return ""
}
