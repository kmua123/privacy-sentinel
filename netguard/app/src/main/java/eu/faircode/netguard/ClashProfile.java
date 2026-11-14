package eu.faircode.netguard;

/* SPDX-License-Identifier: GPL-3.0-or-later */

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Imports node definitions only. Network policy belongs to the local app. */
final class ClashProfile {
    static final int MAX_BYTES = 2 * 1024 * 1024;
    static final String HOME_PROXY = "隐私哨兵-回家";
    static final String OUTBOUND_GROUP = "隐私哨兵-代理";
    static final String CN_DOMAIN_PROVIDER = "cn-domain";
    static final String CN_IP_PROVIDER = "cn-ip";
    private static final int MAX_PROXIES = 2000;
    private static final Set<String> TYPES = new HashSet<>(Arrays.asList(
            "ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2",
            "tuic", "socks5", "http", "anytls", "wireguard"));
    private static final Set<String> NODE_FIELDS = new HashSet<>(Arrays.asList(
            "name", "type", "server", "port", "password", "cipher", "uuid", "alterId",
            "security", "tls", "skip-cert-verify", "servername", "sni", "fingerprint",
            "client-fingerprint", "network", "udp", "packet-encoding", "flow", "alpn",
            "ws-opts", "http-opts", "h2-opts", "grpc-opts", "reality-opts", "plugin",
            "plugin-opts", "obfs", "obfs-param", "protocol", "protocol-param", "auth-str",
            "auth", "up", "down", "ports", "hop-interval", "heartbeat-interval",
            "disable-sni", "reduce-rtt", "udp-relay-mode", "congestion-controller",
            "ip-version", "fast-open", "max-open-streams", "max-stream-receive-window",
            "max-connection-receive-window", "initial-stream-receive-window",
            "initial-connection-receive-window", "recv-window-conn", "recv-window",
            "disable-mtu-discovery", "private-key", "public-key", "pre-shared-key",
            "ip", "ipv6", "reserved", "peers", "persistent-keepalive", "remote-dns-resolve",
            "dns", "mtu", "obfs-password", "idle-session-check-interval", "idle-session-timeout",
            "min-idle-session", "smux"));
    private static final Set<String> RESERVED_NAMES = new HashSet<>(Arrays.asList(
            "DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE", "GLOBAL", "DNS",
            HOME_PROXY, OUTBOUND_GROUP));
    private final List<Map<String, Object>> proxies;

    private ClashProfile(List<Map<String, Object>> proxies) {
        this.proxies = proxies;
    }

    static ClashProfile empty() {
        return new ClashProfile(new ArrayList<>());
    }

    static ClashProfile parse(String source) throws IOException {
        if (source == null || source.length() > MAX_BYTES
                || source.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES)
            throw new IOException("配置文件过大，最多支持 2 MiB");
        LoaderOptions limits = new LoaderOptions();
        limits.setAllowDuplicateKeys(false);
        limits.setMaxAliasesForCollections(20);
        limits.setNestingDepthLimit(20);
        limits.setCodePointLimit(MAX_BYTES);
        final Object document;
        try {
            document = new Yaml(new SafeConstructor(limits)).load(source);
        } catch (RuntimeException invalid) {
            throw new IOException("配置不是有效的 Clash YAML，或包含不允许的 YAML 标签", invalid);
        }
        if (!(document instanceof Map))
            throw new IOException("配置需要包含 proxies 节点列表");
        Map<?, ?> root = (Map<?, ?>) document;
        Object imported = root.get("proxies");
        if (imported == null)
            imported = root.get("payload");
        if (!(imported instanceof List) || ((List<?>) imported).isEmpty())
            throw new IOException("没有找到节点。请导入包含 proxies 或 payload 的 Clash 订阅");
        List<?> entries = (List<?>) imported;
        if (entries.size() > MAX_PROXIES)
            throw new IOException("节点数量超过本机导入上限 2000");
        List<Map<String, Object>> result = new ArrayList<>();
        Set<String> names = new HashSet<>();
        ValueBudget budget = new ValueBudget();
        for (Object entry : entries) {
            if (!(entry instanceof Map))
                throw new IOException("订阅中的节点格式无效");
            Map<?, ?> fields = (Map<?, ?>) entry;
            String name = requiredText(fields, "name");
            if (name.length() > 160 || name.contains(",") || name.contains("\n") || name.contains("\r"))
                throw new IOException("节点名称过长或含有不支持的分隔符");
            if (RESERVED_NAMES.contains(name) || !names.add(name))
                throw new IOException("节点名称重复或与本机策略名称冲突");
            String type = requiredText(fields, "type").toLowerCase(Locale.ROOT);
            if (!TYPES.contains(type))
                throw new IOException("此版本暂不支持订阅中的节点类型 " + type);
            if (!"wireguard".equals(type)) {
                requiredText(fields, "server");
                validatePort(fields.get("port"));
            }
            Object plugin = fields.get("plugin");
            if (plugin != null && !"obfs".equals(plugin) && !"v2ray-plugin".equals(plugin))
                throw new IOException("此版本不支持订阅中的插件类型");
            Map<String, Object> node = new LinkedHashMap<>();
            for (Map.Entry<?, ?> field : fields.entrySet()) {
                if (!(field.getKey() instanceof String))
                    throw new IOException("节点字段名称必须是文字");
                String key = (String) field.getKey();
                if (NODE_FIELDS.contains(key))
                    node.put(key, copyValue(field.getValue(), 0, budget));
            }
            node.put("name", name);
            node.put("type", type);
            result.add(node);
        }
        return new ClashProfile(result);
    }

    private static final class ValueBudget {
        int remaining = 100_000;
    }

    private static Object copyValue(Object value, int depth, ValueBudget budget) throws IOException {
        if (depth > 12 || --budget.remaining < 0)
            throw new IOException("节点参数过多或嵌套过深");
        if (value == null || value instanceof String || value instanceof Boolean
                || value instanceof Integer || value instanceof Long)
            return value;
        if (value instanceof Double && Double.isFinite((Double) value))
            return value;
        if (value instanceof List) {
            List<Object> copy = new ArrayList<>();
            if (((List<?>) value).size() > 4096)
                throw new IOException("节点参数列表过大");
            for (Object item : (List<?>) value)
                copy.add(copyValue(item, depth + 1, budget));
            return copy;
        }
        if (value instanceof Map) {
            Map<String, Object> copy = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                if (!(entry.getKey() instanceof String))
                    throw new IOException("节点参数名称必须是文字");
                copy.put((String) entry.getKey(), copyValue(entry.getValue(), depth + 1, budget));
            }
            return copy;
        }
        throw new IOException("节点包含不支持的数据类型");
    }

    private static String requiredText(Map<?, ?> fields, String key) throws IOException {
        Object value = fields.get(key);
        if (!(value instanceof String) || ((String) value).trim().isEmpty())
            throw new IOException("节点缺少有效的 " + key + " 字段");
        return ((String) value).trim();
    }

    private static void validatePort(Object value) throws IOException {
        try {
            int port = Integer.parseInt(String.valueOf(value));
            if (port < 1 || port > 65535)
                throw new NumberFormatException();
        } catch (NumberFormatException invalid) {
            throw new IOException("节点端口必须在 1 到 65535 之间");
        }
    }

    List<String> names() {
        List<String> result = new ArrayList<>();
        for (Map<String, Object> proxy : proxies)
            result.add((String) proxy.get("name"));
        return Collections.unmodifiableList(result);
    }

    String nodeYaml() {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("proxies", proxies);
        return dump(document);
    }

    String coreYaml(String selected, String mode, boolean zeroTier, String network,
                    List<String> cidrs, String homeDns) throws IOException {
        return coreYaml(selected, mode, zeroTier, network, cidrs, homeDns, "auto");
    }

    String coreYaml(String selected, String mode, boolean zeroTier, String network,
                    List<String> cidrs, String homeDns, String tcpFallbackMode) throws IOException {
        return coreYaml(selected, mode, zeroTier, network, cidrs, homeDns, tcpFallbackMode, true);
    }

    String coreYaml(String selected, String mode, boolean zeroTier, String network,
                    List<String> cidrs, String homeDns, String tcpFallbackMode,
                    boolean outboundIpv6) throws IOException {
        if (!selected.isEmpty() && !names().contains(selected))
            throw new IOException("所选代理节点已不存在，请重新选择后保存");
        if (!"split".equals(mode) && !"home_exit".equals(mode))
            throw new IOException("网络模式无效");
        if ("home_exit".equals(mode) && !zeroTier)
            throw new IOException("回家出口模式需要启用 ZeroTier");
        if (!"auto".equals(tcpFallbackMode) && !"force".equals(tcpFallbackMode))
            throw new IOException("ZeroTier 连接模式无效");
        if (zeroTier && !network.matches("[0-9a-fA-F]{16}"))
            throw new IOException("ZeroTier 网络 ID 应为 16 位十六进制字符");
        if (zeroTier)
            validateAddress(homeDns);
        for (String cidr : cidrs)
            validateCidr(cidr);

        boolean homeExit = "home_exit".equals(mode);
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("mode", "rule");
        config.put("allow-lan", false);
        // Keep IPv6 interception in the host TUN even when outgoing IPv6 and
        // AAAA are disabled. A TUN default route is not evidence that the
        // selected physical network has a usable IPv6 default route.
        // The existing home exit remains IPv4-only in every compatibility mode.
        boolean ipv6 = outboundIpv6 && !homeExit;
        config.put("ipv6", ipv6);
        config.put("log-level", "warning");
        config.put("find-process-mode", "always");
        config.put("tun", Collections.singletonMap("enable", false));
        Map<String, Object> dns = new LinkedHashMap<>();
        dns.put("enable", true);
        dns.put("ipv6", ipv6);
        dns.put("enhanced-mode", "redir-host");
        dns.put("use-hosts", false);
        dns.put("use-system-hosts", false);
        dns.put("respect-rules", true);
        dns.put("default-nameserver", Arrays.asList("223.5.5.5", "1.1.1.1"));
        // Bootstrap node domains through an explicit direct resolver, never
        // through the node whose address is still being resolved.
        String directDns = "https://dns.alidns.com/dns-query#DIRECT";
        dns.put("proxy-server-nameserver", Collections.singletonList(directDns));
        if (homeExit) {
            String homeDnsAddress = addressHost(homeDns) + ":53#" + HOME_PROXY;
            dns.put("nameserver", Arrays.asList("udp://" + homeDnsAddress, "tcp://" + homeDnsAddress));
        } else {
            Map<String, Object> ruleProviders = new LinkedHashMap<>();
            ruleProviders.put(CN_DOMAIN_PROVIDER, localRules("domain", "rules/cn-domain.mrs"));
            ruleProviders.put(CN_IP_PROVIDER, localRules("ipcidr", "rules/cn-ip.mrs"));
            config.put("rule-providers", ruleProviders);
            Map<String, Object> dnsPolicy = new LinkedHashMap<>();
            dnsPolicy.put("rule-set:" + CN_DOMAIN_PROVIDER, Collections.singletonList(directDns));
            dns.put("nameserver-policy", dnsPolicy);
            if (selected.isEmpty()) {
                dns.put("nameserver", Collections.singletonList(directDns));
            } else {
                // A stable local alias keeps node names containing #, &, or =
                // out of DNS URL fragments, which Mihomo interprets as options.
                Map<String, Object> group = new LinkedHashMap<>();
                group.put("name", OUTBOUND_GROUP);
                group.put("type", "select");
                group.put("proxies", Collections.singletonList(selected));
                config.put("proxy-groups", Collections.singletonList(group));
                dns.put("nameserver", Collections.singletonList(
                        "https://cloudflare-dns.com/dns-query#" + OUTBOUND_GROUP));
            }
        }
        config.put("dns", dns);

        List<Map<String, Object>> outbounds = new ArrayList<>(proxies);
        if (zeroTier) {
            Map<String, Object> home = new LinkedHashMap<>();
            home.put("name", HOME_PROXY);
            home.put("type", "zerotier");
            home.put("network", network.toLowerCase(Locale.ROOT));
            home.put("state-dir", "zerotier/home");
            home.put("udp", true);
            home.put("ip-stack", Collections.singletonMap("mode", "gvisor"));
            home.put("tcp-fallback-mode", tcpFallbackMode);
            outbounds.add(home);
        }
        config.put("proxies", outbounds);
        List<String> rules = new ArrayList<>();
        if (zeroTier)
            for (String cidr : cidrs)
                rules.add("IP-CIDR," + cidr + "," + HOME_PROXY + ",no-resolve");
        if (!homeExit) {
            rules.add("RULE-SET," + CN_DOMAIN_PROVIDER + ",DIRECT");
            rules.add("RULE-SET," + CN_IP_PROVIDER + ",DIRECT,no-resolve");
        }
        String finalTarget = selected.isEmpty() ? "DIRECT" : selected;
        if (homeExit)
            finalTarget = HOME_PROXY;
        rules.add("MATCH," + finalTarget);
        // Mihomo skips a proxy rule when that proxy cannot carry UDP.
        if (!"DIRECT".equals(finalTarget))
            rules.add("MATCH,REJECT");
        config.put("rules", rules);
        return dump(config);
    }

    private static Map<String, Object> localRules(String behavior, String path) {
        Map<String, Object> provider = new LinkedHashMap<>();
        provider.put("type", "file");
        provider.put("behavior", behavior);
        provider.put("format", "mrs");
        provider.put("path", path);
        return provider;
    }

    static List<String> cidrs(String text) throws IOException {
        List<String> result = new ArrayList<>();
        for (String raw : text.split("[\\s,;]+")) {
            if (raw.isEmpty())
                continue;
            validateCidr(raw);
            if (!result.contains(raw))
                result.add(raw);
        }
        if (result.isEmpty())
            throw new IOException("请填写至少一个家庭网段");
        return result;
    }

    static void validateCidr(String value) throws IOException {
        int slash = value.indexOf('/');
        if (slash <= 0 || slash != value.lastIndexOf('/'))
            throw new IOException("家庭网段需要使用 IP/掩码 格式");
        String address = value.substring(0, slash);
        validateAddress(address);
        try {
            int prefix = Integer.parseInt(value.substring(slash + 1));
            int bits = address.contains(":") ? 128 : 32;
            if (prefix <= 0 || prefix > bits)
                throw new NumberFormatException();
        } catch (NumberFormatException invalid) {
            throw new IOException("家庭网段掩码无效。默认路由请使用回家出口模式");
        }
    }

    static void validateAddress(String address) throws IOException {
        if (address.contains(":")) {
            if (!address.matches("[0-9a-fA-F:]+"))
                throw new IOException("请填写有效的 IP 地址");
            try {
                if (InetAddress.getByName(address).getAddress().length != 16)
                    throw new IOException("IPv6 地址无效");
            } catch (java.net.UnknownHostException invalid) {
                throw new IOException("IPv6 地址无效");
            }
            return;
        }
        String[] pieces = address.split("\\.", -1);
        if (pieces.length != 4)
            throw new IOException("请填写有效的 IP 地址");
        for (String piece : pieces) {
            try {
                if (!piece.matches("[0-9]{1,3}") || Integer.parseInt(piece) > 255)
                    throw new NumberFormatException();
            } catch (NumberFormatException invalid) {
                throw new IOException("请填写有效的 IP 地址");
            }
        }
    }

    private static String addressHost(String address) {
        return address.contains(":") ? "[" + address + "]" : address;
    }

    private static String dump(Map<String, Object> document) {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setAllowUnicode(true);
        options.setPrettyFlow(true);
        return new Yaml(options).dump(document);
    }
}
