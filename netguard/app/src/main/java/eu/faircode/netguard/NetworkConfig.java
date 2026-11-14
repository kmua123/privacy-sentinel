package eu.faircode.netguard;

/* SPDX-License-Identifier: GPL-3.0-or-later */

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.util.AtomicFile;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Collections;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public final class NetworkConfig {
    public static final String ACTION_CHANGED = "local.privacy.guard.NETWORK_CONFIG_CHANGED";
    public static final String SPLIT = "split";
    public static final String HOME_EXIT = "home_exit";
    public static final String IPV6_AUTO = "auto";
    public static final String IPV6_DISABLED = "ipv4";
    public static final String IPV6_ENABLED = "ipv6";
    public static final String LOCAL_PROFILE_ID = SubscriptionProfiles.LOCAL_ID;
    private static final Object PROFILE_LOCK = new Object();
    private static long configurationRevision;
    private final Context context;
    private final SharedPreferences preferences;
    private final AtomicFile profile;
    private final SubscriptionProfiles subscriptions;

    public static final class Subscription {
        public final String id;
        public final String name;
        public final String url;
        public final boolean active;
        public final boolean cached;

        private Subscription(SubscriptionProfiles.Entry entry, boolean active, boolean cached) {
            id = entry.id;
            name = entry.name;
            url = entry.url;
            this.active = active;
            this.cached = cached;
        }
    }

    public static final class Settings {
        public String subscriptionUrl = "";
        public String selectedProxy = "";
        public String mode = SPLIT;
        public String ipv6Mode = IPV6_AUTO;
        public boolean enabledZeroTier = false;
        public String zeroTierNetwork = "";
        public String homeCidrs = "";
        public String homeDns = "";
        public boolean zeroTierTcpOnly = false;
    }

    /** YAML and TUN address-family decision from one locked settings/profile snapshot. */
    public static final class PreparedCore {
        public final String yaml;
        public final boolean ipv6Enabled;

        private PreparedCore(String yaml, boolean ipv6Enabled) {
            this.yaml = yaml;
            this.ipv6Enabled = ipv6Enabled;
        }
    }

    public NetworkConfig(Context context) {
        this.context = context.getApplicationContext();
        preferences = this.context.getSharedPreferences("unified_network", Context.MODE_PRIVATE);
        profile = new AtomicFile(new File(this.context.getFilesDir(), "subscription-nodes.yaml"));
        subscriptions = new SubscriptionProfiles(this.context.getFilesDir());
    }

    public Settings load() {
        synchronized (PROFILE_LOCK) {
            try {
                ensureMigration();
                return loadLocked(entries());
            } catch (IOException unavailable) {
                // Loading UI fields must not erase a damaged index or silently
                // turn an enabled proxy into DIRECT. Core reads still fail closed.
                return loadBase();
            }
        }
    }

    private Settings loadBase() {
        Settings settings = new Settings();
        settings.subscriptionUrl = preferences.getString("subscriptionUrl", settings.subscriptionUrl);
        settings.selectedProxy = preferences.getString("selectedProxy", settings.selectedProxy);
        settings.mode = preferences.getString("mode", settings.mode);
        settings.ipv6Mode = preferences.getString("ipv6Mode", settings.ipv6Mode);
        settings.enabledZeroTier = preferences.getBoolean("enabledZeroTier", settings.enabledZeroTier);
        settings.zeroTierNetwork = preferences.getString("zeroTierNetwork", settings.zeroTierNetwork);
        settings.homeCidrs = preferences.getString("homeCidrs", settings.homeCidrs);
        settings.homeDns = preferences.getString("homeDns", settings.homeDns);
        settings.zeroTierTcpOnly = preferences.getBoolean("zeroTierTcpOnly", false);
        return settings;
    }

    private Settings loadLocked(List<SubscriptionProfiles.Entry> entries) throws IOException {
        Settings settings = loadBase();
        SubscriptionProfiles.Entry active = activeEntry(entries);
        if (active != null) {
            settings.subscriptionUrl = active.url;
            settings.selectedProxy = active.selected;
        }
        return settings;
    }

    public void save(Settings settings) throws IOException {
        validateIpv6Mode(settings.ipv6Mode);
        if (!settings.subscriptionUrl.trim().isEmpty())
            subscriptionUrl(settings.subscriptionUrl.trim());
        synchronized (PROFILE_LOCK) {
            ensureMigration();
            List<SubscriptionProfiles.Entry> entries = entries();
            buildCoreYaml(readProfileLocked(entries), settings);
            SubscriptionProfiles.Entry active = activeEntry(entries);
            if (active != null)
                SubscriptionProfiles.replace(entries, active.selected(settings.selectedProxy));
            SharedPreferences.Editor editor = preferences.edit()
                .putString(SubscriptionProfiles.INDEX, SubscriptionProfiles.encode(entries))
                .putString("subscriptionUrl", settings.subscriptionUrl.trim())
                .putString("selectedProxy", settings.selectedProxy)
                .putString("mode", settings.mode)
                .putString("ipv6Mode", settings.ipv6Mode)
                .putBoolean("enabledZeroTier", settings.enabledZeroTier)
                .putString("zeroTierNetwork", settings.zeroTierNetwork.trim())
                .putString("homeCidrs", settings.homeCidrs.trim())
                .putString("homeDns", settings.homeDns.trim())
                .putBoolean("zeroTierTcpOnly", settings.zeroTierTcpOnly);
            if (active != null)
                editor.putString("subscriptionUrl", active.url);
            else
                editor.putString(SubscriptionProfiles.LOCAL_SELECTED, settings.selectedProxy);
            committed(editor);
        }
        changed();
    }

    public List<String> proxyNames() throws IOException {
        return readProfile().names();
    }

    public String homeNodeId() {
        File identity = new File(context.getNoBackupFilesDir(),
                "network-core/zerotier/home/identity.public");
        try (InputStream input = new FileInputStream(identity)) {
            byte[] prefix = new byte[11];
            if (input.read(prefix) != prefix.length)
                return "";
            String value = new String(prefix, StandardCharsets.US_ASCII);
            return value.matches("[0-9a-fA-F]{10}:") ? value.substring(0, 10) : "";
        } catch (IOException unavailable) {
            return "";
        }
    }

    public String buildCoreYaml() throws IOException {
        return buildCoreYaml(true);
    }

    /** physicalIpv6 describes the selected non-VPN network, never the TUN itself. */
    public String buildCoreYaml(boolean physicalIpv6) throws IOException {
        return prepareCore(physicalIpv6).yaml;
    }

    /** Keep the published TUN IPv6 address and resolver policy in the same configuration generation. */
    public PreparedCore prepareCore(boolean physicalIpv6) throws IOException {
        synchronized (PROFILE_LOCK) {
            ensureMigration();
            List<SubscriptionProfiles.Entry> entries = entries();
            Settings settings = loadLocked(entries);
            ClashProfile nodes = readProfileLocked(entries);
            return prepareCore(nodes, settings, physicalIpv6);
        }
    }

    public String buildCoreYaml(Settings settings) throws IOException {
        synchronized (PROFILE_LOCK) {
            ensureMigration();
            return buildCoreYaml(readProfileLocked(entries()), settings);
        }
    }

    private String buildCoreYaml(ClashProfile nodes, Settings settings) throws IOException {
        return buildCoreYaml(nodes, settings, true);
    }

    private String buildCoreYaml(ClashProfile nodes, Settings settings, boolean physicalIpv6) throws IOException {
        return prepareCore(nodes, settings, physicalIpv6).yaml;
    }

    private PreparedCore prepareCore(ClashProfile nodes, Settings settings, boolean physicalIpv6) throws IOException {
        validateIpv6Mode(settings.ipv6Mode);
        boolean outboundIpv6 = !HOME_EXIT.equals(settings.mode)
                && (IPV6_ENABLED.equals(settings.ipv6Mode)
                || (IPV6_AUTO.equals(settings.ipv6Mode) && physicalIpv6));
        String yaml = nodes.coreYaml(settings.selectedProxy, settings.mode, settings.enabledZeroTier,
                settings.zeroTierNetwork.trim(), settings.enabledZeroTier
                        ? ClashProfile.cidrs(settings.homeCidrs) : Collections.emptyList(), settings.homeDns.trim(),
                settings.zeroTierTcpOnly ? "force" : "auto", outboundIpv6);
        return new PreparedCore(yaml, outboundIpv6);
    }

    private static void validateIpv6Mode(String mode) throws IOException {
        if (!IPV6_AUTO.equals(mode) && !IPV6_DISABLED.equals(mode) && !IPV6_ENABLED.equals(mode))
            throw new IOException("IPv6 兼容模式无效，请重新选择后保存");
    }

    /** Install only signed-APK-owned local routing data; subscriptions cannot supply these paths. */
    public void prepareRuleAssets(File stateDirectory) throws IOException {
        File rules = new File(stateDirectory, "rules");
        if (!rules.isDirectory() && !rules.mkdirs())
            throw new IOException("无法准备本机分流规则目录");
        for (String name : new String[]{"cn-domain.mrs", "cn-ip.mrs"}) {
            AtomicFile destination = new AtomicFile(new File(rules, name));
            FileOutputStream output = null;
            try (InputStream input = context.getAssets().open("rules/" + name)) {
                output = destination.startWrite();
                byte[] buffer = new byte[16 * 1024];
                int count;
                while ((count = input.read(buffer)) != -1)
                    output.write(buffer, 0, count);
                destination.finishWrite(output);
            } catch (IOException failure) {
                if (output != null)
                    destination.failWrite(output);
                throw new IOException("本机分流规则准备失败", failure);
            }
        }
    }

    public void importYaml(String yaml) throws IOException {
        ClashProfile parsed = ClashProfile.parse(yaml);
        synchronized (PROFILE_LOCK) {
            ensureMigration();
            String oldCache = preferences.getString(SubscriptionProfiles.LOCAL_CACHE, "");
            boolean hadLocal = !oldCache.isEmpty() || profile.getBaseFile().isFile();
            String selected = SubscriptionProfiles.chooseNode(
                    preferences.getString(SubscriptionProfiles.LOCAL_SELECTED, ""), hadLocal, parsed.names());
            Settings settings = loadBase();
            settings.selectedProxy = selected;
            buildCoreYaml(parsed, settings);
            String cache = subscriptions.writeCache(SubscriptionProfiles.LOCAL_ID, parsed.nodeYaml());
            try {
                committed(preferences.edit().putString(SubscriptionProfiles.ACTIVE, "")
                        .putBoolean(SubscriptionProfiles.LOCAL_AVAILABLE, true)
                        .putString(SubscriptionProfiles.LOCAL_CACHE, cache)
                        .putString(SubscriptionProfiles.LOCAL_SELECTED, selected)
                        .putString("subscriptionUrl", "").putString("selectedProxy", selected));
            } catch (IOException failure) {
                subscriptions.discardCache(SubscriptionProfiles.LOCAL_ID, cache);
                throw failure;
            }
            subscriptions.discardCache(SubscriptionProfiles.LOCAL_ID, oldCache);
        }
        changed();
    }

    public void importStream(InputStream input) throws IOException {
        importYaml(readLimited(input));
    }

    public void refreshSubscription(String address) throws IOException {
        String normalized = checkedSubscriptionUrl(address);
        String expectedId;
        long expectedRevision;
        synchronized (PROFILE_LOCK) {
            ensureMigration();
            SubscriptionProfiles.Entry existing = SubscriptionProfiles.byUrl(entries(), normalized);
            expectedId = existing == null ? null : existing.id;
            expectedRevision = configurationRevision;
        }
        ClashProfile downloaded = download(normalized);
        synchronized (PROFILE_LOCK) {
            requireRevision(expectedRevision);
            ensureMigration();
            List<SubscriptionProfiles.Entry> entries = entries();
            SubscriptionProfiles.Entry existing = SubscriptionProfiles.byUrl(entries, normalized);
            if (expectedId != null && (existing == null || !expectedId.equals(existing.id)))
                throw new IOException("订阅已被删除或更改，请重新选择后更新");
            if (existing == null) {
                if (entries.size() >= SubscriptionProfiles.MAX_PROFILES)
                    throw new IOException("最多保存 32 个订阅");
                existing = new SubscriptionProfiles.Entry(SubscriptionProfiles.newId(),
                        "订阅 " + (entries.size() + 1), normalized, "", "");
            }
            publishDownloaded(entries, existing, downloaded);
        }
        changed();
    }

    public List<Subscription> listSubscriptions() throws IOException {
        synchronized (PROFILE_LOCK) {
            ensureMigration();
            List<SubscriptionProfiles.Entry> entries = entries();
            String active = preferences.getString(SubscriptionProfiles.ACTIVE, "");
            activeEntry(entries); // A broken pointer must not masquerade as local/DIRECT.
            List<Subscription> result = new ArrayList<>();
            for (SubscriptionProfiles.Entry entry : entries)
                result.add(new Subscription(entry, entry.id.equals(active), subscriptions.hasCache(entry.id, entry.cache)));
            if (hasLocalProfile())
                result.add(new Subscription(new SubscriptionProfiles.Entry(SubscriptionProfiles.LOCAL_ID,
                        "本地文件导入", "", preferences.getString(SubscriptionProfiles.LOCAL_CACHE, ""),
                        preferences.getString(SubscriptionProfiles.LOCAL_SELECTED, "")), active.isEmpty(), true));
            return Collections.unmodifiableList(result);
        }
    }

    public String saveSubscription(String name, String address) throws IOException {
        String normalized = checkedSubscriptionUrl(address);
        synchronized (PROFILE_LOCK) {
            ensureMigration();
            List<SubscriptionProfiles.Entry> entries = entries();
            SubscriptionProfiles.Entry entry = SubscriptionProfiles.byUrl(entries, normalized);
            String label = name == null || name.trim().isEmpty()
                    ? entry == null ? "订阅 " + (entries.size() + 1) : entry.name
                    : SubscriptionProfiles.checkedName(name);
            if (entry == null) {
                if (entries.size() >= SubscriptionProfiles.MAX_PROFILES)
                    throw new IOException("最多保存 32 个订阅");
                entry = new SubscriptionProfiles.Entry(SubscriptionProfiles.newId(), label, normalized, "", "");
            } else
                entry = entry.renamed(label);
            SubscriptionProfiles.replace(entries, entry);
            committed(preferences.edit().putString(SubscriptionProfiles.INDEX, SubscriptionProfiles.encode(entries)));
            return entry.id;
        }
    }

    public void activateSubscription(String id) throws IOException {
        SubscriptionProfiles.checkedId(id);
        String source;
        long expectedRevision;
        synchronized (PROFILE_LOCK) {
            ensureMigration();
            List<SubscriptionProfiles.Entry> entries = entries();
            if (SubscriptionProfiles.LOCAL_ID.equals(id)) {
                if (!hasLocalProfile())
                    throw new IOException("还没有本地文件配置，请先从文件导入");
                ClashProfile local = readLocalProfile();
                String selected = SubscriptionProfiles.chooseNode(
                        preferences.getString(SubscriptionProfiles.LOCAL_SELECTED, ""), true, local.names());
                validateSelection(local, selected);
                committed(preferences.edit().putString(SubscriptionProfiles.ACTIVE, "")
                        .putString("subscriptionUrl", "").putString("selectedProxy", selected)
                        .putString(SubscriptionProfiles.LOCAL_SELECTED, selected));
                source = null;
            } else {
                SubscriptionProfiles.Entry entry = required(entries, id);
                if (subscriptions.hasCache(entry.id, entry.cache)) {
                    ClashProfile parsed = ClashProfile.parse(subscriptions.readCache(entry.id, entry.cache));
                    String selected = SubscriptionProfiles.chooseNode(entry.selected, true, parsed.names());
                    validateSelection(parsed, selected);
                    SubscriptionProfiles.replace(entries, entry.selected(selected));
                    committed(profileEditor(entries, entry.id, entry.url, selected));
                    source = null;
                } else
                    source = entry.url;
            }
            expectedRevision = configurationRevision;
        }
        if (source != null) {
            ClashProfile downloaded = download(source);
            synchronized (PROFILE_LOCK) {
                requireRevision(expectedRevision);
                List<SubscriptionProfiles.Entry> entries = entries();
                SubscriptionProfiles.Entry entry = required(entries, id);
                if (!entry.url.equals(source))
                    throw new IOException("订阅地址已更改，请重新启用");
                publishDownloaded(entries, entry, downloaded);
            }
        }
        changed();
    }

    public void removeSubscription(String id) throws IOException {
        SubscriptionProfiles.checkedId(id);
        if (SubscriptionProfiles.LOCAL_ID.equals(id))
            throw new IOException("本地文件配置请通过重新导入更新；远程订阅缓存不会被覆盖");
        synchronized (PROFILE_LOCK) {
            ensureMigration();
            List<SubscriptionProfiles.Entry> entries = entries();
            SubscriptionProfiles.Entry entry = required(entries, id);
            if (id.equals(preferences.getString(SubscriptionProfiles.ACTIVE, "")))
                throw new IOException("请先启用另一个订阅，再删除当前订阅");
            entries.remove(entry);
            committed(preferences.edit().putString(SubscriptionProfiles.INDEX, SubscriptionProfiles.encode(entries)));
            subscriptions.discardCache(entry.id, entry.cache);
        }
    }

    private void publishDownloaded(List<SubscriptionProfiles.Entry> entries,
                                   SubscriptionProfiles.Entry entry, ClashProfile parsed) throws IOException {
        String selected = SubscriptionProfiles.chooseNode(entry.selected, !entry.cache.isEmpty(), parsed.names());
        validateSelection(parsed, selected);
        String cache = subscriptions.writeCache(entry.id, parsed.nodeYaml());
        SubscriptionProfiles.replace(entries, entry.cached(cache, selected));
        try {
            committed(profileEditor(entries, entry.id, entry.url, selected));
        } catch (IOException failure) {
            subscriptions.discardCache(entry.id, cache);
            throw failure;
        }
        subscriptions.discardCache(entry.id, entry.cache);
    }

    private void validateSelection(ClashProfile profile, String selected) throws IOException {
        Settings settings = loadBase();
        settings.selectedProxy = selected;
        buildCoreYaml(profile, settings);
    }

    private SharedPreferences.Editor profileEditor(List<SubscriptionProfiles.Entry> entries,
                                                    String active, String url, String selected) throws IOException {
        return preferences.edit().putString(SubscriptionProfiles.INDEX, SubscriptionProfiles.encode(entries))
                .putString(SubscriptionProfiles.ACTIVE, active).putString("subscriptionUrl", url)
                .putString("selectedProxy", selected);
    }

    private void committed(SharedPreferences.Editor editor) throws IOException {
        Map<String, ?> previous = new HashMap<>(preferences.getAll());
        if (!editor.commit()) {
            // Android commits to its in-memory map before disk I/O. Restore the
            // previous map even if the rollback's disk write also fails.
            SharedPreferences.Editor restore = preferences.edit().clear();
            for (Map.Entry<String, ?> value : previous.entrySet()) {
                Object item = value.getValue();
                if (item instanceof String) restore.putString(value.getKey(), (String) item);
                else if (item instanceof Boolean) restore.putBoolean(value.getKey(), (Boolean) item);
                else if (item instanceof Integer) restore.putInt(value.getKey(), (Integer) item);
                else if (item instanceof Long) restore.putLong(value.getKey(), (Long) item);
                else if (item instanceof Float) restore.putFloat(value.getKey(), (Float) item);
                else if (item instanceof Set) {
                    Set<String> strings = new HashSet<>();
                    for (Object entry : (Set<?>) item)
                        if (entry instanceof String) strings.add((String) entry);
                    restore.putStringSet(value.getKey(), strings);
                }
            }
            restore.commit();
            throw new IOException("网络配置未能保存，原有配置未切换，请检查手机存储空间");
        }
        configurationRevision++;
    }

    private static void requireRevision(long expectedRevision) throws IOException {
        if (configurationRevision != expectedRevision)
            throw new IOException("下载期间网络配置已变更，原有选择未覆盖，请重新选择后重试");
    }

    private void changed() {
        context.sendBroadcast(new Intent(ACTION_CHANGED).setPackage(context.getPackageName()));
    }

    private List<SubscriptionProfiles.Entry> entries() throws IOException {
        List<SubscriptionProfiles.Entry> entries = SubscriptionProfiles.parse(
                preferences.getString(SubscriptionProfiles.INDEX, "[]"));
        for (SubscriptionProfiles.Entry entry : entries)
            checkedSubscriptionUrl(entry.url);
        return entries;
    }

    private SubscriptionProfiles.Entry activeEntry(List<SubscriptionProfiles.Entry> entries) throws IOException {
        String active = preferences.getString(SubscriptionProfiles.ACTIVE, "");
        return active.isEmpty() ? null : required(entries, active);
    }

    private static SubscriptionProfiles.Entry required(List<SubscriptionProfiles.Entry> entries, String id) throws IOException {
        SubscriptionProfiles.Entry entry = SubscriptionProfiles.byId(entries, id);
        if (entry == null)
            throw new IOException("所选订阅已不存在，请刷新订阅列表");
        return entry;
    }

    /** Called only under PROFILE_LOCK. Legacy bytes remain untouched until a new source is published. */
    private void ensureMigration() throws IOException {
        if (preferences.getBoolean(SubscriptionProfiles.MIGRATED, false))
            return;
        List<SubscriptionProfiles.Entry> entries = new ArrayList<>();
        String active = "";
        String legacyUrl = preferences.getString("subscriptionUrl", "").trim();
        String selected = preferences.getString("selectedProxy", "");
        String cache = "";
        SubscriptionProfiles.Entry migrated = null;
        if (!legacyUrl.isEmpty()) {
            try {
                String normalized = checkedSubscriptionUrl(legacyUrl);
                migrated = new SubscriptionProfiles.Entry(SubscriptionProfiles.newId(), "原有订阅", normalized, "", selected);
            } catch (IOException unsupportedLegacyUrl) {
                // Preserve the legacy local configuration; no invalid URL is imported.
            }
            if (migrated != null) {
                if (profile.getBaseFile().isFile()) {
                    ClashProfile old = readLegacyProfile();
                    selected = SubscriptionProfiles.chooseNode(selected, true, old.names());
                    cache = subscriptions.writeCache(migrated.id, old.nodeYaml());
                    migrated = migrated.cached(cache, selected);
                    active = migrated.id;
                }
                entries.add(migrated);
            }
        }
        SharedPreferences.Editor editor = preferences.edit().putBoolean(SubscriptionProfiles.MIGRATED, true)
                .putString(SubscriptionProfiles.INDEX, SubscriptionProfiles.encode(entries))
                .putString(SubscriptionProfiles.ACTIVE, active)
                .putBoolean(SubscriptionProfiles.LOCAL_AVAILABLE, legacyUrl.isEmpty() && profile.getBaseFile().isFile())
                .putString(SubscriptionProfiles.LOCAL_SELECTED, preferences.getString("selectedProxy", ""));
        if (!active.isEmpty())
            editor.putString("subscriptionUrl", migrated.url).putString("selectedProxy", selected);
        try {
            committed(editor);
        } catch (IOException failure) {
            if (migrated != null)
                subscriptions.discardCache(migrated.id, cache);
            throw failure;
        }
    }

    private static String checkedSubscriptionUrl(String address) throws IOException {
        String value = address == null ? "" : address.trim();
        if (value.length() > SubscriptionProfiles.MAX_URL)
            throw new IOException("订阅地址过长");
        return subscriptionUrl(value).toExternalForm();
    }

    private ClashProfile download(String address) throws IOException {
        URL url = subscriptionUrl(address.trim());
        for (int redirect = 0; redirect <= 3; redirect++) {
            HttpURLConnection connection = null;
            try {
                connection = (HttpURLConnection) url.openConnection();
                connection.setConnectTimeout(15_000);
                connection.setReadTimeout(20_000);
                connection.setInstanceFollowRedirects(false);
                connection.setRequestProperty("Accept", "application/yaml, text/yaml, text/plain, */*");
                connection.setRequestProperty("User-Agent", "PrivacyGuard/0.2");
                int response = connection.getResponseCode();
                if (response == 301 || response == 302 || response == 303 || response == 307 || response == 308) {
                    String destination = connection.getHeaderField("Location");
                    if (destination == null || redirect == 3)
                        throw new DownloadFailure("订阅地址重定向次数过多或缺少目标");
                    url = subscriptionUrl(new URL(url, destination).toExternalForm());
                    continue;
                }
                if (response != 200)
                    throw new DownloadFailure("订阅服务器返回 HTTP " + response);
                if (connection.getContentLengthLong() > ClashProfile.MAX_BYTES)
                    throw new DownloadFailure("订阅超过 2 MiB 导入上限");
                try (InputStream input = connection.getInputStream()) {
                    return ClashProfile.parse(readLimited(input));
                }
            } catch (javax.net.ssl.SSLException invalidCertificate) {
                throw new IOException("订阅的 HTTPS 证书验证失败");
            } catch (java.net.SocketTimeoutException timeout) {
                throw new IOException("订阅下载超时，请检查当前网络后重试");
            } catch (DownloadFailure safe) {
                throw safe;
            } catch (IOException unavailable) {
                // Transport/parser exception text can contain a token-bearing URL.
                throw new IOException("订阅下载或节点格式验证失败，原有配置未切换", unavailable);
            } finally {
                if (connection != null)
                    connection.disconnect();
            }
        }
        throw new IOException("订阅下载未完成");
    }

    private static final class DownloadFailure extends IOException {
        DownloadFailure(String safeMessage) { super(safeMessage); }
    }

    private static URL subscriptionUrl(String source) throws IOException {
        URL url;
        try {
            url = new URL(source);
        } catch (java.net.MalformedURLException invalid) {
            throw new IOException("请填写有效的 HTTPS 订阅地址");
        }
        if (!"https".equalsIgnoreCase(url.getProtocol()) || url.getHost().isEmpty()
                || url.getUserInfo() != null || url.getRef() != null)
            throw new IOException("订阅需要 HTTPS 地址，且不能包含用户名、密码或片段标记");
        return url;
    }

    private ClashProfile readProfile() throws IOException {
        synchronized (PROFILE_LOCK) {
            ensureMigration();
            return readProfileLocked(entries());
        }
    }

    private ClashProfile readProfileLocked(List<SubscriptionProfiles.Entry> entries) throws IOException {
        SubscriptionProfiles.Entry active = activeEntry(entries);
        if (active != null) {
            if (active.cache.isEmpty())
                throw new IOException("当前订阅还没有节点缓存，请先更新订阅");
            return ClashProfile.parse(subscriptions.readCache(active.id, active.cache));
        }
        return readLocalProfile();
    }

    private boolean hasLocalProfile() throws IOException {
        if (!preferences.getBoolean(SubscriptionProfiles.LOCAL_AVAILABLE, false))
            return false;
        String cache = preferences.getString(SubscriptionProfiles.LOCAL_CACHE, "");
        return cache.isEmpty() ? profile.getBaseFile().isFile()
                : subscriptions.hasCache(SubscriptionProfiles.LOCAL_ID, cache);
    }

    private ClashProfile readLocalProfile() throws IOException {
        String local = preferences.getString(SubscriptionProfiles.LOCAL_CACHE, "");
        return local.isEmpty() ? readLegacyProfile()
                : ClashProfile.parse(subscriptions.readCache(SubscriptionProfiles.LOCAL_ID, local));
    }

    private ClashProfile readLegacyProfile() throws IOException {
        try (InputStream input = profile.openRead()) {
            return ClashProfile.parse(readLimited(input));
        } catch (FileNotFoundException missing) {
            return ClashProfile.empty();
        }
    }

    private static String readLimited(InputStream input) throws IOException {
        if (input == null)
            throw new IOException("无法读取所选配置文件");
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int count;
        while ((count = input.read(buffer)) != -1) {
            if (output.size() + count > ClashProfile.MAX_BYTES)
                throw new IOException("配置文件超过 2 MiB 导入上限");
            output.write(buffer, 0, count);
        }
        return new String(output.toByteArray(), StandardCharsets.UTF_8);
    }
}
