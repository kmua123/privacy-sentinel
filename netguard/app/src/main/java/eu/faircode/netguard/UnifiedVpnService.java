package eu.faircode.netguard;

/* SPDX-License-Identifier: GPL-3.0-or-later */

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.RouteInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.ParcelFileDescriptor;

import androidx.core.app.NotificationCompat;
import androidx.core.content.ContextCompat;
import androidx.preference.PreferenceManager;

import org.json.JSONObject;

import java.io.File;
import java.net.InetAddress;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import guardcore.Callbacks;
import guardcore.Guardcore;

/** Owns the only VPN and enforces app policy before any core egress. */
public final class UnifiedVpnService extends VpnService {
    public static final String ACTION_POLICY = "local.privacy.guard.POLICY_CHANGED";
    private static final String ACTION_STOP = "local.privacy.guard.STOP_VPN";
    private static final String CHANNEL = "unified_network";
    private static final int NOTICE = 9301;
    static volatile boolean running;
    static volatile boolean starting;
    static volatile String error = "";
    static volatile String homeError = "";
    private static volatile UnifiedVpnService liveService;
    private static volatile String physicalNetworkSummary = "联网守卫未运行";
    private static volatile String vpnAddressSummary = "VPN 地址尚未建立";
    private static volatile String socketBindingFailure = "";
    private static volatile String networkMonitoringWarning = "";
    private static volatile boolean networkRecoveryPending;
    private static volatile long lastNetworkRecoveryAt;
    private static volatile int networkRecoveryCount;

    private static final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler networkHandler = new Handler(Looper.getMainLooper());
    private final NetworkHandoffState handoff = new NetworkHandoffState();
    // Callback access is serialized on networkHandler. Only a small recent loss
    // set is needed to reject an OS default that is briefly stale after onLost.
    private final Set<Network> lostPhysicalNetworks = new LinkedHashSet<>();
    private volatile PhysicalNetwork physicalNetwork = PhysicalNetwork.unknown("尚未检测底层网络");
    private ConnectivityManager connectivity;
    private boolean physicalCallbackRegistered;
    private boolean defaultCallbackRegistered;
    private volatile ParcelFileDescriptor tunnel;
    // Read/written only by the serialized core worker alongside tunnel.
    private boolean tunnelIpv6;
    private boolean receiverRegistered;
    private boolean initialStartQueued;
    private volatile boolean stopping;
    private volatile boolean wanted;
    private final Runnable checkNetwork = this::reconcilePhysicalNetwork;

    private final ConnectivityManager.NetworkCallback physicalCallback = new ConnectivityManager.NetworkCallback() {
        @Override public void onAvailable(Network network) {
            lostPhysicalNetworks.remove(network);
            scheduleNetworkCheck();
        }
        @Override public void onLost(Network network) {
            lostPhysicalNetworks.add(network);
            while (lostPhysicalNetworks.size() > 32)
                lostPhysicalNetworks.remove(lostPhysicalNetworks.iterator().next());
            scheduleNetworkCheck();
        }
        @Override public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
            scheduleNetworkCheck();
        }
        @Override public void onLinkPropertiesChanged(Network network, LinkProperties properties) {
            scheduleNetworkCheck();
        }
    };

    // Selection of the OS default can happen after a candidate's onAvailable.
    // This second callback triggers a fresh selection; it never selects its
    // event's Network blindly, and VPN events cannot change the fingerprint.
    private final ConnectivityManager.NetworkCallback defaultCallback = new ConnectivityManager.NetworkCallback() {
        @Override public void onAvailable(Network network) { scheduleNetworkCheck(); }
        @Override public void onLost(Network network) { scheduleNetworkCheck(); }
        @Override public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
            scheduleNetworkCheck();
        }
        @Override public void onLinkPropertiesChanged(Network network, LinkProperties properties) {
            scheduleNetworkCheck();
        }
    };

    private final BroadcastReceiver configChanged = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            worker.execute(() -> {
                if (!isCurrent() || !preferences().getBoolean("enabled", false))
                    return;
                running = false;
                Guardcore.stop();
                startCore();
            });
        }
    };

    static void start(Context context) {
        ContextCompat.startForegroundService(context, new Intent(context, UnifiedVpnService.class));
    }

    static void stop(Context context) {
        context.startService(new Intent(context, UnifiedVpnService.class).setAction(ACTION_STOP));
    }

    static void policyChanged(Context context) {
        if (running || starting)
            context.startService(new Intent(context, UnifiedVpnService.class).setAction(ACTION_POLICY));
    }

    @Override public void onCreate() {
        super.onCreate();
        liveService = this;
        lastNetworkRecoveryAt = 0;
        networkRecoveryCount = 0;
        networkRecoveryPending = false;
        socketBindingFailure = "";
        networkMonitoringWarning = "";
        vpnAddressSummary = "VPN 地址尚未建立";
        connectivity = getSystemService(ConnectivityManager.class);
        physicalNetwork = readPhysicalDefault();
        physicalNetworkSummary = physicalNetwork.summary;
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(CHANNEL, "统一联网守卫",
                NotificationManager.IMPORTANCE_LOW));
        ContextCompat.registerReceiver(this, configChanged,
                new IntentFilter(NetworkConfig.ACTION_CHANGED), ContextCompat.RECEIVER_NOT_EXPORTED);
        receiverRegistered = true;
        registerNetworkMonitoring();
    }

    public static String networkDiagnostics() {
        StringBuilder result = new StringBuilder(physicalNetworkSummary);
        result.append('\n').append(vpnAddressSummary);
        if (networkRecoveryPending)
            result.append("\n正在根据底层网络变化恢复连接，VPN 继续接管流量。");
        if (lastNetworkRecoveryAt > 0)
            result.append("\n最近恢复：")
                    .append(android.text.format.DateFormat.format("MM-dd HH:mm:ss", lastNetworkRecoveryAt))
                    .append(" · 本次运行恢复 ").append(networkRecoveryCount).append(" 次");
        if (!socketBindingFailure.isEmpty())
            result.append('\n').append(socketBindingFailure);
        if (!networkMonitoringWarning.isEmpty())
            result.append('\n').append(networkMonitoringWarning);
        return result.toString();
    }

    private boolean isCurrent() {
        return !stopping && liveService == this;
    }

    private void registerNetworkMonitoring() {
        if (connectivity == null)
            return;
        try {
            NetworkRequest request = new NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build();
            connectivity.registerNetworkCallback(request, physicalCallback, networkHandler);
            physicalCallbackRegistered = true;
            connectivity.registerDefaultNetworkCallback(defaultCallback, networkHandler);
            defaultCallbackRegistered = true;
        } catch (RuntimeException unavailable) {
            networkMonitoringWarning = "底层网络监听未能完整注册；切网后可手动停止并重启守卫。";
        }
    }

    private void scheduleNetworkCheck() {
        if (!isCurrent())
            return;
        networkHandler.removeCallbacks(checkNetwork);
        // Re-read the actual default after Android settles candidate and link events.
        networkHandler.postDelayed(checkNetwork, 1000);
    }

    private void reconcilePhysicalNetwork() {
        if (!isCurrent())
            return;
        PhysicalNetwork observed = readPhysicalDefault();
        if (observed.kind == PhysicalNetwork.UNKNOWN && physicalNetwork.network != null
                && !lostPhysicalNetworks.contains(physicalNetwork.network)) {
            // Some ROMs briefly return the VPN as their default. Do not guess a
            // cellular alternative or rebuild on the VPN's own capability event.
            physicalNetworkSummary = physicalNetwork.summary + "\n底层默认网络暂不可确认，保留现有连接。";
            return;
        }
        physicalNetwork = observed;
        physicalNetworkSummary = observed.summary;
        worker.execute(() -> {
            if (!isCurrent() || !wanted || !preferences().getBoolean("enabled", false)
                    || !handoff.needsRecovery(physicalNetwork.signature))
                return;
            networkRecoveryPending = true;
            running = false;
            starting = true;
            Guardcore.stop();
            // Preserve the original TUN, app policies and on-disk ZeroTier identity.
            startCore(true);
        });
    }

    private PhysicalNetwork readPhysicalDefault() {
        try {
            if (connectivity == null)
                return PhysicalNetwork.unknown("无法读取系统默认网络");
            Network network = connectivity.getActiveNetwork();
            if (network == null || lostPhysicalNetworks.contains(network))
                return PhysicalNetwork.offline();
            NetworkCapabilities capabilities = connectivity.getNetworkCapabilities(network);
            if (capabilities == null)
                return PhysicalNetwork.offline();
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN))
                return PhysicalNetwork.unknown("系统当前返回 VPN 网络，底层默认网络暂不可确认");
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))
                return PhysicalNetwork.offline();
            LinkProperties properties = connectivity.getLinkProperties(network);
            List<String> addresses = new ArrayList<>();
            List<String> dns = new ArrayList<>();
            List<String> routes = new ArrayList<>();
            String interfaceName = "";
            int mtu = 0;
            boolean ipv6Address = false;
            boolean ipv6DefaultRoute = false;
            if (properties != null) {
                interfaceName = properties.getInterfaceName();
                mtu = properties.getMtu();
                for (LinkAddress address : properties.getLinkAddresses()) {
                    addresses.add(address.toString());
                    InetAddress value = address.getAddress();
                    if (value instanceof Inet6Address && !value.isLinkLocalAddress()
                            && !value.isLoopbackAddress() && !value.isAnyLocalAddress()
                            && !value.isMulticastAddress())
                        ipv6Address = true;
                }
                for (InetAddress server : properties.getDnsServers())
                    dns.add(server.getHostAddress());
                for (RouteInfo route : properties.getRoutes()) {
                    routes.add(route.toString());
                    if (route.isDefaultRoute() && route.getDestination().getAddress() instanceof Inet6Address)
                        ipv6DefaultRoute = true;
                }
            }
            boolean ipv6Ready = ipv6Address && ipv6DefaultRoute;
            String type = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ? "Wi-Fi"
                    : capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ? "移动数据"
                    : capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ? "以太网" : "其他网络";
            String summary = "系统默认底层网络：" + type
                    + "\n互联网验证：" + (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                    ? "已通过" : "尚未通过")
                    + "\n网页登录认证：" + (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)
                    ? "系统提示需要认证" : "系统未提示认证")
                    + "\n底层 IPv6：" + (ipv6Ready ? "已检测到地址和默认路由" : "未检测到完整的 IPv6 默认路径");
            return new PhysicalNetwork(PhysicalNetwork.AVAILABLE, network,
                    NetworkHandoffState.fingerprint(Long.toString(network.getNetworkHandle()),
                            interfaceName == null ? "" : interfaceName, mtu, addresses, dns, routes), summary, ipv6Ready);
        } catch (RuntimeException unavailable) {
            return PhysicalNetwork.unknown("底层网络状态暂不可读取，由系统选择默认网络");
        }
    }

    private static final class PhysicalNetwork {
        static final int UNKNOWN = 0;
        static final int OFFLINE = 1;
        static final int AVAILABLE = 2;
        final int kind;
        final Network network;
        final String signature;
        final String summary;
        final boolean ipv6Ready;
        PhysicalNetwork(int kind, Network network, String signature, String summary, boolean ipv6Ready) {
            this.kind = kind;
            this.network = network;
            this.signature = signature;
            this.summary = summary;
            this.ipv6Ready = ipv6Ready;
        }
        static PhysicalNetwork offline() {
            return new PhysicalNetwork(OFFLINE, null, "offline", "系统当前无可用的默认网络；VPN 保持接管，等待恢复。", false);
        }
        static PhysicalNetwork unknown(String summary) {
            return new PhysicalNetwork(UNKNOWN, null, "unknown", summary, false);
        }
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            wanted = false;
            preferences().edit().putBoolean("enabled", false).apply();
            stopSelf();
            return START_NOT_STICKY;
        }
        startForeground(NOTICE, notification());
        if (NetworkApproval.ACTION_DECISION.equals(action)) {
            boolean changed = NetworkApproval.get(this).decide(
                    intent.getStringExtra(NetworkApproval.EXTRA_KEY),
                    intent.getStringExtra(NetworkApproval.EXTRA_DECISION));
            String decision = intent.getStringExtra(NetworkApproval.EXTRA_DECISION);
            if (changed && (NetworkApproval.DENY.equals(decision)
                    || NetworkApproval.FORGET.equals(decision)))
                worker.execute(Guardcore::closeConnections);
            if (!running && !starting && tunnel == null)
                stopSelf();
            return START_NOT_STICKY;
        }
        if (NetworkApproval.ACTION_TEMPORARY_EXPIRY.equals(action)) {
            NetworkApproval.get(this).expireTemporary();
            return START_NOT_STICKY;
        }
        if (ACTION_POLICY.equals(action)) {
            worker.execute(Guardcore::closeConnections);
            return START_STICKY;
        }
        wanted = true;
        preferences().edit().putBoolean("enabled", true).apply();
        if (!initialStartQueued) {
            initialStartQueued = true;
            starting = true;
            stopping = false;
            worker.execute(this::startCore);
        }
        return START_STICKY;
    }

    private SharedPreferences preferences() {
        return PreferenceManager.getDefaultSharedPreferences(this);
    }

    private void startCore() {
        startCore(false);
    }

    private void startCore(boolean recovering) {
        if (!isCurrent() || !wanted)
            return;
        PhysicalNetwork selectedNetwork = physicalNetwork;
        starting = true;
        error = "";
        homeError = "";
        try {
            NetworkConfig.PreparedCore prepared = new NetworkConfig(this).prepareCore(selectedNetwork.ipv6Ready);
            if (tunnel == null || tunnelIpv6 != prepared.ipv6Enabled) {
                if (!isCurrent() || !wanted)
                    return;
                if (tunnel != null) {
                    running = false;
                    Guardcore.stop();
                }
                Builder builder = new Builder().setSession("隐私哨兵 · 审批／代理／回家")
                        .addAddress("10.99.0.1", 30)
                        .addRoute("0.0.0.0", 0).addRoute("::", 0)
                        .addDnsServer("10.99.0.2").setMtu(1400)
                        .addDisallowedApplication(getPackageName());
                // An IPv6 route still captures/blocks that family. Publishing a
                // usable-looking ULA address on an IPv4-only uplink misleads
                // applications using HTTPDNS/HTTPS hints outside normal AAAA.
                if (prepared.ipv6Enabled)
                    builder.addAddress("fd99:7072:6976::1", 126);
                if (Build.VERSION.SDK_INT >= 29)
                    builder.setMetered(false);
                ParcelFileDescriptor replacement = builder.establish();
                if (replacement == null)
                    throw new IllegalStateException("VPN 授权已撤销");
                // establish deactivates the old interface only after success.
                // Never close the existing descriptor before its replacement.
                ParcelFileDescriptor previous = tunnel;
                tunnel = replacement;
                tunnelIpv6 = prepared.ipv6Enabled;
                vpnAddressSummary = "VPN IPv6 地址：" + (tunnelIpv6 ? "已发布" : "未发布（仍接管 IPv6 路由）");
                if (previous != null) {
                    try { previous.close(); }
                    catch (Exception ignored) { /* old interface is already inactive */ }
                }
            }
            if (tunnel == null)
                throw new IllegalStateException("VPN 授权已撤销");
            try {
                setUnderlyingNetworks(selectedNetwork.kind == PhysicalNetwork.AVAILABLE
                        ? new Network[]{selectedNetwork.network}
                        : selectedNetwork.kind == PhysicalNetwork.OFFLINE ? new Network[0] : null);
            } catch (RuntimeException unavailable) {
                // Socket protection/binding below remains mandatory; this API
                // is also used by Android to describe VPN transport properties.
                socketBindingFailure = "系统未能更新 VPN 的底层网络信息。";
            }
            if (selectedNetwork.kind == PhysicalNetwork.OFFLINE) {
                running = false;
                error = "底层网络不可用，VPN 保持阻断，网络恢复后将自动重连";
                return;
            }
            File state = new File(getNoBackupFilesDir(), "network-core");
            if (!state.isDirectory() && !state.mkdirs())
                throw new IllegalStateException("无法创建本地网络状态目录");
            new NetworkConfig(this).prepareRuleAssets(state);
            Guardcore.start(tunnel.getFd(), prepared.yaml, state.getAbsolutePath(), callbacks);
            if (!isCurrent() || !wanted) {
                stopCore();
                return;
            }
            running = true;
            if (recovering) {
                lastNetworkRecoveryAt = System.currentTimeMillis();
                networkRecoveryCount++;
            }
            preferences().edit().putBoolean("enabled", true).apply();
        } catch (Exception failure) {
            if (BuildConfig.DEBUG)
                android.util.Log.e("UnifiedGuard", "Core startup failed", failure);
            running = false;
            Guardcore.stop();
            error = tunnel == null ? "联网守卫启动失败，请检查配置与 VPN 授权"
                    : "核心启动失败，VPN 保持阻断。请检查网络配置后重试或停止守卫";
            if (wanted && !stopping)
                preferences().edit().putBoolean("enabled", tunnel != null).apply();
        } finally {
            handoff.applied(selectedNetwork.signature);
            if (liveService == this) {
                starting = false;
                networkRecoveryPending = false;
                getSystemService(NotificationManager.class).notify(NOTICE, notification());
            }
        }
    }

    private final Callbacks callbacks = new Callbacks() {
        @Override public boolean protect(long fd) {
            if (!isCurrent() || !wanted || fd < 0 || fd > Integer.MAX_VALUE)
                return false;
            PhysicalNetwork selectedNetwork = physicalNetwork;
            if (selectedNetwork.kind == PhysicalNetwork.OFFLINE
                    || !UnifiedVpnService.this.protect((int) fd))
                return false;
            if (selectedNetwork.network != null) {
                // fromFd duplicates ownership. Binding the duplicate binds the
                // same socket, and closing it never closes Go's original FD.
                try (ParcelFileDescriptor duplicate = ParcelFileDescriptor.fromFd((int) fd)) {
                    selectedNetwork.network.bindSocket(duplicate.getFileDescriptor());
                    socketBindingFailure = "";
                } catch (Exception refused) {
                    socketBindingFailure = "底层网络绑定失败，该连接已拒绝；网络变化后会重建连接。";
                    return false;
                }
            }
            return isCurrent();
        }

        @Override public long resolveUid(int protocol, String source, String destination) {
            try {
                return getSystemService(ConnectivityManager.class).getConnectionOwnerUid(protocol,
                        endpoint(source), endpoint(destination));
            } catch (Exception unsupported) {
                return -1;
            }
        }

        @Override public boolean permit(long uid, int protocol, String source, String destination) {
            if (stopping)
                return false;
            try {
                InetSocketAddress peer = endpoint(destination);
                Packet packet = new Packet();
                packet.uid = (int) uid;
                packet.protocol = protocol;
                packet.daddr = peer.getAddress().getHostAddress();
                packet.dport = peer.getPort();
                NetworkApproval approval = NetworkApproval.get(UnifiedVpnService.this);
                return approval.permit(approval.targetForUid((int) uid), packet);
            } catch (Exception invalid) {
                return false;
            }
        }

        @Override public void event(String json) {
            try {
                JSONObject event = new JSONObject(json);
                if ("home_error".equals(event.optString("type"))) {
                    homeError = "回家网络初始化失败，请检查配置并重试";
                    if (BuildConfig.DEBUG)
                        android.util.Log.w("UnifiedGuard", "Home initialization: " + event.optString("message", "unavailable"));
                    return;
                }
                if (!"usage".equals(event.optString("type")))
                    return;
                int uid = event.getInt("uid");
                InetSocketAddress destination = endpoint(event.getString("destination"));
                Usage usage = new Usage();
                usage.Uid = uid;
                usage.Protocol = event.getInt("protocol");
                usage.DAddr = destination.getAddress().getHostAddress();
                usage.DPort = destination.getPort();
                usage.Sent = event.optLong("sent");
                NetworkApproval approval = NetworkApproval.get(UnifiedVpnService.this);
                approval.usage(approval.targetForUid(uid), usage);
            } catch (Exception ignored) {
                // Malformed optional accounting events cannot affect authorization.
            }
        }
    };

    static InetSocketAddress endpoint(String value) throws Exception {
        int separator = value.lastIndexOf(':');
        if (separator <= 0)
            throw new IllegalArgumentException("Missing port");
        String address = value.substring(0, separator);
        if (address.startsWith("[") && address.endsWith("]"))
            address = address.substring(1, address.length() - 1);
        InetAddress numeric;
        if (address.contains(":")) {
            if (!address.matches("[0-9a-fA-F:.%]+"))
                throw new IllegalArgumentException("Expected numeric IPv6 address");
            numeric = InetAddress.getByName(address);
        } else {
            String[] parts = address.split("\\.", -1);
            if (parts.length != 4)
                throw new IllegalArgumentException("Expected numeric IPv4 address");
            byte[] bytes = new byte[4];
            for (int index = 0; index < parts.length; index++) {
                if (!parts[index].matches("[0-9]{1,3}"))
                    throw new IllegalArgumentException("Expected numeric IPv4 address");
                int part = Integer.parseInt(parts[index]);
                if (part > 255)
                    throw new IllegalArgumentException("Invalid IPv4 address");
                bytes[index] = (byte) part;
            }
            numeric = InetAddress.getByAddress(bytes);
        }
        return new InetSocketAddress(numeric,
                Integer.parseInt(value.substring(separator + 1)));
    }

    private Notification notification() {
        PendingIntent home = PendingIntent.getActivity(this, 0,
                new Intent(this, PrivacyHomeActivity.class), PendingIntent.FLAG_IMMUTABLE);
        String detail = !error.isEmpty() ? error : running
                ? "审批在前，直连、代理和回家共用同一策略" : "正在准备统一网络内核";
        return new NotificationCompat.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_security_white_24dp)
                .setContentTitle("隐私哨兵 · 统一联网守卫")
                .setContentText(detail).setContentIntent(home)
                .setOngoing(running || starting || tunnel != null).build();
    }

    private void stopCore() {
        running = false;
        Guardcore.stop();
        if (tunnel != null) {
            try {
                tunnel.close();
            } catch (Exception ignored) {
                // The OS may already have revoked the descriptor.
            }
            tunnel = null;
        }
        if (liveService == null || liveService == this)
            vpnAddressSummary = "VPN 地址尚未建立";
    }

    @Override public void onRevoke() {
        wanted = false;
        preferences().edit().putBoolean("enabled", false).apply();
        stopSelf();
        super.onRevoke();
    }

    @Override public void onDestroy() {
        stopping = true;
        wanted = false;
        networkHandler.removeCallbacks(checkNetwork);
        if (connectivity != null) {
            if (physicalCallbackRegistered) {
                try { connectivity.unregisterNetworkCallback(physicalCallback); }
                catch (RuntimeException ignored) { }
            }
            if (defaultCallbackRegistered) {
                try { connectivity.unregisterNetworkCallback(defaultCallback); }
                catch (RuntimeException ignored) { }
            }
        }
        if (liveService == this) {
            liveService = null;
            physicalNetworkSummary = "联网守卫未运行";
            networkRecoveryPending = false;
        }
        if (receiverRegistered)
            unregisterReceiver(configChanged);
        worker.execute(() -> {
            stopCore();
            NetworkApproval.get(this).clearAlerts();
        });
        starting = false;
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }
}
