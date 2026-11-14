package eu.faircode.netguard;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;

import androidx.core.app.NotificationCompat;
import androidx.core.app.RemoteInput;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Keeps the system pairing dialog open: the code is entered from a notification. */
public final class InternalAdbPairingService extends Service {
    private static final String START = "internal_adb.pairing.start";
    private static final String SUBMIT = "internal_adb.pairing.submit";
    private static final String STOP = "internal_adb.pairing.stop";
    private static final String CODE = "pairing_code";
    private static final String SESSION = "session";
    private static final String CHANNEL = "internal_adb_pairing";
    private static final int NOTIFICATION = 31005;
    private static final int RESULT = 31006;
    private static final long TIMEOUT = 120_000;
    private static volatile String currentStatus = "";

    private final Handler main = new Handler(Looper.getMainLooper());
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Map<String, Integer> pairingPorts = new LinkedHashMap<>();
    private final Map<String, Integer> connectionPorts = new LinkedHashMap<>();
    private final Set<Integer> triedConnections = new LinkedHashSet<>();
    private final ArrayDeque<NsdServiceInfo> resolutionQueue = new ArrayDeque<>();
    private NsdManager nsd;
    private NsdManager.DiscoveryListener pairingDiscovery;
    private NsdManager.DiscoveryListener connectionDiscovery;
    private volatile String session;
    private volatile boolean active;
    private boolean busy;
    private boolean paired;
    private boolean resolving;
    private final Runnable timeout = () -> finish("配对等待已超时，请重新开始");

    static void start(Context context) {
        context.startForegroundService(new Intent(context, InternalAdbPairingService.class).setAction(START));
    }

    static String status() {
        return currentStatus;
    }

    @Override public void onCreate() {
        super.onCreate();
        nsd = (NsdManager) getSystemService(NSD_SERVICE);
        NotificationChannel channel = new NotificationChannel(CHANNEL, "本机无线 ADB 配对", NotificationManager.IMPORTANCE_HIGH);
        channel.setLockscreenVisibility(Notification.VISIBILITY_PRIVATE);
        notifications().createNotificationChannel(channel);
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            stopSelf();
            return START_NOT_STICKY;
        }
        String action = intent.getAction();
        if (START.equals(action)) {
            if (Build.VERSION.SDK_INT < 30) {
                stopSelf();
                return START_NOT_STICKY;
            }
            if (!active) {
                active = true;
                session = UUID.randomUUID().toString();
                currentStatus = "等待系统配对服务；请打开无线调试中的配对码弹窗";
                startForeground(NOTIFICATION, notification());
                notifications().cancel(RESULT);
                main.postDelayed(timeout, TIMEOUT);
                discover();
            }
        } else if (active && session.equals(intent.getStringExtra(SESSION))) {
            if (STOP.equals(action)) {
                finish("已取消无线 ADB 配对");
            } else if (SUBMIT.equals(action)) {
                Bundle results = RemoteInput.getResultsFromIntent(intent);
                CharSequence entered = results == null ? null : results.getCharSequence(CODE);
                String code = entered == null ? "" : entered.toString().trim();
                // The transient system result is never retained in an Intent or preferences.
                intent.setClipData(null);
                submit(code);
            }
        } else if (!active) {
            stopSelf();
        }
        return START_NOT_STICKY;
    }

    private void discover() {
        pairingDiscovery = discovery(true);
        connectionDiscovery = discovery(false);
        try {
            nsd.discoverServices("_adb-tls-pairing._tcp", NsdManager.PROTOCOL_DNS_SD, pairingDiscovery);
            nsd.discoverServices("_adb-tls-connect._tcp", NsdManager.PROTOCOL_DNS_SD, connectionDiscovery);
        } catch (RuntimeException failure) {
            finish("无法发现本机无线调试，请检查 Wi-Fi 和无线调试开关；也可使用分屏手动配对");
        }
    }

    private NsdManager.DiscoveryListener discovery(boolean pairing) {
        return new NsdManager.DiscoveryListener() {
            @Override public void onDiscoveryStarted(String type) { }
            @Override public void onDiscoveryStopped(String type) { }
            @Override public void onStartDiscoveryFailed(String type, int error) {
                main.post(() -> {
                    if (active) {
                        currentStatus = "服务发现暂不可用，可取消后重试，或使用分屏手动配对";
                        update();
                    }
                });
            }
            @Override public void onStopDiscoveryFailed(String type, int error) { }
            @Override public void onServiceFound(NsdServiceInfo info) {
                main.post(() -> {
                    if (active && resolutionQueue.size() < 32) {
                        resolutionQueue.add(info);
                        resolveNext();
                    }
                });
            }
            @Override public void onServiceLost(NsdServiceInfo info) {
                main.post(() -> {
                    (pairing ? pairingPorts : connectionPorts).remove(info.getServiceName());
                    if (active && !paired && !busy) {
                        currentStatus = pairingPorts.isEmpty() ? "等待配对码弹窗，请保持弹窗打开" : "已发现本机配对服务，请在通知中输入六位配对码";
                        update();
                    }
                });
            }
        };
    }

    @SuppressWarnings("deprecation")
    private void resolveNext() {
        if (!active || resolving || resolutionQueue.isEmpty())
            return;
        resolving = true;
        NsdServiceInfo next = resolutionQueue.remove();
        try {
            nsd.resolveService(next, new NsdManager.ResolveListener() {
                @Override public void onResolveFailed(NsdServiceInfo service, int error) {
                    main.post(() -> {
                        resolving = false;
                        resolveNext();
                    });
                }
                @Override public void onServiceResolved(NsdServiceInfo service) {
                    main.post(() -> {
                        resolving = false;
                        if (active && isOwnAddress(service.getHost()) && service.getPort() > 0 && service.getPort() <= 65535) {
                            String type = service.getServiceType();
                            if (type.contains("_adb-tls-pairing.")) {
                                pairingPorts.put(service.getServiceName(), service.getPort());
                                if (!paired && !busy) {
                                    currentStatus = "已发现本机配对服务，请保持系统弹窗打开，在此通知中输入六位配对码";
                                    update();
                                }
                            } else if (type.contains("_adb-tls-connect.")) {
                                connectionPorts.put(service.getServiceName(), service.getPort());
                                connectNext();
                            }
                        }
                        resolveNext();
                    });
                }
            });
        } catch (RuntimeException failure) {
            resolving = false;
            resolveNext();
        }
    }

    private static boolean isOwnAddress(InetAddress address) {
        if (address == null)
            return false;
        if (address.isLoopbackAddress())
            return true;
        try {
            for (NetworkInterface network : Collections.list(NetworkInterface.getNetworkInterfaces()))
                for (InetAddress own : Collections.list(network.getInetAddresses()))
                    if (own.equals(address))
                        return true;
        } catch (Exception ignored) {
        }
        return false;
    }

    private void submit(String code) {
        if (busy || paired)
            return;
        if (!code.matches("[0-9]{6}")) {
            currentStatus = "请输入系统弹窗里的六位数字配对码";
            update();
            return;
        }
        if (pairingPorts.isEmpty()) {
            currentStatus = "尚未发现本机配对端口，请保持系统配对码弹窗打开后重试";
            update();
            return;
        }
        Integer[] ports = new LinkedHashSet<>(pairingPorts.values()).toArray(new Integer[0]);
        String expected = session;
        busy = true;
        currentStatus = "正在配对本机无线调试";
        update();
        worker.execute(() -> {
            boolean success = false;
            for (int index = 0; index < ports.length && index < 3 && active && expected.equals(session); index++) {
                try {
                    // Discovery supplies a port only; credentials are never sent to a network peer.
                    InternalAdbBridge.get(this).pair(ports[index], code);
                    success = true;
                    break;
                } catch (Exception ignored) {
                }
            }
            boolean result = success;
            main.post(() -> {
                if (!active || !expected.equals(session))
                    return;
                busy = false;
                paired = result;
                currentStatus = result ? "配对完成，正在寻找本机连接端口并激活" : "配对未完成，请检查弹窗配对码后重新输入";
                update();
                if (result)
                    connectNext();
            });
        });
    }

    private void connectNext() {
        if (!active || !paired || busy)
            return;
        int port = 0;
        for (int candidate : connectionPorts.values())
            if (!triedConnections.contains(candidate) && triedConnections.size() < 3) {
                port = candidate;
                break;
            }
        if (port == 0)
            return;
        triedConnections.add(port);
        int selectedPort = port;
        String expected = session;
        busy = true;
        worker.execute(() -> {
            boolean success = false;
            try {
                if (active && expected.equals(session)) {
                    InternalAdbBridge.get(this).connect(selectedPort);
                    success = true;
                    if (!active || !expected.equals(session)) {
                        InternalAdbBridge.get(this).disconnect();
                        success = false;
                    }
                }
            } catch (Exception ignored) {
            }
            boolean result = success;
            main.post(() -> {
                if (!active || !expected.equals(session))
                    return;
                busy = false;
                if (result) {
                    finish("内置 ADB 已激活，可以返回隐私哨兵开启相机和麦克风提醒");
                } else {
                    currentStatus = "已配对，自动连接尚未完成；可返回应用填写无线调试主页面的连接端口";
                    update();
                    connectNext();
                }
            });
        });
    }

    private Notification notification() {
        PendingIntent open = PendingIntent.getActivity(this, 31005,
                new Intent(this, InternalAdbActivity.class), PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        PendingIntent cancel = PendingIntent.getService(this, 31006,
                new Intent(this, InternalAdbPairingService.class).setAction(STOP).putExtra(SESSION, session),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_security_white_24dp)
                .setContentTitle("隐私哨兵：无线 ADB 配对")
                .setContentText(currentStatus)
                .setStyle(new NotificationCompat.BigTextStyle().bigText(currentStatus))
                .setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true)
                .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
                .addAction(0, "取消配对", cancel);
        if (!paired && !busy) {
            int mutable = Build.VERSION.SDK_INT >= 31 ? PendingIntent.FLAG_MUTABLE : 0;
            PendingIntent submit = PendingIntent.getForegroundService(this, 31007,
                    new Intent(this, InternalAdbPairingService.class).setAction(SUBMIT).putExtra(SESSION, session),
                    PendingIntent.FLAG_UPDATE_CURRENT | mutable);
            builder.addAction(new NotificationCompat.Action.Builder(0, "输入配对码", submit)
                    .addRemoteInput(new RemoteInput.Builder(CODE).setLabel("六位配对码").build())
                    .setAllowGeneratedReplies(false).build());
        }
        return builder.build();
    }

    private void update() {
        if (active)
            notifications().notify(NOTIFICATION, notification());
    }

    private void finish(String message) {
        if (!active)
            return;
        active = false;
        currentStatus = message;
        cleanupDiscovery();
        stopForeground(STOP_FOREGROUND_REMOVE);
        PendingIntent open = PendingIntent.getActivity(this, 31005,
                new Intent(this, InternalAdbActivity.class), PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        notifications().notify(RESULT, new NotificationCompat.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_security_white_24dp).setContentTitle("隐私哨兵：无线 ADB")
                .setContentText(message).setStyle(new NotificationCompat.BigTextStyle().bigText(message))
                .setContentIntent(open).setAutoCancel(true).setVisibility(NotificationCompat.VISIBILITY_PRIVATE).build());
        stopSelf();
    }

    private void cleanupDiscovery() {
        main.removeCallbacks(timeout);
        if (pairingDiscovery != null) {
            try { nsd.stopServiceDiscovery(pairingDiscovery); } catch (RuntimeException ignored) { }
            pairingDiscovery = null;
        }
        if (connectionDiscovery != null) {
            try { nsd.stopServiceDiscovery(connectionDiscovery); } catch (RuntimeException ignored) { }
            connectionDiscovery = null;
        }
        resolutionQueue.clear();
        pairingPorts.clear();
        connectionPorts.clear();
    }

    private NotificationManager notifications() {
        return (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
    }

    @Override public IBinder onBind(Intent intent) {
        return null;
    }

    @Override public void onDestroy() {
        active = false;
        cleanupDiscovery();
        worker.shutdownNow();
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }
}
