package eu.faircode.netguard;

import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;
import android.os.SystemClock;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.PrivateKey;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import io.github.muntashirakon.adb.AbsAdbConnectionManager;
import io.github.muntashirakon.adb.AdbStream;

/** Local ADB activation followed by a token-authenticated loopback helper. */
public final class InternalAdbBridge {
    public interface SensorListener {
        void onSensorAccess(String operation, int uid, String packageName, long timeMillis);
        void onDisconnected();
    }

    public interface StateListener {
        void onStateChanged(boolean ready, String detail);
    }

    private static volatile InternalAdbBridge instance;
    private final Context context;
    private final Object activationLock = new Object();
    private final AtomicLong nextId = new AtomicLong();
    private final Map<Long, Pending> pending = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<SensorListener> sensors = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<StateListener> states = new CopyOnWriteArrayList<>();
    private final ExecutorService control = Executors.newSingleThreadExecutor();
    private volatile Connection connection;
    private volatile boolean busy;
    private volatile String status = "尚未激活内置 ADB";
    private volatile String lastError;
    private AdbManager manager;

    private InternalAdbBridge(Context context) {
        this.context = context.getApplicationContext();
    }

    public static InternalAdbBridge get(Context context) {
        InternalAdbBridge found = instance;
        if (found == null) {
            synchronized (InternalAdbBridge.class) {
                found = instance;
                if (found == null)
                    instance = found = new InternalAdbBridge(context);
            }
        }
        return found;
    }

    public boolean isReady() {
        return connection != null;
    }

    public boolean isBusy() {
        return busy;
    }

    public String status() {
        return status;
    }

    public String lastError() {
        return lastError;
    }

    public void addStateListener(StateListener listener) {
        states.addIfAbsent(listener);
    }

    public void removeStateListener(StateListener listener) {
        states.remove(listener);
    }

    /** Blocking operation. The pairing port is distinct from the connection port. */
    public void pair(int pairingPort, String code) throws Exception {
        checkPort(pairingPort);
        if (code == null || !code.matches("[0-9]{6}"))
            throw new IllegalArgumentException("请输入系统显示的六位配对码");
        synchronized (activationLock) {
            busy = true;
            updateStatus("正在配对本机无线调试", null);
            try {
                if (!manager().pair("127.0.0.1", pairingPort, code))
                    throw new IOException("本机 ADB 配对未完成");
                updateStatus(isReady() ? "内置 ADB 已激活" : "配对完成，请连接并激活", null);
            } catch (Exception failure) {
                updateStatus("配对失败，请检查配对端口和配对码", "配对失败");
                throw failure;
            } finally {
                busy = false;
            }
        }
    }

    /** Blocking operation. A successful helper survives closing the wireless ADB connection. */
    public void connect(int connectionPort) throws Exception {
        checkPort(connectionPort);
        synchronized (activationLock) {
            if (isReady())
                return;
            busy = true;
            updateStatus("正在连接本机并启动隐私服务", null);
            String token = randomHex(32);
            String stage = "listen";
            try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
                server.setSoTimeout(15_000);
                FutureTask<Connection> accepted = new FutureTask<>(() -> acceptAuthenticated(server, token));
                Thread acceptThread = new Thread(accepted, "internal-adb-accept");
                acceptThread.setDaemon(true);
                AdbStream launch = null;
                try {
                    stage = "identity";
                    debugStage(stage);
                    AdbManager adb = manager();
                    adb.disconnect();
                    stage = "tls-connect";
                    debugStage(stage);
                    if (!adb.connect("127.0.0.1", connectionPort))
                        throw new IOException("本机无线 ADB 连接失败");
                    // Do not spend the helper accept timeout waiting for the TLS handshake.
                    acceptThread.start();
                    stage = "shell-launch";
                    debugStage(stage);
                    String apk = shellQuote(context.getApplicationInfo().sourceDir);
                    String helperOutput = BuildConfig.DEBUG
                            ? "/data/local/tmp/privacy-guard-internal-helper.log" : "/dev/null";
                    // A legacy ADB shell can kill its background jobs when the shell exits.
                    // Keep this command in the foreground until authentication, and detach
                    // the helper's session before closing the ADB stream below.
                    String command = "CLASSPATH=" + apk + " /system/bin/setsid nohup /system/bin/app_process /system/bin "
                            + EmbeddedShellMain.class.getName() + " " + server.getLocalPort() + " " + Process.myUid()
                            + " " + token + " </dev/null >" + helperOutput + " 2>&1";
                    launch = adb.openStream("shell:" + command);
                    stage = "helper-authentication";
                    debugStage(stage);
                    Connection established = accepted.get(15, TimeUnit.SECONDS);
                    connection = established;
                    Thread reader = new Thread(() -> readEvents(established), "internal-adb-events");
                    reader.setDaemon(true);
                    reader.start();
                    stage = "helper-ping";
                    debugStage(stage);
                    request("ping", 3);
                    if (!sensors.isEmpty())
                        request("watch", 3);
                    context.getSharedPreferences("internal_adb", Context.MODE_PRIVATE).edit()
                            .putInt("connection_port", connectionPort).apply();
                    updateStatus("内置 ADB 已激活", null);
                    debugStage("ready");
                } finally {
                    accepted.cancel(true);
                    if (launch != null) {
                        try { launch.close(); } catch (IOException ignored) { }
                    }
                    if (manager != null) {
                        try { manager.disconnect(); } catch (IOException ignored) { }
                    }
                }
            } catch (Exception failure) {
                if (BuildConfig.DEBUG)
                    Log.d("InternalAdbBridge", "Activation failed at " + stage + ": "
                            + failure.getClass().getSimpleName()
                            + (failure.getCause() == null ? "" : " / " + failure.getCause().getClass().getSimpleName()));
                closeConnection(connection, "激活失败，请检查连接端口和系统授权");
                updateStatus("激活失败，请检查连接端口和系统授权", "激活失败");
                throw failure;
            } finally {
                busy = false;
            }
        }
    }

    private static void debugStage(String stage) {
        if (BuildConfig.DEBUG)
            Log.d("InternalAdbBridge", "Activation stage: " + stage);
    }

    public void disconnect() {
        synchronized (activationLock) {
            closeConnection(connection, "内置 ADB 已停用");
            updateStatus("内置 ADB 已停用", null);
        }
    }

    public int lastConnectionPort() {
        return context.getSharedPreferences("internal_adb", Context.MODE_PRIVATE).getInt("connection_port", 0);
    }

    public Bundle readSnapshot() throws Exception {
        JSONObject result = request("snapshot", 9);
        JSONArray ids = result.getJSONArray("uids");
        JSONArray received = result.getJSONArray("rxBytes");
        JSONArray sent = result.getJSONArray("txBytes");
        if (ids.length() > 10_000 || ids.length() != received.length() || ids.length() != sent.length())
            throw new IOException("系统流量样本格式无效");
        int[] uids = new int[ids.length()];
        long[] rx = new long[ids.length()];
        long[] tx = new long[ids.length()];
        for (int i = 0; i < ids.length(); i++) {
            uids[i] = ids.getInt(i);
            rx[i] = received.getLong(i);
            tx[i] = sent.getLong(i);
            if (uids[i] < 0 || rx[i] < 0 || tx[i] < 0)
                throw new IOException("系统流量样本格式无效");
        }
        Bundle snapshot = new Bundle();
        snapshot.putIntArray("uids", uids);
        snapshot.putLongArray("rxBytes", rx);
        snapshot.putLongArray("txBytes", tx);
        snapshot.putLong("elapsedRealtime", result.getLong("elapsedRealtime"));
        return snapshot;
    }

    public void watchSensors(SensorListener listener) throws Exception {
        sensors.addIfAbsent(listener);
        try {
            request("watch", 3);
        } catch (Exception failure) {
            sensors.remove(listener);
            throw failure;
        }
    }

    public void removeSensorListener(SensorListener listener) {
        sensors.remove(listener);
        if (sensors.isEmpty() && isReady()) {
            control.execute(() -> {
                try {
                    if (sensors.isEmpty() && isReady())
                        request("unwatch", 3);
                } catch (Exception ignored) {
                }
            });
        }
    }

    private AdbManager manager() throws Exception {
        if (Build.VERSION.SDK_INT < 30)
            throw new IOException("内置无线 ADB 需要 Android 11 或以上");
        if (manager == null)
            manager = new AdbManager(InternalAdbIdentity.load(context));
        return manager;
    }

    private Connection acceptAuthenticated(ServerSocket server, String token) throws Exception {
        long deadline = SystemClock.elapsedRealtime() + 15_000;
        while (SystemClock.elapsedRealtime() < deadline) {
            Socket candidate = server.accept();
            try {
                return authenticate(candidate, token);
            } catch (Exception ignored) {
                candidate.close();
            }
        }
        throw new IOException("本机隐私服务认证超时");
    }

    private Connection authenticate(Socket socket, String expectedToken) throws Exception {
        try {
            socket.setSoTimeout(1000);
            if (!socket.getInetAddress().isLoopbackAddress())
                throw new SecurityException("Unexpected helper address");
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            JSONObject hello = new JSONObject(readResponse(reader));
            byte[] expected = expectedToken.getBytes(StandardCharsets.US_ASCII);
            byte[] supplied = hello.optString("token").getBytes(StandardCharsets.US_ASCII);
            if (!MessageDigest.isEqual(expected, supplied) || hello.optInt("protocol") != 1
                    || hello.optInt("clientUid", -1) != Process.myUid()
                    || (hello.optInt("shellUid", -1) != 2000 && hello.optInt("shellUid", -1) != 0)
                    || !"hello".equals(hello.optString("event")))
                throw new SecurityException("Invalid helper authentication");
            socket.setSoTimeout(0);
            return new Connection(socket, reader);
        } catch (Exception failure) {
            socket.close();
            throw failure;
        }
    }

    private JSONObject request(String command, int timeoutSeconds) throws Exception {
        Connection active = connection;
        if (active == null)
            throw new IOException("请先激活内置 ADB");
        long id = nextId.incrementAndGet();
        Pending waiting = new Pending(active);
        pending.put(id, waiting);
        try {
            synchronized (active.output) {
                if (connection != active)
                    throw new IOException("内置隐私服务已断开");
                active.output.write(new JSONObject().put("id", id).put("command", command).toString());
                active.output.newLine();
                active.output.flush();
            }
            return waiting.reply.get(timeoutSeconds, TimeUnit.SECONDS);
        } finally {
            pending.remove(id);
        }
    }

    private void readEvents(Connection active) {
        try {
            String line;
            while ((line = readResponse(active.reader)) != null) {
                JSONObject message = new JSONObject(line);
                if ("sensor".equals(message.optString("event"))) {
                    String op = message.getString("operation");
                    int uid = message.getInt("uid");
                    if ((!"android:camera".equals(op) && !"android:record_audio".equals(op))
                            || uid < 0 || uid / 100_000 != Process.myUid() / 100_000)
                        continue;
                    for (SensorListener listener : sensors) {
                        try {
                            listener.onSensorAccess(op, uid, message.getString("package"), message.getLong("time"));
                        } catch (RuntimeException ignored) {
                            // A UI callback cannot revoke other consumers of this connection.
                        }
                    }
                } else if (message.has("id")) {
                    Pending waiting = pending.get(message.getLong("id"));
                    if (waiting != null && waiting.owner == active) {
                        if (message.optBoolean("ok"))
                            waiting.reply.complete(message.getJSONObject("result"));
                        else
                            waiting.reply.completeExceptionally(new IOException(message.optString("error", "隐私服务请求失败")));
                    }
                }
            }
        } catch (Exception ignored) {
            // Failure revokes this connection and completes every waiting request below.
        } finally {
            closeConnection(active, "内置隐私服务已断开，请重新激活");
        }
    }

    private void closeConnection(Connection active, String detail) {
        if (active == null || connection != active)
            return;
        synchronized (activationLock) {
            if (connection != active)
                return;
            connection = null;
            try {
                active.socket.close();
            } catch (IOException ignored) {
            }
            for (Pending waiting : pending.values())
                if (waiting.owner == active)
                    waiting.reply.completeExceptionally(new IOException(detail));
            updateStatus(detail, detail);
            for (SensorListener listener : sensors) {
                try {
                    listener.onDisconnected();
                } catch (RuntimeException ignored) {
                }
            }
        }
    }

    private void updateStatus(String detail, String error) {
        status = detail;
        lastError = error;
        for (StateListener listener : states) {
            try {
                listener.onStateChanged(isReady(), detail);
            } catch (RuntimeException ignored) {
            }
        }
    }

    private static String readResponse(BufferedReader input) throws IOException {
        StringBuilder value = new StringBuilder();
        for (int next; (next = input.read()) != -1; ) {
            if (next == '\n')
                return value.toString();
            if (next != '\r')
                value.append((char) next);
            if (value.length() > 2 * 1024 * 1024)
                throw new IOException("隐私服务响应过大");
        }
        if (value.length() > 0)
            throw new IOException("隐私服务响应不完整");
        return null;
    }

    static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private static void checkPort(int port) {
        if (port < 1 || port > 65_535)
            throw new IllegalArgumentException("端口应为 1 到 65535");
    }

    private static String randomHex(int bytes) {
        byte[] data = new byte[bytes];
        new SecureRandom().nextBytes(data);
        StringBuilder output = new StringBuilder(bytes * 2);
        for (byte value : data)
            output.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return output.toString();
    }

    private static final class Pending {
        final Connection owner;
        final CompletableFuture<JSONObject> reply = new CompletableFuture<>();
        Pending(Connection owner) {
            this.owner = owner;
        }
    }

    private static final class Connection {
        final Socket socket;
        final BufferedReader reader;
        final BufferedWriter output;
        Connection(Socket socket, BufferedReader reader) throws IOException {
            this.socket = socket;
            this.reader = reader;
            output = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
        }
    }

    private static final class AdbManager extends AbsAdbConnectionManager {
        private final InternalAdbIdentity identity;
        AdbManager(InternalAdbIdentity identity) {
            this.identity = identity;
            setApi(Build.VERSION.SDK_INT);
            setHostAddress("127.0.0.1");
            setTimeout(12, TimeUnit.SECONDS);
            setThrowOnUnauthorised(true);
        }
        @Override protected PrivateKey getPrivateKey() {
            return identity.privateKey;
        }
        @Override protected Certificate getCertificate() {
            return identity.certificate;
        }
        @Override protected String getDeviceName() {
            return "Privacy Guard";
        }
    }
}
