package eu.faircode.netguard;

import android.app.AppOpsManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Looper;
import android.os.Process;

import androidx.annotation.Keep;
import androidx.annotation.RequiresApi;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

/** Narrow shell-privileged helper launched only after the user authorizes local ADB. */
@Keep
@RequiresApi(30)
public final class EmbeddedShellMain {
    private final Socket socket;
    private final BufferedWriter output;
    private final Context context;
    private final int clientUid;
    private AppOpsManager appOps;
    private AppOpsManager.OnOpActiveChangedListener watcher;

    private EmbeddedShellMain(Socket socket, Context context, int clientUid) throws IOException {
        this.socket = socket;
        this.context = context;
        this.clientUid = clientUid;
        output = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
    }

    public static void main(String[] args) {
        try {
            if (args.length != 3 || (Process.myUid() != 2000 && Process.myUid() != 0))
                throw new SecurityException("A user-authorized shell is required");
            int clientUid = Integer.parseInt(args[1]);
            int port = Integer.parseInt(args[0]);
            if (clientUid < 10_000 || port < 1 || port > 65_535
                    || !args[2].matches("[0-9a-f]{64}"))
                throw new SecurityException("Invalid helper identity");
            if (Looper.myLooper() == null)
                Looper.prepareMainLooper();
            Class<?> activityThread = Class.forName("android.app.ActivityThread");
            Object thread = activityThread.getMethod("systemMain").invoke(null);
            Context system = (Context) activityThread.getMethod("getSystemContext").invoke(thread);
            Context shell = system.createPackageContext("com.android.shell", 0);
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), 5000);
            EmbeddedShellMain helper = new EmbeddedShellMain(socket, shell, clientUid);
            helper.send(new JSONObject().put("event", "hello").put("token", args[2])
                    .put("clientUid", clientUid).put("shellUid", Process.myUid()).put("protocol", 1));
            Thread reader = new Thread(helper::readCommands, "privacy-shell-commands");
            reader.start();
            Looper.loop();
        } catch (Throwable failure) {
            failure.printStackTrace(System.err);
            // Only this separately launched helper process terminates.
            System.exit(1);
        }
    }

    private void readCommands() {
        try (BufferedReader input = new BufferedReader(new InputStreamReader(
                socket.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = readLine(input)) != null) {
                JSONObject request = new JSONObject(line);
                long id = request.getLong("id");
                String command = request.getString("command");
                try {
                    JSONObject result;
                    switch (command) {
                        case "ping":
                            result = new JSONObject().put("shellUid", Process.myUid()).put("protocol", 1);
                            break;
                        case "snapshot":
                            result = EmbeddedNetstats.collect();
                            break;
                        case "watch":
                            watch();
                            result = new JSONObject();
                            break;
                        case "unwatch":
                            unwatch();
                            result = new JSONObject();
                            break;
                        case "stop":
                            send(new JSONObject().put("id", id).put("ok", true).put("result", new JSONObject()));
                            return;
                        default:
                            throw new SecurityException("Unsupported helper command");
                    }
                    send(new JSONObject().put("id", id).put("ok", true).put("result", result));
                } catch (Exception failure) {
                    send(new JSONObject().put("id", id).put("ok", false)
                            .put("error", failure.getMessage() == null ? failure.getClass().getSimpleName() : failure.getMessage()));
                }
            }
        } catch (Exception ignored) {
            // EOF or malformed requests revoke this helper's lifetime.
        } finally {
            unwatch();
            try {
                socket.close();
            } catch (IOException ignored) {
            }
            System.exit(0);
        }
    }

    private void watch() {
        if (watcher != null)
            return;
        if (context.checkPermission("android.permission.WATCH_APPOPS", Process.myPid(), Process.myUid())
                != PackageManager.PERMISSION_GRANTED)
            throw new SecurityException("The system did not grant WATCH_APPOPS to shell");
        appOps = context.getSystemService(AppOpsManager.class);
        if (appOps == null)
            throw new IllegalStateException("AppOps is unavailable");
        AppOpsManager.OnOpActiveChangedListener listener = (operation, uid, packageName, active) -> {
            if (!active || packageName == null || uid < 0 || uid / 100_000 != clientUid / 100_000)
                return;
            try {
                send(new JSONObject().put("event", "sensor").put("operation", operation)
                        .put("uid", uid).put("package", packageName).put("time", System.currentTimeMillis()));
            } catch (Exception ignored) {
                // Closing the client revokes the helper on its command thread.
            }
        };
        appOps.startWatchingActive(new String[]{AppOpsManager.OPSTR_CAMERA,
                AppOpsManager.OPSTR_RECORD_AUDIO}, Runnable::run, listener);
        watcher = listener;
    }

    private void unwatch() {
        if (watcher != null) {
            try {
                appOps.stopWatchingActive(watcher);
            } catch (RuntimeException ignored) {
            }
            watcher = null;
        }
    }

    private synchronized void send(JSONObject message) throws IOException {
        output.write(message.toString());
        output.newLine();
        output.flush();
    }

    static String readLine(BufferedReader reader) throws IOException {
        StringBuilder value = new StringBuilder();
        for (int next; (next = reader.read()) != -1; ) {
            if (next == '\n')
                return value.toString();
            if (next != '\r')
                value.append((char) next);
            if (value.length() > 16 * 1024)
                throw new IOException("Helper command exceeds limit");
        }
        if (value.length() > 0)
            throw new IOException("Incomplete helper command");
        return null;
    }
}
