package eu.faircode.netguard;

import android.app.AppOpsManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.provider.Settings;
import android.util.Log;

import androidx.core.app.NotificationCompat;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class SensorWatchService extends Service {
    static final String STATE_CHANGED = "sensor_watch.state_changed";
    static final String ALERT_CHANNEL = "sensor_access";
    static final String CAMERA = AppOpsManager.OPSTR_CAMERA;
    static final String MIC = AppOpsManager.OPSTR_RECORD_AUDIO;

    private static final String TAG = "SensorWatch";
    private static final String STOP = "sensor_watch.stop";
    private static final String STATUS_CHANNEL = "sensor_watch";
    private static final int STATUS_ID = 31001;
    private static final int ALERT_ID = 31002;
    private static final int INTERRUPTED_ID = 31003;
    private static final int MAX_HISTORY = 60;
    private static final long CONNECT_TIMEOUT_MS = 12000;

    private static int status = R.string.sensor_stopped;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final Runnable connectTimeout = () -> interrupted(R.string.sensor_connection_error);
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private boolean bound;
    private boolean stopping;
    private final InternalAdbBridge.SensorListener listener = new InternalAdbBridge.SensorListener() {
        @Override public void onSensorAccess(String operation, int uid, String packageName, long timeMillis) {
            main.post(() -> handleAccess(operation, uid, packageName, timeMillis));
        }
        @Override public void onDisconnected() {
            main.post(() -> interrupted(R.string.sensor_shizuku_stopped));
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationManager manager = notifications();
        manager.createNotificationChannel(new NotificationChannel(STATUS_CHANNEL,
                getText(R.string.sensor_title), NotificationManager.IMPORTANCE_LOW));
        NotificationChannel alerts = new NotificationChannel(ALERT_CHANNEL,
                getText(R.string.sensor_alert_channel), NotificationManager.IMPORTANCE_HIGH);
        alerts.setLockscreenVisibility(Notification.VISIBILITY_PRIVATE);
        manager.createNotificationChannel(alerts);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && STOP.equals(intent.getAction())) {
            stopping = true;
            setStatus(R.string.sensor_stopped);
            notifications().cancel(INTERRUPTED_ID);
            stopSelf();
            return START_NOT_STICKY;
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            stopSelf();
            return START_NOT_STICKY;
        }
        if (bound || stopping)
            return START_NOT_STICKY;

        setStatus(R.string.sensor_connecting);
        startForeground(STATUS_ID, statusNotification());
        notifications().cancel(INTERRUPTED_ID);
        InternalAdbBridge bridge = InternalAdbBridge.get(this);
        if (!bridge.isReady()) {
            interrupted(R.string.sensor_shizuku_needed);
            return START_NOT_STICKY;
        }
        bound = true;
        setStatus(R.string.sensor_waiting_event);
        main.postDelayed(connectTimeout, CONNECT_TIMEOUT_MS);
        worker.execute(() -> {
            try {
                bridge.watchSensors(listener);
                main.post(() -> {
                    main.removeCallbacks(connectTimeout);
                    if (!stopping) {
                        notifications().notify(STATUS_ID, statusNotification());
                    } else {
                        bridge.removeSensorListener(listener);
                    }
                });
            } catch (Exception failure) {
                main.post(() -> interrupted(R.string.sensor_connection_error));
            }
        });
        return START_NOT_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        stopping = true;
        main.removeCallbacksAndMessages(null);
        if (bound)
            InternalAdbBridge.get(this).removeSensorListener(listener);
        worker.shutdownNow();
        if (isEnabled())
            setStatus(R.string.sensor_stopped);
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }

    static int getStatus() {
        return status;
    }

    static boolean isEnabled() {
        return status == R.string.sensor_connecting || status == R.string.sensor_waiting_event
                || status == R.string.sensor_running;
    }

    static int operationLabel(String operation) {
        return CAMERA.equals(operation) ? R.string.sensor_camera : R.string.sensor_mic;
    }

    static CharSequence appName(Context context, String packageName) {
        PackageManager manager = context.getPackageManager();
        try {
            ApplicationInfo app = manager.getApplicationInfo(packageName, 0);
            return manager.getApplicationLabel(app);
        } catch (PackageManager.NameNotFoundException ex) {
            return packageName;
        }
    }

    static SharedPreferences historyPreferences(Context context) {
        return context.getSharedPreferences("sensor_events", MODE_PRIVATE);
    }

    static JSONArray readHistory(Context context) {
        try {
            return new JSONArray(historyPreferences(context).getString("events", "[]"));
        } catch (JSONException ex) {
            Log.w(TAG, "Could not read local sensor history", ex);
            return new JSONArray();
        }
    }

    private void handleAccess(String operation, int uid, String packageName, long timeMillis) {
        if (stopping || (status != R.string.sensor_waiting_event && status != R.string.sensor_running)
                || packageName == null
                || (!CAMERA.equals(operation) && !MIC.equals(operation)))
            return;

        if (status == R.string.sensor_waiting_event) {
            setStatus(R.string.sensor_running);
            notifications().notify(STATUS_ID, statusNotification());
        }

        try {
            JSONObject event = new JSONObject();
            event.put("package", packageName);
            event.put("operation", operation);
            event.put("uid", uid);
            event.put("time", timeMillis);
            JSONArray history = readHistory(this);
            history.put(event);
            while (history.length() > MAX_HISTORY)
                history.remove(0);
            historyPreferences(this).edit().putString("events", history.toString()).apply();
        } catch (JSONException ex) {
            Log.w(TAG, "Could not save a sensor event", ex);
        }

        CharSequence label = appName(this, packageName);
        String sensor = getString(operationLabel(operation));
        Intent settings = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.fromParts("package", packageName, null));
        PendingIntent details = PendingIntent.getActivity(this, 0, settings, PendingIntent.FLAG_IMMUTABLE);
        Notification notification = new NotificationCompat.Builder(this, ALERT_CHANNEL)
                .setSmallIcon(R.drawable.ic_security_white_24dp)
                .setContentTitle(getString(R.string.sensor_alert_title, label, sensor))
                .setContentText(getString(R.string.sensor_alert_detail, packageName))
                .setContentIntent(activityIntent())
                .addAction(0, getString(R.string.sensor_app_settings), details)
                .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
                .setAutoCancel(true)
                .build();
        notifications().notify(packageName + ":" + operation, ALERT_ID, notification);
        broadcastState();
    }

    private void interrupted(int message) {
        if (stopping)
            return;
        stopping = true;
        setStatus(message);
        notifications().notify(INTERRUPTED_ID, new NotificationCompat.Builder(this, ALERT_CHANNEL)
                .setSmallIcon(R.drawable.ic_security_white_24dp)
                .setContentTitle(getText(R.string.sensor_interrupted))
                .setContentText(getText(message))
                .setContentIntent(activityIntent())
                .setAutoCancel(true)
                .build());
        stopSelf();
    }

    private Notification statusNotification() {
        Intent stop = new Intent(this, SensorWatchService.class).setAction(STOP);
        PendingIntent stopAction = PendingIntent.getService(this, 0, stop, PendingIntent.FLAG_IMMUTABLE);
        return new NotificationCompat.Builder(this, STATUS_CHANNEL)
                .setSmallIcon(R.drawable.ic_security_white_24dp)
                .setContentTitle(getText(R.string.sensor_title))
                .setContentText(getText(status))
                .setContentIntent(activityIntent())
                .addAction(0, getText(R.string.sensor_stop), stopAction)
                .setOngoing(true)
                .build();
    }

    private PendingIntent activityIntent() {
        Intent open = new Intent(this, ActivitySensorPrivacy.class).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
        return PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE);
    }

    private NotificationManager notifications() {
        return getSystemService(NotificationManager.class);
    }

    private void setStatus(int message) {
        status = message;
        broadcastState();
    }

    private void broadcastState() {
        LocalBroadcastManager.getInstance(this).sendBroadcast(new Intent(STATE_CHANGED));
    }
}
