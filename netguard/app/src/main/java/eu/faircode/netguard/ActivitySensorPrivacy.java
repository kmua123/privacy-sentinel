package eu.faircode.netguard;

import android.Manifest;
import android.app.NotificationManager;
import android.content.ActivityNotFoundException;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.format.DateFormat;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Date;


public final class ActivitySensorPrivacy extends AppCompatActivity {
    private static final int NOTIFICATION_REQUEST = 3101;

    private TextView status;
    private Button toggle;
    private Button clear;
    private LinearLayout history;

    private final BroadcastReceiver stateChanged = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            refresh();
        }
    };
    private final InternalAdbBridge.StateListener bridgeState = (ready, detail) -> runOnUiThread(this::refresh);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle(R.string.sensor_title);
        ScrollView scroll = new ScrollView(this);
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(20), dp(12), dp(20), dp(24));
        scroll.addView(body);
        setContentView(scroll);

        TextView heading = text(body, R.string.sensor_title, 24);
        heading.setAccessibilityHeading(true);
        status = text(body, R.string.sensor_stopped, 17);
        text(body, R.string.sensor_explanation, 14);
        toggle = button(body, R.string.sensor_start, this::toggleWatch);
        button(body, R.string.guard_embedded_activation,
                () -> startActivity(new Intent(this, InternalAdbActivity.class)));
        button(body, R.string.sensor_open_system_privacy,
                () -> launchSettings(new Intent(Settings.ACTION_PRIVACY_SETTINGS)));
        button(body, R.string.sensor_open_notifications, this::openNotificationSettings);
        text(body, R.string.sensor_history_title, 20).setAccessibilityHeading(true);
        clear = button(body, R.string.sensor_history_clear, () -> new AlertDialog.Builder(this)
                .setMessage(R.string.sensor_history_clear_question)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.sensor_history_clear, (dialog, which) -> {
                    SensorWatchService.historyPreferences(this).edit().remove("events").apply();
                    refresh();
                }).show());
        history = new LinearLayout(this);
        history.setOrientation(LinearLayout.VERTICAL);
        body.addView(history);
    }

    @Override
    protected void onStart() {
        super.onStart();
        LocalBroadcastManager.getInstance(this).registerReceiver(stateChanged,
                new IntentFilter(SensorWatchService.STATE_CHANGED));
        InternalAdbBridge.get(this).addStateListener(bridgeState);
        refresh();
    }

    @Override
    protected void onResume() {
        super.onResume();
        refresh();
    }

    @Override
    protected void onStop() {
        LocalBroadcastManager.getInstance(this).unregisterReceiver(stateChanged);
        InternalAdbBridge.get(this).removeStateListener(bridgeState);
        super.onStop();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == NOTIFICATION_REQUEST && grantResults.length > 0) {
            if (grantResults[0] == PackageManager.PERMISSION_GRANTED)
                startWatch();
            else
                showMessage(R.string.sensor_notifications_needed);
        }
    }

    private void toggleWatch() {
        if (SensorWatchService.isEnabled()) {
            stopService(new Intent(this, SensorWatchService.class));
            return;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, NOTIFICATION_REQUEST);
        } else {
            startWatch();
        }
    }

    private void startWatch() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R || SensorWatchService.isEnabled())
            return;
        if (!getSystemService(NotificationManager.class).areNotificationsEnabled()) {
            showMessage(R.string.sensor_notifications_needed);
            return;
        }
        try {
            if (!InternalAdbBridge.get(this).isReady()) {
                startActivity(new Intent(this, InternalAdbActivity.class));
                return;
            }
            ContextCompat.startForegroundService(this, new Intent(this, SensorWatchService.class));
        } catch (RuntimeException ex) {
            showMessage(R.string.sensor_connection_error);
        }
    }

    private void refresh() {
        if (status == null || history == null)
            return;
        int current = SensorWatchService.getStatus();
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R)
            current = R.string.sensor_unsupported;
        else if (current == R.string.sensor_stopped && !InternalAdbBridge.get(this).isReady())
            current = R.string.sensor_shizuku_needed;
        status.setText(current);
        toggle.setEnabled(Build.VERSION.SDK_INT >= Build.VERSION_CODES.R);
        toggle.setText(SensorWatchService.isEnabled() ? R.string.sensor_stop : R.string.sensor_start);

        history.removeAllViews();
        JSONArray events = SensorWatchService.readHistory(this);
        clear.setEnabled(events.length() > 0);
        if (events.length() == 0)
            text(history, R.string.sensor_history_empty, 14);
        for (int index = events.length() - 1; index >= 0; index--) {
            JSONObject event = events.optJSONObject(index);
            if (event == null)
                continue;
            String app = event.optString("package");
            long time = event.optLong("time");
            Date date = new Date(time);
            TextView item = text(history, 0, 15);
            item.setText(getString(R.string.sensor_history_item,
                    DateFormat.getDateFormat(this).format(date),
                    DateFormat.format(DateFormat.is24HourFormat(this) ? "HH:mm:ss" : "h:mm:ss a", date),
                    SensorWatchService.appName(this, app),
                    getString(SensorWatchService.operationLabel(event.optString("operation"))), app));
        }
    }

    private void openNotificationSettings() {
        NotificationManager notifications = getSystemService(NotificationManager.class);
        Intent settings;
        if (notifications.getNotificationChannel(SensorWatchService.ALERT_CHANNEL) == null
                || !notifications.areNotificationsEnabled()) {
            settings = new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS);
        } else {
            settings = new Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
                    .putExtra(Settings.EXTRA_CHANNEL_ID, SensorWatchService.ALERT_CHANNEL);
        }
        launchSettings(settings.putExtra(Settings.EXTRA_APP_PACKAGE, getPackageName()));
    }

    private void launchSettings(Intent intent) {
        try {
            startActivity(intent);
        } catch (ActivityNotFoundException ex) {
            try {
                startActivity(new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.fromParts("package", getPackageName(), null)));
            } catch (ActivityNotFoundException ignored) {
                showMessage(R.string.sensor_settings_unavailable);
            }
        }
    }

    private void showMessage(int resource) {
        Toast.makeText(this, resource, Toast.LENGTH_LONG).show();
    }

    private TextView text(LinearLayout parent, int value, int size) {
        TextView view = new TextView(this);
        if (value != 0)
            view.setText(value);
        view.setTextSize(size);
        view.setPadding(0, dp(6), 0, dp(6));
        parent.addView(view);
        return view;
    }

    private Button button(LinearLayout parent, int value, Runnable action) {
        Button button = new Button(this);
        button.setText(value);
        button.setOnClickListener(view -> action.run());
        parent.addView(button);
        return button;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
