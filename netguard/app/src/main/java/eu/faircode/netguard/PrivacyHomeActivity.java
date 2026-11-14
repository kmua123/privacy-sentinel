package eu.faircode.netguard;

/* SPDX-License-Identifier: GPL-3.0-or-later */

import android.Manifest;
import android.app.NotificationManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;
import androidx.preference.PreferenceManager;

public class PrivacyHomeActivity extends AppCompatActivity {
    private final Handler main = new Handler(Looper.getMainLooper());
    private final Runnable refresh = new Runnable() {
        @Override
        public void run() {
            showStatus();
            main.postDelayed(this, 1000);
        }
    };
    private final ActivityResultLauncher<Intent> vpnConsent = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(), result -> {
                if (result.getResultCode() == RESULT_OK)
                    startVpn();
                else
                    Toast.makeText(this, R.string.guard_vpn_cancelled, Toast.LENGTH_SHORT).show();
            });
    private final ActivityResultLauncher<String> notificationConsent = registerForActivityResult(
            new ActivityResultContracts.RequestPermission(), allowed -> {
                if (allowed)
                    confirmVpn();
                else
                    showNotificationSettings();
            });

    private SharedPreferences preferences;
    private TextView vpnStatus;
    private Button vpnButton;
    private int ink;
    private int secondary;
    private int panel;
    private int border;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        if (getSupportActionBar() != null)
            getSupportActionBar().hide();

        preferences = PreferenceManager.getDefaultSharedPreferences(this);
        if (!preferences.getBoolean("unified_acknowledged", false))
            preferences.edit().putBoolean("enabled", false).apply();
        boolean dark = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK)
                == Configuration.UI_MODE_NIGHT_YES;
        ink = Color.parseColor(dark ? "#EAF8F2" : "#142F29");
        secondary = Color.parseColor(dark ? "#B5CEC4" : "#4A655D");
        panel = Color.parseColor(dark ? "#20342E" : "#FFFFFF");
        border = Color.parseColor(dark ? "#3A5148" : "#D5E5DE");
        WindowCompat.setDecorFitsSystemWindows(getWindow(), false);
        getWindow().setStatusBarColor(Color.TRANSPARENT);
        getWindow().setNavigationBarColor(Color.TRANSPARENT);
        getWindow().setNavigationBarContrastEnforced(false);
        WindowInsetsControllerCompat insetsController = new WindowInsetsControllerCompat(getWindow(), getWindow().getDecorView());
        insetsController.setAppearanceLightStatusBars(!dark);
        insetsController.setAppearanceLightNavigationBars(!dark);

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(Color.parseColor(dark ? "#15261F" : "#EFF6F3"));
        ViewCompat.setOnApplyWindowInsetsListener(scroll, (view, windowInsets) -> {
            Insets insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars() | WindowInsetsCompat.Type.displayCutout());
            view.setPadding(insets.left, insets.top, insets.right, insets.bottom);
            return WindowInsetsCompat.CONSUMED;
        });

        LinearLayout page = column();
        page.setPadding(dp(20), dp(22), dp(20), dp(20));
        ImageView icon = new ImageView(this);
        icon.setImageResource(R.drawable.ic_privacy_guard);
        icon.setImportantForAccessibility(ImageView.IMPORTANT_FOR_ACCESSIBILITY_NO);
        page.addView(icon, new LinearLayout.LayoutParams(dp(48), dp(48)));
        append(page, text(R.string.app_name, 30, ink, true), 12);
        append(page, text(R.string.guard_subtitle, 15, secondary, false), 4);

        LinearLayout watch = card(page, R.string.watch_title, R.string.watch_home_description);
        Button openWatch = button(R.string.watch_open);
        openWatch.setOnClickListener(view -> startActivity(new Intent(this, ActivityTrafficWatch.class)));
        append(watch, openWatch, 8);

        LinearLayout network = card(page, R.string.guard_network_title, R.string.guard_network_description);
        vpnStatus = text(R.string.guard_vpn_stopped, 15, ink, true);
        append(network, vpnStatus, 12);
        Button rules = button(R.string.guard_network_rules);
        rules.setOnClickListener(view -> startActivity(new Intent(this, ActivityNetworkApproval.class)));
        append(network, rules, 10);
        Button routing = button(R.string.guard_unified_settings);
        routing.setOnClickListener(view -> startActivity(new Intent(this, ActivityUnifiedNetwork.class)));
        append(network, routing, 2);
        vpnButton = button(R.string.guard_vpn_start);
        vpnButton.setOnClickListener(view -> toggleVpn());
        append(network, vpnButton, 2);

        LinearLayout sensors = card(page, R.string.sensor_title, R.string.guard_sensor_description);
        Button sensorPage = button(R.string.guard_sensor_open);
        sensorPage.setOnClickListener(view -> startActivity(new Intent(this, ActivitySensorPrivacy.class)));
        append(sensors, sensorPage, 10);
        Button activate = button(R.string.guard_embedded_activation);
        activate.setOnClickListener(view -> startActivity(new Intent(this, InternalAdbActivity.class)));
        append(sensors, activate, 2);
        Button protection = button(R.string.guard_system_vpn_settings);
        protection.setOnClickListener(view -> startActivity(new Intent(Settings.ACTION_VPN_SETTINGS)));
        append(network, protection, 2);
        append(page, text(R.string.guard_data_notice, 13, secondary, false), 16);
        Button publicInfo = button(R.string.public_info_title);
        publicInfo.setOnClickListener(view -> startActivity(new Intent(this, ActivityPublicInfo.class)));
        append(page, publicInfo, 8);

        scroll.addView(page);
        setContentView(scroll);
    }

    @Override
    protected void onResume() {
        super.onResume();
        // An APK upgrade stops services without clearing the user's enabled
        // preference. Resume an acknowledged guard when its existing VPN
        // authorization is still valid, rather than displaying a stale state.
        if (preferences.getBoolean("enabled", false)
                && preferences.getBoolean("unified_acknowledged", false)
                && !UnifiedVpnService.running && !UnifiedVpnService.starting
                && UnifiedVpnService.error.isEmpty()) {
            if (VpnService.prepare(this) == null)
                UnifiedVpnService.start(this);
            else
                preferences.edit().putBoolean("enabled", false).apply();
        }
        refresh.run();
    }

    @Override
    protected void onPause() {
        main.removeCallbacks(refresh);
        super.onPause();
    }

    private void showStatus() {
        boolean requested = preferences.getBoolean("enabled", false);
        if (UnifiedVpnService.running)
            vpnStatus.setText(R.string.guard_unified_running);
        else if (!UnifiedVpnService.error.isEmpty())
            vpnStatus.setText(UnifiedVpnService.error);
        else
            vpnStatus.setText(requested ? R.string.guard_vpn_starting : R.string.guard_vpn_stopped);
        vpnButton.setText(requested || UnifiedVpnService.running ? R.string.guard_vpn_stop : R.string.guard_vpn_start);
    }

    private void toggleVpn() {
        if (preferences.getBoolean("enabled", false) || UnifiedVpnService.running) {
            preferences.edit().putBoolean("enabled", false).apply();
            UnifiedVpnService.stop(this);
            showStatus();
            return;
        }
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            notificationConsent.launch(Manifest.permission.POST_NOTIFICATIONS);
        } else if (!getSystemService(NotificationManager.class).areNotificationsEnabled()) {
            showNotificationSettings();
        } else {
            confirmVpn();
        }
    }

    private void confirmVpn() {
        new AlertDialog.Builder(this).setTitle(R.string.guard_vpn_start)
                .setMessage(R.string.guard_vpn_consent)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(android.R.string.ok, (dialog, which) -> prepareVpn())
                .show();
    }

    private void prepareVpn() {
        try {
            Intent permission = VpnService.prepare(this);
            if (permission == null)
                startVpn();
            else
                vpnConsent.launch(permission);
        } catch (RuntimeException error) {
            Toast.makeText(this, R.string.guard_vpn_failed, Toast.LENGTH_LONG).show();
        }
    }

    private void startVpn() {
        preferences.edit().putBoolean("enabled", true).putBoolean("unified_acknowledged", true).apply();
        UnifiedVpnService.start(this);
        showStatus();
    }

    private void showNotificationSettings() {
        new AlertDialog.Builder(this).setMessage(R.string.guard_notification_required)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.guard_notification_settings, (dialog, which) ->
                        startActivity(new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                                .putExtra(Settings.EXTRA_APP_PACKAGE, getPackageName())))
                .show();
    }

    private LinearLayout card(LinearLayout parent, int title, int description) {
        LinearLayout card = column();
        card.setPadding(dp(16), dp(15), dp(16), dp(12));
        GradientDrawable background = new GradientDrawable();
        background.setColor(panel);
        background.setStroke(dp(1), border);
        background.setCornerRadius(dp(18));
        card.setBackground(background);
        append(card, text(title, 20, ink, true), 0);
        append(card, text(description, 14, secondary, false), 5);
        append(parent, card, 16);
        return card;
    }

    private LinearLayout column() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        return layout;
    }

    private TextView text(int message, int sp, int color, boolean bold) {
        TextView label = new TextView(this);
        label.setText(message);
        label.setTextSize(sp);
        label.setTextColor(color);
        if (bold)
            label.setTypeface(null, Typeface.BOLD);
        return label;
    }

    private Button button(int title) {
        Button button = new Button(this);
        button.setText(title);
        button.setAllCaps(false);
        return button;
    }

    private void append(LinearLayout parent, android.view.View child, int top) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.topMargin = dp(top);
        parent.addView(child, params);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
