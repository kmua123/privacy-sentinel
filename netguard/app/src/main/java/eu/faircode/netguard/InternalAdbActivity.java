package eu.faircode.netguard;

import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Build;
import android.Manifest;
import android.content.pm.PackageManager;
import android.provider.Settings;
import android.text.InputFilter;
import android.text.InputType;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** User-controlled pairing and activation, all inside the Privacy Guard APK. */
public final class InternalAdbActivity extends AppCompatActivity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private InternalAdbBridge bridge;
    private TextView status;
    private EditText pairingPort;
    private EditText pairingCode;
    private EditText connectionPort;
    private Button pair;
    private Button activate;
    private Button deactivate;
    private boolean working;
    private final Runnable refresh = new Runnable() {
        @Override public void run() {
            showState();
            main.postDelayed(this, 1000);
        }
    };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        setTitle("内置无线 ADB");
        if (getSupportActionBar() != null)
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        bridge = InternalAdbBridge.get(this);
        int padding = Math.round(20 * getResources().getDisplayMetrics().density);
        ScrollView scroll = new ScrollView(this);
        LinearLayout column = new LinearLayout(this);
        column.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        column.setOrientation(LinearLayout.VERTICAL);
        column.setPadding(padding, padding, padding, padding);
        scroll.addView(column);
        setContentView(scroll);

        text(column, "为系统流量监看和相机、麦克风提醒激活本机辅助服务。首次使用需要在系统无线调试中配对。配对凭据仅加密保存在本机。", 16);
        status = text(column, bridge.status(), 16);
        text(column, "推荐使用通知配对：先点击下方按钮，再到系统设置开启无线调试并打开“使用配对码配对设备”。保持配对弹窗打开，下拉通知栏，在隐私哨兵通知中输入六位配对码。应用会自动寻找本机端口并激活。", 16);
        Button notificationPair = button(column, "开始通知配对（两分钟内）");
        notificationPair.setOnClickListener(view -> {
            if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 91);
                Toast.makeText(this, "允许通知后，请再次点击开始通知配对", Toast.LENGTH_LONG).show();
                return;
            }
            if (Build.VERSION.SDK_INT < 30) {
                Toast.makeText(this, "内置无线 ADB 需要 Android 11 或以上", Toast.LENGTH_LONG).show();
                return;
            }
            InternalAdbPairingService.start(this);
            Toast.makeText(this, "配对通知已开启，请到系统无线调试打开配对码弹窗", Toast.LENGTH_LONG).show();
        });
        Button settings = button(column, "打开开发者选项");
        settings.setOnClickListener(view -> {
            try {
                startActivity(new Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS));
            } catch (ActivityNotFoundException failure) {
                Toast.makeText(this, "请在系统设置里开启开发者选项和无线调试", Toast.LENGTH_LONG).show();
            }
        });
        text(column, "手动备用方式：请先将本应用与系统设置分屏显示。保持“使用配对码配对设备”弹窗打开，在这里输入配对端口和六位配对码。直接切换应用会使系统配对端口失效。", 16);
        pairingPort = number(column, "配对端口", 5, false);
        pairingCode = number(column, "六位配对码", 6, true);
        pair = button(column, "配对本机");
        pair.setOnClickListener(view -> {
            String port = pairingPort.getText().toString();
            String code = pairingCode.getText().toString().trim();
            pairingCode.setText("");
            run(() -> bridge.pair(parsePort(port), code));
        });

        text(column, "2. 返回无线调试主页面，填写“IP 地址和端口”中的连接端口。连接端口与配对端口通常不同。", 16);
        connectionPort = number(column, "连接端口", 5, false);
        int previousPort = bridge.lastConnectionPort();
        if (previousPort > 0)
            connectionPort.setText(Integer.toString(previousPort));
        activate = button(column, "连接并激活隐私服务");
        activate.setOnClickListener(view -> {
            String port = connectionPort.getText().toString();
            run(() -> bridge.connect(parsePort(port)));
        });
        deactivate = button(column, "停止辅助服务");
        deactivate.setOnClickListener(view -> run(bridge::disconnect));
        text(column, "设备重启、撤销配对或辅助服务中断后，需要重新激活。流量守卫的 VPN 与此辅助服务分别显示状态。", 14);
    }

    @Override protected void onResume() {
        super.onResume();
        main.post(refresh);
    }

    @Override protected void onPause() {
        main.removeCallbacks(refresh);
        super.onPause();
    }

    @Override protected void onDestroy() {
        main.removeCallbacksAndMessages(null);
        worker.shutdownNow();
        super.onDestroy();
    }

    @Override public boolean onSupportNavigateUp() {
        finish();
        return true;
    }

    private void run(Operation operation) {
        if (working || bridge.isBusy())
            return;
        working = true;
        showState();
        worker.execute(() -> {
            String error = null;
            try {
                operation.run();
            } catch (IllegalArgumentException failure) {
                error = failure.getMessage();
            } catch (Exception failure) {
                error = bridge.lastError();
                if (error == null)
                    error = "连接未完成，请检查系统无线调试端口和授权";
            }
            String result = error;
            main.post(() -> {
                working = false;
                if (!isFinishing() && !isDestroyed()) {
                    showState();
                    Toast.makeText(this, result == null ? bridge.status() : result, Toast.LENGTH_LONG).show();
                }
            });
        });
    }

    private void showState() {
        if (status == null)
            return;
        String pairing = InternalAdbPairingService.status();
        status.setText(bridge.status() + (pairing.isEmpty() ? "" : "\n" + pairing));
        boolean enabled = !working && !bridge.isBusy();
        pair.setEnabled(enabled);
        activate.setEnabled(enabled && !bridge.isReady());
        deactivate.setEnabled(enabled && bridge.isReady());
    }

    private TextView text(LinearLayout parent, String value, int size) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setPadding(0, 12, 0, 12);
        parent.addView(view);
        return view;
    }

    private EditText number(LinearLayout parent, String hint, int length, boolean password) {
        EditText view = new EditText(this);
        view.setHint(hint);
        view.setSingleLine(true);
        view.setInputType(InputType.TYPE_CLASS_NUMBER |
                (password ? InputType.TYPE_NUMBER_VARIATION_PASSWORD : InputType.TYPE_NUMBER_VARIATION_NORMAL));
        view.setFilters(new InputFilter[]{new InputFilter.LengthFilter(length)});
        view.setSaveEnabled(!password);
        parent.addView(view);
        return view;
    }

    private Button button(LinearLayout parent, String title) {
        Button view = new Button(this);
        view.setText(title);
        parent.addView(view);
        return view;
    }

    private static int parsePort(String text) {
        try {
            int port = Integer.parseInt(text.trim());
            if (port >= 1 && port <= 65_535)
                return port;
        } catch (NumberFormatException ignored) {
        }
        throw new IllegalArgumentException("请输入 1 到 65535 之间的端口");
    }

    private interface Operation {
        void run() throws Exception;
    }
}
