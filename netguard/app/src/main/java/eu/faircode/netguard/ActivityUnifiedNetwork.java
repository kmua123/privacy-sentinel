package eu.faircode.netguard;

/* SPDX-License-Identifier: GPL-3.0-or-later */

import android.content.Intent;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.text.method.PasswordTransformationMethod;
import android.view.WindowManager;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AlertDialog;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.json.JSONArray;
import org.json.JSONObject;
import guardcore.Guardcore;

public final class ActivityUnifiedNetwork extends AppCompatActivity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final List<Button> actions = new ArrayList<>();
    private final List<String> proxyNames = new ArrayList<>();
    private NetworkConfig config;
    private final Handler main = new Handler(Looper.getMainLooper());
    private TextView homeIdentity;
    private final Runnable refreshIdentity = new Runnable() {
        @Override public void run() {
            String node = config.homeNodeId();
            homeIdentity.setText(!UnifiedVpnService.homeError.isEmpty() ? UnifiedVpnService.homeError
                    : node.isEmpty() ? "本机 ZeroTier 节点 ID · 启动守卫后生成"
                    : "本机 ZeroTier 节点 ID · " + node + "\n请在自建控制器中授权这个节点。");
            main.postDelayed(this, 1000);
        }
    };
    private final ActivityResultLauncher<Intent> importFile = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(), result -> {
                if (result.getResultCode() != RESULT_OK || result.getData() == null
                        || result.getData().getData() == null)
                    return;
                android.net.Uri uri = result.getData().getData();
                runWork(() -> {
                    try (InputStream input = getContentResolver().openInputStream(uri)) {
                        config.importStream(input);
                    }
                }, () -> afterImport());
            });
    private TextView status;
    private EditText subscription;
    private Spinner proxy;
    private Spinner mode;
    private Spinner ipv6Mode;
    private CheckBox zeroTier;
    private CheckBox tcpCompatibility;
    private EditText networkId;
    private EditText homeCidrs;
    private EditText homeDns;
    private LinearLayout page;
    private boolean working;
    private boolean refreshSubscriptionOnResume;
    private String diagnostics;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle(R.string.unified_network_title);
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }
        config = new NetworkConfig(this);
        ScrollView scroll = new ScrollView(this);
        page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        int padding = dp(18);
        page.setPadding(padding, padding, padding, padding);
        scroll.addView(page);
        ViewCompat.setOnApplyWindowInsetsListener(scroll, (view, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars()
                    | WindowInsetsCompat.Type.displayCutout());
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return WindowInsetsCompat.CONSUMED;
        });
        section(R.string.unified_subscription_title);
        note(R.string.unified_subscription_description);
        subscription = input(R.string.unified_subscription_address, InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_VARIATION_URI, false);
        subscription.setTransformationMethod(PasswordTransformationMethod.getInstance());
        subscription.setImportantForAutofill(android.view.View.IMPORTANT_FOR_AUTOFILL_NO);
        button(R.string.unified_subscription_download, () -> {
            String url = subscription.getText().toString().trim();
            runWork(() -> config.refreshSubscription(url), this::afterImport);
        });
        button(R.string.unified_subscription_file, () -> {
            Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*")
                    .addCategory(Intent.CATEGORY_OPENABLE)
                    .putExtra(Intent.EXTRA_MIME_TYPES, new String[]{"application/yaml", "text/yaml",
                            "text/plain", "application/octet-stream", "application/json"});
            importFile.launch(picker);
        });
        button(R.string.subscriptions_title, () -> {
            refreshSubscriptionOnResume = true;
            startActivity(new Intent(this, ActivitySubscriptions.class));
        });
        label(R.string.unified_selected_proxy);
        proxy = new Spinner(this);
        page.addView(proxy);
        button(R.string.node_delay_title, () -> {
            refreshSubscriptionOnResume = true;
            startActivity(new Intent(this, ActivityNodeDelay.class));
        });
        section(R.string.unified_route_title);
        mode = new Spinner(this);
        mode.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item,
                new String[]{getString(R.string.unified_mode_split), getString(R.string.unified_mode_home)}));
        page.addView(mode);
        note(R.string.unified_route_description);
        label(R.string.unified_ipv6_title);
        ipv6Mode = new Spinner(this);
        ipv6Mode.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item,
                new String[]{getString(R.string.unified_ipv6_auto), getString(R.string.unified_ipv6_off),
                        getString(R.string.unified_ipv6_on)}));
        page.addView(ipv6Mode);
        note(R.string.unified_ipv6_description);
        section(R.string.unified_home_title);
        zeroTier = new CheckBox(this);
        zeroTier.setText(R.string.unified_zerotier_enabled);
        page.addView(zeroTier);
        networkId = input(R.string.unified_network_id, InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, false);
        homeCidrs = input(R.string.unified_home_cidrs, InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_MULTI_LINE | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, true);
        homeDns = input(R.string.unified_home_dns, InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, false);
        tcpCompatibility = new CheckBox(this);
        tcpCompatibility.setText(R.string.unified_tcp_compatibility);
        page.addView(tcpCompatibility);
        note(R.string.unified_tcp_description);
        note(R.string.unified_home_description);
        homeIdentity = new TextView(this);
        homeIdentity.setTextIsSelectable(true);
        page.addView(homeIdentity);
        button(R.string.unified_home_diagnostics, () -> runWork(() ->
                diagnostics = describeHome(Guardcore.homeStatus()) + "\n\n" + UnifiedVpnService.networkDiagnostics(), () -> {
            TextView report = new TextView(this);
            report.setPadding(dp(20), dp(12), dp(20), dp(12));
            report.setTextIsSelectable(true);
            report.setText(diagnostics);
            ScrollView details = new ScrollView(this);
            details.addView(report);
            new AlertDialog.Builder(this).setTitle(R.string.unified_home_diagnostics)
                    .setView(details).setPositiveButton(android.R.string.ok, null).show();
        }));
        status = new TextView(this);
        status.setTextSize(14);
        status.setPadding(0, dp(12), 0, dp(12));
        page.addView(status);
        button(R.string.unified_save, this::save);
        note(R.string.unified_policy_notice);
        setContentView(scroll);
        NetworkConfig.Settings settings = config.load();
        if (state != null) {
            settings.subscriptionUrl = state.getString("url", settings.subscriptionUrl);
            settings.selectedProxy = state.getString("proxy", settings.selectedProxy);
            settings.mode = state.getString("mode", settings.mode);
            settings.enabledZeroTier = state.getBoolean("zeroTier", settings.enabledZeroTier);
            settings.zeroTierNetwork = state.getString("network", settings.zeroTierNetwork);
            settings.homeCidrs = state.getString("cidrs", settings.homeCidrs);
            settings.homeDns = state.getString("dns", settings.homeDns);
            settings.zeroTierTcpOnly = state.getBoolean("tcpCompatibility", settings.zeroTierTcpOnly);
            settings.ipv6Mode = state.getString("ipv6Mode", settings.ipv6Mode);
        }
        subscription.setText(settings.subscriptionUrl);
        mode.setSelection(NetworkConfig.HOME_EXIT.equals(settings.mode) ? 1 : 0);
        zeroTier.setChecked(settings.enabledZeroTier);
        networkId.setText(settings.zeroTierNetwork);
        homeCidrs.setText(settings.homeCidrs);
        homeDns.setText(settings.homeDns);
        tcpCompatibility.setChecked(settings.zeroTierTcpOnly);
        ipv6Mode.setSelection("ipv4".equals(settings.ipv6Mode) ? 1 : "ipv6".equals(settings.ipv6Mode) ? 2 : 0);
        populateProxies(settings.selectedProxy, false);
    }

    @Override
    public boolean onSupportNavigateUp() {
        finish();
        return true;
    }

    @Override
    protected void onSaveInstanceState(Bundle out) {
        NetworkConfig.Settings settings = readSettings();
        out.putString("url", settings.subscriptionUrl);
        out.putString("proxy", settings.selectedProxy);
        out.putString("mode", settings.mode);
        out.putBoolean("zeroTier", settings.enabledZeroTier);
        out.putString("network", settings.zeroTierNetwork);
        out.putString("cidrs", settings.homeCidrs);
        out.putString("dns", settings.homeDns);
        out.putBoolean("tcpCompatibility", settings.zeroTierTcpOnly);
        out.putString("ipv6Mode", settings.ipv6Mode);
        super.onSaveInstanceState(out);
    }

    @Override
    protected void onDestroy() {
        main.removeCallbacksAndMessages(null);
        worker.shutdownNow();
        super.onDestroy();
    }

    @Override protected void onResume() {
        super.onResume();
        if (refreshSubscriptionOnResume) {
            refreshSubscriptionOnResume = false;
            NetworkConfig.Settings saved = config.load();
            subscription.setText(saved.subscriptionUrl);
            populateProxies(saved.selectedProxy, false);
        }
        main.post(refreshIdentity);
    }

    @Override protected void onPause() {
        main.removeCallbacks(refreshIdentity);
        super.onPause();
    }

    private NetworkConfig.Settings readSettings() {
        NetworkConfig.Settings settings = new NetworkConfig.Settings();
        settings.subscriptionUrl = subscription.getText().toString().trim();
        int selected = proxy.getSelectedItemPosition() - 1;
        settings.selectedProxy = selected >= 0 && selected < proxyNames.size() ? proxyNames.get(selected) : "";
        settings.mode = mode.getSelectedItemPosition() == 1 ? NetworkConfig.HOME_EXIT : NetworkConfig.SPLIT;
        settings.enabledZeroTier = zeroTier.isChecked();
        settings.zeroTierNetwork = networkId.getText().toString().trim();
        settings.homeCidrs = homeCidrs.getText().toString().trim();
        settings.homeDns = homeDns.getText().toString().trim();
        settings.zeroTierTcpOnly = tcpCompatibility.isChecked();
        settings.ipv6Mode = ipv6Mode.getSelectedItemPosition() == 1 ? "ipv4"
                : ipv6Mode.getSelectedItemPosition() == 2 ? "ipv6" : "auto";
        return settings;
    }

    private void afterImport() {
        NetworkConfig.Settings saved = config.load();
        subscription.setText(saved.subscriptionUrl);
        populateProxies(saved.selectedProxy, false);
        status.setText(getString(R.string.unified_imported, proxyNames.size()));
    }

    private void populateProxies(String selected, boolean importing) {
        try {
            proxyNames.clear();
            proxyNames.addAll(config.proxyNames());
            List<String> labels = new ArrayList<>();
            labels.add(getString(R.string.unified_proxy_direct));
            labels.addAll(proxyNames);
            proxy.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, labels));
            int index = proxyNames.indexOf(selected);
            int selection = 0;
            if (index >= 0)
                selection = index + 1;
            else if (importing && !proxyNames.isEmpty())
                selection = 1;
            proxy.setSelection(selection);
            if (!importing)
                status.setText(getString(R.string.unified_node_count, proxyNames.size()));
        } catch (IOException invalid) {
            status.setText(invalid.getMessage());
        }
    }

    private void save() {
        NetworkConfig.Settings settings = readSettings();
        runWork(() -> config.save(settings), () -> {
            status.setText(R.string.unified_saved);
            Toast.makeText(this, R.string.unified_saved, Toast.LENGTH_LONG).show();
        });
    }

    private static String describeHome(String json) throws Exception {
        JSONObject state = new JSONObject(json);
        String name = state.optString("state");
        String description;
        switch (name) {
            case "stopped": description = "联网守卫未运行，请先启动守卫。"; break;
            case "disabled": description = "当前未启用 ZeroTier 回家。"; break;
            case "access-denied": description = "控制器尚未授权，请核对并授权下面的节点 ID。"; break;
            case "network-not-found": description = "控制器未找到该网络，请检查网络 ID。"; break;
            case "authentication-required": description = "网络需要额外认证，请检查控制器。"; break;
            case "ready": description = "已获得网络配置；请继续实际访问家庭服务确认连通。"; break;
            case "configuration-error":
            case "initialization-error": description = "回家网络初始化失败，请检查配置并重新应用。"; break;
            case "closed": description = "回家连接已停止，请重新启动守卫。"; break;
            default: description = "正在等待网络配置；请核对节点授权和手机网络。";
        }
        StringBuilder text = new StringBuilder(description);
        text.append("\n\n节点 ID：").append(state.optString("nodeId", ""));
        text.append("\n分配地址：").append(join(state.optJSONArray("assignedIps")));
        text.append("\n有活动路径的已知节点：").append(state.optInt("peersWithActivePath"));
        text.append("\n回家连接策略：").append("force".equals(state.optString("tcpFallbackMode"))
                ? "TCP 兼容模式" : "自动（优先直连，必要时尝试 TCP）");
        text.append("\n\n网络下发路由：\n").append(join(state.optJSONArray("managedRoutes")));
        text.append("\n\n上述状态不等于家庭网页已可访问。当前内核不提供 TCP 中继是否已连接的状态，请通过家庭网页或文件确认。此版本不模拟远端 Ping 应答，暂不提供经回家通道的 ICMP Ping。页面不包含身份私钥或订阅令牌。");
        return text.toString();
    }

    private static String join(JSONArray values) {
        if (values == null || values.length() == 0)
            return "尚未获得";
        List<String> result = new ArrayList<>();
        for (int index = 0; index < values.length(); index++)
            result.add(values.optString(index));
        return String.join("\n", result);
    }

    private interface Work {
        void run() throws Exception;
    }

    private void runWork(Work task, Runnable success) {
        if (working)
            return;
        working = true;
        for (Button button : actions)
            button.setEnabled(false);
        status.setText(R.string.unified_working);
        worker.execute(() -> {
            String failure = null;
            try {
                task.run();
            } catch (Exception error) {
                failure = error instanceof IOException ? error.getMessage() : getString(R.string.unified_operation_failed);
            }
            final String message = failure;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed())
                    return;
                working = false;
                for (Button button : actions)
                    button.setEnabled(true);
                if (message == null)
                    success.run();
                else
                    status.setText(message);
            });
        });
    }

    private void section(int text) {
        TextView title = new TextView(this);
        title.setText(text);
        title.setTextSize(20);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        title.setPadding(0, dp(20), 0, dp(8));
        page.addView(title);
    }

    private void note(int text) {
        TextView description = new TextView(this);
        description.setText(text);
        description.setTextSize(14);
        description.setPadding(0, dp(4), 0, dp(8));
        page.addView(description);
    }

    private void label(int text) {
        TextView label = new TextView(this);
        label.setText(text);
        label.setPadding(0, dp(12), 0, 0);
        page.addView(label);
    }

    private EditText input(int labelResource, int type, boolean multiline) {
        label(labelResource);
        EditText field = new EditText(this);
        field.setInputType(type);
        field.setSingleLine(!multiline);
        if (multiline)
            field.setMinLines(2);
        field.setTextSize(15);
        page.addView(field, new LinearLayout.LayoutParams(-1, -2));
        return field;
    }

    private void button(int label, Runnable action) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false);
        button.setOnClickListener(view -> action.run());
        page.addView(button, new LinearLayout.LayoutParams(-1, -2));
        actions.add(button);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
