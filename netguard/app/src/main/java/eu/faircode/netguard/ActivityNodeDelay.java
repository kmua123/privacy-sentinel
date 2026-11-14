package eu.faircode.netguard;

/* SPDX-License-Identifier: GPL-3.0-or-later */

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;

import guardcore.Guardcore;

/** Measures the real proxy HTTP path; never substitutes a local ICMP response. */
public final class ActivityNodeDelay extends AppCompatActivity {
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ExecutorService storage = Executors.newSingleThreadExecutor();
    private final ThreadPoolExecutor tests = (ThreadPoolExecutor) Executors.newFixedThreadPool(3);
    private final List<Future<?>> pending = new ArrayList<>();
    private final List<Row> rows = new ArrayList<>();
    private final NodeAdapter adapter = new NodeAdapter();
    private NetworkConfig config;
    private TextView status;
    private Button all;
    private Button stop;
    private int generation;
    private int total;
    private int completed;
    private String profile = "";
    private String selected = "";
    private boolean loading;
    private boolean selecting;
    private boolean destroyed;

    private final BroadcastReceiver configurationChanged = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            reload();
        }
    };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle(R.string.node_delay_title);
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }
        config = new NetworkConfig(this);
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        int padding = dp(16);
        page.setPadding(padding, padding, padding, padding);
        ViewCompat.setOnApplyWindowInsetsListener(page, (view, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars()
                    | WindowInsetsCompat.Type.displayCutout());
            view.setPadding(padding + bars.left, padding + bars.top,
                    padding + bars.right, padding + bars.bottom);
            return WindowInsetsCompat.CONSUMED;
        });
        TextView description = new TextView(this);
        description.setText(R.string.node_delay_description);
        description.setTextSize(14);
        page.addView(description);
        LinearLayout buttons = new LinearLayout(this);
        all = new Button(this);
        all.setText(R.string.node_delay_all);
        all.setAllCaps(false);
        all.setOnClickListener(view -> testAll());
        buttons.addView(all, new LinearLayout.LayoutParams(0, -2, 1));
        stop = new Button(this);
        stop.setText(R.string.node_delay_stop);
        stop.setAllCaps(false);
        stop.setOnClickListener(view -> cancelTests());
        buttons.addView(stop, new LinearLayout.LayoutParams(0, -2, 1));
        page.addView(buttons);
        status = new TextView(this);
        status.setPadding(0, dp(6), 0, dp(10));
        page.addView(status);
        RecyclerView list = new RecyclerView(this);
        list.setLayoutManager(new LinearLayoutManager(this));
        list.setAdapter(adapter);
        page.addView(list, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(page);
        ContextCompat.registerReceiver(this, configurationChanged,
                new IntentFilter(NetworkConfig.ACTION_CHANGED), ContextCompat.RECEIVER_NOT_EXPORTED);
    }

    @Override protected void onResume() {
        super.onResume();
        reload();
    }

    @Override protected void onStop() {
        cancelTests();
        super.onStop();
    }

    @Override protected void onDestroy() {
        destroyed = true;
        generation++;
        unregisterReceiver(configurationChanged);
        main.removeCallbacksAndMessages(null);
        tests.shutdownNow();
        storage.shutdownNow();
        super.onDestroy();
    }

    @Override public boolean onSupportNavigateUp() {
        finish();
        return true;
    }

    private void reload() {
        if (destroyed)
            return;
        cancelTests();
        loading = true;
        final int expected = generation;
        status.setText(R.string.node_delay_loading);
        updateActions();
        storage.execute(() -> {
            List<String> names = null;
            String yaml = "";
            String current = "";
            try {
                yaml = config.buildCoreYaml();
                names = config.proxyNames();
                current = config.load().selectedProxy;
            } catch (Exception ignored) {
                // Do not display exception text: subscription errors may contain credentials.
            }
            final List<String> loaded = names;
            final String loadedProfile = yaml;
            final String loadedCurrent = current;
            main.post(() -> {
                if (!current(expected))
                    return;
                loading = false;
                rows.clear();
                if (loaded != null)
                    for (String name : loaded)
                        rows.add(new Row(name));
                profile = loadedProfile;
                selected = loadedCurrent;
                adapter.notifyDataSetChanged();
                status.setText(loaded == null ? getString(R.string.node_delay_load_failed)
                        : rows.isEmpty() ? getString(R.string.node_delay_empty)
                        : getString(R.string.node_delay_idle, rows.size()));
                updateActions();
            });
        });
    }

    private void testAll() {
        if (loading || selecting || !guardReady())
            return;
        cancelTests();
        total = rows.size();
        completed = 0;
        for (Row row : rows)
            enqueue(row);
        updateProgress();
    }

    private void testOne(Row row) {
        if (loading || selecting || row.pending || !guardReady())
            return;
        if (completed == total) {
            total = 0;
            completed = 0;
            pending.clear();
        }
        total++;
        enqueue(row);
        updateProgress();
    }

    private boolean guardReady() {
        if (UnifiedVpnService.running && !UnifiedVpnService.starting)
            return true;
        Toast.makeText(this, R.string.node_delay_need_guard, Toast.LENGTH_LONG).show();
        return false;
    }

    private void enqueue(Row row) {
        row.pending = true;
        row.result = getString(R.string.node_delay_queued);
        final int expected = generation;
        final String expectedProfile = profile;
        pending.add(tests.submit(() -> {
            main.post(() -> {
                if (current(expected)) {
                    row.result = getString(R.string.node_delay_testing);
                    notifyRow(row);
                }
            });
            String result;
            try {
                if (!UnifiedVpnService.running || UnifiedVpnService.starting) {
                    result = getString(R.string.node_delay_need_guard);
                } else if (!expectedProfile.equals(config.buildCoreYaml())) {
                    result = getString(R.string.node_delay_node_changed);
                } else {
                    String network = UnifiedVpnService.networkDiagnostics();
                    JSONObject measured = new JSONObject(Guardcore.testProxyDelay(row.name, 8000));
                    if (!expectedProfile.equals(config.buildCoreYaml()))
                        result = getString(R.string.node_delay_node_changed);
                    else if (!UnifiedVpnService.running || UnifiedVpnService.starting
                            || !network.equals(UnifiedVpnService.networkDiagnostics()))
                        result = getString(R.string.node_delay_network_changed);
                    else if (measured.optBoolean("ok") && measured.optLong("delayMs", -1) >= 0)
                        result = getString(R.string.node_delay_ms, measured.getLong("delayMs"));
                    else
                        result = failureLabel(measured.optString("errorCode"));
                }
            } catch (Exception ignored) {
                result = getString(R.string.node_delay_unavailable);
            }
            final String outcome = result;
            main.post(() -> {
                if (!current(expected))
                    return;
                row.pending = false;
                row.result = outcome;
                completed++;
                notifyRow(row);
                updateProgress();
            });
        }));
        notifyRow(row);
    }

    private String failureLabel(String code) {
        switch (code) {
            case "timeout": return getString(R.string.node_delay_timeout);
            case "core_stopped": return getString(R.string.node_delay_need_guard);
            case "node_not_found": return getString(R.string.node_delay_node_changed);
            case "unexpected_status": return getString(R.string.node_delay_wrong_status);
            default: return getString(R.string.node_delay_unavailable);
        }
    }

    private void cancelTests() {
        generation++;
        for (Future<?> future : pending)
            future.cancel(false);
        pending.clear();
        tests.purge();
        for (Row row : rows)
            if (row.pending) {
                row.pending = false;
                row.result = getString(R.string.node_delay_cancelled);
            }
        total = 0;
        completed = 0;
        adapter.notifyDataSetChanged();
        if (status != null && !loading && !selecting)
            status.setText(rows.isEmpty() ? getString(R.string.node_delay_empty)
                    : getString(R.string.node_delay_idle, rows.size()));
        updateActions();
    }

    private void updateProgress() {
        status.setText(getString(R.string.node_delay_progress, completed, total));
        updateActions();
    }

    private void updateActions() {
        if (all != null) {
            all.setEnabled(!loading && !selecting && !rows.isEmpty() && completed == total);
            stop.setEnabled(!loading && !selecting && completed < total);
        }
    }

    private boolean current(int expected) {
        return !destroyed && !isFinishing() && generation == expected;
    }

    private void choose(Row row) {
        if (loading || selecting)
            return;
        new AlertDialog.Builder(this).setTitle(R.string.node_delay_select_title)
                .setMessage(getString(R.string.node_delay_select_message, row.name))
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.node_delay_select, (dialog, which) -> apply(row.name))
                .show();
    }

    private void apply(String name) {
        cancelTests();
        selecting = true;
        final int expected = generation;
        final String expectedProfile = profile;
        status.setText(R.string.node_delay_selecting);
        updateActions();
        storage.execute(() -> {
            boolean saved = false;
            try {
                if (expectedProfile.equals(config.buildCoreYaml()) && config.proxyNames().contains(name)) {
                    NetworkConfig.Settings settings = config.load();
                    settings.selectedProxy = name;
                    config.save(settings);
                    saved = true;
                }
            } catch (Exception ignored) {
                // Configuration is left unchanged on validation failure.
            }
            final boolean success = saved;
            main.post(() -> {
                if (destroyed || isFinishing())
                    return;
                selecting = false;
                if (success) {
                    Toast.makeText(this, getString(R.string.node_delay_selected, name), Toast.LENGTH_LONG).show();
                    reload();
                } else if (current(expected)) {
                    status.setText(R.string.node_delay_select_failed);
                    updateActions();
                }
            });
        });
    }

    private void notifyRow(Row row) {
        int index = rows.indexOf(row);
        if (index >= 0)
            adapter.notifyItemChanged(index);
    }

    private final class Row {
        final String name;
        String result = getString(R.string.node_delay_untested);
        boolean pending;
        Row(String name) { this.name = name; }
    }

    private final class NodeAdapter extends RecyclerView.Adapter<NodeHolder> {
        @Override public NodeHolder onCreateViewHolder(ViewGroup parent, int type) {
            LinearLayout line = new LinearLayout(parent.getContext());
            line.setOrientation(LinearLayout.VERTICAL);
            line.setPadding(dp(12), dp(12), dp(12), dp(12));
            line.setBackgroundResource(android.R.drawable.list_selector_background);
            line.setMinimumHeight(dp(76));
            line.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            TextView name = new TextView(parent.getContext());
            name.setTextSize(16);
            name.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
            line.addView(name);
            TextView detail = new TextView(parent.getContext());
            detail.setTextSize(14);
            line.addView(detail);
            line.setFocusable(true);
            return new NodeHolder(line, name, detail);
        }

        @Override public void onBindViewHolder(NodeHolder holder, int position) {
            Row row = rows.get(position);
            holder.name.setText(row.name);
            holder.detail.setText(row.result + (row.name.equals(selected)
                    ? " · " + getString(R.string.node_delay_current) : ""));
            holder.itemView.setOnClickListener(view -> testOne(row));
            holder.itemView.setOnLongClickListener(view -> { choose(row); return true; });
        }

        @Override public int getItemCount() { return rows.size(); }
    }

    private static final class NodeHolder extends RecyclerView.ViewHolder {
        final TextView name;
        final TextView detail;
        NodeHolder(View view, TextView name, TextView detail) {
            super(view);
            this.name = name;
            this.detail = detail;
        }
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
