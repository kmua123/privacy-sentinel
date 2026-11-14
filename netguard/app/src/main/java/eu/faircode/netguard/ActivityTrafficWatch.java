package eu.faircode.netguard;

/* SPDX-License-Identifier: GPL-3.0-or-later */

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.format.Formatter;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.core.content.ContextCompat;

import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;


public class ActivityTrafficWatch extends Activity {
    private static final int REQUEST_NOTIFICATION = 301;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final Runnable refresh = new Runnable() {
        @Override public void run() {
            render(false);
            main.postDelayed(this, 1000);
        }
    };
    private final List<TrafficScan.Row> shownRows = new ArrayList<>();
    private final List<Long> shownTimes = new ArrayList<>();
    private TrafficScan shownScan;
    private List<TrafficWatchService.Finding> shownFindings;
    private boolean findingsOnly;
    private TextView status;
    private TextView empty;
    private Button toggle;
    private Button findings;
    private Button all;
    private Button retry;
    private ArrayAdapter<String> adapter;

    @Override protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        setTitle(R.string.watch_title);
        findingsOnly = saved == null ? getIntent().getBooleanExtra("findings", false)
                : saved.getBoolean("findingsOnly", false);
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        int pad = Math.round(16 * getResources().getDisplayMetrics().density);
        page.setPadding(pad, pad, pad, 0);
        TextView title = new TextView(this);
        title.setText(R.string.watch_title);
        title.setTextSize(20);
        title.setTypeface(null, android.graphics.Typeface.BOLD);
        title.setPadding(0, 0, 0, pad / 2);
        page.addView(title);
        TextView introduction = new TextView(this);
        introduction.setText(R.string.watch_description);
        page.addView(introduction);
        status = new TextView(this);
        status.setPadding(0, pad / 2, 0, pad / 2);
        page.addView(status);
        toggle = new Button(this);
        toggle.setAllCaps(false);
        toggle.setOnClickListener(view -> {
            if (TrafficWatchService.active)
                stopService(new Intent(this, TrafficWatchService.class));
            else if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED)
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQUEST_NOTIFICATION);
            else
                startMonitoring();
        });
        page.addView(toggle);

        LinearLayout actions = new LinearLayout(this);
        retry = new Button(this);
        retry.setAllCaps(false);
        retry.setText(R.string.watch_retry);
        retry.setOnClickListener(view -> {
            if (!TrafficWatchService.active) {
                startMonitoring();
                return;
            }
            try {
                ContextCompat.startForegroundService(this,
                        new Intent(this, TrafficWatchService.class).setAction(TrafficWatchService.ACTION_SAMPLE));
            } catch (RuntimeException failure) {
                message(R.string.watch_status_bind_failed);
            }
        });
        actions.addView(retry, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        Button activation = new Button(this);
        activation.setAllCaps(false);
        activation.setText(R.string.watch_activation);
        activation.setOnClickListener(view -> startActivity(new Intent(this, InternalAdbActivity.class)));
        actions.addView(activation, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        page.addView(actions);

        LinearLayout tabs = new LinearLayout(this);
        findings = tab(tabs, R.string.watch_findings, true);
        all = tab(tabs, R.string.watch_all, false);
        page.addView(tabs);
        empty = new TextView(this);
        page.addView(empty);
        ListView list = new ListView(this);
        adapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1);
        list.setAdapter(adapter);
        list.setOnItemClickListener((parent, view, position, id) -> details(shownRows.get(position), shownTimes.get(position)));
        page.addView(list, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1));
        setContentView(page);
        render(true);
    }

    private Button tab(LinearLayout tabs, int title, boolean showFindings) {
        Button button = new Button(this);
        button.setAllCaps(false);
        button.setText(title);
        button.setOnClickListener(view -> {
            findingsOnly = showFindings;
            render(true);
        });
        tabs.addView(button, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        return button;
    }

    @Override protected void onResume() {
        super.onResume();
        refresh.run();
    }

    @Override protected void onPause() {
        main.removeCallbacks(refresh);
        super.onPause();
    }

    @Override protected void onDestroy() {
        main.removeCallbacksAndMessages(null);
        super.onDestroy();
    }

    @Override protected void onSaveInstanceState(Bundle state) {
        state.putBoolean("findingsOnly", findingsOnly);
        super.onSaveInstanceState(state);
    }

    @Override public void onRequestPermissionsResult(int request, String[] permissions, int[] grants) {
        super.onRequestPermissionsResult(request, permissions, grants);
        if (request == REQUEST_NOTIFICATION)
            startMonitoring();
    }

    private void startMonitoring() {
        if (isFinishing() || isDestroyed() || TrafficWatchService.active)
            return;
        try {
            if (!InternalAdbBridge.get(this).isReady() && !UnifiedVpnService.running) {
                startActivity(new Intent(this, InternalAdbActivity.class));
                return;
            }
            ContextCompat.startForegroundService(this, new Intent(this, TrafficWatchService.class));
        } catch (RuntimeException failure) {
            message(R.string.watch_status_bind_failed);
        }
    }

    private void render(boolean redraw) {
        TrafficScan scan = TrafficWatchService.latest;
        List<TrafficWatchService.Finding> recent = TrafficWatchService.findings;
        String detail = getString(TrafficWatchService.status);
        if (!TrafficWatchService.failureCode.isEmpty())
            detail += "\n" + getString(TrafficWatchService.diagnosticText(TrafficWatchService.failureCode));
        if (scan != null) {
            detail += "\n" + getString("vpn".equals(scan.source) ? R.string.watch_source_vpn : R.string.watch_source_system);
            detail += "\n" + getString(R.string.watch_snapshot, formatTime(scan.capturedAt), scan.observedCount, scan.rows.size());
        }
        if (TrafficWatchService.sampling)
            detail += "\n" + getString(R.string.watch_sampling);
        else if (TrafficWatchService.active && TrafficWatchService.nextSampleAt > 0)
            detail += "\n" + getString(R.string.watch_retry_in,
                    Math.max(0, (TrafficWatchService.nextSampleAt - System.currentTimeMillis() + 999) / 1000));
        if (scan == null && TrafficWatchService.lastAttemptAt > 0)
            detail += "\n" + getString(R.string.watch_last_attempt, formatTime(TrafficWatchService.lastAttemptAt));
        status.setText(detail);
        toggle.setText(TrafficWatchService.active ? R.string.watch_stop : R.string.watch_start);
        retry.setEnabled(!TrafficWatchService.sampling);
        findings.setSelected(findingsOnly);
        all.setSelected(!findingsOnly);
        findings.setText(findingsOnly ? getString(R.string.watch_current_tab, getString(R.string.watch_findings))
                : getString(R.string.watch_findings));
        all.setText(!findingsOnly ? getString(R.string.watch_current_tab, getString(R.string.watch_all))
                : getString(R.string.watch_all));
        empty.setText(scan == null && !TrafficWatchService.failureCode.isEmpty()
                ? R.string.watch_no_snapshot_error : findingsOnly && scan != null && scan.hasBaseline
                ? R.string.watch_no_findings : R.string.watch_no_snapshot);
        if (!redraw && shownScan == scan && shownFindings == recent)
            return;
        shownScan = scan;
        shownFindings = recent;
        shownRows.clear();
        shownTimes.clear();
        if (findingsOnly) {
            for (TrafficWatchService.Finding item : recent) {
                shownRows.add(item.row);
                shownTimes.add(item.capturedAt);
            }
        } else if (scan != null) {
            shownRows.addAll(scan.rows);
            for (TrafficScan.Row ignored : scan.rows)
                shownTimes.add(scan.capturedAt);
        }
        adapter.setNotifyOnChange(false);
        adapter.clear();
        for (TrafficScan.Row row : shownRows) {
            String label = (row.packages.length == 1 ? row.label + " · UID " + row.uid : row.label)
                    + "\n" + usage(row);
            if (!row.reasons.isEmpty())
                label += "\n" + getString(R.string.watch_reasons_count, row.reasons.size());
            adapter.add(label);
        }
        adapter.notifyDataSetChanged();
        empty.setVisibility(shownRows.isEmpty() ? View.VISIBLE : View.GONE);
    }

    private void details(TrafficScan.Row row, long time) {
        StringBuilder body = new StringBuilder(getString(R.string.watch_row_time, row.uid, formatTime(time)));
        body.append('\n').append(usage(row));
        if (row.packages.length == 0)
            body.append("\n\n").append(getString(R.string.watch_unknown_uid));
        else {
            if (row.packages.length > 1)
                body.append("\n\n").append(getString(R.string.watch_shared_uid));
            for (String name : row.packages)
                body.append('\n').append(name);
        }
        if (!row.reasons.isEmpty()) {
            body.append("\n\n").append(getString(R.string.watch_reasons_title));
            for (TrafficRisk.Reason reason : row.reasons)
                body.append("\n• ").append(getString(reasonLabel(reason)));
        }
        AlertDialog.Builder dialog = new AlertDialog.Builder(this).setTitle(row.label).setMessage(body)
                .setNegativeButton(android.R.string.ok, null);
        if (eligible(row) != null)
            dialog.setPositiveButton(R.string.watch_block, (ignored, which) -> confirmBlock(row));
        dialog.show();
    }

    private NetworkApproval.Target eligible(TrafficScan.Row row) {
        if (row.packages.length != 1)
            return null;
        try {
            ApplicationInfo info = getPackageManager().getApplicationInfo(row.packages[0], 0);
            return info.uid == row.uid ? NetworkApproval.get(this).eligibleTarget(info) : null;
        } catch (PackageManager.NameNotFoundException removed) {
            return null;
        }
    }

    private void confirmBlock(TrafficScan.Row row) {
        new AlertDialog.Builder(this).setTitle(R.string.watch_block)
                .setMessage(getString(R.string.watch_block_explainer, row.label))
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.watch_block_confirm, (ignored, which) -> {
                    NetworkApproval.Target target = eligible(row);
                    if (target == null) {
                        message(R.string.watch_block_unavailable);
                        return;
                    }
                    NetworkApproval.get(this).setMode(target.packageName, NetworkApproval.BLOCK);
                    UnifiedVpnService.policyChanged(this);
                    message(UnifiedVpnService.running ? R.string.watch_block_rule_saved
                            : R.string.watch_block_start_vpn);
                }).show();
    }

    private int reasonLabel(TrafficRisk.Reason reason) {
        switch (reason) {
            case FOCUS_PACKAGE: return R.string.watch_reason_focus;
            case OUTBOUND_HEAVY: return R.string.watch_reason_heavy;
            case ACCESSIBILITY_WITH_OUTBOUND: return R.string.watch_reason_accessibility;
            case NOTIFICATION_ACCESS_WITH_OUTBOUND: return R.string.watch_reason_notification;
            default: throw new IllegalArgumentException("Unrecognized risk reason");
        }
    }

    private String usage(TrafficScan.Row row) {
        if (!row.hasDelta)
            return getString(row.observed ? R.string.watch_row_baseline : R.string.watch_row_unobserved);
        return getString(R.string.watch_delta, Formatter.formatShortFileSize(this, row.tx),
                Formatter.formatShortFileSize(this, row.rx));
    }

    private String formatTime(long time) {
        return DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM).format(new Date(time));
    }

    private void message(int text) {
        Toast.makeText(this, text, Toast.LENGTH_LONG).show();
    }
}
