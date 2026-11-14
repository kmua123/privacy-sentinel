package eu.faircode.netguard;

/* SPDX-License-Identifier: GPL-3.0-or-later */

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;

import guardcore.Guardcore;


public class TrafficWatchService extends Service {
    private static final String TAG = "PrivacyTrafficWatch";
    private static final String WATCH_CHANNEL = "global_traffic_status";
    private static final String FINDING_CHANNEL = "global_traffic_findings";
    private static final int WATCH_ID = 9101;
    private static final int FINDING_ID = 9102;
    private static final long SAMPLE_DELAY = 30_000;
    private static final long ALERT_DELAY = 5 * 60_000;
    private static final int MAX_FINDINGS = 60;
    static final String ACTION_SAMPLE = "local.privacy.guard.SAMPLE_TRAFFIC";

    static volatile boolean active;
    static volatile int status = R.string.watch_status_stopped;
    static volatile TrafficScan latest;
    static volatile List<Finding> findings = Collections.emptyList();
    static volatile String failureCode = "";
    static volatile long lastAttemptAt;
    static volatile long nextSampleAt;
    static volatile boolean sampling;

    static final class Finding {
        final TrafficScan.Row row;
        final long capturedAt;

        Finding(TrafficScan.Row row, long capturedAt) {
            this.row = row;
            this.capturedAt = capturedAt;
        }
    }

    private final Handler main = new Handler(Looper.getMainLooper());
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Map<Integer, Finding> recent = new LinkedHashMap<>();
    private final Map<Integer, Long> lastAlert = new HashMap<>();
    private final Runnable sample = this::sample;
    private final InternalAdbBridge.StateListener bridgeState = (ready, detail) -> main.post(this::sampleSoon);
    private boolean stopping;
    private TrafficScan baseline;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (active) {
            if (intent != null && ACTION_SAMPLE.equals(intent.getAction()))
                sampleSoon();
            return START_NOT_STICKY;
        }
        active = true;
        baseline = null;
        // A failed restart must not erase the last successful sample or findings.
        for (Finding finding : findings)
            recent.put(finding.row.uid, finding);
        failureCode = "";
        status = R.string.watch_status_connecting;
        NotificationManager notifications = getSystemService(NotificationManager.class);
        notifications.createNotificationChannel(new NotificationChannel(WATCH_CHANNEL,
                getString(R.string.watch_title), NotificationManager.IMPORTANCE_LOW));
        notifications.createNotificationChannel(new NotificationChannel(FINDING_CHANNEL,
                getString(R.string.watch_findings), NotificationManager.IMPORTANCE_HIGH));
        startForeground(WATCH_ID, foreground());
        InternalAdbBridge bridge = InternalAdbBridge.get(this);
        bridge.addStateListener(bridgeState);
        sample();
        return START_NOT_STICKY;
    }

    private void sample() {
        if (stopping || sampling)
            return;
        main.removeCallbacks(sample);
        nextSampleAt = 0;
        lastAttemptAt = System.currentTimeMillis();
        sampling = true;
        TrafficScan previous = baseline;
        worker.execute(() -> {
            try {
                Bundle snapshot;
                TrafficScan scan;
                String degraded = "";
                try {
                    InternalAdbBridge bridge = InternalAdbBridge.get(this);
                    if (!bridge.isReady())
                        throw new IOException("netstats_disconnected");
                    snapshot = bridge.readSnapshot();
                    int[] uids = snapshot == null ? null : snapshot.getIntArray("uids");
                    if (uids != null && uids.length == 0)
                        throw new IOException("netstats_empty");
                    if (snapshot != null) {
                        snapshot.putString("source", "system");
                        snapshot.putString("epoch", "boot");
                    }
                    scan = TrafficScan.collect(this, snapshot, previous);
                } catch (Exception systemFailure) {
                    degraded = diagnostic(systemFailure);
                    if (!UnifiedVpnService.running)
                        throw systemFailure;
                    snapshot = vpnSnapshot();
                    scan = TrafficScan.collect(this, snapshot, previous);
                }
                String sourceFailure = degraded;
                TrafficScan result = scan;
                main.post(() -> accept(result, sourceFailure));
            } catch (Exception failure) {
                // Only a short classified code is displayed; no raw system dump is retained.
                String code = diagnostic(failure);
                Log.w(TAG, "UID snapshot unavailable: " + code);
                main.post(() -> {
                    if (stopping)
                        return;
                    sampling = false;
                    failureCode = code;
                    status = R.string.watch_status_sample_failed;
                    notifyStatus();
                    schedule();
                });
            }
        });
    }

    private void sampleSoon() {
        main.removeCallbacks(sample);
        if (!stopping && !sampling)
            sample();
    }

    private void schedule() {
        nextSampleAt = System.currentTimeMillis() + SAMPLE_DELAY;
        main.postDelayed(sample, SAMPLE_DELAY);
    }

    private void accept(TrafficScan scan, String degraded) {
        if (stopping)
            return;
        sampling = false;
        if (latest != null && (!scan.source.equals(latest.source) || !scan.epoch.equals(latest.epoch))) {
            // Cumulative byte counters from different sources or VPN sessions cannot be compared.
            recent.clear();
            lastAlert.clear();
        }
        latest = scan;
        baseline = scan;
        failureCode = degraded;
        status = scan.hasBaseline ? R.string.watch_status_running : R.string.watch_status_baseline;
        int alerts = 0;
        TrafficScan.Row first = null;
        long now = SystemClock.elapsedRealtime();
        for (TrafficScan.Row row : scan.rows) {
            if (row.reasons.isEmpty() || row.tx <= 0)
                continue;
            recent.remove(row.uid);
            recent.put(row.uid, new Finding(row, scan.capturedAt));
            while (recent.size() > MAX_FINDINGS)
                recent.remove(recent.keySet().iterator().next());
            Long previousAlert = lastAlert.get(row.uid);
            if (previousAlert == null || now - previousAlert >= ALERT_DELAY) {
                lastAlert.put(row.uid, now);
                if (first == null)
                    first = row;
                alerts++;
            }
        }
        List<Finding> copy = new ArrayList<>(recent.values());
        Collections.reverse(copy);
        findings = Collections.unmodifiableList(copy);
        if (alerts > 0 && Util.canNotify(this))
            notifyFindings(first, alerts);
        notifyStatus();
        schedule();
    }

    private static Bundle vpnSnapshot() throws Exception {
        String encoded = Guardcore.trafficSnapshot();
        if (encoded == null || encoded.length() > 2 * 1024 * 1024)
            throw new IOException("vpn_snapshot_invalid");
        JSONObject json = new JSONObject(encoded);
        if (!"running".equals(json.optString("state")))
            throw new IOException("vpn_snapshot_stopped");
        JSONArray ids = json.getJSONArray("uids");
        JSONArray received = json.getJSONArray("rxBytes");
        JSONArray sent = json.getJSONArray("txBytes");
        if (ids.length() > 10_000 || ids.length() != received.length() || ids.length() != sent.length())
            throw new IOException("vpn_snapshot_invalid");
        int[] uids = new int[ids.length()];
        long[] rx = new long[ids.length()];
        long[] tx = new long[ids.length()];
        for (int index = 0; index < ids.length(); index++) {
            uids[index] = ids.getInt(index);
            rx[index] = received.getLong(index);
            tx[index] = sent.getLong(index);
            if (uids[index] < 0 || rx[index] < 0 || tx[index] < 0)
                throw new IOException("vpn_snapshot_invalid");
        }
        String epoch = String.valueOf(json.get("epoch"));
        if (epoch.isEmpty() || "null".equals(epoch))
            throw new IOException("vpn_snapshot_invalid");
        Bundle snapshot = new Bundle();
        snapshot.putIntArray("uids", uids);
        snapshot.putLongArray("rxBytes", rx);
        snapshot.putLongArray("txBytes", tx);
        snapshot.putLong("elapsedRealtime", SystemClock.elapsedRealtime());
        snapshot.putString("source", "vpn");
        snapshot.putString("epoch", epoch);
        return snapshot;
    }

    private String diagnostic(Throwable failure) {
        if (!InternalAdbBridge.get(this).isReady() && !UnifiedVpnService.running)
            return "netstats_disconnected";
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof TimeoutException)
                return "netstats_timeout";
            String code = cause.getMessage();
            if (code != null && (code.matches("netstats_(timeout|permission_denied|unsupported|invalid_counters|too_large|failed|empty|disconnected)")
                    || code.matches("vpn_snapshot_(invalid|stopped)")))
                return code;
        }
        return "netstats_failed";
    }

    static int diagnosticText(String code) {
        switch (code) {
            case "netstats_disconnected": return R.string.watch_error_disconnected;
            case "netstats_timeout": return R.string.watch_error_timeout;
            case "netstats_permission_denied": return R.string.watch_error_permission;
            case "netstats_unsupported": return R.string.watch_error_unsupported;
            case "netstats_empty": return R.string.watch_error_empty;
            case "netstats_invalid_counters": return R.string.watch_error_invalid;
            case "netstats_too_large": return R.string.watch_error_large;
            case "vpn_snapshot_stopped": return R.string.watch_error_vpn_stopped;
            case "vpn_snapshot_invalid": return R.string.watch_error_vpn_invalid;
            default: return R.string.watch_error_failed;
        }
    }

    private PendingIntent open(boolean showFindings) {
        Intent intent = new Intent(this, ActivityTrafficWatch.class).putExtra("findings", showFindings);
        return PendingIntent.getActivity(this, showFindings ? 1 : 0, intent,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    private Notification foreground() {
        return new NotificationCompat.Builder(this, WATCH_CHANNEL)
                .setSmallIcon(R.drawable.ic_security_white_24dp)
                .setContentTitle(getString(R.string.watch_title))
                .setContentText(getString(status) + (latest != null && "vpn".equals(latest.source)
                        ? " · " + getString(R.string.watch_source_vpn_short) : ""))
                .setContentIntent(open(false))
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .build();
    }

    private void notifyStatus() {
        if (Util.canNotify(this))
            getSystemService(NotificationManager.class).notify(WATCH_ID, foreground());
    }

    private void notifyFindings(TrafficScan.Row first, int count) {
        Notification alert = new NotificationCompat.Builder(this, FINDING_CHANNEL)
                .setSmallIcon(R.drawable.ic_cloud_upload_white_24dp)
                .setContentTitle(getString(R.string.watch_alert_title, count))
                .setContentText(getString(R.string.watch_alert_body, first.label))
                .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
                .setContentIntent(open(true))
                .setAutoCancel(true)
                .build();
        getSystemService(NotificationManager.class).notify(FINDING_ID, alert);
    }

    @Override
    public void onDestroy() {
        stopping = true;
        active = false;
        sampling = false;
        nextSampleAt = 0;
        main.removeCallbacksAndMessages(null);
        worker.shutdownNow();
        InternalAdbBridge.get(this).removeStateListener(bridgeState);
        if (status == R.string.watch_status_connecting || status == R.string.watch_status_baseline ||
                status == R.string.watch_status_running || status == R.string.watch_status_sample_failed)
            status = R.string.watch_status_stopped;
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
