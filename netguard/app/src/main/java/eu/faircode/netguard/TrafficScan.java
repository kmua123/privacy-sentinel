package eu.faircode.netguard;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Bundle;
import android.os.Process;
import android.os.UserHandle;
import android.view.accessibility.AccessibilityManager;

import androidx.core.app.NotificationManagerCompat;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

final class TrafficScan {
    static final class Row {
        final int uid;
        final String[] packages;
        final String label;
        final long rx;
        final long tx;
        final boolean observed;
        final boolean hasDelta;
        final EnumSet<TrafficRisk.Reason> reasons;

        private Row(int uid, String[] packages, String label, long rx, long tx,
                    boolean observed, boolean hasDelta, EnumSet<TrafficRisk.Reason> reasons) {
            this.uid = uid;
            this.packages = packages.clone();
            this.label = label;
            this.rx = rx;
            this.tx = tx;
            this.observed = observed;
            this.hasDelta = hasDelta;
            this.reasons = reasons.clone();
        }
    }

    private static final class Sample {
        final String[] packages;
        final long rx;
        final long tx;
        final boolean observed;

        Sample(String[] packages, long rx, long tx, boolean observed) {
            this.packages = packages;
            this.rx = rx;
            this.tx = tx;
            this.observed = observed;
        }
    }

    final List<Row> rows;
    final long elapsed;
    final long capturedAt;
    final boolean hasBaseline;
    final int observedCount;
    final String source;
    final String epoch;
    private final Map<Integer, Sample> samples;

    private TrafficScan(List<Row> rows, long elapsed, long capturedAt, boolean hasBaseline,
                        int observedCount, Map<Integer, Sample> samples, String source, String epoch) {
        this.rows = Collections.unmodifiableList(rows);
        this.elapsed = elapsed;
        this.capturedAt = capturedAt;
        this.hasBaseline = hasBaseline;
        this.observedCount = observedCount;
        this.source = source;
        this.epoch = epoch;
        this.samples = Collections.unmodifiableMap(samples);
    }

    static TrafficScan collect(Context context, Bundle reply, TrafficScan previous) throws IOException {
        if (reply == null)
            throw new IOException("没有收到流量样本");
        String error = reply.getString("error");
        if (error != null)
            throw new IOException(error);
        int[] uids = reply.getIntArray("uids");
        long[] rxTotals = reply.getLongArray("rxBytes");
        long[] txTotals = reply.getLongArray("txBytes");
        long elapsed = reply.getLong("elapsedRealtime", -1);
        String source = reply.getString("source", "system");
        String epoch = reply.getString("epoch", "boot");
        if (uids == null || rxTotals == null || txTotals == null ||
                uids.length != rxTotals.length || uids.length != txTotals.length || elapsed < 0)
            throw new IOException("流量样本格式无效");
        long capturedAt = System.currentTimeMillis();

        UserHandle profile = Process.myUserHandle();
        Map<Integer, TreeMap<String, String>> apps = installedApps(context, profile);
        Map<Integer, Sample> samples = new HashMap<>();
        for (int i = 0; i < uids.length; i++) {
            int uid = uids[i];
            if (uid < 0 || rxTotals[i] < 0 || txTotals[i] < 0)
                throw new IOException("流量样本含无效 UID 或字节数");
            Sample sample = new Sample(packageNames(apps.get(uid)), rxTotals[i], txTotals[i], true);
            if (samples.put(uid, sample) != null)
                throw new IOException("流量样本含重复 UID");
        }
        int observedCount = samples.size();
        for (Map.Entry<Integer, TreeMap<String, String>> entry : apps.entrySet())
            samples.putIfAbsent(entry.getKey(), new Sample(packageNames(entry.getValue()), 0, 0, false));

        Set<String> accessibility = enabledAccessibility(context);
        Set<String> notifications = NotificationManagerCompat.getEnabledListenerPackages(context);
        boolean hasBaseline = previous != null && elapsed > previous.elapsed
                && source.equals(previous.source) && epoch.equals(previous.epoch);
        List<Row> rows = new ArrayList<>(samples.size());
        for (Map.Entry<Integer, Sample> entry : samples.entrySet()) {
            int uid = entry.getKey();
            Sample current = entry.getValue();
            Sample baseline = hasBaseline ? previous.samples.get(uid) : null;
            long rx = 0;
            long tx = 0;
            boolean comparable = current.observed && baseline != null &&
                    Arrays.equals(current.packages, baseline.packages) &&
                    baseline.observed &&
                    current.rx >= baseline.rx && current.tx >= baseline.tx;
            if (comparable) {
                rx = current.rx - baseline.rx;
                tx = current.tx - baseline.tx;
            }
            TreeMap<String, String> labels = apps.get(uid);
            String label = current.packages.length == 1 ? labels.firstEntry().getValue() : "UID " + uid;
            rows.add(new Row(uid, current.packages, label, rx, tx, current.observed, comparable,
                    TrafficRisk.reasons(current.packages, containsAny(accessibility, current.packages),
                            containsAny(notifications, current.packages), rx, tx)));
        }
        rows.sort(Comparator.comparingLong((Row row) -> row.tx).reversed()
                .thenComparingInt(row -> row.uid));
        return new TrafficScan(rows, elapsed, capturedAt, hasBaseline, observedCount, samples, source, epoch);
    }

    private static Map<Integer, TreeMap<String, String>> installedApps(Context context, UserHandle profile) {
        PackageManager manager = context.getPackageManager();
        Map<Integer, TreeMap<String, String>> apps = new HashMap<>();
        for (ApplicationInfo info : manager.getInstalledApplications(0)) {
            if (info.uid < 0 || !profile.equals(UserHandle.getUserHandleForUid(info.uid)))
                continue;
            CharSequence label = manager.getApplicationLabel(info);
            apps.computeIfAbsent(info.uid, unused -> new TreeMap<>())
                    .put(info.packageName, label == null ? info.packageName : label.toString());
        }
        return apps;
    }

    private static String[] packageNames(TreeMap<String, String> apps) {
        return apps == null ? new String[0] : apps.keySet().toArray(new String[0]);
    }

    private static Set<String> enabledAccessibility(Context context) {
        AccessibilityManager manager = context.getSystemService(AccessibilityManager.class);
        if (manager == null)
            return Collections.emptySet();
        Set<String> packages = new HashSet<>();
        for (AccessibilityServiceInfo service :
                manager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)) {
            ResolveInfo info = service.getResolveInfo();
            if (info != null && info.serviceInfo != null)
                packages.add(info.serviceInfo.packageName);
        }
        return packages;
    }

    private static boolean containsAny(Set<String> enabled, String[] packages) {
        for (String packageName : packages)
            if (enabled.contains(packageName))
                return true;
        return false;
    }
}
