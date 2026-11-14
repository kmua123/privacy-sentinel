package eu.faircode.netguard;

import android.app.AlarmManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.os.SystemClock;
import android.util.Log;

import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class NetworkApproval {
    static final String RECORD = "record";
    static final String ASK = "ask";
    static final String ASK_APP = "ask_app";
    static final String BLOCK = "block";
    static final String ALLOW = "allow";
    static final String DENY = "deny";
    static final String TEMPORARY = "temporary";
    static final String FORGET = "forget";
    private static final String DISMISS = "dismiss";
    static final String ACTION_DECISION = "eu.faircode.netguard.NETWORK_DECISION";
    static final String ACTION_TEMPORARY_EXPIRY = "eu.faircode.netguard.NETWORK_TEMPORARY_EXPIRY";
    static final String EXTRA_KEY = "approval_key";
    static final String EXTRA_DECISION = "approval_decision";
    private static final String CHANNEL = "network_approval";
    private static final String BLOCKED_CHANNEL = "network_blocked";
    private static final int APPROVAL_NOTICE = 37;
    private static final int BLOCKED_NOTICE = 38;
    private static final long TEMPORARY_DURATION = 10 * 60 * 1000L;
    private static final long ALERT_INTERVAL = 2500L;
    private static final long DISMISS_COOLDOWN = 30_000L;
    private static final int MAX_EVENTS = 120;
    private static final long HISTORY_WRITE_DELAY_MS = 3000L;
    private static final String TAG = "PrivacyNetwork";

    private static NetworkApproval instance;

    static synchronized NetworkApproval get(Context context) {
        if (instance == null)
            instance = new NetworkApproval(context.getApplicationContext());
        return instance;
    }

    static final class Target {
        final String packageName;
        final String label;
        final int uid;

        Target(String packageName, String label, int uid) {
            this.packageName = packageName;
            this.label = label;
            this.uid = uid;
        }
    }

    static final class Event {
        final String key;
        final String app;
        final String destination;
        final String status;
        final long time;
        final long sent;

        Event(String key, String app, String destination, String status, long time, long sent) {
            this.key = key;
            this.app = app;
            this.destination = destination;
            this.status = status;
            this.time = time;
            this.sent = sent;
        }
    }

    private final Context context;
    private final SharedPreferences modes;
    private final SharedPreferences rules;
    private final SharedPreferences history;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final Runnable saveHistory = this::flushHistory;
    private final Runnable expireRules = this::expireTemporary;
    private final Runnable dispatchAlerts = this::dispatchNextAlert;
    private final Map<String, Long> temporary = new HashMap<>();
    private final Map<String, Event> events = new LinkedHashMap<>();
    private final Map<String, String> activeAlerts = new HashMap<>();
    private final Map<String, Event> queuedAlerts = new LinkedHashMap<>();
    private final Set<String> blockedAlerts = new HashSet<>();
    private final Map<String, Long> dismissedUntil = new HashMap<>();
    private long lastAlert;
    private boolean alertDispatchScheduled;
    private boolean historyDirty;

    private NetworkApproval(Context context) {
        this.context = context;
        modes = context.getSharedPreferences("privacy_network_apps", Context.MODE_PRIVATE);
        rules = context.getSharedPreferences("privacy_network_rules", Context.MODE_PRIVATE);
        history = context.getSharedPreferences("privacy_network_history", Context.MODE_PRIVATE);
        loadHistory();
    }

    Target eligibleTarget(ApplicationInfo info) {
        if (!info.enabled || info.uid == Process.myUid())
            return null;
        PackageManager pm = context.getPackageManager();
        if (pm.checkPermission(android.Manifest.permission.INTERNET, info.packageName) !=
                PackageManager.PERMISSION_GRANTED)
            return null;
        return targetForUid(info.uid);
    }

    Target targetForUid(int uid) {
        PackageManager pm = context.getPackageManager();
        String[] names = pm.getPackagesForUid(uid);
        if (names != null && names.length == 1 && uid >= Process.FIRST_APPLICATION_UID) {
            try {
                ApplicationInfo info = pm.getApplicationInfo(names[0], 0);
                return new Target(names[0], pm.getApplicationLabel(info).toString(), uid);
            } catch (PackageManager.NameNotFoundException ignored) {
                // Keep an unresolved identity grouped by UID.
            }
        }
        int count = names == null ? 0 : names.length;
        String label = uid < 0 ? "身份未知的连接" : "UID " + uid + " · " + count + " 个包";
        return new Target("@uid:" + uid, label, uid);
    }

    Target targetForName(String name) {
        if (name.startsWith("@uid:")) {
            try {
                return targetForUid(Integer.parseInt(name.substring(5)));
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        try {
            return eligibleTarget(context.getPackageManager().getApplicationInfo(name, 0));
        } catch (PackageManager.NameNotFoundException ignored) {
            return null;
        }
    }

    String members(Target target) {
        String[] names = context.getPackageManager().getPackagesForUid(target.uid);
        if (names == null)
            return "系统未提供原始应用归属。";
        Arrays.sort(names);
        return String.join("\n", names);
    }

    List<Target> availableTargets() {
        List<Target> result = new ArrayList<>();
        Set<Integer> seen = new HashSet<>();
        for (ApplicationInfo info : context.getPackageManager().getInstalledApplications(0)) {
            Target target = eligibleTarget(info);
            if (target != null && seen.add(target.uid))
                result.add(target);
        }
        result.sort((left, right) -> left.label.compareToIgnoreCase(right.label));
        return result;
    }

    List<Target> selectedTargets() {
        List<Target> result = new ArrayList<>();
        for (String name : modes.getAll().keySet()) {
            Target target = targetForName(name);
            if (target != null)
                result.add(target);
        }
        result.sort((left, right) -> left.label.compareToIgnoreCase(right.label));
        return result;
    }

    boolean hasSelections() {
        return !selectedTargets().isEmpty();
    }

    String mode(String packageName) {
        String fallback = packageName.startsWith("@uid:") ? RECORD : ASK_APP;
        if (packageName.startsWith("@uid:")) {
            try {
                int uid = Integer.parseInt(packageName.substring(5));
                String[] owners = context.getPackageManager().getPackagesForUid(uid);
                if (uid < 0 || (uid >= Process.FIRST_APPLICATION_UID &&
                        (owners == null || owners.length == 0)))
                    fallback = BLOCK;
            } catch (NumberFormatException invalidIdentity) {
                fallback = BLOCK;
            }
        }
        return modes.getString(packageName, fallback);
    }

    static boolean isAsking(String mode) {
        return ASK.equals(mode) || ASK_APP.equals(mode);
    }

    synchronized void setMode(String packageName, String mode) {
        if (mode == null) {
            modes.edit().remove(packageName).apply();
            SharedPreferences.Editor editor = rules.edit();
            for (String key : rules.getAll().keySet())
                if (key.startsWith(packageName + "|"))
                    editor.remove(key);
            editor.apply();
            temporary.keySet().removeIf(key -> key.startsWith(packageName + "|"));
        } else {
            modes.edit().putString(packageName, mode).apply();
        }
        dismissedUntil.remove(packageName);
        clearAlert(packageName);
    }

    private String key(Target target, int protocol, String address, int port) {
        return target.packageName + "|" + protocol + "|" + address + "|" + port;
    }

    private String endpoint(int protocol, String address, int port) {
        String host = address.indexOf(':') >= 0 ? "[" + address + "]" : address;
        return host + ":" + port + (protocol == 6 ? " / TCP" : " / UDP");
    }

    synchronized boolean permit(Target target, Packet packet) {
        String appMode = mode(target.packageName);
        if (appMode == null || (packet.protocol != 6 && packet.protocol != 17))
            return false;
        String key = ASK_APP.equals(appMode) ? key(target, 0, "*", 0)
                : key(target, packet.protocol, packet.daddr, packet.dport);
        String destination = endpoint(packet.protocol, packet.daddr, packet.dport);
        // Destination approvals are only active when the app is in ASK mode.
        String status = isAsking(appMode) ? currentDecision(key) : appMode;
        if (status == null)
            status = ASK;
        boolean allowed = RECORD.equals(status) || ALLOW.equals(status) || TEMPORARY.equals(status);
        putEvent(key, target.label, destination, status, 0);
        if (BLOCK.equals(status)) {
            if (Util.canNotify(context) && blockedAlerts.add(target.packageName))
                main.post(() -> showBlockedAlert(target));
            return false;
        }
        long now = SystemClock.elapsedRealtime();
        Long dismissed = dismissedUntil.get(target.packageName);
        if (ASK.equals(status) && !activeAlerts.containsKey(target.packageName) &&
                (dismissed == null || now >= dismissed) &&
                Util.canNotify(context) && NotificationManagerCompat.from(context).areNotificationsEnabled()) {
            // Keep the first pending attempt from each application. A global
            // notification throttle must delay another app's first alert,
            // rather than silently lose it until that app happens to retry.
            if (!queuedAlerts.containsKey(target.packageName)) {
                if (queuedAlerts.size() >= MAX_EVENTS)
                    queuedAlerts.remove(queuedAlerts.keySet().iterator().next());
                queuedAlerts.put(target.packageName, events.get(key));
            }
            scheduleAlerts();
        }
        return allowed;
    }

    private void scheduleAlerts() {
        if (queuedAlerts.isEmpty()) {
            main.removeCallbacks(dispatchAlerts);
            alertDispatchScheduled = false;
        } else if (!alertDispatchScheduled) {
            alertDispatchScheduled = true;
            main.postDelayed(dispatchAlerts,
                    Math.max(0, ALERT_INTERVAL - (SystemClock.elapsedRealtime() - lastAlert)));
        }
    }

    private synchronized void dispatchNextAlert() {
        alertDispatchScheduled = false;
        while (!queuedAlerts.isEmpty()) {
            String app = queuedAlerts.keySet().iterator().next();
            Event queued = queuedAlerts.remove(app);
            String appMode = mode(app);
            Long dismissed = dismissedUntil.get(app);
            long now = SystemClock.elapsedRealtime();
            if (!isAsking(appMode) || activeAlerts.containsKey(app) ||
                    (dismissed != null && now < dismissed) || currentDecision(queued.key) != null)
                continue;
            // A mode change from per-app to per-destination approval must
            // never display a queued decision with the previous scope.
            if (ASK_APP.equals(appMode) != queued.key.equals(app + "|0|*|0"))
                continue;
            Event current = events.get(queued.key);
            if (current != null && !ASK.equals(current.status))
                continue;
            if (!Util.canNotify(context) ||
                    !NotificationManagerCompat.from(context).areNotificationsEnabled())
                continue;
            if (current == null) {
                // Busy apps can evict an earlier one-shot attempt from the
                // bounded history. Retain its bounded queue snapshot so it
                // can still be reviewed without requiring another attempt.
                putEvent(queued.key, queued.app, queued.destination, ASK, 0);
                current = events.get(queued.key);
            }
            activeAlerts.put(app, queued.key);
            lastAlert = now;
            showAlert(app, current);
            break;
        }
        scheduleAlerts();
    }

    synchronized void usage(Target target, Usage usage) {
        if (usage.Sent <= 0 || (usage.Protocol != 6 && usage.Protocol != 17))
            return;
        String key = ASK_APP.equals(mode(target.packageName)) ? key(target, 0, "*", 0)
                : key(target, usage.Protocol, usage.DAddr, usage.DPort);
        Event previous = events.get(key);
        String status = previous == null ? ALLOW : previous.status;
        putEvent(key, target.label, endpoint(usage.Protocol, usage.DAddr, usage.DPort), status, usage.Sent);
    }

    private void putEvent(String key, String app, String destination, String status, long sent) {
        Event previous = events.remove(key);
        long total = sent + (previous == null ? 0 : previous.sent);
        events.put(key, new Event(key, app, destination, status, System.currentTimeMillis(), total));
        if (events.size() > MAX_EVENTS)
            events.remove(events.keySet().iterator().next());
        if (!historyDirty) {
            historyDirty = true;
            main.postDelayed(saveHistory, HISTORY_WRITE_DELAY_MS);
        }
    }

    private void loadHistory() {
        try {
            JSONArray stored = new JSONArray(history.getString("events", "[]"));
            for (int i = Math.max(0, stored.length() - MAX_EVENTS); i < stored.length(); i++) {
                JSONObject item = stored.getJSONObject(i);
                String key = item.getString("key");
                if (key.indexOf('|') > 0)
                    events.put(key, new Event(key, item.getString("app"), item.getString("destination"),
                            item.getString("status"), item.getLong("time"), item.getLong("sent")));
            }
        } catch (JSONException malformed) {
            Log.w(TAG, "Could not read saved connection history", malformed);
        }
    }

    synchronized void flushHistory() {
        if (!historyDirty)
            return;
        main.removeCallbacks(saveHistory);
        JSONArray stored = new JSONArray();
        try {
            for (Event event : events.values())
                stored.put(new JSONObject().put("key", event.key).put("app", event.app)
                        .put("destination", event.destination).put("status", event.status)
                        .put("time", event.time).put("sent", event.sent));
            history.edit().putString("events", stored.toString()).apply();
        } catch (JSONException malformed) {
            Log.w(TAG, "Could not save connection history", malformed);
        }
        historyDirty = false;
    }

    synchronized List<Event> recentEvents() {
        List<Event> result = new ArrayList<>(events.values());
        Collections.reverse(result);
        return result;
    }

    synchronized List<String> savedRules() {
        List<String> result = new ArrayList<>(rules.getAll().keySet());
        result.addAll(temporary.keySet());
        Collections.sort(result);
        return result;
    }

    synchronized String currentDecision(String key) {
        Long expiration = temporary.get(key);
        if (expiration != null && SystemClock.elapsedRealtime() < expiration)
            return TEMPORARY;
        return rules.getString(key, null);
    }

    synchronized boolean decide(String key, String choice) {
        if (key == null || choice == null)
            return false;
        int split = key.indexOf('|');
        if (split <= 0)
            return false;
        String app = key.substring(0, split);
        if (DISMISS.equals(choice)) {
            Event queued = queuedAlerts.get(app);
            if (key.equals(activeAlerts.get(app)) ||
                    (queued != null && key.equals(queued.key))) {
                dismissedUntil.put(app, SystemClock.elapsedRealtime() + DISMISS_COOLDOWN);
                clearAlert(app);
            }
            return false;
        }
        if ((!isAsking(mode(app)) && !FORGET.equals(choice)) ||
                (!events.containsKey(key) && currentDecision(key) == null &&
                        !key.equals(activeAlerts.get(app))))
            return false;

        if (TEMPORARY.equals(choice)) {
            long expiration = SystemClock.elapsedRealtime() + TEMPORARY_DURATION;
            rules.edit().remove(key).apply();
            temporary.put(key, expiration);
        } else if (ALLOW.equals(choice) || DENY.equals(choice) || FORGET.equals(choice)) {
            temporary.remove(key);
            SharedPreferences.Editor editor = rules.edit();
            if (FORGET.equals(choice))
                editor.remove(key);
            else
                editor.putString(key, choice);
            editor.apply();
        } else {
            return false;
        }
        scheduleExpiry();
        queuedAlerts.remove(app);
        scheduleAlerts();
        if (key.equals(activeAlerts.get(app)))
            clearAlert(app);
        return true;
    }

    synchronized void expireTemporary() {
        long now = SystemClock.elapsedRealtime();
        if (temporary.values().removeIf(expiration -> expiration <= now))
            UnifiedVpnService.policyChanged(context);
        scheduleExpiry();
    }

    private void scheduleExpiry() {
        main.removeCallbacks(expireRules);
        AlarmManager alarm = context.getSystemService(AlarmManager.class);
        Intent action = new Intent(ACTION_TEMPORARY_EXPIRY).setPackage(context.getPackageName());
        PendingIntent pending = PendingIntent.getBroadcast(context, 82, action,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        if (temporary.isEmpty()) {
            alarm.cancel(pending);
            return;
        }
        long firstExpiry = Collections.min(temporary.values());
        main.postDelayed(expireRules, Math.max(0, firstExpiry - SystemClock.elapsedRealtime()));
        alarm.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, firstExpiry, pending);
    }

    synchronized void clearAlerts() {
        Set<String> apps = new HashSet<>(activeAlerts.keySet());
        apps.addAll(blockedAlerts);
        apps.addAll(queuedAlerts.keySet());
        for (String app : apps)
            clearAlert(app);
        dismissedUntil.clear();
        flushHistory();
    }

    private void clearAlert(String app) {
        activeAlerts.remove(app);
        queuedAlerts.remove(app);
        scheduleAlerts();
        blockedAlerts.remove(app);
        NotificationManagerCompat manager = NotificationManagerCompat.from(context);
        manager.cancel(app, APPROVAL_NOTICE);
        manager.cancel(app, BLOCKED_NOTICE);
    }

    private NotificationManager alertManager(String channelId, int channelTitle) {
        NotificationManager manager = context.getSystemService(NotificationManager.class);
        if (manager == null || !Util.canNotify(context) || !manager.areNotificationsEnabled())
            return null;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(channelId,
                    context.getString(channelTitle), NotificationManager.IMPORTANCE_HIGH);
            manager.createNotificationChannel(channel);
            if (manager.getNotificationChannel(channelId).getImportance() ==
                    NotificationManager.IMPORTANCE_NONE)
                return null;
        }
        return manager;
    }

    private synchronized void showAlert(String app, Event event) {
        if (!event.key.equals(activeAlerts.get(app)))
            return;
        NotificationManager manager = alertManager(CHANNEL, R.string.privacy_network_channel);
        if (manager == null) {
            clearAlert(app);
            return;
        }

        Intent open = new Intent(context, ActivityNetworkApproval.class);
        open.setData(Uri.fromParts("privacy-review", event.key, null));
        PendingIntent review = PendingIntent.getActivity(context, 0, open,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification notification = new NotificationCompat.Builder(context, CHANNEL)
                .setSmallIcon(R.drawable.ic_cloud_upload_white_24dp)
                .setContentTitle(context.getString(R.string.privacy_network_alert, event.app))
                .setContentText(ASK_APP.equals(mode(app))
                        ? "此次决定适用此应用的全部联网目标 · " + event.destination : event.destination)
                .setContentIntent(review)
                .setDeleteIntent(action(event.key, DISMISS))
                .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_STATUS)
                .setAutoCancel(false)
                .addAction(0, context.getString(R.string.privacy_network_temporary), action(event.key, TEMPORARY))
                .addAction(0, context.getString(R.string.privacy_network_allow), action(event.key, ALLOW))
                .addAction(0, context.getString(R.string.privacy_network_deny), action(event.key, DENY))
                .build();
        manager.notify(app, APPROVAL_NOTICE, notification);
    }

    private synchronized void showBlockedAlert(Target target) {
        if (!blockedAlerts.contains(target.packageName) || !BLOCK.equals(mode(target.packageName)))
            return;
        NotificationManager manager = alertManager(BLOCKED_CHANNEL, R.string.privacy_network_blocked_channel);
        if (manager == null)
            return;
        Intent open = new Intent(context, ActivityNetworkApproval.class);
        PendingIntent review = PendingIntent.getActivity(context, 0, open,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification notification = new NotificationCompat.Builder(context, BLOCKED_CHANNEL)
                .setSmallIcon(R.drawable.ic_cloud_upload_white_24dp)
                .setContentTitle(context.getString(R.string.privacy_network_blocked_alert, target.label))
                .setContentText(context.getString(R.string.privacy_network_blocked_alert_text))
                .setContentIntent(review)
                .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_STATUS)
                .setAutoCancel(true)
                .build();
        manager.notify(target.packageName, BLOCKED_NOTICE, notification);
    }

    private PendingIntent action(String key, String decision) {
        Intent intent = new Intent(context, UnifiedVpnService.class).setAction(ACTION_DECISION);
        intent.setData(Uri.fromParts("privacy-rule", key + "|" + decision, null));
        intent.putExtra(EXTRA_KEY, key);
        intent.putExtra(EXTRA_DECISION, decision);
        return PendingIntentCompat.getForegroundService(context, 0, intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
    }
}
