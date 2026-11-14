package eu.faircode.netguard;

import androidx.activity.ComponentActivity;
import androidx.activity.OnBackPressedCallback;
import android.app.AlertDialog;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.text.format.Formatter;
import android.view.WindowManager;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;

import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class ActivityNetworkApproval extends ComponentActivity {
    private static final String SYSTEM_HELPER = "com.mobiletools.systemhelper";
    private NetworkApproval approval;
    private ScrollView scroll;
    private LinearLayout content;
    private boolean openedFromNotification;
    private String viewedPackage;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override public void handleOnBackPressed() {
                if (viewedPackage == null)
                    finish();
                else
                    showPackage(null);
            }
        });
        approval = NetworkApproval.get(this);
        if (state != null) {
            viewedPackage = state.getString("viewedPackage");
            openedFromNotification = state.getBoolean("openedFromNotification");
        }
        scroll = new ScrollView(this);
        content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        int padding = Math.round(18 * getResources().getDisplayMetrics().density);
        content.setPadding(padding, padding, padding, padding);
        scroll.addView(content);
        setContentView(scroll);
    }

    @Override
    protected void onResume() {
        super.onResume();
        render();
        if (!openedFromNotification && getIntent().getData() != null) {
            openedFromNotification = true;
            String requestedKey = getIntent().getData().getSchemeSpecificPart();
            if (requestedKey != null && NetworkApproval.isAsking(approval.mode(packageOf(requestedKey)))) {
                showPackage(packageOf(requestedKey));
                showRule(requestedKey, describeKey(requestedKey));
            }
        }
    }

    @Override
    protected void onSaveInstanceState(Bundle state) {
        state.putString("viewedPackage", viewedPackage);
        state.putBoolean("openedFromNotification", openedFromNotification);
        super.onSaveInstanceState(state);
    }

    private void render() {
        content.removeAllViews();
        List<NetworkApproval.Event> events = approval.recentEvents();
        if (viewedPackage != null) {
            renderDetails(events);
            return;
        }
        heading(R.string.privacy_network_title);
        note(getString(R.string.privacy_network_description));
        button(getString(R.string.privacy_network_add), this::chooseApp);
        button(getString(R.string.privacy_network_refresh), this::render);

        NetworkApproval.Target systemHelper = targetFor(SYSTEM_HELPER);
        if (systemHelper == null) {
            int status = applicationInfo(SYSTEM_HELPER) == null ? R.string.privacy_network_systemhelper_missing
                    : R.string.privacy_network_systemhelper_unsupported;
            note(getString(status));
        } else if (approval.mode(SYSTEM_HELPER) == null) {
            button(getString(R.string.privacy_network_systemhelper_add), () -> chooseMode(systemHelper));
        }

        Map<String, List<NetworkApproval.Event>> byPackage = new LinkedHashMap<>();
        for (NetworkApproval.Event event : events)
            byPackage.computeIfAbsent(packageOf(event.key), key -> new ArrayList<>()).add(event);
        heading(R.string.privacy_network_selected);
        List<NetworkApproval.Target> targets = approval.selectedTargets();
        if (targets.isEmpty())
            note(getString(R.string.privacy_network_no_selection));
        Set<String> selected = new HashSet<>();
        for (NetworkApproval.Target target : targets) {
            selected.add(target.packageName);
            button(target.label + " · " + appModeLabel(approval.mode(target.packageName)) +
                            "\n" + summarize(byPackage.get(target.packageName)),
                    () -> showPackage(target.packageName));
        }

        if (byPackage.keySet().stream().anyMatch(packageName -> !selected.contains(packageName))) {
            heading(R.string.privacy_network_other_history);
            for (Map.Entry<String, List<NetworkApproval.Event>> group : byPackage.entrySet())
                if (!selected.contains(group.getKey()))
                    button(group.getValue().get(0).app + "\n" + summarize(group.getValue()),
                            () -> showPackage(group.getKey()));
        }
    }

    private void showPackage(String packageName) {
        viewedPackage = packageName;
        render();
        scroll.scrollTo(0, 0);
    }

    private void renderDetails(List<NetworkApproval.Event> recent) {
        String packageName = viewedPackage;
        NetworkApproval.Target target = targetFor(packageName);
        List<NetworkApproval.Event> events = new ArrayList<>();
        for (NetworkApproval.Event event : recent)
            if (packageName.equals(packageOf(event.key)))
                events.add(event);

        button(getString(R.string.privacy_network_back), () -> showPackage(null));
        note((target != null ? target.label : events.isEmpty() ? packageName : events.get(0).app) +
                "\n" + packageName);
        String mode = approval.mode(packageName);
        if (target != null)
            button(getString(R.string.privacy_network_change_mode, appModeLabel(mode)), () -> chooseMode(target));
        note(summarize(events));
        button(getString(R.string.privacy_network_refresh), this::render);

        if (target != null && target.packageName.startsWith("@uid:"))
            note("同一 UID 的包共用策略\n" + approval.members(target));
        if (NetworkApproval.isAsking(mode)) {
            heading(R.string.privacy_network_rules);
            boolean hasRules = false;
            for (String key : approval.savedRules()) {
                if (!packageName.equals(packageOf(key)))
                    continue;
                hasRules = true;
                String description = describeKey(key);
                button(eventLabel(approval.currentDecision(key)) + " · " + description,
                        () -> showRule(key, description));
            }
            if (!hasRules)
                note(getString(R.string.privacy_network_no_rules));
        }

        heading(R.string.privacy_network_recent);
        note(getString(R.string.privacy_network_event_note));
        if (events.isEmpty())
            note(getString(R.string.privacy_network_no_events));
        for (NetworkApproval.Event event : events) {
            String time = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM)
                    .format(new Date(event.time));
            String text = eventLabel(event.status) + " · " + time + "\n" + event.destination;
            if (event.sent > 0)
                text += "\n" + getString(R.string.privacy_network_sent, event.sent);
            if (NetworkApproval.isAsking(mode))
                button(text, () -> showRule(event.key, event.app + "\n" + event.destination));
            else
                note(text);
        }
    }

    private String summarize(List<NetworkApproval.Event> events) {
        if (events == null || events.isEmpty())
            return getString(R.string.privacy_network_no_events);
        long sent = 0;
        for (NetworkApproval.Event event : events)
            sent += event.sent;
        return getString(R.string.privacy_network_summary, events.size(), Formatter.formatShortFileSize(this, sent));
    }

    private ApplicationInfo applicationInfo(String packageName) {
        try {
            return getPackageManager().getApplicationInfo(packageName, 0);
        } catch (PackageManager.NameNotFoundException absent) {
            return null;
        }
    }

    private NetworkApproval.Target targetFor(String packageName) {
        return approval.targetForName(packageName);
    }

    private String packageOf(String key) {
        int separator = key.indexOf('|');
        return separator < 0 ? key : key.substring(0, separator);
    }

    private void chooseApp() {
        List<NetworkApproval.Target> targets = approval.availableTargets();
        if (targets.isEmpty()) {
            new AlertDialog.Builder(this)
                    .setMessage(R.string.privacy_network_no_eligible)
                    .setPositiveButton(android.R.string.ok, null)
                    .show();
            return;
        }
        LinearLayout picker = new LinearLayout(this);
        picker.setOrientation(LinearLayout.VERTICAL);
        int inset = Math.round(16 * getResources().getDisplayMetrics().density);
        picker.setPadding(inset, 0, inset, 0);
        EditText search = new EditText(this);
        search.setSingleLine();
        search.setHint(R.string.privacy_network_search);
        picker.addView(search);
        ListView apps = new ListView(this);
        int height = Math.round(340 * getResources().getDisplayMetrics().density);
        picker.addView(apps, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, height));

        List<NetworkApproval.Target> matches = new ArrayList<>();
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1);
        apps.setAdapter(adapter);
        updateMatches(targets, matches, adapter, "");
        search.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence text, int start, int count, int after) { }
            @Override public void onTextChanged(CharSequence text, int start, int before, int count) {
                updateMatches(targets, matches, adapter, text.toString());
            }
            @Override public void afterTextChanged(Editable text) { }
        });
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(R.string.privacy_network_add)
                .setView(picker)
                .setNegativeButton(android.R.string.cancel, null)
                .create();
        if (dialog.getWindow() != null)
            dialog.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);
        apps.setOnItemClickListener((list, view, position, id) -> {
            dialog.dismiss();
            showPackage(matches.get(position).packageName);
        });
        dialog.show();
    }

    private void updateMatches(List<NetworkApproval.Target> targets, List<NetworkApproval.Target> matches,
                               ArrayAdapter<String> adapter, String input) {
        String term = input.trim().toLowerCase(Locale.ROOT);
        matches.clear();
        adapter.setNotifyOnChange(false);
        adapter.clear();
        for (NetworkApproval.Target target : targets) {
            String label = target.label + "\n" + target.packageName;
            if (label.toLowerCase(Locale.ROOT).contains(term)) {
                matches.add(target);
                adapter.add(label);
            }
        }
        adapter.notifyDataSetChanged();
    }

    private void chooseMode(NetworkApproval.Target target) {
        String[] modes = {NetworkApproval.BLOCK, NetworkApproval.RECORD,
                NetworkApproval.ASK_APP, NetworkApproval.ASK, null};
        new AlertDialog.Builder(this)
                .setTitle(target.label)
                .setItems(new CharSequence[]{
                        getString(R.string.privacy_network_block),
                        getString(R.string.privacy_network_record),
                        getString(R.string.privacy_network_ask_app),
                        getString(R.string.privacy_network_ask),
                        getString(R.string.privacy_network_remove)
                }, (dialog, which) -> {
                    approval.setMode(target.packageName, modes[which]);
                    UnifiedVpnService.policyChanged(this);
                    showPackage(modes[which] == null ? null : target.packageName);
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void showRule(String key, String description) {
        if (key.contains("|0|*|0")) {
            NetworkApproval.Target target = approval.targetForName(packageOf(key));
            description = (target == null ? packageOf(key) : target.label) + "\n此应用的全部联网目标";
        }
        String[] choices = {NetworkApproval.TEMPORARY, NetworkApproval.ALLOW,
                NetworkApproval.DENY, NetworkApproval.FORGET};
        new AlertDialog.Builder(this)
                .setTitle(description)
                .setItems(new CharSequence[]{
                        getString(R.string.privacy_network_temporary),
                        getString(R.string.privacy_network_allow),
                        getString(R.string.privacy_network_deny),
                        getString(R.string.privacy_network_forget)
                }, (dialog, which) -> {
                    if (approval.decide(key, choices[which]))
                        UnifiedVpnService.policyChanged(this);
                    render();
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private String describeKey(String key) {
        String[] parts = key.split("\\|", -1);
        if (parts.length != 4)
            return key;
        if ("*".equals(parts[2]))
            return parts[0] + "\n此应用的全部目标";
        String host = parts[2].indexOf(':') >= 0 ? "[" + parts[2] + "]" : parts[2];
        return parts[0] + "\n" + host + ":" + parts[3] + ("6".equals(parts[1]) ? " / TCP" : " / UDP");
    }

    private String appModeLabel(String mode) {
        if (NetworkApproval.BLOCK.equals(mode))
            return getString(R.string.privacy_network_block);
        if (NetworkApproval.RECORD.equals(mode))
            return getString(R.string.privacy_network_record);
        if (NetworkApproval.ASK.equals(mode))
            return getString(R.string.privacy_network_ask);
        if (NetworkApproval.ASK_APP.equals(mode))
            return getString(R.string.privacy_network_ask_app);
        return getString(R.string.privacy_network_not_monitored);
    }

    private String eventLabel(String mode) {
        if (NetworkApproval.BLOCK.equals(mode))
            return getString(R.string.privacy_network_attempt_blocked);
        if (NetworkApproval.RECORD.equals(mode))
            return getString(R.string.privacy_network_observed);
        if (NetworkApproval.ALLOW.equals(mode))
            return getString(R.string.privacy_network_allow);
        if (NetworkApproval.DENY.equals(mode))
            return getString(R.string.privacy_network_deny);
        if (NetworkApproval.TEMPORARY.equals(mode))
            return getString(R.string.privacy_network_temporary);
        return getString(R.string.privacy_network_pending);
    }

    private void heading(int string) {
        TextView title = new TextView(this);
        title.setText(string);
        title.setTextSize(19);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        title.setPadding(0, 18, 0, 10);
        content.addView(title);
    }

    private void note(String text) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setPadding(0, 6, 0, 8);
        content.addView(view);
    }

    private void button(String text, Runnable action) {
        Button view = new Button(this);
        view.setAllCaps(false);
        view.setText(text);
        view.setOnClickListener(v -> action.run());
        content.addView(view);
    }
}
