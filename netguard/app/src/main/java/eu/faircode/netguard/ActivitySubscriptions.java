package eu.faircode.netguard;

/* SPDX-License-Identifier: GPL-3.0-or-later */

import android.os.Bundle;
import android.text.InputType;
import android.text.method.PasswordTransformationMethod;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Subscription addresses stay in app-private storage and are never displayed in the list. */
public final class ActivitySubscriptions extends AppCompatActivity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final List<Button> actions = new ArrayList<>();
    private NetworkConfig config;
    private EditText name;
    private EditText address;
    private TextView status;
    private LinearLayout list;
    private boolean working;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle(R.string.subscriptions_title);
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }
        config = new NetworkConfig(this);
        ScrollView scroll = new ScrollView(this);
        scroll.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(18), dp(12), dp(18), dp(24));
        scroll.addView(page);
        ViewCompat.setOnApplyWindowInsetsListener(scroll, (view, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars()
                    | WindowInsetsCompat.Type.displayCutout());
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return WindowInsetsCompat.CONSUMED;
        });
        text(page, getString(R.string.subscriptions_description));
        text(page, getString(R.string.subscriptions_name));
        name = new EditText(this);
        name.setSingleLine(true);
        name.setInputType(InputType.TYPE_CLASS_TEXT);
        page.addView(name);
        text(page, getString(R.string.unified_subscription_address));
        address = new EditText(this);
        address.setSingleLine(true);
        address.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        address.setTransformationMethod(PasswordTransformationMethod.getInstance());
        address.setSaveEnabled(false);
        page.addView(address);
        button(page, R.string.subscriptions_save, () -> save(false));
        button(page, R.string.subscriptions_save_use, () -> save(true));
        status = text(page, "");
        list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        page.addView(list);
        setContentView(scroll);
        refresh();
    }

    private void save(boolean activate) {
        final String label = name.getText().toString().trim();
        final String url = address.getText().toString().trim();
        runWork(() -> {
            String id = config.saveSubscription(label, url);
            if (activate)
                config.activateSubscription(id);
        }, () -> {
            name.setText("");
            address.setText("");
            status.setText(activate ? R.string.subscriptions_activated : R.string.subscriptions_saved);
            refresh();
        });
    }

    private void refresh() {
        // Local metadata only; downloading and profile activation always run on worker.
        try {
            List<NetworkConfig.Subscription> entries = config.listSubscriptions();
            list.removeAllViews();
            // Preserve the two add buttons; discard controls belonging to old rows.
            while (actions.size() > 2)
                actions.remove(actions.size() - 1);
            if (entries.isEmpty())
                text(list, getString(R.string.subscriptions_empty));
            for (NetworkConfig.Subscription entry : entries) {
                LinearLayout row = new LinearLayout(this);
                row.setOrientation(LinearLayout.VERTICAL);
                row.setPadding(0, dp(18), 0, dp(12));
                list.addView(row);
                TextView title = text(row, entry.name);
                title.setTextSize(19);
                text(row, getString(entry.active ? R.string.subscriptions_current : R.string.subscriptions_inactive)
                        + " · " + getString(entry.cached ? R.string.subscriptions_cached : R.string.subscriptions_uncached));
                Button use = button(row, R.string.subscriptions_use,
                        () -> runWork(() -> config.activateSubscription(entry.id), () -> {
                            status.setText(R.string.subscriptions_activated);
                            refresh();
                        }));
                use.setEnabled(!entry.active);
                if (!entry.url.isEmpty())
                    button(row, R.string.subscriptions_refresh_use,
                            () -> runWork(() -> config.refreshSubscription(entry.url), () -> {
                                status.setText(R.string.subscriptions_updated);
                                refresh();
                            }));
                if (!entry.url.isEmpty()) {
                    Button remove = button(row, R.string.subscriptions_remove, () ->
                            new AlertDialog.Builder(this).setTitle(R.string.subscriptions_remove)
                                    .setMessage(getString(R.string.subscriptions_remove_confirm, entry.name))
                                    .setNegativeButton(android.R.string.cancel, null)
                                    .setPositiveButton(android.R.string.ok, (dialog, which) ->
                                            runWork(() -> config.removeSubscription(entry.id), this::refresh)).show());
                    remove.setEnabled(!entry.active);
                } else
                    text(row, getString(R.string.subscriptions_local_note));
            }
        } catch (Exception failure) {
            status.setText(R.string.subscriptions_failed);
        }
    }

    private interface Work { void run() throws Exception; }

    private void runWork(Work task, Runnable success) {
        if (working)
            return;
        working = true;
        for (Button button : actions)
            button.setEnabled(false);
        name.setEnabled(false);
        address.setEnabled(false);
        status.setText(R.string.unified_working);
        worker.execute(() -> {
            boolean completed = false;
            try {
                task.run();
                completed = true;
            } catch (Exception ignored) {
                // Connection and parser exceptions may contain subscription credentials.
            }
            final boolean ok = completed;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed())
                    return;
                working = false;
                name.setEnabled(true);
                address.setEnabled(true);
                for (Button button : actions)
                    button.setEnabled(true);
                refresh();
                if (ok)
                    success.run();
                else
                    status.setText(R.string.subscriptions_failed);
            });
        });
    }

    private TextView text(LinearLayout parent, String value) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(15);
        view.setPadding(0, dp(6), 0, dp(6));
        parent.addView(view);
        return view;
    }

    private Button button(LinearLayout parent, int label, Runnable action) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false);
        button.setOnClickListener(view -> action.run());
        parent.addView(button, new LinearLayout.LayoutParams(-1, -2));
        actions.add(button);
        return button;
    }

    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }

    @Override public boolean onSupportNavigateUp() { finish(); return true; }

    @Override protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }
}
