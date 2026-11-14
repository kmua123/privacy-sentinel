package eu.faircode.netguard;

/* SPDX-License-Identifier: GPL-3.0-or-later */

import android.os.Bundle;
import android.text.util.Linkify;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Offline privacy and third-party notices, shipped with every public APK. */
public final class ActivityPublicInfo extends AppCompatActivity {
    private TextView document;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle(R.string.public_info_title);
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        int padding = Math.round(16 * getResources().getDisplayMetrics().density);
        ViewCompat.setOnApplyWindowInsetsListener(page, (view, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars()
                    | WindowInsetsCompat.Type.displayCutout());
            view.setPadding(padding + bars.left, padding + bars.top, padding + bars.right, bars.bottom);
            return WindowInsetsCompat.CONSUMED;
        });
        Button privacy = new Button(this);
        privacy.setText(R.string.public_info_privacy);
        privacy.setOnClickListener(view -> showDocument("privacy.md"));
        page.addView(privacy);
        Button licenses = new Button(this);
        licenses.setText(R.string.public_info_licenses);
        licenses.setOnClickListener(view -> selectLicense());
        page.addView(licenses);
        ScrollView scroll = new ScrollView(this);
        document = new TextView(this);
        document.setTextSize(14);
        document.setTextIsSelectable(true);
        document.setAutoLinkMask(Linkify.WEB_URLS);
        document.setPadding(0, padding, 0, padding);
        scroll.addView(document);
        page.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(page);
        showDocument("privacy.md");
    }

    private void selectLicense() {
        try {
            List<String> names = new ArrayList<>();
            collect("third_party", names, 0);
            Collections.sort(names);
            new AlertDialog.Builder(this).setTitle(R.string.public_info_licenses)
                    .setItems(names.toArray(new String[0]), (dialog, which) -> showDocument(names.get(which)))
                    .setNegativeButton(android.R.string.cancel, null).show();
        } catch (Exception failure) {
            document.setText(R.string.public_info_failed);
        }
    }

    private void collect(String directory, List<String> result, int depth) throws Exception {
        if (depth > 6)
            return;
        String[] entries = getAssets().list(directory);
        if (entries == null)
            return;
        for (String entry : entries) {
            String path = directory + "/" + entry;
            String[] children = getAssets().list(path);
            if (children != null && children.length > 0)
                collect(path, result, depth + 1);
            else
                result.add(path);
        }
    }

    private void showDocument(String path) {
        if (!"privacy.md".equals(path) && (!path.startsWith("third_party/") || path.contains("..")))
            return;
        try (InputStream input = getAssets().open(path)) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (bytes.size() + count > 512 * 1024)
                    throw new java.io.IOException("Document exceeds size limit");
                bytes.write(buffer, 0, count);
            }
            document.setText(new String(bytes.toByteArray(), StandardCharsets.UTF_8));
        } catch (Exception failure) {
            document.setText(R.string.public_info_failed);
        }
    }

    @Override public boolean onSupportNavigateUp() { finish(); return true; }
}
