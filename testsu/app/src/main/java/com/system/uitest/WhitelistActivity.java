package com.system.uitest;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Root whitelist: the dfsud gatekeeper only answers uids listed in
 * files/whitelist.txt (one "uid package" per line).  Everything else is dropped
 * silently, so a probing app cannot tell "denied" from "no su here".
 */
public class WhitelistActivity extends Activity {

    private final Map<Integer, String> selected = new LinkedHashMap<>();
    private File whitelistFile;
    private TextView status;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        whitelistFile = new File(getFilesDir(), "whitelist.txt");
        ensureDefaults();
        loadWhitelist();

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFF101014);
        int pad = dp(16);
        root.setPadding(pad, pad, pad, 0);

        TextView title = new TextView(this);
        title.setText("Root 白名单");
        title.setTextColor(0xFFEDEDED);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 22);
        root.addView(title);

        status = new TextView(this);
        status.setTextColor(0xFF9A9AA2);
        status.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        status.setPadding(0, dp(6), 0, dp(10));
        root.addView(status);

        ScrollView scroll = new ScrollView(this);
        LinearLayout list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        scroll.addView(list);
        root.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        List<ApplicationInfo> apps = new ArrayList<>();
        PackageManager pm = getPackageManager();
        for (ApplicationInfo ai : pm.getInstalledApplications(0)) {
            if (ai.packageName.equals(getPackageName())) continue;
            if (pm.getLaunchIntentForPackage(ai.packageName) == null) continue;
            apps.add(ai);
        }
        apps.sort((a, b) -> String.valueOf(a.loadLabel(pm))
                .compareToIgnoreCase(String.valueOf(b.loadLabel(pm))));

        for (ApplicationInfo ai : apps) {
            final int uid = ai.uid;
            final String pkg = ai.packageName;

            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(0, dp(10), 0, dp(10));

            CheckBox cb = new CheckBox(this);
            cb.setChecked(selected.containsKey(uid));
            cb.setOnCheckedChangeListener((b, checked) -> {
                if (checked) selected.put(uid, pkg);
                else selected.remove(uid);
                saveWhitelist();
                relaxPermissions();
            });
            row.addView(cb);

            LinearLayout texts = new LinearLayout(this);
            texts.setOrientation(LinearLayout.VERTICAL);
            TextView name = new TextView(this);
            name.setText(String.valueOf(ai.loadLabel(pm)));
            name.setTextColor(0xFFEDEDED);
            name.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
            TextView sub = new TextView(this);
            sub.setText(pkg + "  ·  uid " + uid);
            sub.setTextColor(0xFF7E7E88);
            sub.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
            texts.addView(name);
            texts.addView(sub);
            LinearLayout.LayoutParams tlp = new LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
            row.addView(texts, tlp);

            View divider = new View(this);
            GradientDrawable g = new GradientDrawable();
            g.setColor(0xFF23232A);
            divider.setBackground(g);

            list.addView(row, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            list.addView(divider, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, dp(1) / 2)));
        }

        setContentView(root);
        updateStatus();
    }

    /** Packages granted root out of the box; uids are resolved at runtime
     *  because they change with every install. */
    private static final String[] DEFAULT_PACKAGES = {
            "com.system.uitest",
            "com.termux",
            "bin.mt.plus",
            "moe.shizuku.privileged.api",
    };

    private void ensureDefaults() {
        if (whitelistFile.exists() && whitelistFile.length() > 0) return;
        StringBuilder sb = new StringBuilder();
        for (String pkg : DEFAULT_PACKAGES) {
            try {
                int uid = getPackageManager().getApplicationInfo(pkg, 0).uid;
                sb.append(uid).append(' ').append(pkg).append('\n');
            } catch (android.content.pm.PackageManager.NameNotFoundException ignored) {
                /* not installed: skip it */
            }
        }
        try (FileWriter w = new FileWriter(whitelistFile, false)) {
            w.write(sb.toString());
        } catch (Exception ignored) {
        }
        relaxPermissions();
    }

    /** The kernel reads this file from arbitrary task contexts, so it has to be
     *  readable by any uid; the contents are just uid/package pairs. */
    private void relaxPermissions() {
        //noinspection ResultOfMethodCallIgnored
        whitelistFile.setReadable(true, false);
    }

    private void loadWhitelist() {
        if (!whitelistFile.exists()) return;
        try (BufferedReader r = new BufferedReader(new FileReader(whitelistFile))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] parts = line.split("\\s+");
                try {
                    int uid = Integer.parseInt(parts[0]);
                    selected.put(uid, parts.length > 1 ? parts[1] : "");
                } catch (NumberFormatException ignored) {
                }
            }
        } catch (IOException ignored) {
        }
    }

    private void saveWhitelist() {
        try (FileWriter w = new FileWriter(whitelistFile, false)) {
            for (Map.Entry<Integer, String> e : selected.entrySet())
                w.write(e.getKey() + " " + e.getValue() + "\n");
            w.flush();
        } catch (IOException ignored) {
        }
        updateStatus();
    }

    private void updateStatus() {
        if (status == null) return;
        status.setText(selected.isEmpty()
                ? "当前没有任何应用被允许（su 对所有应用静默无响应）"
                : "已允许 " + selected.size() + " 个应用");
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density);
    }
}
