package com.system.uitest;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Session log written to /sdcard/exp.log.
 *
 * The in-app log view only ever shows a filtered subset (progress steps and
 * synthesised failures), which is useless when the chain dies somewhere the UI
 * does not model. This writes every raw line instead: native stdout/stderr,
 * stage markers, exit codes, timings, exceptions with stacks.
 *
 * /sdcard needs MANAGE_EXTERNAL_STORAGE on API 30+; if that has not been
 * granted yet the writers below silently fall back to the app's external files
 * dir and then to internal storage, and {@link #path()} reports which one won.
 */
public final class DfLog {
    private static final Object LOCK = new Object();
    private static final String PRIMARY = "/sdcard/exp.log";
    private static final SimpleDateFormat TS =
            new SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US);

    private static File sFile;
    private static boolean sReady;

    private DfLog() {}

    /** Must be called before anything else in onCreate. */
    public static void init(Context ctx) {
        synchronized (LOCK) {
            File[] candidates = {
                    new File(PRIMARY),
                    new File(ctx.getExternalFilesDir(null), "exp.log"),
                    new File(ctx.getFilesDir(), "exp.log"),
            };
            for (File f : candidates) {
                try {
                    File parent = f.getParentFile();
                    if (parent != null && !parent.exists()) parent.mkdirs();
                    FileWriter w = new FileWriter(f, true);
                    w.write("\n===== session " + new Date() + " (" + BuildInfo() + ") =====\n");
                    w.flush();
                    w.close();
                    sFile = f;
                    sReady = true;
                    Log.i("DfLog", "logging to " + f.getAbsolutePath());
                    return;
                } catch (Throwable t) {
                    Log.w("DfLog", "cannot write " + f + ": " + t);
                }
            }
            sReady = false;
        }
    }

    private static String BuildInfo() {
        return android.os.Build.MANUFACTURER + " " + android.os.Build.MODEL
                + " / android " + android.os.Build.VERSION.RELEASE
                + " / " + System.getProperty("os.version");
    }

    public static String path() {
        return sFile != null ? sFile.getAbsolutePath() : "(no writable log file)";
    }

    /** Logs verbatim, one timestamped line per input line. */
    public static void raw(String tag, String msg) {
        if (msg == null) return;
        try {
            Log.i(tag, msg.trim());
        } catch (Throwable ignored) {}
        write(tag, msg);
    }

    public static void w(String tag, String msg) {
        raw(tag, msg);
    }

    public static void e(String tag, String msg, Throwable t) {
        try {
            Log.e(tag, msg, t);
        } catch (Throwable ignored) {}
        StringBuilder sb = new StringBuilder(msg);
        if (t != null) sb.append('\n').append(Log.getStackTraceString(t));
        write(tag, sb.toString());
    }

    private static void write(String tag, String msg) {
        synchronized (LOCK) {
            if (!sReady || sFile == null) return;
            try {
                FileWriter w = new FileWriter(sFile, true);
                String head = "[" + TS.format(new Date()) + "]["
                        + Thread.currentThread().getName() + "][" + tag + "] ";
                StringBuilder sb = new StringBuilder();
                for (String line : msg.split("\n", -1)) {
                    sb.append(head).append(line).append('\n');
                }
                w.write(sb.toString());
                w.flush();
                w.close();
            } catch (Throwable ignored) {
            }
        }
    }
}
