package com.system.uitest;

import android.content.Context;

/**
 * Legacy root gatekeeper.
 *
 * The old design staged dfsud/dfinject out of assets and started a root
 * daemon behind /dev/khack.  With the binfmt hook the kernel hands root to
 * a whitelisted "su" at execve time, so there is nothing to extract, no
 * daemon to start and no /dev/khack to open.  Kept as a no-op so existing
 * call sites keep compiling.
 */
public final class RootManager {

    private RootManager() {
    }

    public static synchronized void onRooted(final Context ctx) {
        /* nothing to do */
    }
}
