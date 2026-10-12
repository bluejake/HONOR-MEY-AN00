package honor.root;

import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.PowerManager;
import android.util.Log;

import java.io.File;

/**
 * v18: boot-time auto-root via the WATCHDOG, not a single run.
 * Old behavior (single ExploitRunner.run + fail-self-disable) is gone:
 * the watchdog already contains 5s witnessing, ~3min zero-gap re-poison
 * rounds and an 8h limit - strictly stronger than one boot-time shot,
 * and a failed round no longer disarms future attempts.
 * Gates kept: already-rooted skip, valid license required.
 */
public class BootReceiver extends BroadcastReceiver implements IReporter {
    private static final String TAG = "honorroot";

    @Override
    public void report(String msg) {
        Log.i(TAG, msg.trim());
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        if (new File(ExploitRunner.s(21)).exists()) {
            Log.i(TAG, "boot: already hooked, skipping");
            return;
        }
        Log.i(TAG, "boot: " + intent.getAction());
        final Context deCtx = context.createDeviceProtectedStorageContext();
        String licStr = LicenseManager.findValidLicense(deCtx);
        if (licStr == null) {
            Log.i(TAG, "boot: not licensed - autorun skipped");
            return;
        }
        try {
            byte[] fp = LicenseManager.certFingerprint(deCtx);
            if (fp == null) {
                Log.i(TAG, "boot: cert fingerprint unavailable - autorun skipped");
                return;
            }
            ExploitRunner.setLicense(
                    android.util.Base64.decode(licStr, android.util.Base64.DEFAULT), fp);
        } catch (Exception e) {
            Log.i(TAG, "boot: license decode failed - autorun skipped");
            return;
        }
        try {
            context.startForegroundService(new Intent(context, WatchService.class));
            Log.i(TAG, "boot: watchdog started");
        } catch (Throwable t) {
            Log.e(TAG, "boot: watchdog start failed", t);
        }
    }
}