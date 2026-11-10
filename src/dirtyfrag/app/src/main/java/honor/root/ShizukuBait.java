package honor.root;

import android.content.ComponentName;
import android.content.ServiceConnection;
import android.content.Context;
import android.os.IBinder;

import java.io.File;
import java.io.FileOutputStream;

import rikka.shizuku.Shizuku;

/**
 * v210: Shizuku bait + adb-fire layer.
 *
 * pullExpCli(): copy the bundled exp_cli binary from the app's native lib
 * dir into an app-writable location, then (via the UserService shell) place
 * it at /data/local/tmp with exec permissions.
 *
 * fireViaAdb(): run the full exploit as the SHELL DOMAIN by executing
 * /data/local/tmp/exp_cli through the Shizuku service. The shell domain has
 * a completely different SELinux context than untrusted_app - the field
 * experiment decides which generation/context hits faster.
 */
public class ShizukuBait {

    public static final String REQ_PERMISSION_CODE = "honor.root.shizuku.bait";
    private static final int USER_SERVICE_VERSION = 2;
    private static IUserService sService;
    private static ServiceConnection sConn;

    public static boolean isAvailable() {
        try { return Shizuku.pingBinder(); } catch (Throwable t) { return false; }
    }

    public static boolean hasPermission() {
        try { return Shizuku.checkSelfPermission() == 0; } catch (Throwable t) { return false; }
    }

    public static void requestPermission() {
        try { Shizuku.requestPermission(0); } catch (Throwable ignored) {}
    }

    public static void bind(Context ctx, final Runnable onReady) {
        if (!isAvailable() || !hasPermission()) return;
        Shizuku.UserServiceArgs args = new Shizuku.UserServiceArgs(
                new ComponentName(ctx, UserService.class))
                .processNameSuffix("bait")
                .tag("df_bait")
                .version(USER_SERVICE_VERSION);
        sConn = new ServiceConnection() {
            @Override public void onServiceConnected(ComponentName name, IBinder binder) {
                sService = IUserService.Stub.asInterface(binder);
                if (onReady != null) onReady.run();
            }
            @Override public void onServiceDisconnected(ComponentName name) { sService = null; }
        };
        try { Shizuku.bindUserService(args, sConn); } catch (Throwable ignored) {}
    }

    private static boolean ready() { return sService != null; }

    /** Stage the exp_cli binary: copy from the app native lib dir (as
     *  libexpcli.so, extracted by the system) to /data/local/tmp/exp_cli
     *  with 0755. Must be called after bind() - runs in the shell domain. */
    public static String pullExpCli(Context ctx) {
        File src = new File(ctx.getApplicationInfo().nativeLibraryDir, "libexpcli.so");
        if (!src.exists()) return "ERR: libexpcli.so not found in nativeLibraryDir";
        String cmd = "cp '" + src.getAbsolutePath() + "' /data/local/tmp/exp_cli"
                + " && chmod 755 /data/local/tmp/exp_cli && ls -la /data/local/tmp/exp_cli";
        return sh(cmd);
    }

    /** Fire the whole exploit as the SHELL DOMAIN. full log returned. */
    public static String fireViaAdb(String args) {
        return sh("/data/local/tmp/exp_cli " + args + " 2>&1");
    }

    /** Bait: orphan spawn cycle through the shell domain. */
    public static String fireOrphans(int count) {
        if (!ready()) return "service not bound";
        try { return sService.spawnOrphans(count); } catch (Throwable t) { return "ERR:" + t; }
    }

    /** Raw shell command. */
    public static String sh(String cmd) {
        if (!ready()) return "service not bound";
        try { return sService.runShell(cmd); } catch (Throwable t) { return "ERR:" + t; }
    }
}
