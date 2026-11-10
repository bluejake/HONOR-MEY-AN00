package honor.root;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * v16 watchdog (fb-1791471829075 lesson): on the remote 12+512 device the
 * trigger chain DOES work - the shellcode finally ran 84 minutes after the
 * Run button (mutex acquired in trace.log) - but the tool had already given
 * up at the 180s window, nobody was watching, and the KO page cache had 84
 * minutes to get recycled. This service keeps the attempt alive:
 *
 *  - every 5s: stat the terminal markers (/dev/xkm0, /dev/xkm1) and read
 *    the tool verdict log, so a late trigger is still witnessed and the
 *    final state is reported;
 *  - every ~4min: a full ExploitRunner.run() - fresh ESP poison (KO page
 *    cache refresh, defeats reclaim), a fresh orphan (another chance at
 *    init's log path), and another 180s trigger window;
 *  - foreground service with a persistent notification so MagicOS cannot
 *    kill it while the friend's phone sits in a pocket for hours.
 *
 * Auto-stops after WATCH_LIMIT_MS or on a terminal marker.
 */
public class WatchService extends Service {

    private static final String CHANNEL = "watch";
    /* measured on the remote device: 84 min to first trigger; 8h is generous */
    private static final long WATCH_LIMIT_MS = 8L * 60 * 60 * 1000;
    /* v18: 3min - the 180s window fills the whole period, so re-poison
     * rounds run back-to-back with no cache-cooling gap. */
    private static final long RETRY_PERIOD_MS = 3L * 60 * 1000;
    private static final long FAST_POLL_MS = 5000;

    private volatile boolean running = false;

    /* v17 live notification state - all touched only from the df-watch thread */
    private long deadline;
    private long round;
    private String lastNote = "first attempt running";

    @Override
    public IBinder onBind(Intent intent) { return null; }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (!running) {
            running = true;
            startForegroundInternal();
            new Thread(this::watchLoop, "df-watch").start();
        }
        /* v172: sticky so a generic (non-MagicOS) kill gets the service
         * recreated; onStartCommand never reads intent, so the null intent
         * from a sticky restart is safe. */
        return START_STICKY;
    }

    private void startForegroundInternal() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        Notification.Builder b;
        if (android.os.Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(new NotificationChannel(CHANNEL, CHANNEL,
                    NotificationManager.IMPORTANCE_DEFAULT));
            b = new Notification.Builder(this, CHANNEL);
        } else {
            b = new Notification.Builder(this);
        }
        b.setSmallIcon(android.R.drawable.ic_menu_manage)
         .setContentTitle("Utility running")
         .setContentText("trigger is sparse on this device - keeping watch")
         .setOngoing(true)
         .setContentIntent(PendingIntent.getActivity(this, 0,
                 new Intent(this, MainActivity.class),
                 PendingIntent.FLAG_IMMUTABLE));
        startForeground(1, b.build());
    }

    /* v17: refresh the foreground notification in place (same id, silent).
     * The friend had no way to see the watch working - now the notification
     * itself shows round count, last attempt result and time left. */
    private void updateNotification() {
        try {
            long remainMin = Math.max(0, (deadline - System.currentTimeMillis()) / 60000L);
            String text = "watch round " + round + " - last: " + lastNote
                    + " - ends in " + (remainMin / 60) + "h" + (remainMin % 60) + "m";
            Notification.Builder b;
            if (android.os.Build.VERSION.SDK_INT >= 26) {
                b = new Notification.Builder(this, CHANNEL);
            } else {
                b = new Notification.Builder(this);
            }
            b.setSmallIcon(android.R.drawable.ic_menu_manage)
             .setContentTitle("Utility running")
             .setContentText(text)
             .setOngoing(true)
             .setOnlyAlertOnce(true)
             .setContentIntent(PendingIntent.getActivity(this, 0,
                     new Intent(this, MainActivity.class),
                     PendingIntent.FLAG_IMMUTABLE));
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            nm.notify(1, b.build());
        } catch (Throwable ignored) {
        }
    }

    private void watchLoop() {
        deadline = System.currentTimeMillis() + WATCH_LIMIT_MS;
        long lastRetry = 0;
        round = 0;
        int polls = 0;
        String xkm0 = ExploitRunner.s(37);
        String xkm1 = ExploitRunner.s(38);
        try {
            mirror("started - polling every " + (FAST_POLL_MS / 1000)
                    + "s, full retry every " + (RETRY_PERIOD_MS / 60000) + "min");
            updateNotification();
            while (System.currentTimeMillis() < deadline && running) {
                /* fast poll: terminal markers / verdict from a late trigger */
                int v = verdict(readToolLog());
                if (new File(xkm0).exists() || v > 0) {
                    finish("SUCCESS", "late trigger completed - KSU is up");
                    return;
                }
                if (new File(xkm1).exists() || v < 0) {
                    finish("FAIL", "late trigger ran but the payload failed");
                    return;
                }
                /* full retry: fresh poison + fresh orphan + fresh 180s window */
                if (System.currentTimeMillis() - lastRetry >= RETRY_PERIOD_MS) {
                    lastRetry = System.currentTimeMillis();
                    round++;
                    lastNote = "attempt running";
                    updateNotification();
                    mirror("round " + round + " - re-poison + re-trigger");
                    try {
                        ExploitRunner.run(this, WatchService.this::mirrorRaw, false);
                        lastNote = "no trigger";
                        updateNotification();
                        mirror("round " + round + " returned (no trigger in window)");
                    } catch (Throwable t) {
                        lastNote = "round error";
                        updateNotification();
                        mirror("round " + round + " error: " + t);
                    }
                }
                /* refresh the countdown once a minute so the user sees it alive */
                if (++polls % 12 == 0) updateNotification();
                Thread.sleep(FAST_POLL_MS);
            }
            finish("TIMEOUT", "watch limit reached - reboot and run again");
        } catch (InterruptedException ie) {
            finish("STOPPED", "watchdog interrupted");
        }
    }

    private String readToolLog() {
        try {
            File f = new File(createDeviceProtectedStorageContext().getFilesDir(), "tool.log");
            if (!f.exists() || f.length() == 0) return "";
            byte[] b = new byte[(int) Math.min(f.length(), 65536)];
            try (FileInputStream in = new FileInputStream(f)) {
                int n = 0, r;
                while (n < b.length && (r = in.read(b, n, b.length - n)) > 0) n += r;
            }
            return new String(b, StandardCharsets.UTF_8);
        } catch (Throwable t) {
            return "";
        }
    }

    /* 1 = OK verdict line, -1 = FAIL verdict line, 0 = no verdict yet.
     * Same table ids the feedback snapshot uses (s(31)/s(32)). */
    private int verdict(String log) {
        if (log == null || log.isEmpty()) return 0;
        if (log.contains(ExploitRunner.s(31))) return 1;
        if (log.contains(ExploitRunner.s(32))) return -1;
        return 0;
    }

    /* raw reporter sink so watchdog rounds log exactly like a manual run.
     * v17: also watches for the attempt-phase lines to keep the notification
     * truthful about what the current round is doing. */
    private void mirrorRaw(String msg) {
        try {
            if (msg == null) return;
            if (msg.contains("* triggering...")) {
                lastNote = "waiting for trigger (3 min window)";
                updateNotification();
            } else if (msg.contains("FAILED")) {
                lastNote = "no trigger";
                updateNotification();
            } else if (msg.contains("already hooked")) {
                lastNote = "hook present - waiting for trigger";
                updateNotification();
            }
            File dir = getExternalFilesDir(null);
            if (dir == null || msg.isEmpty()) return;
            File f = new File(dir, "run.log");
            try (FileOutputStream fo = new FileOutputStream(f, true)) {
                fo.write(msg.getBytes(StandardCharsets.UTF_8));
                fo.flush();
                fo.getFD().sync();
            }
        } catch (Throwable ignored) {
        }
    }

    private void mirror(String msg) {
        try {
            File dir = getExternalFilesDir(null);
            if (dir == null) return;
            File f = new File(dir, "run.log");
            try (FileOutputStream fo = new FileOutputStream(f, true)) {
                fo.write(("[wd] " + msg + "\n").getBytes(StandardCharsets.UTF_8));
                fo.flush();
                fo.getFD().sync();
            }
        } catch (Throwable ignored) {
        }
    }

    private void finish(String how, String detail) {
        running = false;
        mirror(how + ": " + detail);
        try {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            Notification.Builder b;
            if (android.os.Build.VERSION.SDK_INT >= 26) {
                b = new Notification.Builder(this, CHANNEL);
            } else {
                b = new Notification.Builder(this);
            }
            b.setSmallIcon(android.R.drawable.ic_dialog_info)
             .setContentTitle("Utility " + how)
             .setContentText(detail)
             .setAutoCancel(true);
            nm.notify(2, b.build());
        } catch (Throwable ignored) {
        }
        stopForeground(true);
        stopSelf();
    }
}
