package honor.root;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * One-tap log feedback over the corporate IM webhook.
 *
 * Collects (all app-readable, no root required):
 *   run.log / crash.log                - app external files dir
 *   tool.log / last_run.log / su_block.log - device-protected files dir
 *   snapshot.txt                       - device identity + runtime state
 *   logcat.txt                         - tail of `logcat -d`
 *   root_probe.txt                     - su-based probes (skipped without root)
 *
 * Packs everything into one zip and uploads it as an IM file message.
 * The two webhook URLs live in the encrypted asset (name via s(25),
 * decrypted at send time with the same keystream as stageAsset); neither
 * the key nor the host name ever enters dex or .rodata in plaintext.
 */
public final class FeedbackSender {
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static final byte[] MAGIC = {0, 'O', 'B', 'F', 'A', 'S', 1, 0};

    /** stage text + percent; percent < 0 means indeterminate. */
    public interface Progress { void on(String stage, int percent); }
    public interface Done { void on(boolean ok, String msg); }

    private FeedbackSender() {}

    public static void send(Context ctx, Progress progress, Done done) {
        MAIN.post(() -> progress.on("采集日志", -1));
        new Thread(() -> {
            boolean ok = false;
            String msg;
            try {
                File zip = pack(ctx, progress);
                try {
                    MAIN.post(() -> progress.on("上传日志包", 0));
                    upload(ctx, zip, progress);
                    ok = true;
                    msg = "已发送";
                } finally {
                    zip.delete();
                }
            } catch (Throwable e) {
                msg = "发送失败: " + e.getMessage();
            }
            final boolean fok = ok;
            final String fmsg = msg;
            MAIN.post(() -> done.on(fok, fmsg));
        }, "w0").start();
    }

    // ── collect ──────────────────────────────────────────────────────────

    private static File pack(Context ctx, Progress p) throws Exception {
        File out = new File(ctx.getCacheDir(),
                "fb-" + System.currentTimeMillis() + ".zip");
        ZipOutputStream zos = new ZipOutputStream(
                new BufferedOutputStream(new FileOutputStream(out)));
        zos.setLevel(9);
        try {
            Context de = ctx.createDeviceProtectedStorageContext();
            File ext = ctx.getExternalFilesDir(null);
            addFile(zos, "run.log", new File(ext, "run.log"));
            addFile(zos, "crash.log", new File(ext, "crash.log"));
            addFile(zos, "tool.log", new File(de.getFilesDir(), "tool.log"));
            addFile(zos, "trace.log", new File(de.getFilesDir(), "trace.log"));
            addFile(zos, "last_run.log", new File(de.getFilesDir(), "last_run.log"));
            addFile(zos, "su_block.log", new File(de.getFilesDir(), "su_block.log"));
            /* v193: system binary samples for the 6.6.89 trigger analysis -
             * both are world-readable on /system, no root required. Used to
             * diff the hook-site/init paths against the 6.6.118 devices. */
            addFile(zos, "diag_libcxx.so", new File("/system/lib64/libc++.so"));
            addFile(zos, "diag_init", new File("/system/bin/init"));
            MAIN.post(() -> p.on("采集系统快照", -1));
            putEntry(zos, "snapshot.txt",
                    snapshot(ctx).getBytes(StandardCharsets.UTF_8));
            MAIN.post(() -> p.on("采集 logcat", -1));
            putEntry(zos, "logcat.txt",
                    logcatDump().getBytes(StandardCharsets.UTF_8));
            putEntry(zos, "root_probe.txt",
                    rootProbe().getBytes(StandardCharsets.UTF_8));
        } finally {
            zos.close();
        }
        return out;
    }

    private static void addFile(ZipOutputStream zos, String name, File f)
            throws IOException {
        if (f == null || !f.exists() || f.length() == 0) return;
        zos.putNextEntry(new ZipEntry(name));
        try (InputStream in = new BufferedInputStream(new FileInputStream(f))) {
            byte[] b = new byte[16384];
            for (int n; (n = in.read(b)) != -1; ) zos.write(b, 0, n);
        }
        zos.closeEntry();
    }

    private static void putEntry(ZipOutputStream zos, String name, byte[] data)
            throws IOException {
        if (data == null || data.length == 0) return;
        zos.putNextEntry(new ZipEntry(name));
        zos.write(data);
        zos.closeEntry();
    }

    private static String snapshot(Context ctx) {
        StringBuilder s = new StringBuilder();
        s.append("time=").append(
                new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss",
                        java.util.Locale.US).format(new java.util.Date()))
          .append('\n');
        s.append("version=").append(BuildConfig.VERSION_NAME).append('\n');
        s.append("mem_total=").append(firstLines(readText("/proc/meminfo"), 1))
          .append('\n');
        s.append("model=").append(android.os.Build.MODEL).append('\n');
        s.append("device=").append(android.os.Build.DEVICE).append('\n');
        s.append("fingerprint=").append(android.os.Build.FINGERPRINT).append('\n');
        s.append("release=").append(android.os.Build.VERSION.RELEASE).append('\n');
        s.append("sdk=").append(android.os.Build.VERSION.SDK_INT).append('\n');
        s.append("kernel=").append(System.getProperty("os.version")).append('\n');
        s.append("uid=").append(android.os.Process.myUid()).append('\n');
        s.append("boot_id=").append(readText("/proc/sys/kernel/random/boot_id"))
          .append('\n');
        /* v1.5: one-shot ESP-in-UDP encapsulation probe (same as dfprobe).
         * Success means the kernel esp4/xfrm stack is present at all - the
         * exploit's delivery channel cannot exist without it. Read-only,
         * no packet is sent. */
        s.append("esp_probe=").append(espProbe()).append('\n');
        s.append("selinux_enforce=")
          .append(readText("/sys/fs/selinux/enforce")).append('\n');
        String modules = readText(ExploitRunner.s(26));
        s.append("kmodules_readable=").append(!modules.contains("unreadable"))
          .append('\n');
        s.append("ksu_loaded=").append(modules.contains(ExploitRunner.s(27)))
          .append('\n');
        s.append("modules_head=")
          .append(modules.contains("unreadable") ? "(unreadable)"
                  : firstLines(modules, 5)).append('\n');
        /* v1.2: once the daemon finishes it restores SELinux enforcing, and the
         * untrusted_app domain then gets EACCES on /proc/modules - so
         * kernelsu_loaded above reads false even when root is alive and
         * well (seen on-device, boot c1de0ca0). The tool's own verdict line
         * in OUR device-protected files dir is always readable by this app:
         * trust that as the primary liveness signal. */
        String verdict = readText(new File(
                ctx.createDeviceProtectedStorageContext().getFilesDir(),
                "tool.log").getPath());
        s.append("tool_verdict=")
          .append(verdict.contains(ExploitRunner.s(31)) ? "OK"
                : verdict.contains(ExploitRunner.s(32)) ? "FAIL"
                : "absent")
          .append('\n');
        return s.toString();
    }

    private static String firstLines(String text, int n) {
        String[] lines = text.split("\n");
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < n && i < lines.length; i++) s.append(lines[i]).append("; ");
        return s.toString().trim();
    }

    /* v1.5: ESP-in-UDP encapsulation support probe (read-only, no packets).
     * IPPROTO_UDP=17, UDP_ENCAP=100, UDP_ENCAP_ESPINUDP=2. */
    private static String espProbe() {
        try {
            java.io.FileDescriptor fd = android.system.Os.socket(
                    android.system.OsConstants.AF_INET,
                    android.system.OsConstants.SOCK_DGRAM, 17);
            String r;
            try {
                android.system.Os.setsockoptInt(fd, 17, 100, 2);
                r = "OK(esp-in-udp supported)";
            } catch (android.system.ErrnoException ee) {
                r = "NO(UDP_ENCAP errno=" + ee.errno + ")";
            }
            try {
                android.system.Os.close(fd);
            } catch (android.system.ErrnoException ignored) {
            }
            return r;
        } catch (android.system.ErrnoException ee) {
            return "NO(socket errno=" + ee.errno + ")";
        } catch (Throwable t) {
            return "ERR(" + t.getClass().getSimpleName() + ")";
        }
    }

    private static String readText(String path) {
        try (BufferedInputStream in = new BufferedInputStream(
                new FileInputStream(path))) {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] b = new byte[4096];
            for (int n; (n = in.read(b)) != -1; ) bo.write(b, 0, n);
            return bo.toString("UTF-8").trim();
        } catch (Exception e) {
            return "(unreadable)";
        }
    }

    private static String logcatDump() {
        try {
            Process pr = new ProcessBuilder("logcat", "-d", "-t", "6000")
                    .redirectErrorStream(true).start();
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            try (InputStream in = pr.getInputStream()) {
                byte[] b = new byte[8192];
                for (int n; (n = in.read(b)) != -1; ) bo.write(b, 0, n);
            }
            pr.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            return bo.toString("UTF-8");
        } catch (Throwable e) {
            return "(logcat unavailable: " + e + ")";
        }
    }

    /** Best-effort root-side probes; every failure degrades to a note. */
    private static String rootProbe() {
        try {
            Process pr = new ProcessBuilder("su", "-c", ExploitRunner.s(28))
                    .redirectErrorStream(true).start();
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            try (InputStream in = pr.getInputStream()) {
                byte[] b = new byte[8192];
                for (int n; (n = in.read(b)) != -1; ) bo.write(b, 0, n);
            }
            boolean done = pr.waitFor(8, java.util.concurrent.TimeUnit.SECONDS);
            if (!done) {
                pr.destroy();
                return "(probe timeout)";
            }
            return "exit=" + pr.exitValue() + "\n" + bo.toString("UTF-8");
        } catch (Throwable e) {
            return "(su unavailable: " + e + ")";
        }
    }

    // ── upload ───────────────────────────────────────────────────────────

    private static void upload(Context ctx, File zip, Progress p)
            throws Exception {
        String[] urls = webhookUrls(ctx);
        String boundary = "----fb" + Long.toHexString(System.currentTimeMillis());

        // 1) upload_media -> media_id
        HttpURLConnection c = (HttpURLConnection) new URL(urls[0]).openConnection();
        c.setConnectTimeout(15000);
        c.setReadTimeout(30000);
        c.setDoOutput(true);
        c.setRequestProperty("Content-Type",
                "multipart/form-data; boundary=" + boundary);
        long total = Math.max(1, zip.length());
        try (OutputStream os = new BufferedOutputStream(c.getOutputStream())) {
            os.write(("--" + boundary + "\r\n"
                    + "Content-Disposition: form-data; name=\"media\"; filename=\""
                    + zip.getName() + "\"\r\n"
                    + "Content-Type: application/zip\r\n\r\n")
                    .getBytes(StandardCharsets.UTF_8));
            try (InputStream in = new BufferedInputStream(new FileInputStream(zip))) {
                byte[] b = new byte[32768];
                long done = 0;
                for (int n; (n = in.read(b)) != -1; ) {
                    os.write(b, 0, n);
                    done += n;
                    final int pct = (int) (done * 100 / total);
                    MAIN.post(() -> p.on("上传日志包", pct));
                }
            }
            os.write(("\r\n--" + boundary + "--\r\n")
                    .getBytes(StandardCharsets.UTF_8));
        }
        int rc = c.getResponseCode();
        String resp = slurp(rc < 400 ? c.getInputStream() : c.getErrorStream());
        if (rc != 200)
            throw new IOException("upload_media http " + rc + ": " + resp);
        Matcher m = Pattern.compile("\"media_id\"\\s*:\\s*\"([^\"]+)\"")
                .matcher(resp);
        if (!m.find())
            throw new IOException("upload_media no media_id: " + resp);
        String mediaId = m.group(1);

        // 2) send as file message
        HttpURLConnection s = (HttpURLConnection) new URL(urls[1]).openConnection();
        s.setConnectTimeout(15000);
        s.setReadTimeout(30000);
        s.setDoOutput(true);
        s.setRequestProperty("Content-Type", "application/json");
        try (OutputStream os = s.getOutputStream()) {
            os.write(("{\"msgtype\":\"file\",\"file\":{\"media_id\":\""
                    + mediaId + "\"}}").getBytes(StandardCharsets.UTF_8));
        }
        int rc2 = s.getResponseCode();
        String resp2 = slurp(rc2 < 400 ? s.getInputStream() : s.getErrorStream());
        if (rc2 != 200 || !Pattern.compile("\"errcode\"\\s*:\\s*0")
                .matcher(resp2).find())
            throw new IOException("send http " + rc2 + ": " + resp2);
    }

    private static String slurp(InputStream in) throws IOException {
        if (in == null) return "(no body)";
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] b = new byte[8192];
        for (int n; (n = in.read(b)) != -1; ) bo.write(b, 0, Math.min(n, 4096));
        return bo.toString("UTF-8").trim();
    }

    /** Reads the two webhook URLs from the encrypted asset named s(25).
     *  Same decryption as stageAsset: ASSET_MAGIC header + native ks(). */
    private static String[] webhookUrls(Context ctx) throws Exception {
        InputStream in = ctx.getAssets().open(ExploitRunner.s(25));
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] b = new byte[8192];
        for (int n; (n = in.read(b)) != -1; ) bo.write(b, 0, n);
        in.close();
        byte[] d = bo.toByteArray();
        boolean enc = d.length > 8;
        for (int i = 0; enc && i < 8; i++) enc = d[i] == MAGIC[i];
        if (enc) {
            byte[] ks = ExploitRunner.ks();
            byte[] out = new byte[d.length - 8];
            for (int i = 0; i < out.length; i++)
                out[i] = (byte) (d[i + 8] ^ ks[i % ks.length]);
            d = out;
        }
        String s = new String(d, StandardCharsets.UTF_8).trim();
        String[] lines = s.split("\n");
        if (lines.length < 2 || !lines[0].startsWith("https://")
                || !lines[1].startsWith("https://"))
            throw new IOException("asset invalid");
        lines[0] = lines[0].trim();
        lines[1] = lines[1].trim();
        return lines;
    }
}
