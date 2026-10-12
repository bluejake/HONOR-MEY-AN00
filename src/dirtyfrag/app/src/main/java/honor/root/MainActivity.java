package honor.root;

import android.content.Context;
import android.content.ComponentName;
import android.content.ContentValues;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.MediaStore;
import android.text.SpannableString;
import android.text.style.ForegroundColorSpan;
import android.text.style.RelativeSizeSpan;
import android.text.style.StyleSpan;
import android.util.Log;
import android.view.HapticFeedbackConstants;
import android.view.MotionEvent;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;
import androidx.core.content.res.ResourcesCompat;

import androidx.appcompat.app.AppCompatActivity;

import honor.root.databinding.ActivityMainBinding;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity implements IReporter {

    private static final String TAG = "honorroot";

    private ActivityMainBinding binding;
    private final Handler mMain = new Handler(Looper.getMainLooper());
    private final Executor mExec = Executors.newSingleThreadExecutor();
    private final StringBuilder logBuffer = new StringBuilder();
    private File lastLogFile;
    private boolean running;
    private boolean runArmed;
    private boolean expertMode;
    private String exploitPhase = "";
    private boolean watchdogTookOver;
    private int cleanupSteps;
    private float seg1;
    /* v181: live ticking during the 180s trigger wait - without this the
     * bar freezes at 85% and users read it as a hang ("卡在85%"). */
    private final android.os.Handler uiHandler =
            new android.os.Handler(android.os.Looper.getMainLooper());
    private Runnable triggerWaitTicker;
    private long triggerStartMs;
    private float pillPercent = 0.48f;
    private VersionPillSpan pillSpan;
    private TextView titleView;
    private boolean updateAvailable;
    private boolean moduleRefresh;
    private boolean licensed;

    @Override
    public void report(String msg) {
        Log.i(TAG, msg.trim());
        /* v13: wall-clock prefix per line - lets a feedback zip show HOW LONG
         * each stage took and whether the run.log went silent mid-window
         * (reporter chain died) vs the run still being in progress. */
        String stamped = "[" + new java.text.SimpleDateFormat("HH:mm:ss",
                java.util.Locale.US).format(new java.util.Date()) + "] " + msg;
        /* MEY: logcat 缓冲区会在 reboot 时清空，而 exploit 恰恰是会触发重启的
         * 那一步 —— 崩溃类实验等于永远看不到最后几行。这里把每一行同步追加到
         * shell 可读的 external files 目录（O_APPEND + fsync），重启后仍可
         * `adb shell cat` 取回，作为独立于 logcat 的第二个观测透镜。 */
        mirrorRunLog(stamped);
        mMain.post(() -> {
            // Drive the two-step progress bar from the raw (unfiltered) lines.
            for (String line : msg.split("\n", -1)) {
                driveProgress(line.trim());
            }
            for (String line : msg.split("\n", -1)) {
                String t = line.trim();
                // Skip empty lines to keep the log compact.
                if (t.isEmpty()) {
                    continue;
                }
                // Drop byte-progress counters ("0 ?", "512 ?", ...).
                if (t.matches("\\d+\\s*(\\u2026|\\.{3})?")) {
                    continue;
                }
                // Drop internal patch/hook details and result headers.
                if (t.contains("hook=") || t.matches("\\*+SUCCESS\\*+")
                        || t.contains("exploit success")) {
                    continue;
                }
                // Strip hex file offsets: ".../libc.so+0x6e8b0" -> ".../libc.so"
                t = t.replaceAll("\\+0x[0-9a-fA-F]+$", "");
                t = stripHeader(t);
                appendLog(t);
            }
            // auto-scroll only when the user is already reading at the bottom;
            // otherwise a background merge (tool poll) yanks the view around
            binding.outputScroll.post(() -> {
                android.widget.ScrollView sc = binding.outputScroll;
                int max = binding.outputView.getHeight() + binding.outputView.getPaddingBottom()
                        - sc.getHeight();
                if (sc.getScrollY() >= max - 40) sc.fullScroll(View.FOCUS_DOWN);
            });
        });
    }

    private void appendLog(String line) {
        binding.outputView.append(styleLogLine(line));
        binding.outputView.append("\n");
        logBuffer.append(line).append('\n');
        saveLog();
    }

    /** Append one raw reporter line to a shell-readable file and fsync it.
     * Deliberately not buffered: if the kernel goes down mid-exploit the
     * lines already written must still be on disk. */
    private void mirrorRunLog(String msg) {
        if (msg == null || msg.isEmpty()) return;
        try {
            java.io.File dir = getExternalFilesDir(null);
            if (dir == null) return;
            java.io.File f = new java.io.File(dir, "run.log");
            try (FileOutputStream fo = new FileOutputStream(f, true)) {
                fo.write(msg.getBytes(StandardCharsets.UTF_8));
                fo.flush();
                try { fo.getFD().sync(); } catch (Throwable ignored) { }
            }
        } catch (Throwable ignored) {
            // mirroring is best-effort: never let diagnostics kill the run
        }
    }

    /** Truncate the mirrored log so each run's file is that run's only. */
    private void resetRunLog() {
        try {
            java.io.File dir = getExternalFilesDir(null);
            if (dir != null) new java.io.File(dir, "run.log").delete();
        } catch (Throwable ignored) { }
    }

    /** Translates raw native log lines into two-step progress-bar states. */
    private void driveProgress(String t) {
        if (t.isEmpty()) return;
        switch (t) {
            case "=== setup ===":
                exploitPhase = "setup";
                setSeg1(0.05f);
                break;
            case "=== exploit ===":
                exploitPhase = "exploit";
                setSeg1(0.15f);
                break;
            case "=== cleanup ===":
                exploitPhase = "cleanup";
                cleanupSteps = 0;
                stopTriggerTicker();
                setSeg1(1f);
                setSeg2(0.05f, "Verification", 0xFFFFFFFF);
                break;
            default:
                break;
        }
        if (exploitPhase.equals("setup") && t.startsWith(new String(new char[]{'k','s','u','d'}) + " staged")) {
            setSeg1(0.10f);
        }
        if (exploitPhase.equals("exploit") && t.startsWith("patched")) {
            if (t.contains(ExploitRunner.s(215))) {
                setSeg1(0.30f);
            } else if (t.contains(ExploitRunner.s(117))) {
                setSeg1(0.55f);
            } else if (t.contains("libc++.so")) {
                setSeg1(Math.min(0.80f, seg1 + 0.05f));
            }
        }
        if (t.startsWith("* triggering")) {
            triggerStartMs = android.os.SystemClock.elapsedRealtime();
            setSeg1(0.85f);
            startTriggerTicker();
        }
        if (t.startsWith("libc++: mutex acquired")) {
            stopTriggerTicker();
            setSeg1(0.95f);
        }
        if (exploitPhase.equals("cleanup")
                && (t.startsWith("* restore") || t.startsWith("* cache dropped"))) {
            cleanupSteps++;
            setSeg2(Math.min(1f, cleanupSteps / 3f), "Verification", 0xFFFFFFFF);
        }
    }

    private void setSeg1(float p) {
        seg1 = p;
        binding.twoStep.setSeg1(p, Math.round(p * 100) + "%");
    }

    /* v181: during the 180s trigger window the bar crawls 85%->94% and the
     * label counts down, so waiting reads as progress, not a hang. */
    private void startTriggerTicker() {
        stopTriggerTicker();
        triggerWaitTicker = new Runnable() {
            @Override public void run() {
                long el = android.os.SystemClock.elapsedRealtime() - triggerStartMs;
                float frac = Math.min(1f, el / 180000f);
                setSeg1(0.85f + 0.09f * frac);
                long remain = Math.max(0, 180 - el / 1000);
                binding.twoStep.setSeg1(seg1, "等待触发 " + remain + "s");
                if (frac < 1f) uiHandler.postDelayed(this, 1000);
            }
        };
        uiHandler.post(triggerWaitTicker);
    }

    private void stopTriggerTicker() {
        if (triggerWaitTicker != null) {
            uiHandler.removeCallbacks(triggerWaitTicker);
            triggerWaitTicker = null;
        }
    }

    private void setSeg2(float p, String label, int color) {
        binding.twoStep.setSeg2(p, label, color);
    }

    /** Log list is always visible and scrollable. */
    private void updateLogVisibility() {
        binding.outputScroll.setVisibility(View.VISIBLE);
    }

    /** UMH log (written by the kernel-spawned root script), polled and
     *  merged into the on-screen log. Lives in our device-protected files
     *  dir; /data/local/tmp/tool.log is the adb-side copy. */
    private long toolLogPos = 0;
    private java.io.File toolLogFile() {
        return new File(createDeviceProtectedStorageContext().getFilesDir(), "tool.log");
    }
    private void pollToolLog() {
        try {
            java.io.File f = toolLogFile();
            if (!f.exists()) return;
            long len = f.length();
            if (len == toolLogPos) return;
            if (len < toolLogPos) toolLogPos = 0; // truncated by a new run
            try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(f, "r")) {
                raf.seek(toolLogPos);
                byte[] buf = new byte[(int) (len - toolLogPos)];
                raf.readFully(buf);
                toolLogPos = len;
                String chunk = new String(buf, java.nio.charset.StandardCharsets.UTF_8);
                if (!chunk.trim().isEmpty()) report("[tool] " + chunk.trim());
            }
        } catch (Exception ignored) { }
    }
    private final Runnable toolPoll = new Runnable() {
        @Override public void run() {
            pollToolLog();
            mMain.postDelayed(this, 1500);
        }
    };

    /** "=== setup ===" -> "SETUP"; "=== exploit failed: x ===" -> "EXPLOIT FAILED: X". */
    private static String stripHeader(String t) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("^===\\s*(.*?)\\s*===$").matcher(t);
        return m.matches() ? m.group(1).toUpperCase() : t;
    }

    /** Short firmware token from the build display string, e.g. "S931BXXU1AYB2"
     *  - everything that is not the model-prefixed version is dropped. */
    private static String fwToken() {
        String d = android.os.Build.DISPLAY;
        String model = android.os.Build.MODEL == null
                ? "" : android.os.Build.MODEL.replace("SM-", "").trim();
        if (d == null || d.trim().isEmpty()) return "UNKNOWN";
        if (model.isEmpty()) return d.trim();
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("[A-Z0-9]*" + java.util.regex.Pattern.quote(model) + "[A-Z0-9]*")
                .matcher(d);
        return m.find() ? m.group() : d.trim();
    }

    /** Header lines render big, white and bold; the rest is dimmed. */
    private boolean isHeader(String line) {
        return line.equals("SETUP") || line.equals("EXPLOIT") || line.equals("CLEANUP")
                || line.startsWith("EXPLOIT FAILED")
                || line.equals(fwToken());
    }

    /** Header lines render big, white and bold; the rest is dimmed. */
    private CharSequence styleLogLine(String line) {
        SpannableString ss = new SpannableString(line);
        if (isHeader(line)) {
            ss.setSpan(new StyleSpan(Typeface.BOLD), 0, line.length(), 0);
            ss.setSpan(new RelativeSizeSpan(1.3f), 0, line.length(), 0);
            ss.setSpan(new ForegroundColorSpan(0xFFFFFFFF), 0, line.length(), 0);
        } else {
            ss.setSpan(new ForegroundColorSpan(0xFFB3B3B3), 0, line.length(), 0);
        }
        return ss;
    }

    private void saveLog() {
        try (FileOutputStream out = new FileOutputStream(lastLogFile)) {
            out.write(logBuffer.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (IOException ignored) {
        }
        // Remember which boot this log came from - it is invalidated on reboot.
        createDeviceProtectedStorageContext()
                .getSharedPreferences("honorroot", MODE_PRIVATE)
                .edit().putInt("log_boot_count", bootCount()).apply();
    }

    private int bootCount() {
        try {
            return android.provider.Settings.Global.getInt(getContentResolver(),
                    android.provider.Settings.Global.BOOT_COUNT, -1);
        } catch (Exception e) {
            return -1;
        }
    }

    private String readLastLog() {
        if (lastLogFile == null || !lastLogFile.exists()) return "";
        try (java.io.FileInputStream in = new java.io.FileInputStream(lastLogFile);
             java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            for (int n; (n = in.read(buf)) != -1; ) bos.write(buf, 0, n);
            String log = bos.toString(java.nio.charset.StandardCharsets.UTF_8.name()).trim();
            // Normalize exploit-result headers to lowercase (older runs saved
            // them uppercase); the file gets rewritten on next save.
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("(===\\s*exploit\\s+(?:success|failed[^=]*)\\s*===)",
                            java.util.regex.Pattern.CASE_INSENSITIVE)
                    .matcher(log);
            StringBuilder sb = new StringBuilder();
            while (m.find()) m.appendReplacement(sb, java.util.regex.Matcher
                    .quoteReplacement(m.group().toLowerCase()));
            m.appendTail(sb);
            return sb.toString();
        } catch (IOException e) {
            return "";
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Crash forensics: any uncaught exception lands in
        // Android/data/honor.root/files/crash.log so a failure can be
        // reported back without adb.
        final java.io.File crashLog = new File(getExternalFilesDir(null), "crash.log");
        Thread.setDefaultUncaughtExceptionHandler((thread, e) -> {
            try (java.io.FileOutputStream fo = new java.io.FileOutputStream(crashLog, true)) {
                fo.write(("==== " + new java.util.Date() + " thread=" + thread.getName()
                        + " sdk=" + android.os.Build.VERSION.SDK_INT + " ====\n")
                        .getBytes(StandardCharsets.UTF_8));
                fo.write(Log.getStackTraceString(e).getBytes(StandardCharsets.UTF_8));
                fo.write("\n\n".getBytes(StandardCharsets.UTF_8));
            } catch (Exception ignored) { }
            Log.e(TAG, "fatal", e);
            android.os.Process.killProcess(android.os.Process.myPid());
        });
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        initDeviceProfile();

        // License gate: offline RSA device-bound activation. Unlicensed
        // installs can only see their device code - the exploit path is
        // unreachable (gated here, on the run button, in runExploit and in
        // BootReceiver).
        licensed = LicenseManager.isLicensed(this);
        if (licensed) {
            applyLicense(LicenseManager.findValidLicense(this));
        } else {
            Log.i(TAG, "device_code=" + LicenseManager.deviceCode(this));
            mMain.post(this::showLicenseDialog);
        }

        // Version tag flowing right after the header title. Always mirrors
        // the real versionName so the pill and system settings never diverge.
        SpannableString title = new SpannableString("荣耀提权工具 "
                + BuildConfig.VERSION_NAME);
        pillSpan = new VersionPillSpan(0.45f);
        title.setSpan(pillSpan, 7, title.length(),
                SpannableString.SPAN_EXCLUSIVE_EXCLUSIVE);
        binding.toolbar.setTitle(title);
        // NOTE: no setSupportActionBar() - it makes the ActionBar delegate draw
        // the title and ignore the toolbar's titleTextAppearance (breaks bold).
        // The toolbar renders its own title via app:titleTextAppearance.

        // Fully offline build: no update check, no outbound connections.

        // MEY patch: adb-triggerable run (licensed installs only).
        // adb shell am start -n honor.root/.MainActivity --ez auto_run true
        if (licensed && getIntent() != null
                && getIntent().getBooleanExtra("auto_run", false)) {
            binding.btnRun.post(() -> {
                binding.btnRun.performClick(); // arm ("Are you sure")
                binding.btnRun.performClick(); // fire
            });
        }

        // D2 vault status (Samsung VaultKeeper): Odin flashing allowed or
        // locked. Read-only; non-Samsung devices show "not available".

        // KSU modules toggle: marks every installed module disabled/enabled
        // (diabl0w ksud convention: per-module `disable` flag files, honored
        // at next boot). State is read back from the device via su.
        binding.switchModules.setOnCheckedChangeListener((btn, on) -> {
            if (moduleRefresh) return;
            btn.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            applyModuleState(on);
        });
        mExec.execute(this::refreshModuleState);

        // Force real bold (wght 700) One UI Sans on the toolbar title TextView.
        binding.toolbar.post(() -> {
            Typeface base = ResourcesCompat.getFont(this, R.font.inter_vf);
            if (base == null) return;
            Typeface bold = Typeface.create(base, 700, false);
            for (int i = 0; i < binding.toolbar.getChildCount(); i++) {
                View child = binding.toolbar.getChildAt(i);
                if (child instanceof TextView) {
                    titleView = (TextView) child;
                    titleView.setTypeface(bold);
                    }
            }
        });

        if (new File(ExploitRunner.s(21)).exists()) {
            setRootedState();
        }

        // Show the log from the last run, if any. No run yet -> log hidden.
        // A log saved before the current boot is stale: delete it so a reboot
        // always starts with a clean screen (log + share icon hidden).
        lastLogFile = new File(createDeviceProtectedStorageContext().getFilesDir(), "last_run.log");
        int savedBoot = createDeviceProtectedStorageContext()
                .getSharedPreferences("honorroot", MODE_PRIVATE).getInt("log_boot_count", -1);
        if (lastLogFile.exists() && savedBoot != bootCount()) {
            lastLogFile.delete();
            createDeviceProtectedStorageContext()
                    .getSharedPreferences("honorroot", MODE_PRIVATE)
                    .edit().putBoolean("last_run_success", false).apply();
        }
        String last = readLastLog();
        boolean hasLastLog = !last.isEmpty();
        if (hasLastLog) {
            appendLog(fwToken());
            for (String l : last.split("\n")) {
                String t = stripHeader(l.trim());
                // Skip stale headers, old result lines and duplicate fw lines.
                if (t.isEmpty()
                        || t.equals("LAST RUN")
                        || t.equals("EXPLOIT SUCCESS")
                        || t.equals(fwToken())) {
                    continue;
                }
                appendLog(t);
            }
        }

        updateLogVisibility();

        // Restore the simple status for the current state: rooted device or a
        // successful last run -> 100% + Verified; failed run -> Failed.
        boolean rootedNow = new File(ExploitRunner.s(21)).exists();
        boolean lastSuccess = hasLastLog
                && createDeviceProtectedStorageContext()
                        .getSharedPreferences("honorroot", MODE_PRIVATE)
                        .getBoolean("last_run_success", false);
        boolean lastFailed = hasLastLog
                && last.toLowerCase().contains("=== exploit failed");
        if (rootedNow || lastSuccess) {
            binding.twoStep.setSeg1(1f, "100%");
            binding.twoStep.setSeg2(1f, "Verified", 0xFFFFFFFF);
        } else if (lastFailed) {
            setFailedState();
        }

        binding.btnRun.setOnClickListener(v -> {
            if (running) return;
            if (!licensed) {
                showLicenseDialog();
                return;
            }
            // Two-tap confirmation: first tap arms ("Are you sure"), second runs.
            if (!runArmed) {
                runArmed = true;
                // tool log: start merging from the file's current end (skip history)
                java.io.File dlf = toolLogFile();
                toolLogPos = dlf.exists() ? dlf.length() : 0;
                mMain.post(toolPoll);
                v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                binding.btnRun.setText("Are you sure");
                return;
            }
            runArmed = false;
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            running = true;
            binding.btnRun.setEnabled(false);
            binding.btnRun.setText("Running");
            // Same dark greyed-out styling as the Rooted state.
            binding.btnRun.setTextColor(0xFF6E6E6E);
            binding.btnRun.setBackgroundTintList(ColorStateList.valueOf(0xFF1F1F1F));
            ((com.google.android.material.button.MaterialButton) binding.btnRun)
                    .setStrokeColor(ColorStateList.valueOf(0xFF1F1F1F));
            binding.outputView.setText("");
            logBuffer.setLength(0);
            if (lastLogFile.exists()) lastLogFile.delete();
            resetRunLog();   // mirrored log = this run only
            createDeviceProtectedStorageContext()
                    .getSharedPreferences("honorroot", MODE_PRIVATE)
                    .edit().putBoolean("last_run_success", false).apply();
            appendLog(fwToken());
            binding.twoStep.reset();
            setCompactButton(true, false);
            updateLogVisibility();
            mExec.execute(() -> runExploit(false));
        });

        binding.btnKsu.setOnClickListener(v2 -> adbFire());  // v220: reuse KSU row as adb-fire trigger


        binding.btnKsu.setOnClickListener(v -> {
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            openKsu();
        });

        // Subtle push-in + keyboard-tap haptic on the run button.
        binding.btnRun.setOnTouchListener((v, ev) -> {
            switch (ev.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                    v.animate().scaleX(0.96f).scaleY(0.96f).setDuration(80).start();
                    break;
                case MotionEvent.ACTION_UP:
                case MotionEvent.ACTION_CANCEL:
                    v.animate().scaleX(1f).scaleY(1f).setDuration(120).start();
                    break;
                default:
                    break;
            }
            return false;
        });

        // One-tap feedback: collect + pack + upload run logs to the IM webhook.
        binding.btnFeedback.setOnClickListener(v -> confirmFeedback());

        // Overflow menu on the custom grey-circle button: the popup closes
        // ONLY on outside taps, so multi-tap actions are possible.
        binding.btnMenu.setOnClickListener(v -> {
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            float md = getResources().getDisplayMetrics().density;
            boolean rootedMenu = new File(ExploitRunner.s(21)).exists();
            final android.widget.PopupWindow[] pwRef = {null};

            android.widget.LinearLayout box = new android.widget.LinearLayout(this);
            box.setOrientation(android.widget.LinearLayout.VERTICAL);
            box.setBackgroundResource(R.drawable.popup_bg);
            box.setPadding(0, (int) (6 * md), 0, (int) (6 * md));

            // -- Expert Mode row: white dot appears when enabled --
            android.widget.LinearLayout exRow = new android.widget.LinearLayout(this);
            exRow.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            exRow.setPadding((int) (20 * md), 0, 0, 0);
            TextView exText = new TextView(this);
            exRow.setBackgroundResource(R.drawable.menu_row_highlight);
            exText.setText("Expert Mode");
            exText.setTextColor(0xFFE8E8E8);
            exText.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            exRow.addView(exText);
            final android.view.View[] dotRef = {null};
            android.view.View dot = new android.view.View(this);
            dot.setBackgroundResource(R.drawable.dot_white);
            android.widget.LinearLayout.LayoutParams dotLp =
                    new android.widget.LinearLayout.LayoutParams(
                            (int) (7 * md), (int) (7 * md));
            dotLp.setMargins((int) (7 * md), 0, 0, 0);
            dot.setVisibility(expertMode ? View.VISIBLE : View.GONE);
            exRow.addView(dot, dotLp);
            dotRef[0] = dot;
            exRow.setOnClickListener(v2 -> {
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                expertMode = !expertMode;
                createDeviceProtectedStorageContext()
                        .getSharedPreferences("honorroot", MODE_PRIVATE)
                        .edit().putBoolean("expert_mode", expertMode).apply();
                applyExpertMode();
                if (dotRef[0] != null)
                    dotRef[0].setVisibility(expertMode ? View.VISIBLE : View.GONE);
            });
            box.addView(exRow, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (46 * md)));

            // -- Remove KSU/KSUD row: 3-tap confirm, greyed without root --
            android.widget.LinearLayout rmCol = new android.widget.LinearLayout(this);
            rmCol.setOrientation(android.widget.LinearLayout.VERTICAL);
            rmCol.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            rmCol.setPadding((int) (20 * md), 0, (int) (20 * md), 0);
            TextView rmTitle = new TextView(this);
            rmCol.setBackgroundResource(R.drawable.menu_row_highlight);
            rmTitle.setText("Remove KSU/KSUD");
            rmTitle.setGravity(android.view.Gravity.START);
            rmTitle.setTextColor(rootedMenu ? 0xFFE8E8E8 : 0xFF6E6E6E);
            rmTitle.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            rmCol.addView(rmTitle);
            TextView rmSub = new TextView(this);
            rmSub.setText(rootedMenu ? "Click 3 times" : "Requires root");
            rmSub.setGravity(android.view.Gravity.START);
            rmSub.setTextColor(rootedMenu ? 0xFF8E8E8E : 0xFF5A5A5A);
            rmSub.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 11);
            rmCol.addView(rmSub);
            final int[] taps = {0};
            rmCol.setOnClickListener(v2 -> {
                if (!rootedMenu) return;
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                taps[0]++;
                if (taps[0] == 1) {
                    rmTitle.setText("Are you sure");
                    rmSub.setText("Click 2 times");
                    return;
                }
                if (taps[0] == 2) {
                    rmTitle.setText("One more click");
                    rmSub.setText("Click 1 time");
                    return;
                }
                if (pwRef[0] != null) pwRef[0].dismiss();
                try {
                    // Deliberately NOT calling `ksud uninstall`: its upstream
                    // implementation force-flashes a stored boot image when a
                    // backup exists and reboots the device after 5 seconds -
                    // surprises we don't want. Explicit removals only, plus
                    // the manager app this row promises to remove.
                    Process p = Runtime.getRuntime().exec(new String[]{
                            "su", "-c",
                            ExploitRunner.s(29) + ExploitRunner.s(22)
                                    + ExploitRunner.s(30)});
                    int rc = p.waitFor();
                    mMain.post(() -> {
                        Toast.makeText(MainActivity.this,
                                rc == 0 ? "KSU/KSUD removed"
                                        : "Removal failed (code " + rc + ")",
                                Toast.LENGTH_SHORT).show();
                        setRootedState(false);
                    });
                } catch (Exception e) {
                    Toast.makeText(MainActivity.this,
                            "su not available", Toast.LENGTH_SHORT).show();
                }
            });
            box.addView(rmCol, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (58 * md)));

            // Width: content, but at least 210dp so the popup reads properly.
            box.measure(View.MeasureSpec.UNSPECIFIED, View.MeasureSpec.UNSPECIFIED);
            int pw_w = Math.max(box.getMeasuredWidth(), (int) (190 * md));

            final android.widget.PopupWindow pw = new android.widget.PopupWindow(box,
                    pw_w, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, true);
            pw.setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(
                    android.graphics.Color.TRANSPARENT));
            pw.setOutsideTouchable(true);
            pwRef[0] = pw;
            pw.setOnDismissListener(() ->
                    binding.dimOverlay.animate().alpha(0f).setDuration(150)
                            .withEndAction(() -> binding.dimOverlay
                                    .setVisibility(View.GONE)).start());

            // Centered separators between the rows.
            android.widget.LinearLayout.LayoutParams sepLp =
                    new android.widget.LinearLayout.LayoutParams(
                            android.view.ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, (int) md));
            sepLp.setMargins((int) (20 * md), 0, (int) (20 * md), 0);
            android.view.View sep1 = new android.view.View(this);
            sep1.setBackgroundColor(0xFF3F3F3F);
            box.addView(sep1, 1, sepLp);
            android.view.View sep2 = new android.view.View(this);
            sep2.setBackgroundColor(0xFF3F3F3F);
            android.widget.LinearLayout.LayoutParams sep2Lp =
                    new android.widget.LinearLayout.LayoutParams(
                            android.view.ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, (int) md));
            sep2Lp.setMargins((int) (20 * md), 0, (int) (20 * md), 0);
            box.addView(sep2, 3, sep2Lp);

            box.setOutlineProvider(new android.view.ViewOutlineProvider() {
                @Override
                public void getOutline(View view, android.graphics.Outline outline) {
                    outline.setRoundRect(0, 0, view.getWidth(), view.getHeight(), 26 * md);
                }
            });
            box.setClipToOutline(true);
            box.setElevation(48 * md);

            int[] loc = new int[2];
            binding.menuAnchor.getLocationOnScreen(loc);
            int x = loc[0] + binding.menuAnchor.getWidth() - pw_w;
            int y = loc[1] + (int) (2 * md);
            binding.dimOverlay.setVisibility(View.VISIBLE);
            binding.dimOverlay.setAlpha(0f);
            binding.dimOverlay.animate().alpha(0.5f).setDuration(150).start();
            box.setPivotX(pw_w);
            box.setPivotY(0f);
            box.setScaleX(0.85f);
            box.setScaleY(0.9f);
            box.setAlpha(0f);
            pw.showAtLocation(binding.menuAnchor,
                    android.view.Gravity.TOP | android.view.Gravity.START, x, y);
            box.animate().scaleX(1f).scaleY(1f).alpha(1f).setDuration(150)
                    .setInterpolator(new android.view.animation.DecelerateInterpolator())
                    .start();
        });
        ComponentName bootReceiver = new ComponentName(this, BootReceiver.class);
        int state = getPackageManager().getComponentEnabledSetting(bootReceiver);
        boolean bootEnabled = state == PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
        binding.switchBootStart.setChecked(bootEnabled);
        binding.switchBootStart.setOnCheckedChangeListener((btn, checked) -> {
            getPackageManager().setComponentEnabledSetting(bootReceiver,
                checked ? PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                        : PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP);
            binding.switchAutoSoftReboot.setEnabled(checked);
        });

        boolean autoSoftReboot = createDeviceProtectedStorageContext()
                .getSharedPreferences("honorroot", MODE_PRIVATE)
                .getBoolean("auto_soft_reboot", false);
        binding.switchAutoSoftReboot.setChecked(autoSoftReboot);
        binding.switchAutoSoftReboot.setEnabled(bootEnabled);
        binding.switchAutoSoftReboot.setOnCheckedChangeListener((btn, checked) ->
            createDeviceProtectedStorageContext()
                .getSharedPreferences("honorroot", MODE_PRIVATE)
                .edit().putBoolean("auto_soft_reboot", checked).apply());

        // Expert mode gates the autorun card: locked until toggled in the menu.
        expertMode = createDeviceProtectedStorageContext()
                .getSharedPreferences("honorroot", MODE_PRIVATE)
                .getBoolean("expert_mode", false);
        applyExpertMode();
    }

    /** Expert mode off: the autorun card is inaccessible - greyed text and
     *  disabled toggles, titles suffixed with (Expert). */
    private void applyExpertMode() {
        boolean ok = expertMode;
        binding.tvAutorunTitle.setText(ok ? "Autorun" : "Autorun (Expert)");
        binding.tvRebootTitle.setText(ok ? "Auto reboot" : "Auto reboot (Expert)");
        binding.tvAutorunTitle.setTextColor(ok ? 0xFFFFFFFF : 0xFF6E6E6E);
        binding.tvAutorunDesc.setTextColor(ok ? 0xFF9E9E9E : 0xFF5A5A5A);
        binding.tvRebootTitle.setTextColor(ok ? 0xFFFFFFFF : 0xFF6E6E6E);
        binding.tvRebootDesc.setTextColor(ok ? 0xFF9E9E9E : 0xFF5A5A5A);
        binding.switchBootStart.setEnabled(ok);
        binding.switchAutoSoftReboot.setEnabled(ok
                && binding.switchBootStart.isChecked());
    }

    /** Re-read the modules state when returning to the app: if the user just
     *  granted root in the KSU manager, the toggle updates immediately
     *  instead of staying stale until the next app open. */
    @Override
    protected void onResume() {
        super.onResume();
        // Pick up a license.txt dropped into our external files dir while
        // the app was backgrounded.
        if (!licensed) licensed = LicenseManager.isLicensed(this);
        mExec.execute(this::refreshModuleState);
    }

    private void setRootedState() {
        setRootedState(true);
    }

    /** Runs a command as root (su). Returns stdout, or null when su is
     *  unavailable (module not loaded / not granted). Sets suState with the
     *  failure reason for the UI. */
    private String suState = "unknown";
    private String runSu(String cmd) {
        suState = "unknown";
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", cmd});
            java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));
            java.io.BufferedReader err = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getErrorStream()));
            StringBuilder sb = new StringBuilder();
            String ln;
            while ((ln = r.readLine()) != null) sb.append(ln).append('\n');
            StringBuilder eb = new StringBuilder();
            while ((ln = err.readLine()) != null) eb.append(ln).append('\n');
            err.close();
            r.close();
            int rc = p.waitFor();
            if (rc == 0) {
                suState = "ok";
                return sb.toString();
            }
            suState = ("denied (rc " + rc + ")" + (eb.length() > 0 ? ": " + eb.toString().trim() : ""));
            Log.i(TAG, "su probe failed: " + suState);
            return null;
        } catch (Exception e) {
            suState = "not found";
            return null;
        }
    }

    /** Reads the modules' disable-flag state from /data/adb/modules via su and
     *  syncs the toggle. All-disabled = switch off, otherwise on. */
    private void refreshModuleState() {
        String mods = runSu(ExploitRunner.s(33));
        if (mods == null) {
            mMain.post(() -> {
                moduleRefresh = true;
                binding.switchModules.setChecked(false);
                binding.switchModules.setEnabled(false);
                moduleRefresh = false;
                binding.modulesSubtitle.setText("not found".equals(suState)
                        ? "Requires root (run the exploit first)"
                        : "No Modules Installed");
            });
            return;
        }
        int total = 0;
        for (String s : mods.split("\n")) if (!s.trim().isEmpty()) total++;
        if (total == 0) {
            mMain.post(() -> {
                moduleRefresh = true;
                binding.switchModules.setChecked(false);
                binding.switchModules.setEnabled(false);
                moduleRefresh = false;
                Log.i(TAG, "modules toggle: no modules installed");
                binding.modulesSubtitle.setText("No Modules Installed");
            });
            return;
        }
        String dis = runSu(ExploitRunner.s(34));
        int disabled = 0;
        if (dis != null) for (String s : dis.split("\n")) if (!s.trim().isEmpty()) disabled++;
        boolean allDisabled = disabled >= total;
        final int fTotal = total, fDisabled = Math.min(disabled, total);
        String text = fDisabled == 0
                ? "Enabled - Active at next reroot"
                : fDisabled == fTotal
                    ? "Disabled - No Modules on reroot"
                    : fDisabled + " of " + fTotal + " disabled - applies at next reroot";
        Log.i(TAG, "modules toggle: " + fDisabled + "/" + fTotal + " disabled -> " + text);
        mMain.post(() -> {
            moduleRefresh = true;
            binding.switchModules.setChecked(!allDisabled);
            binding.switchModules.setEnabled(true);
            moduleRefresh = false;
            binding.modulesSubtitle.setText(text);
        });
    }

    /** Applies the toggle: disable = touch a `disable` flag in every module,
     *  enable = remove them. Takes effect at the next reboot (modules are
     *  mounted during boot only). */
    private void applyModuleState(boolean on) {
        String cmd = on ? ExploitRunner.s(35) : ExploitRunner.s(36);
        mExec.execute(() -> {
            String r = runSu(cmd);
            mMain.post(() -> {
                Toast.makeText(MainActivity.this,
                        r == null ? "su not available"
                                : on ? "KSU modules enabled - applies after reboot"
                                : "KSU modules disabled - applies after reboot",
                        Toast.LENGTH_SHORT).show();
                refreshModuleState();
            });
        });
    }

    /** Failure presentation: left bar label "Failure", right label "Reboot",
     *  bars + labels red, run pill greyed out like the Running/Rooted state.
     *  The pill stays disabled because the vendor patch is page-cache only:
     *  retrying without rebooting would fail the same way. */
    /** v182: the manual run ended without a trigger, but the watchdog took
     *  over - show that as an ongoing state (yellow), not a red Failure:
     *  the round counter lives in the notification, retries continue in the
     *  background, and nothing about the attempt is over. */
    private void setWatchdogState() {
        stopTriggerTicker();
        binding.twoStep.setFailed(false);
        binding.twoStep.setSeg1(seg1, "Watchdog");
        binding.twoStep.setSeg2(1f, "守候中 · 看通知栏", 0xFFE5C073);
        binding.btnRun.setEnabled(false);
        binding.btnRun.setText("Watchdog running");
        binding.btnRun.setTextColor(0xFF6E6E6E);
        binding.btnRun.setBackgroundTintList(ColorStateList.valueOf(0xFF1F1F1F));
        ((com.google.android.material.button.MaterialButton) binding.btnRun)
                .setStrokeColor(ColorStateList.valueOf(0xFF1F1F1F));
        setCompactButton(false, false);
        report("\n==============================================");
        report("  本轮未触发 = 正常现象,不是失败");
        report("  守候已接管:每 3 分钟自动重试,最长 8 小时");
        report("  root 成功会弹 SUCCESS 通知,期间可正常使用手机");
        report("  上面的 FAILED 只是本轮日志,守候会一直跑");
        report("==============================================\n");
        report("[watchdog] UI: the attempt is NOT over - the foreground watch is "
                + "re-firing every 3 min for up to 8 h; progress lives in the "
                + "notification, a SUCCESS alert will pop on root\n");
    }

    private void setFailedState() {
        stopTriggerTicker();
        binding.twoStep.setFailed(true);
        binding.twoStep.setSeg1(seg1, "Failure");
        binding.twoStep.setSeg2(1f, "Reboot", 0xFFE57373);
        binding.btnRun.setEnabled(false);
        binding.btnRun.setText("Run exploit");
        binding.btnRun.setTextColor(0xFF6E6E6E);
        binding.btnRun.setBackgroundTintList(ColorStateList.valueOf(0xFF1F1F1F));
        ((com.google.android.material.button.MaterialButton) binding.btnRun)
                .setStrokeColor(ColorStateList.valueOf(0xFF1F1F1F));
        setCompactButton(false, false);
    }

    private void setRootedState(boolean rooted) {
        stopTriggerTicker();
        runArmed = false;
        binding.btnRun.setEnabled(!rooted);
        binding.btnRun.setText(rooted ? "Rooted" : "Run exploit");
        binding.btnRun.setTextColor(
                rooted ? 0xFF6E6E6E : 0xFFE0E0E0);
        binding.btnRun.setBackgroundTintList(ColorStateList.valueOf(
                rooted ? 0xFF1F1F1F : 0xFF7A7A7A));
        ((com.google.android.material.button.MaterialButton) binding.btnRun)
                .setStrokeColor(ColorStateList.valueOf(
                        rooted ? 0xFF1F1F1F : 0xFFA6A6A6));
        // Rooted/running: shrink the pill left and pop the KSU circle next to
        // it (lit when rooted); fresh run state: full-width pill, no circle.
        setCompactButton(rooted, rooted);
    }

    /** Shrinks the main pill to the left and pops the KSU launcher circle
     *  next to it (compact=true, ksuLit=lit after successful root), or
     *  restores the full-width pill. */
    private void setCompactButton(boolean compact, boolean ksuLit) {
        // Fresh pill: 48% wide starting at the 26% guideline → right edge at
        // 74%. Compact: pill + 12dp gap + 54dp circle must occupy the same
        // 48% total (left edge pinned), so pill = 48% - extras.
        float target = 0.48f;
        if (compact) {
            float parentW = ((View) binding.btnRun.getParent()).getWidth();
            if (parentW <= 0) parentW = getResources().getDisplayMetrics().widthPixels;
            float density = getResources().getDisplayMetrics().density;
            float extrasPx = (12f + 54f) * density;
            target = Math.max(0.20f, 0.48f - extrasPx / parentW);
        }
        android.animation.ValueAnimator a =
                android.animation.ValueAnimator.ofFloat(pillPercent, target);
        a.setDuration(250);
        a.addUpdateListener(anim -> {
            pillPercent = (float) anim.getAnimatedValue();
            androidx.constraintlayout.widget.ConstraintLayout.LayoutParams lp =
                    (androidx.constraintlayout.widget.ConstraintLayout.LayoutParams)
                            binding.btnRun.getLayoutParams();
            lp.matchConstraintPercentWidth = pillPercent;
            binding.btnRun.setLayoutParams(lp);
        });
        a.start();
        binding.btnKsu.setEnabled(ksuLit);
        boolean wasVisible = binding.btnKsu.getVisibility() == View.VISIBLE
                && binding.btnKsu.getAlpha() > 0.99f;
        binding.btnKsu.setBackgroundTintList(ColorStateList.valueOf(
                ksuLit ? 0xFFB0B0B0 : 0xFF1F1F1F));
        binding.btnKsu.setImageResource(R.drawable.ksu_logo);
        if (compact && !wasVisible) {
            // First appearance: pop in quickly.
            binding.btnKsu.setVisibility(View.VISIBLE);
            binding.btnKsu.setAlpha(0f);
            binding.btnKsu.setScaleX(0.6f);
            binding.btnKsu.setScaleY(0.6f);
            binding.btnKsu.postDelayed(() -> binding.btnKsu.animate()
                    .alpha(1f).scaleX(1f).scaleY(1f).setDuration(180)
                    .withEndAction(() -> settleKsuTint(ksuLit)).start(), 150);
        } else if (compact) {
            // Already visible (state change): stay in place, just recolor.
            settleKsuTint(ksuLit);
        } else {
            binding.btnKsu.animate().alpha(0f).scaleX(0.6f).scaleY(0.6f)
                    .setDuration(200)
                    .withEndAction(() -> binding.btnKsu.setVisibility(View.GONE))
                    .start();
        }
    }

    /** After the lit circle settles, ease it slightly towards grey. */
    private void settleKsuTint(boolean ksuLit) {
        if (!ksuLit) return;
        android.animation.ValueAnimator g =
                android.animation.ValueAnimator.ofFloat(0f, 1f);
        g.setStartDelay(250);
        g.setDuration(300);
        g.addUpdateListener(anim -> binding.btnKsu
                .setBackgroundTintList(ColorStateList.valueOf(
                        mixColor(0xFFB0B0B0, 0xFF9A9A9E,
                                (float) anim.getAnimatedValue()))));
        g.start();
    }

    private void openKsu() {
        // Try the known manager packages (resolved from the native name table).
        String[] candidates = {
                ExploitRunner.s(22), ExploitRunner.s(23), ExploitRunner.s(24)};
        PackageManager pm = getPackageManager();
        for (String pkg : candidates) {
            Intent launch = pm.getLaunchIntentForPackage(pkg);
            if (launch != null) {
                launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(launch);
                return;
            }
        }
        Toast.makeText(this, "Manager not found", Toast.LENGTH_SHORT).show();
    }

    private static int mixColor(int a, int b, float t) {
        int ar = (a >> 16) & 0xFF, ag = (a >> 8) & 0xFF, ab = a & 0xFF;
        int br = (b >> 16) & 0xFF, bg = (b >> 8) & 0xFF, bb = b & 0xFF;
        return 0xFF000000
                | (Math.round(ar + (br - ar) * t) << 16)
                | (Math.round(ag + (bg - ag) * t) << 8)
                | Math.round(ab + (bb - ab) * t);
    }

    /** Saves the current log to Downloads and opens the Downloads screen. */
    /** Feedback: confirm, then collect + pack + upload run logs to the IM
     *  webhook with a live progress dialog. */
    private void confirmFeedback() {
        new androidx.appcompat.app.AlertDialog.Builder(this, R.style.DF_Dialog)
                .setTitle("发送反馈")
                .setMessage("将收集本次运行日志、系统快照与 logcat 并打包发送。\n\n现在发送？")
                .setPositiveButton("发送", (d, w) -> runFeedback())
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void runFeedback() {
        float md = getResources().getDisplayMetrics().density;
        android.widget.LinearLayout box = new android.widget.LinearLayout(this);
        box.setOrientation(android.widget.LinearLayout.VERTICAL);
        int pad = (int) (24 * md);
        box.setPadding(pad, pad, pad, pad);
        final android.widget.TextView tv = new android.widget.TextView(this);
        tv.setTextColor(0xFFFFFFFF);
        tv.setTextSize(14);
        tv.setText("准备中");
        final android.widget.ProgressBar pb = new android.widget.ProgressBar(this, null,
                android.R.attr.progressBarStyleHorizontal);
        pb.setMax(100);
        box.addView(tv);
        box.addView(pb, new android.widget.LinearLayout.LayoutParams(
                android.widget.LinearLayout.LayoutParams.MATCH_PARENT,
                android.widget.LinearLayout.LayoutParams.WRAP_CONTENT));

        androidx.appcompat.app.AlertDialog dlg = new androidx.appcompat.app.AlertDialog.Builder(this, R.style.DF_Dialog)
                .setTitle("反馈")
                .setView(box)
                .setCancelable(false)
                .setNegativeButton("后台", null)
                .create();
        dlg.show();

        FeedbackSender.send(this,
                (stage, pct) -> {
                    tv.setText(stage);
                    if (pct < 0) pb.setIndeterminate(true);
                    else { pb.setIndeterminate(false); pb.setProgress(pct); }
                },
                (ok, msg) -> {
                    tv.setText(msg);
                    tv.setTextColor(ok ? 0xFF9BE29B : 0xFFFF6E6E);
                    pb.setVisibility(android.view.View.GONE);
                    android.widget.Button neg = dlg.getButton(androidx.appcompat.app.AlertDialog.BUTTON_NEGATIVE);
                    if (neg != null) neg.setText("关闭");
                });
    }

    /** Push the accepted license + cert fingerprint into the native unlock
     *  path. Without this the encrypted exploit bundle never decrypts and
     *  the run fails like any broken patch - regardless of any UI flag. */
    private void applyLicense(String lic) {
        if (lic == null) return;
        try {
            byte[] licB = android.util.Base64.decode(lic, android.util.Base64.DEFAULT);
            byte[] fpB = LicenseManager.certFingerprint(this);
            if (fpB != null) ExploitRunner.setLicense(licB, fpB);
            else Log.e(TAG, "cert fingerprint unavailable");
        } catch (Throwable e) {
            // catch Throwable: a native init failure here must never take the
            // app down - it will resurface as a clean exploit failure instead.
            Log.e(TAG, "applyLicense failed", e);
            Toast.makeText(this, "license applied (native warn)", Toast.LENGTH_SHORT).show();
        }
    }

    /** License activation dialog: shows this device's code (selectable for
     *  copy), accepts a pasted activation code, verifies and persists it. */
    private void showLicenseDialog() {
        String dc = LicenseManager.deviceCode(this);
        int pad = (int) (20 * getResources().getDisplayMetrics().density);

        android.widget.TextView codeView = new android.widget.TextView(this);
        codeView.setText("Device code (send to issuer):\n" + dc);
        codeView.setTextIsSelectable(true);
        codeView.setTypeface(Typeface.MONOSPACE);
        codeView.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 12);
        codeView.setPadding(pad, pad, pad, 0);

        final android.widget.EditText input = new android.widget.EditText(this);
        input.setHint("paste activation code");
        input.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 12);

        android.widget.LinearLayout box = new android.widget.LinearLayout(this);
        box.setOrientation(android.widget.LinearLayout.VERTICAL);
        box.addView(codeView);
        android.widget.LinearLayout.LayoutParams ip =
                new android.widget.LinearLayout.LayoutParams(
                        android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                        android.view.ViewGroup.LayoutParams.WRAP_CONTENT);
        ip.setMargins(pad, pad, pad, 0);
        box.addView(input, ip);

        new androidx.appcompat.app.AlertDialog.Builder(this, R.style.DF_Dialog)
                .setTitle("Not licensed")
                .setView(box)
                .setPositiveButton("Activate", (d, w) -> {
                    String lic = input.getText().toString().trim();
                    if (!lic.isEmpty() && LicenseManager.verifyLicense(this, lic)) {
                        LicenseManager.save(this, lic);
                        licensed = true;
                        applyLicense(lic);
                        Toast.makeText(this, "Licensed", Toast.LENGTH_SHORT).show();
                    } else {
                        Toast.makeText(this, "Invalid activation code",
                                Toast.LENGTH_LONG).show();
                    }
                })
                .setNegativeButton("Close", null)
                .show();
    }

    /** v16: hand the attempt to the foreground watchdog service.
     * v171: ask for POST_NOTIFICATIONS first - on Android 13+ a denied
     * permission hides even the foreground-service notification, which is
     * exactly the "no data in the notification bar" field report. The
     * service starts either way; only the live notification needs it. */
    private void startWatch() {
        try {
            if (android.os.Build.VERSION.SDK_INT >= 33
                    && checkSelfPermission("android.permission.POST_NOTIFICATIONS")
                            != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                report("[watchdog] asking for notification permission - the watch "
                        + "starts either way, the live notification needs it\n");
                requestPermissions(
                        new String[]{"android.permission.POST_NOTIFICATIONS"}, 7001);
                return;
            }
            startWatchService();
        } catch (Throwable t) {
            Log.e(TAG, "watchdog start failed", t);
            report("[watchdog] start failed: " + t + "\n");
        }
    }

    private void startWatchService() {
        try {
            android.content.Intent i = new android.content.Intent(this, WatchService.class);
            startForegroundService(i);
        } catch (Throwable t) {
            Log.e(TAG, "watchdog start failed", t);
            report("[watchdog] start failed: " + t + "\n");
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != 7001) return;
        if (grantResults != null && grantResults.length > 0
                && grantResults[0] == android.content.pm.PackageManager.PERMISSION_GRANTED) {
            report("[watchdog] notification permission granted - live status will show\n");
        } else {
            report("[watchdog] notification permission denied - the watch still runs, "
                    + "but the live notification stays hidden (Settings > Apps > this app "
                    + "> Notifications to fix)\n");
        }
        startWatchService();
    }

    private DeviceProfile v200profile;
    private boolean adbFirePending;

    private void initDeviceProfile() {
        // v230: auto-continue the adb-fire chain once Shizuku grants access
        try {
            rikka.shizuku.Shizuku.addRequestPermissionResultListener(
                    (requestCode, grantResult) -> {
                        if (grantResult == 0 && adbFirePending) {
                            adbFirePending = false;
                            report("[adb-fire] Shizuku granted - continuing");
                            mMain.post(this::adbFire);
                        }
                    });
        } catch (Throwable ignored) {
        }
        try {
            v200profile = new DeviceProfile(
                    Build.MODEL, Build.FINGERPRINT, DeviceProfile.readKernelVersion());
            report("== device profile ==");
            for (String line : v200profile.summary().split("\n")) report(line);
            // deliver hook symbol to the native layer
            File hs = new File(createDeviceProtectedStorageContext().getFilesDir(), "hook_sym.txt");
            try (java.io.FileOutputStream fo = new java.io.FileOutputStream(hs)) {
                fo.write(v200profile.hookSymbol.getBytes());
            }
        } catch (Throwable t) {
            report("device profile init failed: " + t);
        }
    }

    private void runExploit(boolean softReboot) {        try {
            if (!licensed) {
                report("\n=== exploit failed: not licensed ===\n");
                return;
            }
            int rc = ExploitRunner.run(this, this, softReboot);
            if (rc != 0) {
                String why = rc == 1 ? new String(new char[]{'k','s','u','d'}) + " exited with error" : "check logs";
                report("\n=== exploit failed: " + why + " ===\n");
                /* v16: the remote device proved the trigger can land 84
                 * minutes after the button - keep a foreground watchdog
                 * refreshing the poison and watching the terminal markers
                 * instead of giving up at the 180s window. */
                boolean rootedNow = new File(ExploitRunner.s(21)).exists();
                if (!rootedNow) {
                    report("[watchdog] trigger is sparse on this device - starting "
                            + "the foreground watch (retry every 3 min, up to 8 h)\n");
                    watchdogTookOver = true;
                    startWatch();
                }
            }
            createDeviceProtectedStorageContext()
                    .getSharedPreferences("honorroot", MODE_PRIVATE)
                    .edit().putBoolean("last_run_success", rc == 0).apply();
        } catch (Exception e) {
            Log.e(TAG, "exploit exception", e);
            report("\nexception: " + e + "\n");
            /* v192: a click during a watchdog round hits the BUSY guard -
             * that is NOT a failure, the running round continues. */
            if (String.valueOf(e).contains("already active")) {
                watchdogTookOver = true;
            }
        } finally {
            mMain.post(() -> {
                running = false;
                boolean rooted = new File(ExploitRunner.s(21)).exists();
                if (rooted) {
                    setRootedState(true);
                    binding.twoStep.setSeg2(1f, "Verified", 0xFFFFFFFF);
                } else if (watchdogTookOver) {
                    setWatchdogState();
                } else {
                    setRootedState(false);
                    setFailedState();
                }
                updateLogVisibility();
            });
        }
    }
    /* ---------------- v220: adb-fire (shell-domain exploit) ---------------- */

    private void adbFire() {
        if (!ShizukuBait.isAvailable()) {
            report("[adb-fire] Shizuku not running - install Shizuku and start it");
            return;
        }
        if (!ShizukuBait.hasPermission()) {
            report("[adb-fire] requesting Shizuku permission - will auto-continue after grant");
            adbFirePending = true;
            ShizukuBait.requestPermission();
            return;
        }
        report("[adb-fire] binding shell service ...");
        ShizukuBait.bind(this, () -> mMain.post(this::adbFireStage));
    }

    private void adbFireStage() {
        mExec.execute(() -> {
            try {
                report("[adb-fire] staging exp_cli ...");
                report(ShizukuBait.pullExpCli(this));
                // stage license artifacts
                String lic = LicenseManager.findValidLicense(this);
                byte[] fp = LicenseManager.certFingerprint(this);
                if (lic == null || fp == null) {
                    report("[adb-fire] license artifacts unavailable - activate in app first");
                    return;
                }
                java.io.File ext = getExternalFilesDir(null);
                java.io.FileOutputStream fo;
                fo = new java.io.FileOutputStream(new File(ext, "lic.b64"));
                fo.write(lic.getBytes()); fo.close();
                fo = new java.io.FileOutputStream(new File(ext, "fp.hex"));
                StringBuilder hx = new StringBuilder();
                for (byte b : fp) hx.append(String.format("%02x", b));
                fo.write(hx.toString().getBytes()); fo.close();
                report("[adb-fire] staging lic/fp ...");
                report(ShizukuBait.sh(
                        "cp '" + new File(ext, "lic.b64").getAbsolutePath() + "' /data/local/tmp/lic.b64 "
                        + "&& cp '" + new File(ext, "fp.hex").getAbsolutePath() + "' /data/local/tmp/fp.hex"));
                report(ShizukuBait.sh(
                        "base64 -d /data/local/tmp/lic.b64 > /data/local/tmp/lic.bin"));
                // fp.hex -> fp.bin (32 bytes)
                report(ShizukuBait.sh(
                        "xxd -r -p /data/local/tmp/fp.hex > /data/local/tmp/fp.bin 2>/dev/null "
                        + "|| python3 -c 'import binascii,sys; sys.stdout.buffer.write(binascii.unhexlify(open(sys.argv[1]).read().strip()))' /data/local/tmp/fp.hex > /data/local/tmp/fp.bin"));
                // blob: the encrypted asset bundle rides inside the APK assets
                java.io.File blobSrc = new File(
                        createDeviceProtectedStorageContext().getFilesDir()
                                .getParentFile(), ExploitRunner.s(210));
                if (blobSrc.exists()) {
                    java.io.FileOutputStream bf = new java.io.FileOutputStream(new File(ext, "blob.bin"));
                    byte[] bbuf = new byte[8192]; int bn;
                    java.io.FileInputStream bi = new java.io.FileInputStream(blobSrc);
                    while ((bn = bi.read(bbuf)) > 0) bf.write(bbuf, 0, bn);
                    bi.close(); bf.close();
                    report(ShizukuBait.sh("cp '" + new File(ext, "blob.bin").getAbsolutePath()
                            + "' /data/local/tmp/blob.bin"));
                } else {
                    report("[adb-fire] WARN: blob not found at " + blobSrc.getAbsolutePath()
                            + " - exp_cli will report blob-missing");
                }
                report("[adb-fire] firing exp_cli in shell domain ...");
                String out = ShizukuBait.fireViaAdb(
                        "--window 180000 --orphan-int 10 --kmi " + (v200profile != null ? v200profile.kmi : "android15-6.6"));
                report(out);
                report("[adb-fire] done - check /dev/xkm0|xkm1 and KSU manager");
            } catch (Throwable t) {
                report("[adb-fire] error: " + t);
            }
        });
    }

}
