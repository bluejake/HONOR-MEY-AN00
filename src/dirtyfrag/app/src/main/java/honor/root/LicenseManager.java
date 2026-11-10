package honor.root;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.provider.Settings;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

/**
 * Offline license gate for the MEY-AN00 build.
 *
 * Device code: SHA-256(ANDROID_ID | Build.FINGERPRINT), 64 hex chars upper.
 *   - ANDROID_ID is scoped per (signing key, user, device) on Android 8+;
 *     this app always ships the same bundled keystore, so the code is stable
 *     across reinstalls and app updates. Factory reset changes it.
 * License: Base64( raw32(device code) || RSA-2048/PKCS1v15-SHA256 signature
 *          over "MEYLIC1|" + deviceCodeHex ). 384 chars, one line.
 * Verification is fully offline against assets/public.pem.
 *
 * Generator (PC side, private key): license_kit/gen_license.py.
 */
public class LicenseManager {
    private static final String TAG = "honorroot";
    private static final String MAGIC = "MEYLIC1|";
    private static final int CODE_LEN = 32;   // raw SHA-256
    private static final int SIG_LEN = 256;   // RSA-2048
    private static final int IV_LEN = 16;     // AES-CTR initial counter block
    private static final int DK_LEN = 32;     // bundle key (carried encrypted)
    private static final int MAC_LEN = 16;    // KEK-domain HMAC truncation
    private static final int RAW_LEN = CODE_LEN + SIG_LEN + IV_LEN + DK_LEN + MAC_LEN; // 352

    /** Device-bound activation code: 64 uppercase hex chars. */
    public static String deviceCode(Context ctx) {
        String aid;
        try {
            aid = Settings.Secure.getString(ctx.getContentResolver(),
                    Settings.Secure.ANDROID_ID);
        } catch (Exception e) {
            aid = null;
        }
        if (aid == null || aid.isEmpty()) aid = "unknown";
        String basis = aid + "|" + android.os.Build.FINGERPRINT;
        try {
            byte[] d = MessageDigest.getInstance("SHA-256")
                    .digest(basis.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : d) sb.append(String.format("%02X", b));
            return sb.toString();
        } catch (Exception e) {
            Log.e(TAG, "deviceCode: digest failed", e);
            return "UNKNOWN";
        }
    }

    /* 公钥不再以 PEM 形式躺在 assets 里：native 侧解密 + SHA-256 完整性校验，
     * 资产被替换 => pk() 返回 null => 校验直接失败（堵死换公钥伪造激活码）。 */
    private static PublicKey publicKey(Context ctx) {
        try {
            byte[] der = ExploitRunner.pk();
            if (der == null) {
                Log.e(TAG, "publicKey: integrity check failed");
                return null;
            }
            return KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            Log.e(TAG, "publicKey: load failed", e);
            return null;
        }
    }

    /** Full verification: format + signature + device binding. */
    public static boolean verifyLicense(Context ctx, String license) {
        if (license == null) return false;
        license = license.trim();
        PublicKey key = publicKey(ctx);
        if (key == null) return false;
        try {
            byte[] raw = Base64.decode(license, Base64.DEFAULT);
            if (raw.length != RAW_LEN) {
                Log.i(TAG, "license: bad length " + raw.length);
                return false;
            }
            StringBuilder sb = new StringBuilder(64);
            for (int i = 0; i < CODE_LEN; i++)
                sb.append(String.format("%02X", raw[i]));
            String code = sb.toString();
            byte[] payload = (MAGIC + code).getBytes(StandardCharsets.UTF_8);
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initVerify(key);
            s.update(payload);
            if (!s.verify(raw, CODE_LEN, SIG_LEN)) {
                Log.i(TAG, "license: bad signature");
                return false;
            }
            String mine = deviceCode(ctx);
            if (!mine.equals(code)) {
                Log.i(TAG, "license: device mismatch (license=" + code
                        + " mine=" + mine + ")");
                return false;
            }
            return true;
        } catch (Exception e) {
            Log.i(TAG, "license: invalid (" + e + ")");
            return false;
        }
    }

    /** SHA-256 of the signing certificate (DER) - must match the fp the PC
     *  side used when issuing the license (keytool -list -v, SHA256 line).
     *  A repacked APK has a different cert, so the bundle never decrypts. */
    public static byte[] certFingerprint(Context ctx) {
        try {
            PackageManager pm = ctx.getPackageManager();
            PackageInfo pi = pm.getPackageInfo(ctx.getPackageName(),
                    PackageManager.GET_SIGNING_CERTIFICATES);
            if (pi.signingInfo == null) return null;
            android.content.pm.Signature[] sigs = pi.signingInfo.getApkContentsSigners();
            if (sigs == null || sigs.length == 0) return null;
            String hex = sigs[0].toCharsString();
            byte[] der = new byte[hex.length() / 2];
            for (int i = 0; i < der.length; i++)
                der[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            return MessageDigest.getInstance("SHA-256").digest(der);
        } catch (Exception e) {
            Log.e(TAG, "certFingerprint failed", e);
            return null;
        }
    }

    private static android.content.SharedPreferences prefs(Context ctx) {
        return ctx.createDeviceProtectedStorageContext()
                .getSharedPreferences("license", Context.MODE_PRIVATE);
    }

    public static void save(Context ctx, String license) {
        prefs(ctx).edit().putString("license", license).apply();
    }

    /** Accepted license or null. Sources: saved prefs, then the
     *  getExternalFilesDir()/license.txt drop (pushable over adb/MTP
     *  without any permission). */
    public static String findValidLicense(Context ctx) {
        String l = prefs(ctx).getString("license", null);
        if (l != null && verifyLicense(ctx, l)) return l;
        try {
            File f = new File(ctx.getExternalFilesDir(null), "license.txt");
            if (f.exists()) {
                try (FileInputStream in = new FileInputStream(f);
                     ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
                    byte[] buf = new byte[4096];
                    for (int n; (n = in.read(buf)) != -1; ) bos.write(buf, 0, n);
                    String cand = new String(bos.toByteArray(),
                            StandardCharsets.UTF_8).trim();
                    if (!cand.isEmpty() && verifyLicense(ctx, cand)) return cand;
                }
            }
        } catch (Exception ignored) { }
        return null;
    }

    public static boolean isLicensed(Context ctx) {
        return findValidLicense(ctx) != null;
    }
}
