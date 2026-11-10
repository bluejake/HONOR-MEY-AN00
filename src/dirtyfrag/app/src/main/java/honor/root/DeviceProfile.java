package honor.root;

import android.os.Build;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * v200: universal device profile - identifies the device family, kernel
 * generation and KMI from Build.FINGERPRINT + /proc/version, then selects
 * the exploit strategy (hook symbol, KO asset) without user input.
 *
 * Families known from the adaptation batch (19 init samples analyzed):
 *   MEY-AN00 / NDL2-xxx   -> Honor 500 line   (6.6.89 or 6.6.118)
 *   DNN-AN00 / HEY4-xxx   -> Honor 400 line   (6.6.118)
 *   HEY3-xxx              -> Honor 300 line   (6.6.118)
 *   ELN2-xxx              -> Honor Pad line   (6.6.118)
 * Kernel generations:
 *   A: 6.6.118-android15-8 (init reaps orphans through ostream::sentry)
 *   B: 6.6.89-android15-8  (init imports sentry, zero runtime calls found)
 *   C: 6.12.23-android16-5 (verified upstream, structure A-like)
 */
public class DeviceProfile {

    public final String model;
    public final String fingerprint;
    public final String kernel;
    public final String family;
    public final String generation;   // "A" | "B" | "C" | "?"
    public final String kmi;          // e.g. "android15-6.6"
    public final String hookSymbol;   // which PLT symbol to hook
    public final String strategy;     // human-readable plan
    public final boolean supported;

    public DeviceProfile(String model_, String fingerprint_, String kernelStr) {
        model = model_;
        fingerprint = fingerprint_;
        kernel = kernelStr == null ? "" : kernelStr;

        // ---- family from fingerprint device codename ----
        String fam = "?";
        if (fingerprint.contains(":16/")) {
            if (kernel.contains("6.6.118")) fam = guessFamilyByModel();
            else if (kernel.contains("6.6.89")) fam = "honor-500b";
            else if (kernel.contains("6.12")) fam = "honor-misc";
        }
        family = fam;

        // ---- kernel generation from version string ----
        String gen = "?";
        if (kernel.contains("6.6.118-android15-8")) gen = "A";
        else if (kernel.contains("6.6.89-android15-8")) gen = "B";
        else if (kernel.contains("6.12.23-android16")) gen = "C";
        generation = gen;

        // ---- KMI extraction for KO selection ----
        String k = "?";
        Matcher m = Pattern.compile("android(\\d+)-(\\d+\\.\\d+)").matcher(kernel);
        if (m.find()) k = "android" + m.group(1) + "-" + m.group(2);
        kmi = k;

        // ---- hook symbol strategy ----
        // Gen A (6.6.118): init reaps orphans through ostream::sentry (2x verified).
        // Gen B/C: sentry has a call site too, but the runtime output event is
        // sparse; ios_base::init migration is EXPERIMENTAL (v1.9.6 boot loop on
        // gen A) - default to sentry for B/C until the Shizuku bait is proven.
        String sym;
        boolean sup;
        switch (gen) {
            case "A":
                sym = "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_";
                sup = true;
                strategy = "sentry hook + multi-orphan bait (verified x4)";
                break;
            case "B":
                sym = "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_";
                sup = true;
                strategy = "sentry hook (call site verified) + Shizuku orphan bait "
                         + "(runtime output event sparse - use reboot-timing)";
                break;
            case "C":
                sym = "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_";
                sup = true;
                strategy = "sentry hook (upstream verified on 6.12)";
                break;
            default:
                sym = "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_";
                sup = false;
                strategy = "unknown kernel - experimental";
                break;
        }
        hookSymbol = sym;
        supported = sup;
    }

    private String guessFamilyByModel() {
        if (model.startsWith("MEY")) return "honor-500";
        if (model.startsWith("DNN")) return "honor-400";
        if (model.startsWith("NDL")) return "honor-500-variant";
        if (model.startsWith("HEY4")) return "honor-400-variant";
        if (model.startsWith("HEY3")) return "honor-300";
        if (model.startsWith("ELN")) return "honor-pad";
        return "honor-misc";
    }

    public static String readKernelVersion() {
        try {
            BufferedReader r = new BufferedReader(new FileReader("/proc/version"), 512);
            String line = r.readLine();
            r.close();
            return line;
        } catch (Exception e) {
            return "";
        }
    }

    public String summary() {
        return "model: " + model
                + "\nfamily: " + family
                + "\nkernel: " + kernel
                + "\nKMI: " + kmi
                + "\ngeneration: " + generation
                + "\nsupported: " + supported
                + "\nstrategy: " + strategy
                + "\nhook: " + hookSymbol;
    }
}
