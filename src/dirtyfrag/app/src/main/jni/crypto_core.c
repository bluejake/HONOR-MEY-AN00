/* crypto_core.c - license unlock (HKDF + AES-256-CTR + HMAC-SHA256) and
 * encrypted bundle access for the MEY-AN00 build.
 *
 * Trust model (frozen with license_kit/*.py):
 *   KEK       = HKDF-SHA256(ikm = raw32(device code),
 *                           salt = raw32 | cert_fp32 | extra32,
 *                           info = OBF(85))
 *   enc_dk    = AES-256-CTR(KEK, iv16, dk32)
 *   mac16     = HMAC-SHA256(KEK, iv16 || enc_dk32) [:16]
 *   payload: DFENCRT1 magic | u32 pt_len | u32 0 | iv16 | ct | mac32(HMAC dk)
 *   plaintext bundle: DFASSET1 magic | u32 count | u32 0 |
 *                     entries { name[32] u32 off u32 len } | members
 *
 * Hardening:
 *  - The AES S-box is never referenced in plaintext here; the license path
 *    uses the masked table from obf_data.h (per-byte XOR mask, generated).
 *  - Protocol strings (OBF(86)/OBF(87)/OBF(85)/OBF(88)) are
 *    XOR-masked constants; nothing comparable survives `strings`.
 *  - Post-decryption every member is checked against the SHA-256 table in
 *    bundle_hashes.h - a single flipped bit keeps the bundle locked.
 *  - A poisoned run (tamper detected) derives keys from a random extra salt
 *    AND lic_bundle_get returns wrong-member data: failures are silent,
 *    late, and indistinguishable from ordinary exploit failure.
 */
#include "crypto_core.h"
#include "obf_data.h"
#include "hmac_sha256.h"  /* sha256_* / hmac_sha256 */
#include "aes256.h"       /* _gmul / _add_rk only (no sbox use here) */
#include "bundle_hashes.h"
#include <stdlib.h>
#include <string.h>
#include "obf_strings.h"
#include "obf_rt.h"

/* ---- AES-256 forward with masked sbox ---- */

static void _lic_sub_bytes(uint8_t s[16]) {
    for (int i = 0; i < 16; i++) s[i] = OBF_SKEY(s[i]);
}

static void _lic_shift_rows(uint8_t s[16]) {
    uint8_t t;
    t = s[1];  s[1] = s[5];   s[5] = s[9];   s[9] = s[13];  s[13] = t;
    t = s[2];  s[2] = s[10];  s[10] = t;
    t = s[6];  s[6] = s[14];  s[14] = t;
    t = s[3];  s[3] = s[15];  s[15] = s[11]; s[11] = s[7];  s[7] = t;
}

static void _lic_mix_cols(uint8_t s[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t a = s[4*c], b = s[4*c+1], cc = s[4*c+2], d = s[4*c+3];
        s[4*c+0] = (uint8_t)(_gmul(2,a) ^ _gmul(3,b) ^ cc ^ d);
        s[4*c+1] = (uint8_t)(a ^ _gmul(2,b) ^ _gmul(3,cc) ^ d);
        s[4*c+2] = (uint8_t)(a ^ b ^ _gmul(2,cc) ^ _gmul(3,d));
        s[4*c+3] = (uint8_t)(_gmul(3,a) ^ b ^ cc ^ _gmul(2,d));
    }
}

static void _lic_expand(const uint8_t k[32], uint32_t rk[60]) {
    for (int i = 0; i < 8; i++)
        rk[i] = ((uint32_t)k[4*i]<<24)|((uint32_t)k[4*i+1]<<16)|
                ((uint32_t)k[4*i+2]<<8)|k[4*i+3];
    for (int i = 8; i < 60; i++) {
        uint32_t t = rk[i-1];
        if (i % 8 == 0) {
            t = ((uint32_t)OBF_SKEY((t>>16)&0xff)<<24)|((uint32_t)OBF_SKEY((t>>8)&0xff)<<16)|
                ((uint32_t)OBF_SKEY(t&0xff)<<8)|(uint32_t)OBF_SKEY((t>>24)&0xff);
            t ^= (uint32_t)_rcon[i/8] << 24;
        } else if (i % 8 == 4) {
            t = ((uint32_t)OBF_SKEY((t>>24)&0xff)<<24)|((uint32_t)OBF_SKEY((t>>16)&0xff)<<16)|
                ((uint32_t)OBF_SKEY((t>>8)&0xff)<<8)|(uint32_t)OBF_SKEY(t&0xff);
        }
        rk[i] = rk[i-8] ^ t;
    }
}

static void _lic_ecb_block(const uint8_t key[32], const uint8_t in[16],
                           uint8_t out[16]) {
    uint32_t rk[60];
    _lic_expand(key, rk);
    uint8_t s[16];
    memcpy(s, in, 16);
    _add_rk(s, &rk[0]);
    for (int r = 1; r < 14; r++) {
        _lic_sub_bytes(s); _lic_shift_rows(s); _lic_mix_cols(s);
        _add_rk(s, &rk[4*r]);
    }
    _lic_sub_bytes(s); _lic_shift_rows(s); _add_rk(s, &rk[56]);
    memcpy(out, s, 16);
}

/* In-place CTR. iv = full 128-bit initial counter block, big-endian
 * increment. Byte-compatible with python cryptography modes.CTR(iv16). */
static void lic_aes_ctr(const uint8_t key[32], const uint8_t iv[16],
                        uint8_t *buf, size_t len) {
    uint8_t ctrb[16], ks[16];
    memcpy(ctrb, iv, 16);
    for (size_t off = 0; off < len; off += 16) {
        _lic_ecb_block(key, ctrb, ks);
        size_t n = (len - off < 16) ? (len - off) : 16;
        for (size_t i = 0; i < n; i++) buf[off + i] ^= ks[i];
        for (int i = 15; i >= 0; i--) if (++ctrb[i]) break;
    }
}

/* ---- HKDF-SHA256 (RFC 5869) ---- */

static void lic_hkdf(const uint8_t *ikm, size_t ikm_len,
                     const uint8_t *salt, size_t salt_len,
                     const uint8_t *info, size_t info_len,
                     uint8_t *out, size_t out_len) {
    uint8_t prk[32], t[32];
    size_t t_len = 0, pos = 0;
    uint8_t ctr = 1;
    uint8_t msg[32 + 96 + 1];

    if (!salt || !salt_len) {
        static const uint8_t zeros[32] = {0};
        salt = zeros; salt_len = 32;
    }
    hmac_sha256(salt, (int)salt_len, ikm, (int)ikm_len, prk);
    if (info_len > 96) info_len = 96;

    while (pos < out_len) {
        memcpy(msg, t, t_len);
        memcpy(msg + t_len, info, info_len);
        msg[t_len + info_len] = ctr;
        hmac_sha256(prk, 32, msg, (int)(t_len + info_len + 1), t);
        t_len = 32;
        size_t n = (out_len - pos < 32) ? (out_len - pos) : 32;
        memcpy(out + pos, t, n);
        pos += n;
        ctr++;
    }
}

/* ---- state ---- */

static int      g_unlocked;
static int      g_poison;          /* set by the tamper check points */
static uint8_t *g_pt;
static uint32_t g_pt_len, g_count;
static const uint8_t *g_entries, *g_payload;

static uint32_t _le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void _deobf(uint8_t *out, const uint8_t *src, int len, uint8_t key) {
    /* volatile: stop the optimizer from constant-folding the XOR loop back
     * into plaintext .rodata (audit caught exactly that at -O2). */
    volatile uint8_t k = key;
    for (int i = 0; i < len; i++) out[i] = (uint8_t)(src[i] ^ k);
    out[len] = 0;
}

void lic_set_poisoned(void) { g_poison = 1; }

int lic_unlock(const uint8_t *lic, size_t lic_len,
               const uint8_t fp[32],
               const uint8_t *salt_extra, size_t salt_extra_len,
               const uint8_t *blob, size_t blob_len) {
    g_unlocked = 0;

    JUNK();
    if (!lic || MBA_NEQ((uint32_t)lic_len, (uint32_t)LIC_RAW_LEN) || !fp || !blob ||
        blob_len < MBA_ADD(MBA_ADD(16u, 16u), MBA_ADD(32u, 40u)))
        return 1;

    const uint8_t *raw = lic;
    const uint8_t *iv  = lic + LIC_CODE_LEN + LIC_SIG_LEN;
    const uint8_t *edk = iv + LIC_IV_LEN;
    const uint8_t *mac = edk + LIC_DK_LEN;

    uint8_t salt[32 + 32 + 32];
    memcpy(salt, raw, 32);
    memcpy(salt + 32, fp, 32);
    /* MEY FIX: the issuer (license_kit/gen_license.py) derives the KEK over a
     * 96-byte salt = raw32 | fp32 | tail32, tail32 = zeros on a clean run and
     * the 32-byte poison value on a tampered run. The original code used a
     * 64-byte salt whenever salt_extra was NULL, so the KEK never matched the
     * issuer's and every unlock died at rc=2 (KEK mac) with a perfectly valid
     * license. Proven offline: salt64 => mac mismatch, salt96 => mac match. */
    uint8_t tail[32];
    memset(tail, 0, sizeof tail);
    if (salt_extra && salt_extra_len) {
        if (salt_extra_len > 32) salt_extra_len = 32;
        memcpy(tail, salt_extra, salt_extra_len);
    }
    memcpy(salt + 64, tail, 32);
    size_t salt_len = 96;
    uint8_t info[4];
    _deobf(info, _obf_s_INF, OBF_S_INF_LEN, OBF_S_INF_KEY);
    uint8_t kek[32];
    lic_hkdf(raw, 32, salt, salt_len, info, OBF_S_INF_LEN, kek, 32);

    uint8_t calc[32];
    hmac_sha256(kek, 32, iv, LIC_IV_LEN + LIC_DK_LEN, calc);
    if (OPAQUE_T() && memcmp(calc, mac, LIC_MAC_LEN) != 0) return 2;
    JUNK();

    uint8_t dk[LIC_DK_LEN];
    memcpy(dk, edk, LIC_DK_LEN);
    lic_aes_ctr(kek, iv, dk, LIC_DK_LEN);

    uint8_t m_enc[9], m_ast[9];
    _deobf(m_enc, _obf_s_ENC, OBF_S_ENC_LEN, OBF_S_ENC_KEY);
    _deobf(m_ast, _obf_s_AST, OBF_S_AST_LEN, OBF_S_AST_KEY);

    if (OPAQUE_T() && memcmp(blob, m_enc, 8) != 0) return 3;
    uint32_t pt_len = _le32(blob + 8);
    if (pt_len < 16 + 40 || (size_t)(16 + 16 + pt_len + 32) != blob_len)
        return 4;
    const uint8_t *biv  = blob + 16;
    const uint8_t *ct   = blob + 32;
    const uint8_t *bmac = blob + 32 + pt_len;
    hmac_sha256(dk, 32, blob, (int)(16 + 16 + pt_len), calc);
    if (OPAQUE_T() && memcmp(calc, bmac, 32) != 0) return 5;

    uint8_t *pt = malloc(pt_len);
    if (!pt) return 8;
    memcpy(pt, ct, pt_len);
    lic_aes_ctr(dk, biv, pt, pt_len);

    if (memcmp(pt, m_ast, 8) != 0) { free(pt); return 6; }
    uint32_t count = _le32(pt + 8);
    if (count == 0 || count > 64 ||
        (size_t)(16 + count * 40) > pt_len) { free(pt); return 8; }

    const uint8_t *entries = pt + 16;
    const uint8_t *payload = pt + 16 + count * 40;
    size_t payload_len = pt_len - 16 - count * 40;
    sha256_ctx hc;
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *e = entries + i * 40;
        uint32_t off = _le32(e + 32), len = _le32(e + 36);
        if (off > payload_len || len > payload_len - off) { free(pt); return 7; }
        uint8_t dg[32];
        sha256_init(&hc);
        sha256_update(&hc, payload + off, len);
        sha256_final(&hc, dg);
        /* order-only mapping: bundle entry i <-> _bundle_sha[i]; a mismatch
         * (wrong order, tampered member, bad decrypt) keeps it locked */
        if (i >= BUNDLE_COUNT || memcmp(dg, _bundle_sha[i], 32) != 0) {
            free(pt); return 7;
        }
    }

    g_pt = pt; g_pt_len = pt_len; g_count = count;
    g_entries = entries; g_payload = payload;
    g_unlocked = 1;
    /* MEY FIX: contract in crypto_core.h says 0 = success, 1..8 = failure
     * step, and exp.c:n0() gates on (rc == 0). Returning 1 here made n0()
     * report failure for a perfectly valid license, so runExploit() threw
     * "unlock failed" before n1() was ever reached - 100% reproducible,
     * independent of the license contents. */
    return 0;
}

int lic_is_unlocked(void) { return g_unlocked; }

const uint8_t *lic_bundle_get(const char *name, size_t *out_len) {
    if (!g_unlocked || !name) return NULL;
    int idx = -1;
    for (uint32_t i = 0; i < g_count; i++) {
        const uint8_t *e = g_entries + i * 40;
        if (strncmp((const char *)e, name, 32) == 0) { idx = (int)i; break; }
    }
    if (idx < 0) return NULL;
    /* Misdirection poison: a tampered run gets a DIFFERENT, valid-looking
     * member - the KO won't load, the failure is silent and late. */
    if (g_poison && g_count > 1)
        idx = (idx + 1) % (int)g_count;
    const uint8_t *e = g_entries + (size_t)idx * 40;
    uint32_t off = _le32(e + 32), len = _le32(e + 36);
    if (out_len) *out_len = len;
    return g_payload + off;
}

const uint8_t *lic_bundle_get_splicer(size_t *out_len) {
    uint8_t nm[16];
    _deobf(nm, _obf_s_SPL, OBF_S_SPL_LEN, OBF_S_SPL_KEY);
    return lic_bundle_get((const char *)nm, out_len);
}

int lic_bundle_count(void) { return g_unlocked ? (int)g_count : 0; }

const char *lic_bundle_name(int idx) {
    if (!g_unlocked || idx < 0 || (uint32_t)idx >= g_count) return NULL;
    return (const char *)(g_entries + (size_t)idx * 40);
}

const uint8_t *lic_bundle_data(int idx, size_t *out_len) {
    if (!g_unlocked || idx < 0 || (uint32_t)idx >= g_count) return NULL;
    const uint8_t *e = g_entries + (size_t)idx * 40;
    uint32_t off = _le32(e + 32), len = _le32(e + 36);
    if (out_len) *out_len = len;
    return g_payload + off;
}

/* Minimize the plaintext window: wipe the decrypted bundle. Called once the
 * KO/splicehelper bytes have been copied out for patching. */
void lic_scrub(void) {
    if (g_pt) {
        memset(g_pt, 0, g_pt_len);
        free(g_pt);
        g_pt = NULL;
    }
    g_pt_len = 0; g_count = 0; g_entries = NULL; g_payload = NULL;
    g_unlocked = 0;
}
