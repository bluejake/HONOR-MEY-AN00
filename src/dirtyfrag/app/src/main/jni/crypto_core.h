/* crypto_core.h - license unlock + encrypted bundle access. Pure C, no JNI. */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* MEYLIC2 raw layout:  raw32 | sig256 | iv16 | enc_dk32 | mac16  = 352 */
#define LIC_RAW_LEN   352
#define LIC_CODE_LEN  32
#define LIC_SIG_LEN   256
#define LIC_IV_LEN    16
#define LIC_DK_LEN    32
#define LIC_MAC_LEN   16

/* fp: SHA-256 of the APK signing certificate (DER).
 * salt_extra: poisoning input from the tamper check; NULL = clean run.
 * blob: contents of payload.bin (DFENCRT1).
 * On success the bundle is held in memory and members become available.
 * Returns 0 on success; 1..8 = failure step (1 lic format, 2 KEK mac,
 * 3 blob magic, 4 blob len, 5 blob mac, 6 bundle magic, 7 entry/hash,
 * 8 alloc). Diagnostic field builds only. */
int lic_unlock(const uint8_t *lic, size_t lic_len,
               const uint8_t fp[32],
               const uint8_t *salt_extra, size_t salt_extra_len,
               const uint8_t *blob, size_t blob_len);

int lic_is_unlocked(void);

/* Member lookup. NULL when locked or absent. *out_len receives length. */
const uint8_t *lic_bundle_get(const char *name, size_t *out_len);

int lic_bundle_count(void);
const char *lic_bundle_name(int idx);          /* NUL-padded within 32B */
const uint8_t *lic_bundle_data(int idx, size_t *out_len);

/* splicehelper member (name resolved internally from masked constants) */
const uint8_t *lic_bundle_get_splicer(size_t *out_len);

/* Tamper switch: once set, member lookups are silently misdirected. */
void lic_set_poisoned(void);

/* Wipe + free the decrypted bundle (minimize plaintext window). */
void lic_scrub(void);
