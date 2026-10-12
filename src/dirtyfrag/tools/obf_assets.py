#!/usr/bin/env python3
"""资产层加固：改名 + 公钥去 PEM 外壳并加密 + 生成 native 名字表。

做什么：
  1. assets/ 下所有会暴露意图的名字（public.pem / kernelsu-<kmi>.ko / ksu-daemon）
     改成中性名，原名在 APK 里彻底消失。
  2. public.pem -> 剥掉 PEM armor 得到 DER -> XOR 加密 -> 落盘为中性名文件。
     APK 里再也 grep 不到 "-----BEGIN PUBLIC KEY-----"。
  3. 生成 jni/asset_names.c：
       - asset_name(id)  资产名 / 目标名 / KMI 串，全部走 OBF 表（dex 里无明文）
       - pk_decode()     运行时解密 DER，并用内建 SHA-256 校验；
                         资产被替换则解密结果对不上 hash，直接失败（防伪造激活码）

用法:  python tools/obf_assets.py            # 执行（默认 dry-run=false）
       python tools/obf_assets.py --dry      # 只打印计划
改动后必须重跑 tools/obf_strings_gen.py --append <jni> asset_names.c 补齐 OBF id。
"""
import base64, hashlib, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.join(ROOT, 'app', 'src', 'main', 'assets')
JNI = os.path.join(ROOT, 'app', 'src', 'main', 'jni')

# 中性名（O0oIl1 字符集，肉眼难辨、不携带任何语义）
NAMES = {
    'pk':     'Ol00O',
    'daemon': 'O0l1O',
    'script': 'O0l0O',     # assets/tool：4KB UMH shell 脚本，明文等于把攻击链摊开
    'webhook': 'O1l0O',    # 反馈通道 webhook URL 两行（upload_media + send），明文=key 本体
}
KO_NAMES = ['Ol10O', 'Oll0O', 'Ol1lO', 'Ol01O', 'O101O', 'O110O', 'O11OO']

KMIS = ['android12-5.10', 'android13-5.10', 'android13-5.15', 'android14-5.15',
        'android15-6.6', 'android16-6.12', 'android17-6.18']

# 目标名（落到设备私有目录的文件名）—— 值必须保持原语义，只是不再躺进 dex
DEST_PREFIX = 'kernelsu-'
DEST_SUFFIX = '.ko'
DEST_DAEMON = 'ksu-daemon'
DEST_SCRIPT = 'tool'
# libcxx.S 的互斥文件：Java 侧用它判断"已 root"，同样不能躺进 dex
MUTEX_FILE = '/dev/xkm'
# 管理器包名（启动/卸载用），明文等于告诉逆向者在装什么
MGR_PKGS = ['me.weishu.kernelsu', 'com.rifsxd.ksunext', 'me.bmax.apatch']

# 加密资产的文件头哨兵：用来判断"这个文件已经加密过"，保证脚本可重跑。
# 没有这个头 = 明文资产，运行时原样拷贝（同一套代码兼容加密/明文两种形态）。
ASSET_MAGIC = b'\x00OBFAS\x01\x00'

PK_KEY   = 0xA5        # 公钥密文流密钥
TOOL_KEY = 0x5A        # UMH 脚本密文流密钥

BIG_KEY  = 0x3C        # KO / daemon 的块流密钥（周期 64 KiB）
BIG_KS_LEN = 65536


def big_keystream(skey, n=BIG_KS_LEN):
    """64 KiB 周期流密钥。够长到看不出明文，又不至于让 .so 变胖（运行时生成）。

    C 侧 asset_ks() 必须用完全相同的公式，否则解密出来是噪声。
    """
    out = bytearray(n)
    for i in range(n):
        out[i] = (skey[(i + BIG_KEY) & 0xFF]
                  ^ ((i * 31) & 0xFF)
                  ^ skey[(i >> 8) & 0xFF]
                  ^ ((i >> 12) & 0xFF)) & 0xFF
    return bytes(out)


def load_skey(d):
    od = open(os.path.join(d, 'obf_data.h'), encoding='utf-8').read()
    def arr(name):
        m = re.search(name + r'\[256\] = \{(.*?)\}', od, re.S)
        return [int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', m.group(1))]
    sb, mk = arr('_obf_sbox'), arr('_obf_sbox_mask')
    return [sb[i] ^ mk[i] for i in range(256)]


def keystream(skey, k, n):
    return bytes((k ^ skey[(i + k) & 0xFF] ^ (i * 31)) & 0xFF for i in range(n))


def sha256(b):
    return hashlib.sha256(b).digest()


def xor(ks, data):
    return bytes(a ^ b for a, b in zip(data, ks))


def sniff_script(data, ks):
    """tool 资产没有长度不变的头可用，靠内容嗅探判断是明文还是密文。

    UMH 脚本一定以 "#!/system/bin/sh" 开头，据此区分。返回 (is_enc, plaintext)。
    """
    if data[:8] == ASSET_MAGIC:
        return True, xor(ks, data[8:])
    if data[:2] == b'#!':
        return False, data
    return True, xor(ks, data)


def main():
    dry = '--dry' in sys.argv
    noenc = '--no-encrypt' in sys.argv   # 交付"先跑通"版本：资产落明文，运行时零解密
    skey = load_skey(JNI)
    print('action =', 'DRY-RUN' if dry else 'APPLY')

    # ── 1. 公钥：PEM -> DER -> 加密（幂等：已加固则从密文还原 DER）─────────
    pem_path = os.path.join(ASSETS, 'public.pem')
    enc_path = os.path.join(ASSETS, NAMES['pk'])
    if os.path.exists(pem_path):
        pem = open(pem_path, encoding='ascii').read()
        body = re.sub(r'\s', '', re.sub(r'-----(BEGIN|END) PUBLIC KEY-----', '', pem))
        der = base64.b64decode(body)
        print('public.pem -> DER %d bytes, SHA-256=%s' % (len(der), sha256(der).hex()))
        if not dry:
            os.remove(pem_path)
    elif os.path.exists(enc_path):
        raw = open(enc_path, 'rb').read()
        der = xor(keystream(skey, PK_KEY, len(raw)), raw)
        print('public key 已加固，从 %s 还原 DER %d bytes, SHA-256=%s'
              % (NAMES['pk'], len(der), sha256(der).hex()))
    else:
        raise SystemExit('既没有 public.pem 也没有 %s —— 无法继续' % NAMES['pk'])
    enc = xor(keystream(skey, PK_KEY, len(der)), der)
    if not dry:
        open(enc_path, 'wb').write(enc)
        print('  wrote assets/%s (%d bytes)' % (NAMES['pk'], len(enc)))

    # ── 2. UMH 脚本：加密 + 改名（幂等；--no-encrypt 时落明文）─────────────
    tool_path = os.path.join(ASSETS, 'tool')
    tool_enc_path = os.path.join(ASSETS, NAMES['script'])
    if os.path.exists(tool_path):
        script = open(tool_path, 'rb').read()
        print('tool -> %d bytes, 明文含 %r 等指纹'
              % (len(script), [k for k in (b'KernelSU', b'kernelsu-', b'ksu-daemon') if k in script]))
        if not dry:
            os.remove(tool_path)
    elif os.path.exists(tool_enc_path):
        raw = open(tool_enc_path, 'rb').read()
        was_enc, script = sniff_script(raw, keystream(skey, TOOL_KEY, len(raw)))
        print('tool: %s 态，还原 %d bytes，开头 %r'
              % ('密文' if was_enc else '明文', len(script), script[:20]))
    else:
        raise SystemExit('既没有 tool 也没有 %s —— 无法继续' % NAMES['script'])
    # ★ MEY: UMH 脚本必须 LF。该文件曾在 Windows 被文本模式写过一次，114 个
    # CRLF 跟着加密/解密一路走：shebang 变 '#!/system/bin/sh\r'，execve 直接
    # ENOENT -> 模块 `touch /dev/xkm1` ->「ksud exited with error」，且
    # tool.log 永不生成（脚本根本没被执行）。断言保证此类问题绝不再溜进构建。
    if b'\r' in script:
        script = script.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
        print('  ★ 行尾规范化: CRLF -> LF')
    assert b'\r' not in script, 'tool 脚本仍含 \\r —— shebang 会坏'
    assert script.startswith(b'#!/system/bin/sh\n'), 'shebang 损坏: %r' % script[:24]
    if noenc:
        tool_out = script
        print('  --no-encrypt: 落明文 %d bytes' % len(tool_out))
    else:
        tool_out = ASSET_MAGIC + xor(keystream(skey, TOOL_KEY, len(script)), script)
        print('  wrote 密文 assets/%s (%d bytes)' % (NAMES['script'], len(tool_out)))
    if not dry:
        open(tool_enc_path, 'wb').write(tool_out)

    # ── 3. KO / daemon 改名 + 内容加密 ─────────────────────────────────────
    #    加密是幂等的：同一个 keystream 异或两次回到原文。
    #    判断"是否已加密"靠哨兵：密文文件头 8 字节固定为 ASSET_MAGIC。
    ks = big_keystream(skey)
    big = [(os.path.join(ASSETS, n), n)
           for n in KO_NAMES + [NAMES['daemon'], NAMES['webhook']]]
    for kmi, new in zip(KMIS, KO_NAMES):
        old = os.path.join(ASSETS, 'kernelsu-%s.ko' % kmi)
        if os.path.exists(old):
            print('rename kernelsu-%s.ko -> %s' % (kmi, new))
            if not dry:
                os.rename(old, os.path.join(ASSETS, new))
    old = os.path.join(ASSETS, 'ksu-daemon')
    if os.path.exists(old):
        print('rename ksu-daemon -> %s' % NAMES['daemon'])
        if not dry:
            os.rename(old, os.path.join(ASSETS, NAMES['daemon']))
    old = os.path.join(ASSETS, 'webhook.txt')
    if os.path.exists(old):
        print('rename webhook.txt -> %s' % NAMES['webhook'])
        if not dry:
            os.rename(old, os.path.join(ASSETS, NAMES['webhook']))
    for path, name in big:
        if not os.path.exists(path):
            print('SKIP (missing)', name)
            continue
        data = open(path, 'rb').read()
        is_enc = data[:8] == ASSET_MAGIC
        if noenc:
            if is_enc:
                body = bytes(data[8 + i] ^ ks[i % BIG_KS_LEN] for i in range(len(data) - 8))
                print('%-8s 解密回明文 %d bytes' % (name, len(body)))
                if not dry:
                    open(path, 'wb').write(body)
            else:
                print('%-8s 已是明文 (%d bytes)' % (name, len(data)))
            continue
        if is_enc:
            print('%-8s already encrypted (%d bytes)' % (name, len(data)))
            continue
        print('encrypt %-8s %d bytes' % (name, len(data)))
        if not dry:
            body = bytes(data[i] ^ ks[i % BIG_KS_LEN] for i in range(len(data)))
            open(path, 'wb').write(ASSET_MAGIC + body)

    if dry:
        print('--dry，跳过 asset_names.c 生成')
        return

    # ── 3. 生成 asset_names.c ──────────────────────────────────────────────
    h = sha256(der)
    L = []
    L.append('/* auto-generated by tools/obf_assets.py - do not edit */')
    L.append('/* 资产名/目标名/KMI 全部走 OBF 表：dex 与 APK 里都不再出现明文。 */')
    L.append('#include <stddef.h>')
    L.append('#include <stdint.h>')
    L.append('#include <string.h>')
    L.append('#include "obf_data.h"')
    L.append('#include "obf_strings.h"')
    L.append('#include "hmac_sha256.h"')
    L.append('')
    L.append('/* id 约定（Java 侧 ExploitRunner.s(int) 使用）')
    L.append('   0      资产：公钥密文')
    L.append('   1..7   资产：KO（顺序对应 KMI）')
    L.append('   8      资产：daemon')
    L.append('   9..15  KMI 串')
    L.append('   16     dest 前缀')
    L.append('   17     dest 后缀')
    L.append('   18     dest daemon 名')
    L.append('   19     资产：UMH 脚本密文')
    L.append('   20     dest 脚本名')
    L.append('   21     已 root 标志文件（libcxx.S 互斥文件）')
    L.append('   22..24 管理器包名')
    L.append('   25     资产：反馈 webhook URL（企微，Java FeedbackSender 用）')
    L.append(' */')
    L.append('const char *asset_name(int id) {')
    L.append('    switch (id) {')
    L.append('        case 0:  return "%s";' % NAMES['pk'])
    for i, n in enumerate(KO_NAMES):
        L.append('        case %d:  return "%s";' % (i + 1, n))
    L.append('        case 8:  return "%s";' % NAMES['daemon'])
    for i, k in enumerate(KMIS):
        L.append('        case %d:  return "%s";' % (i + 9, k))
    L.append('        case 16: return "%s";' % DEST_PREFIX)
    L.append('        case 17: return "%s";' % DEST_SUFFIX)
    L.append('        case 18: return "%s";' % DEST_DAEMON)
    L.append('        case 19: return "%s";' % NAMES['script'])
    L.append('        case 20: return "%s";' % DEST_SCRIPT)
    L.append('        case 21: return "%s";' % MUTEX_FILE)
    for i, p in enumerate(MGR_PKGS):
        L.append('        case %d: return "%s";' % (22 + i, p))
    L.append('        case 25: return "%s";' % NAMES['webhook'])
    L.append('    }')
    L.append('    return NULL;')
    L.append('}')
    L.append('')
    L.append('/* JNI 注册元数据（n2/n3/n4 的方法名与签名）——同样不躺进 dex */')
    L.append('const char *jni_meta(int id) {')
    L.append('    switch (id) {')
    L.append('        case 0: return "s";')
    L.append('        case 1: return "(I)Ljava/lang/String;";')
    L.append('        case 2: return "pk";')
    L.append('        case 3: return "()[B";')
    L.append('        case 4: return "tool";')
    L.append('        case 5: return "()[B";')
    L.append('        case 6: return "ks";')
    L.append('        case 7: return "()[B";')
    L.append('    }')
    L.append('    return NULL;')
    L.append('}')
    L.append('')
    L.append('/* UMH 脚本（原 assets/tool，4KB shell，明文就是一整条攻击链说明）*/')
    L.append('static const uint8_t tool_enc[%d] = {' % len(tool_out))
    L.append('    ' + ','.join('0x%02x' % x for x in tool_out))
    L.append('};')
    L.append('')
    L.append('/* KO / daemon 的块流密钥，运行时生成（不占 .rodata）。')
    L.append('   公式必须与 tools/obf_assets.py 的 big_keystream() 逐字节一致，')
    L.append('   一旦不一致解密结果就是噪声（落盘后 KO 加载失败）。*/')
    L.append('#define BIG_KS_LEN %d' % BIG_KS_LEN)
    L.append('size_t asset_ks_len(void) { return BIG_KS_LEN; }')
    L.append('void asset_ks(uint8_t *out, size_t n) {')
    L.append('    for (size_t i = 0; i < n; i++)')
    L.append('        out[i] = (uint8_t)(OBF_SKEY((i + 0x%02x) & 0xFF)' % BIG_KEY)
    L.append('                          ^ (uint8_t)((i * 31) & 0xFF)')
    L.append('                          ^ OBF_SKEY((i >> 8) & 0xFF)')
    L.append('                          ^ (uint8_t)((i >> 12) & 0xFF));')
    L.append('}')
    L.append('')
    L.append('/* 运行时取 UMH 脚本。')
    L.append('   带 ASSET_MAGIC 头 = 密文，XOR 解密；')
    L.append('   没有头 = 明文（--no-encrypt 交付态），原样拷贝。同一套代码兼容两种资产。*/')
    L.append('static const uint8_t tool_magic[8] = {0x00,0x4f,0x42,0x46,0x41,0x53,0x01,0x00};')
    L.append('int tool_decode(uint8_t *out, size_t out_cap, size_t *out_len) {')
    L.append('    size_t n = sizeof(tool_enc);')
    L.append('    const uint8_t *src = tool_enc;')
    L.append('    int enc = 0;')
    L.append('    if (n >= 8 && memcmp(tool_enc, tool_magic, 8) == 0) { enc = 1; src += 8; n -= 8; }')
    L.append('    if (out_cap < n + 1) return -1;')
    L.append('    for (size_t i = 0; i < n; i++)')
    L.append('        out[i] = enc ? (uint8_t)(src[i] ^ (uint8_t)(0x%02x ^ OBF_SKEY((i + 0x%02x) & 0xFF) ^ (uint8_t)(i * 31))) : src[i];' % (TOOL_KEY, TOOL_KEY))
    L.append('    out[n] = 0;')
    L.append('    *out_len = n;')
    L.append('    return 0;')
    L.append('}')
    L.append('')
    L.append('/* 公钥密文（DER ^ keystream(k=0x%02x)）；数组形式，生成器不会动它 */' % PK_KEY)
    L.append('static const uint8_t pk_enc[%d] = {' % len(enc))
    L.append('    ' + ','.join('0x%02x' % x for x in enc))
    L.append('};')
    L.append('/* 明文 DER 的 SHA-256，按 sbox 掩码存（与 obf_data.h 同一手法）*/')
    L.append('static const uint8_t pk_hash_mask[32] = {')
    L.append('    ' + ','.join('0x%02x' % (h[i] ^ skey[i]) for i in range(32)))
    L.append('};')
    L.append('')
    L.append('/* 运行时解密 + 完整性校验。资产被替换 => hash 对不上 => 返回 NULL，')
    L.append('   verifyLicense 直接失败（换 public.pem 伪造激活码这条路被堵死）。*/')
    L.append('int pk_decode(uint8_t *out, size_t out_cap, size_t *out_len) {')
    L.append('    if (out_cap < sizeof(pk_enc)) return -1;')
    L.append('    for (size_t i = 0; i < sizeof(pk_enc); i++)')
    L.append('        out[i] = pk_enc[i] ^ (uint8_t)(0x%02x ^ OBF_SKEY((i + 0x%02x) & 0xFF) ^ (uint8_t)(i * 31));' % (PK_KEY, PK_KEY))
    L.append('    uint8_t d[32];')
    L.append('    sha256_ctx c; sha256_init(&c); sha256_update(&c, out, sizeof(pk_enc)); sha256_final(&c, d);')
    L.append('    for (int i = 0; i < 32; i++)')
    L.append('        if (d[i] != (uint8_t)(pk_hash_mask[i] ^ OBF_SKEY(i))) return -2;')
    L.append('    *out_len = sizeof(pk_enc);')
    L.append('    return 0;')
    L.append('}')
    open(os.path.join(JNI, 'asset_names.c'), 'w', encoding='utf-8').write('\n'.join(L) + '\n')
    print('wrote jni/asset_names.c (%d 条名字常量)' % (1 + len(KO_NAMES) + 1 + len(KMIS) + 3))


main()
