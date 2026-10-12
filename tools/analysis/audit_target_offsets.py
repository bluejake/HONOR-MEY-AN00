# -*- coding: utf-8 -*-
"""
audit_target_offsets.py
把 target_mey_an00.h 里所有 `#define XXX_OFF 0xNNN` 常量，
拿去和我们自己恢复的 kallsyms 逐条比对。

用法: python audit_target_offsets.py
"""
import os
import re
import sys

ROOT = r"D:/MEY-AN00-root-repro"
TARGET = os.path.join(ROOT, "exploit-src", "target_mey_an00.h")
KALLSYMS = os.path.join(ROOT, "analysis", "output", "kallsyms_mey_an00.txt")
BASE = 0xFFFFFFC080000000

DEF_RE = re.compile(r"^#define\s+([A-Za-z0-9_]+_OFF)\s+(\S+)")


def load_kallsyms(path):
    sym = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 3:
                continue
            addr = int(parts[0], 16)
            name = parts[2]
            sym.setdefault(name, addr)
    return sym


def load_target(path):
    """返回 [(const_name, raw_value_expr)]，并保留已解析的字面值替换表"""
    raw = {}
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            m = DEF_RE.match(line.rstrip())
            if m:
                raw[m.group(1)] = m.group(2)
                out.append((m.group(1), m.group(2), i))
    return out, raw


def resolve(expr, raw, depth=0):
    """把可能是别的宏名的 expr 解析成 int"""
    if depth > 8:
        return None
    if expr.lower().startswith("0x"):
        body = expr[2:]
        for suf in ("ULL", "UL", "LL", "U", "L"):
            if body.upper().endswith(suf):
                body = body[: -len(suf)]
                break
        try:
            return int(body, 16)
        except ValueError:
            return None
    if expr.startswith("("):  # 形如 (KIMAGE_TEXT_BASE + X) 之类，跳过
        return None
    if expr in raw:
        return resolve(raw[expr], raw, depth + 1)
    return None


def candidates(const_name):
    """由常量名反推可能的符号名（前缀/后缀自由组合，避免漏配）"""
    base = const_name[:-4] if const_name.endswith("_OFF") else const_name
    b = base.lower()
    prefixes = ("slide_", "app_", "fops_", "kernelsnitch_", "p0_", "cga_", "ks_")
    suffixes = ("_image", "_object", "_name", "_ptr", "_addr", "_base")

    forms = {b}
    for p in prefixes:
        if b.startswith(p):
            forms.add(b[len(p):])
    grown = set(forms)
    for s in suffixes:
        for f in forms:
            if f.endswith(s):
                grown.add(f[: -len(s)])
    out = list(grown)
    out.append(b.replace("_log_", "_logger_"))
    return list(dict.fromkeys(out))


# 小于这个值的一定是结构体字段偏移（如 MISC_LIST_OFF=0x18），不是符号地址
SYM_MIN_VALUE = 0x100000


def main():
    if not os.path.exists(KALLSYMS):
        print("缺少 kallsyms:", KALLSYMS)
        return 1

    sym = load_kallsyms(TARGET and KALLSYMS)
    defs, raw = load_target(TARGET)

    ok, bad, unres, nosym = [], [], [], []
    for cname, expr, lineno in defs:
        val = resolve(expr, raw)
        if val is None:
            if expr.startswith("("):
                continue  # 表达式形式，单独核
            unres.append((cname, expr, lineno))
            continue
        if val < SYM_MIN_VALUE:
            continue  # 结构体字段偏移，交给 BTF 侧核对
        hit_names = [c for c in candidates(cname) if c in sym]
        if not hit_names:
            nosym.append((cname, val, lineno))
            continue
        nm = hit_names[0]
        expect = sym[nm] - BASE
        if expect == val:
            ok.append((cname, nm, val))
        else:
            bad.append((cname, nm, val, expect, lineno))

    print("=" * 78)
    print("target_mey_an00.h 符号偏移核对（基准 _text=0x%016x）" % BASE)
    print("=" * 78)
    print("对得上 : %d" % len(ok))
    print("不一致 : %d" % len(bad))
    print("无符号 : %d（多为结构体字段偏移，非符号）" % len(nosym))
    print("无法解析:%d" % len(unres))
    print()

    if bad:
        print("---- ★ 不一致（必须处理） ----")
        for cname, nm, val, exp, ln in sorted(bad):
            print("  %-42s target=0x%08x  kallsyms[%s]=0x%08x  diff=%+d  (line %d)"
                  % (cname, val, nm, exp, val - exp, ln))
        print()

    print("---- 已核对一致 ----")
    for cname, nm, val in sorted(ok):
        print("  %-42s 0x%08x  <- %s" % (cname, val, nm))

    if unres:
        print()
        print("---- 未能解析（引用了别的宏，需单独看）----")
        for cname, expr, ln in unres:
            print("  %-42s = %s  (line %d)" % (cname, expr, ln))
    return 0


if __name__ == "__main__":
    sys.exit(main())
