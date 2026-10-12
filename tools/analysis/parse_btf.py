#!/usr/bin/env python3
# 解析裸内核 Image 中的 BTF 段，抽取关键结构体的字段偏移（字节）。
import os, struct, sys

ROOT = "D:/MEY-AN00-root-repro"
KERNEL = ROOT + "/analysis/output/kernel_mey_an00.raw"
OUT = ROOT + "/analysis/output/btf_offsets.txt"

MAGIC = b"\x9f\xeb"  # BTF magic (LE u16 = 0xEB9F)

def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]

def find_btf(kernel):
    cands = []
    start = 0
    while True:
        i = kernel.find(MAGIC, start)
        if i < 0:
            break
        if i + 24 <= len(kernel):
            version = kernel[i+2]
            flags = kernel[i+3]
            hdr_len = u32(kernel, i+4)
            type_off = u32(kernel, i+8)
            type_len = u32(kernel, i+12)
            str_off = u32(kernel, i+16)
            str_len = u32(kernel, i+20)
            # 基本合法性
            if (version == 1 and (flags == 0 or flags == 1) and hdr_len >= 8
                    and type_off + type_len <= str_off + str_len + 8
                    and str_off >= type_off and str_len > 0):
                # 校验字符串表是否像 NUL 分隔的 ASCII
                s0 = i + hdr_len + str_off
                if s0 + 16 <= len(kernel):
                    sample = kernel[s0:s0+16]
                    if all((c == 0 or 32 <= c < 127) for c in sample):
                        cands.append((i, hdr_len, type_off, type_len, str_off, str_len))
        start = i + 2
    return cands

BTF_KIND_STRUCT = 4
BTF_KIND_UNION = 5

def parse_btf(kernel, cand):
    i, hdr_len, type_off, type_len, str_off, str_len = cand
    base = i + hdr_len
    type_data = kernel[base + type_off: base + type_off + type_len]
    str_data = kernel[base + str_off: base + str_off + str_len]

    def get_str(off):
        end = str_data.find(b"\x00", off)
        if end < 0: end = len(str_data)
        return str_data[off:end].decode("utf-8", "replace")

    # 需要跳过尾随字节的 kind（BTF 真实编号）
    # 3 ARRAY: +4 (index type); 6 ENUM: +8/enum; 13 FUNC_PROTO: +8/param;
    # 14 VAR: +4 (linkage); 15 DATASEC: +12/var; 19 ENUM64: +12/enum
    SKIP = {3: 4, 6: 8, 13: 8, 14: 4, 15: 12, 19: 12}
    types = []  # list of dict
    pos = 0
    n = len(type_data)
    while pos + 8 <= n:
        name_off = u32(type_data, pos)
        info = u32(type_data, pos+4)
        kind = (info >> 24) & 0x1f
        vlen = info & 0xffff
        # 第三 u32 = size_or_type
        sot = u32(type_data, pos+8)
        t = {"kind": kind, "name": get_str(name_off), "vlen": vlen, "sot": sot}
        pos += 12
        if kind in (BTF_KIND_STRUCT, BTF_KIND_UNION):
            size = sot
            members = []
            for _ in range(vlen):
                m_name = u32(type_data, pos)
                m_type = u32(type_data, pos+4)
                m_off = u32(type_data, pos+8)
                pos += 12
                members.append((get_str(m_name), m_off))
            t["size"] = size
            t["members"] = members
        else:
            # 跳过尾随字节，保持同步
            if kind in SKIP:
                pos += SKIP[kind] * vlen
        types.append(t)
    return types, str_data

def struct_by_name(types, name):
    for t in types:
        if t["kind"] in (BTF_KIND_STRUCT, BTF_KIND_UNION) and t["name"] == name:
            return t
    return None

def member_off_bytes(m_off):
    # BTF 成员 offset 单位为 bit；高位（bit 31）置位表示 bitfield 打包
    BITFIELD_BIT = 1 << 31
    if m_off & BITFIELD_BIT:
        bit_offset = m_off & 0x7fffffff
        # bit_size 在 24..30 位
        return bit_offset >> 3, True
    else:
        return (m_off >> 3), False

def find_structs(types, names):
    out = {}
    for nm in names:
        t = struct_by_name(types, nm)
        if t:
            out[nm] = t
    return out

def main():
    kernel = open(KERNEL, "rb").read()
    cands = find_btf(kernel)
    print("BTF candidates:", len(cands))
    # 选字符串表包含 task_struct 的
    sel = None
    for c in cands:
        _, _, to, tl, so, sl = c
        base = c[0] + c[1]
        str_data = kernel[base + so: base + so + sl]
        if b"task_struct" in str_data:
            sel = c
            break
    if not sel:
        sel = cands[0] if cands else None
    if not sel:
        print("NO BTF found"); sys.exit(1)
    print("selected BTF @", hex(sel[0]), "str_len", sel[5])
    types, str_data = parse_btf(kernel, sel)

    want = ["task_struct", "cred", "file_operations", "rt_mutex_waiter",
            "module", "task_struct", "thread_info", "mm_struct"]
    structs = find_structs(types, want)
    lines = []
    for nm in want:
        t = structs.get(nm)
        if not t:
            lines.append(f"## {nm}: NOT FOUND"); continue
        lines.append(f"## struct {nm}  (size=0x{t['size']:x}  vlen={t['vlen']})")
        for mname, moff in t["members"]:
            boff, bf = member_off_bytes(moff)
            tag = " [bitfield]" if bf else ""
            lines.append(f"    {mname:32s} off=0x{boff:04x} ({boff}){tag}")
    txt = "\n".join(lines)
    open(OUT, "w").write(txt)
    print(txt[:3000])
    print("\n... full written to", OUT)

if __name__ == "__main__":
    main()
