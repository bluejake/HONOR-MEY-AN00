#!/usr/bin/env python3
# dump_btf.py - 正确解析裸内核 Image 中的 BTF 段, 抽取关键结构体字段偏移。
#
# 修正了原 parse_btf.py 的两处 BTF 解析错位 bug:
#   * INT (kind 1) 头后还有 4 字节 (btf_int: nr_bits/encoding/offset) -> 必须跳过
#   * ARRAY (kind 3) 头后还有 8 字节 (btf_array: index_type + nelems) -> 必须跳过
# 否则首个 INT 之后的所有类型记录都会错位 (表现为 mm_struct vlen=2 之类垃圾)。
import os, struct, sys

ROOT = "D:/MEY-AN00-root-repro"
KERNEL = ROOT + "/analysis/output/kernel_mey_an00.raw"
OUT = ROOT + "/analysis/output/btf_offsets.txt"
NAMES_OUT = ROOT + "/analysis/output/btf_structs_all.txt"

MAGIC = b"\x9f\xeb"

def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]

def find_btf(kernel):
    cands = []
    start = 0
    while True:
        i = kernel.find(MAGIC, start)
        if i < 0: break
        if i + 24 <= len(kernel):
            version = kernel[i+2]; flags = kernel[i+3]
            hdr_len = u32(kernel, i+4); type_off = u32(kernel, i+8)
            type_len = u32(kernel, i+12); str_off = u32(kernel, i+16); str_len = u32(kernel, i+20)
            if (version == 1 and (flags == 0 or flags == 1) and hdr_len >= 8
                    and type_off + type_len <= str_off + str_len + 8
                    and str_off >= type_off and str_len > 0):
                s0 = i + hdr_len + str_off
                if s0 + 16 <= len(kernel):
                    sample = kernel[s0:s0+16]
                    if all((c == 0 or 32 <= c < 127) for c in sample):
                        cands.append((i, hdr_len, type_off, type_len, str_off, str_len))
        start = i + 2
    return cands

K_STRUCT=4; K_UNION=5

# 严格按 libbpf btf_type_size() 计算每种 kind 的记录总长(含 12 字节头)。
# 这是 BTF 解析唯一权威依据; 任何尾随字节漏算都会导致其后所有类型错位。
def btf_type_size(kind, vlen):
    base = 12
    if kind == 1:  return base + 4          # INT     (btf_int 4B)
    if kind == 3:  return base + 12         # ARRAY   (btf_array: type+index_type+nelems)
    if kind in (4, 5): return base + vlen*12  # STRUCT/UNION (btf_member)
    if kind == 6:  return base + vlen*8     # ENUM    (btf_enum)
    if kind == 13: return base + vlen*8     # FUNC_PROTO (btf_param)
    if kind == 14: return base + 4          # VAR     (btf_var)
    if kind == 15: return base + vlen*12    # DATASEC (btf_var_secinfo)
    if kind == 17: return base + 4          # DECL_TAG(btf_decl_tag)
    if kind == 19: return base + vlen*12    # ENUM64  (btf_enum64)
    return base                             # PTR/TYPEDEF/FWD/CONST/VOLATILE/RESTRICT/FUNC/FLOAT/TYPE_TAG

def parse_btf(kernel, cand):
    i, hdr_len, type_off, type_len, str_off, str_len = cand
    base = i + hdr_len
    type_data = kernel[base + type_off: base + type_off + type_len]
    str_data = kernel[base + str_off: base + str_off + str_len]
    def get_str(off):
        end = str_data.find(b"\x00", off)
        if end < 0: end = len(str_data)
        return str_data[off:end].decode("utf-8", "replace")
    types = []; pos = 0; n = len(type_data)
    while pos + 12 <= n:
        name_off = u32(type_data, pos); info = u32(type_data, pos+4)
        kind = (info >> 24) & 0x1f; vlen = info & 0xffff
        sot = u32(type_data, pos+8)
        t = {"kind": kind, "name": get_str(name_off), "vlen": vlen, "sot": sot,
             "type_off": pos, "name_off": name_off}
        pos += 12
        if kind in (K_STRUCT, K_UNION):
            size = sot; members = []
            for _ in range(vlen):
                m_name = u32(type_data, pos); m_type = u32(type_data, pos+4); m_off = u32(type_data, pos+8)
                pos += 12
                members.append((get_str(m_name), m_type, m_off))
            t["size"] = size; t["members"] = members
        else:
            # 用权威 size 函数推进到下一个类型记录
            pos += (btf_type_size(kind, vlen) - 12)
        types.append(t)
    parse_ok = (pos == n)
    print("PARSE INTEGRITY: final_pos=%d type_len=%d exact_match=%s" % (pos, n, parse_ok))
    return types, str_data, type_data

def by_name(types, name):
    for t in types:
        if t["kind"] in (K_STRUCT, K_UNION) and t["name"] == name:
            return t
    return None

def resolve_typedef(types, name):
    # 处理 typedef 名 -> 底层 struct/union
    for t in types:
        if t["kind"] == 8 and t["name"] == name:  # TYPEDEF
            tid = t["sot"]
            # 顺着 const/volatile/restrict/type_tag 找到 struct/union
            seen=set()
            while True:
                if tid in seen: break
                seen.add(tid)
                tt = types[tid] if tid < len(types) else None
                if tt is None: break
                if tt["kind"] in (K_STRUCT, K_UNION):
                    return tt
                if tt["kind"] in (8,9,10,11,18):  # typedef/const/volatile/restrict/type_tag
                    tid = tt["sot"]
                else:
                    break
    return None

def member_off_bytes(m_off):
    BITFIELD = 1 << 31
    if m_off & BITFIELD:
        bit_off = m_off & 0x7fffffff
        return bit_off >> 3, True
    return m_off >> 3, False

def dump_struct(t):
    lines = [f"## struct {t['name']}  (size=0x{t['size']:x}  vlen={t['vlen']})"]
    for mname, mtype, moff in t["members"]:
        boff, bf = member_off_bytes(moff)
        tag = " [bitfield]" if bf else ""
        lines.append(f"    {mname:34s} off=0x{boff:04x} ({boff}){tag}")
    return lines

def main():
    kernel = open(KERNEL, "rb").read()
    cands = find_btf(kernel)
    print("BTF candidates:", len(cands))
    sel = None
    for c in cands:
        _,_,to,tl,so,sl = c
        base = c[0] + c[1]
        sd = kernel[base+so: base+so+sl]
        if b"task_struct" in sd:
            sel = c; break
    if not sel:
        sel = cands[0] if cands else None
    if not sel:
        print("NO BTF"); sys.exit(1)
    print("selected BTF @", hex(sel[0]), "str_len", sel[5], "type_len", sel[3])
    types, str_data, type_data = parse_btf(kernel, sel)
    print("total BTF types parsed:", len(types))

    # 全部 struct/union 名 -> 文件
    allnames = sorted({t["name"] for t in types if t["kind"] in (K_STRUCT,K_UNION) and t["name"]})
    open(NAMES_OUT,"w").write("\n".join(allnames))
    print("wrote struct name list:", NAMES_OUT, "count", len(allnames))

    # 可用命令行覆盖要导出的结构体: python dump_btf.py rq cred task_struct ...
    if len(sys.argv) > 1:
        want = sys.argv[1:]
    else:
        want = ["task_struct","cred","mm_struct","selinux_state","list_head","mutex",
                "spinlock_t","atomic_t","refcount_t","file_operations","rt_mutex_waiter",
                "module","thread_info","files_struct","fs_struct","nsproxy","pid",
                "vm_area_struct","seqcount_t","wait_queue_head_t","task_group",
                "signal_struct","sched_entity","avc_node","selinux_inode_security",
                "superblock","inode","dentry","uts_namespace","user_namespace",
                "cred_jit_keyring","key","mm_struct"]
    seen=set(); lines=[]
    for nm in want:
        if nm in seen: continue
        seen.add(nm)
        t = by_name(types, nm)
        if not t:
            t = resolve_typedef(types, nm)
        if not t:
            lines.append(f"## {nm}: NOT FOUND (struct/typedef)")
            continue
        lines += dump_struct(t)
        lines.append("")
    txt = "\n".join(lines)
    open(OUT,"w").write(txt)
    print("wrote", OUT)
    # 一致性 sanity: 已知结构体尺寸
    print("==== sanity sizes ====")
    for nm in ["task_struct","cred","inode","file","super_block","mm_struct","list_head",
               "selinux_state","miscdevice","rt_mutex_waiter","module","thread_info","pid"]:
        t = by_name(types, nm)
        print("  %-16s size=%s vlen=%s" % (nm, hex(t['size']) if t else "-", t['vlen'] if t else "-"))
    # mm_struct 全部同名记录
    ms = [t for t in types if t["name"]=="mm_struct" and t["kind"] in (K_STRUCT,K_UNION)]
    print("  mm_struct records:", [(hex(t['type_off']), t['vlen'], hex(t['size'])) for t in ms][:10])
    print("==== selinux / mm / list_head / mutex / spinlock ====")
    for nm in ["selinux_state","mm_struct","list_head","mutex","spinlock_t"]:
        print("----", nm, "----")
        t = by_name(types,nm) or resolve_typedef(types,nm)
        if t:
            for l in dump_struct(t)[:40]:
                print(l)
        else:
            print("NOT FOUND")

if __name__ == "__main__":
    main()
