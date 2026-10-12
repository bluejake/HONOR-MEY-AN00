#!/usr/bin/env python3
# recover_kallsyms.py - 从裸内核 Image 恢复 kallsyms (MEY-AN00 6.6.118 / Honor)
#
# 已确认的编解码方案: 内核使用 OLD (pre-5.2) kallsyms 压缩方案
#   (证据: 110992 个符号经此解码 100% 为可打印 ASCII, 且首符号依次为
#    _text/_stext/__irqentry_text_start/gic_handle_irq/... 完全符合 arm64 内核符号顺序)
#
# OLD 方案规则:
#   * 每个符号首字节 = 压缩后字节数 L (无 ULEB128, 直接单字节)
#   * 其后的 L 个字节, 每一个都是 token 索引 0..255 -> kallsyms_token_index -> token_table
#     (没有 0x80 字面量/引用位之分, 与 v6.6 的 2 字符 token + 0x80 位方案不同)
#   * skipped_first: 每个符号第一个 token 的首字符被跳过(压缩器把类型字符'T'/'t'/'D'...
#     作为首 token 首字符写入, 解码时丢弃, 运行时再据地址段推导类型)
#
# 段地址(经 numpy 严格递增 u16 扫描 + relbase u64 搜索确认):
#   names   [ns,  ms)            ;  ms = markers 起点
#   markers [ms,  ts)   u32*434
#   token_table [ts, p)          ;  NUL 终止的多字符 token 串
#   token_index [p, p+512) u16*256 (严格递增)
#   offsets [offs_start, relbase_off)  s32*N
#   relative_base @ relbase_off (= 0xffffffc080000000)
#
# 符号地址 addr[i] = (relative_base + s32(offset[i])) & 0xffffffffffffffff
# 镜像偏移 off = addr[i] - relative_base  (KASLR 无关, 直接等于 Image 文件内偏移)
import struct, sys

ROOT="D:/MEY-AN00-root-repro"
KERNEL=ROOT+"/analysis/output/kernel_mey_an00.raw"
OUT=ROOT+"/analysis/output/kallsyms_mey_an00.txt"
ADDR_OUT=ROOT+"/analysis/output/kallsyms_key_syms.txt"

RELBASE_VAL=0xffffffc080000000

P_TOKEN_INDEX = 0x14d07e0
TS_TOKEN_TABLE = 0x14d0450
MS_MARKERS     = 0x14cfd88
OFFS_START     = 0x14d09e0
RELBASE_OFF    = 0x153d020
NS             = 0x13522c0   # names 起点(经 banner 定位 + 433 块 checkpoint + 末位==ms-4 确认)

def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def s32(b,o): return struct.unpack_from("<i",b,o)[0]
def u64(b,o): return struct.unpack_from("<Q",b,o)[0]

def build_token_str(kb):
    tidx=[u16(kb,P_TOKEN_INDEX+j*2) for j in range(256)]
    token_table=kb[TS_TOKEN_TABLE:P_TOKEN_INDEX]
    token_str=[b'']*256
    for idx in range(256):
        ti=tidx[idx]; j=ti
        while j<len(token_table) and token_table[j]!=0: j+=1
        token_str[idx]=token_table[ti:j]
    return tidx,token_str

def decode_symbol(K, token_str, pos):
    """OLD 方案解码一个符号, 返回 (name_bytes, new_pos)。"""
    L=K[pos]; pos+=1
    out=bytearray(); end=pos+L; first=True
    while pos<end:
        b=K[pos]; pos+=1
        tok=token_str[b]
        if first:
            first=False
            tok=tok[1:]          # skipped_first: 丢弃首 token 首字符(类型字符)
        out+=tok
    return bytes(out),pos

def main():
    kb=open(KERNEL,"rb").read(); K=kb
    n=len(K)

    # ---- 完整性自检: token_index / relbase / N ----
    assert u64(kb,RELBASE_OFF)==RELBASE_VAL, "relative_base 不符"
    relbase=u64(kb,RELBASE_OFF)
    N=(RELBASE_OFF-OFFS_START)//4
    print("relative_base=",hex(relbase),"N=",N)

    tidx,token_str=build_token_str(kb)

    # ---- markers 一致性自检 ----
    mcnt=(TS_TOKEN_TABLE-MS_MARKERS)//4
    markers=[u32(kb,MS_MARKERS+4*i) for i in range(mcnt)]
    pos=NS; mk_ok=True; mi=0
    for i in range(N):
        _,pos=decode_symbol(K,token_str,pos)
        if (i+1)%256==0:
            mi+=1
            if mi<mcnt and (pos-NS)!=markers[mi]:
                mk_ok=False; break
    print("markers consistent:",mk_ok," final_pos=",hex(pos)," ms=",hex(MS_MARKERS)," (tail pad 4B)")

    # ---- 全量解码 (解码为 ASCII 字符串, 便于按名检索) ----
    pos=NS; names=[]
    for i in range(N):
        nm,pos=decode_symbol(K,token_str,pos)
        names.append(nm.decode('ascii'))
    bad=sum(1 for nm in names if not all(32<=ord(c)<127 for c in nm))
    print("decoded N=",len(names)," non-printable:",bad)

    offs=[s32(kb,OFFS_START+i*4) for i in range(N)]
    addrs=[(relbase+offs[i]) & 0xffffffffffffffff for i in range(N)]

    # ---- 段边界符号 -> 推导类型字符(尽力而为, 离线无法取得 binding) ----
    name2addr={}
    for a,nm in zip(addrs,names):
        if nm and nm not in name2addr: name2addr[nm]=a
    def ga(s): return name2addr.get(s)
    def span(s0,s1):
        a0,a1=ga(s0),ga(s1)
        return (a0,a1) if a0 is not None and a1 is not None else None
    text_sp   = span("_stext","_etext")  or span("_text","_etext")
    rodata_sp = span("__start_rodata","__end_rodata") or span("_srodata","_erodata")
    data_sp   = span("_data","_edata")
    bss_sp    = span("__bss_start","_end")
    init_sp   = span("__init_begin","__init_end")
    def classify(a):
        for sp,c in ((init_sp,'T'),(text_sp,'T'),(rodata_sp,'R'),(data_sp,'D'),(bss_sp,'B')):
            if sp and sp[0]<=a<sp[1]: return c
        return 'A'

    # ---- 写出完整 kallsyms (addr type name) ----
    with open(OUT,"w") as f:
        for i in range(N):
            f.write("%016x %s %s\n"%(addrs[i],classify(addrs[i]),names[i]))
    print("wrote",OUT)

    # ---- 关键利用符号地址/镜像偏移 (只列真实全局符号; 结构体字段另行在 offset.h 标注) ----
    key=["_text","_stext","init_task","init_cred","selinux_state",
         "ashmem_fops","kallsyms_lookup_name","avc_has_perm","avc_has_perm_nonbool",
         "commit_creds","prepare_creds","runqueues","__per_cpu_offset",
         "random_table","misc_list","uhid_misc","sysctl_bootid",
         "cred_init","security_hook_heads","tasklist_lock","init_pid_ns",
         "init_uts_ns","init_mm","kasan_init","is_module_sig_enforced"]
    with open(ADDR_OUT,"w") as f:
        f.write("# MEY-AN00 6.6.118 kallsyms 关键符号 (OLD pre-5.2 压缩方案恢复)\n")
        f.write("# token_index=%s token_table=%s relbase=%s relbase_off=%s N=%d ns=%s ms=%s\n"
                %(hex(P_TOKEN_INDEX),hex(TS_TOKEN_TABLE),hex(relbase),hex(RELBASE_OFF),N,hex(NS),hex(MS_MARKERS)))
        f.write("# off = vaddr - relbase  (== 裸 Image 文件内偏移, KASLR 无关)\n")
        f.write("%-26s %-20s %-12s %s\n"%("symbol","vaddr","off","note"))
        for k in key:
            if k in name2addr:
                a=name2addr[k]
                f.write("%-26s 0x%016x 0x%08x\n"%(k,a,a-relbase))
            else:
                f.write("%-26s NOT FOUND\n"%k)
        f.write("\n# 说明:\n")
        f.write("# selinux_enforcing 在 6.6 不再是独立全局, 而是 struct selinux_state 的 bool 字段;\n")
        f.write("#   selinux_state 全局 @ off=0x%08x; 设备 BTF 显示 enforcing 字段偏移 = 0x0 (厂商自定义布局)\n"%(name2addr.get('selinux_state',0)-relbase))
        f.write("# ashmem_miscs 非独立全局; misc 设备链表锚点为 misc_list @ off=0x%08x, 经 list_head 遍历找 ashmem miscdevice\n"%(name2addr.get('misc_list',0)-relbase))
        f.write("# sig_enforce 本内核未导出(可能 CONFIG_MODULE_SIG 未强制或改名); is_module_sig_enforced 为函数\n")
    print("wrote",ADDR_OUT)
    print("---- key syms ----")
    print(open(ADDR_OUT).read())

if __name__=="__main__":
    main()
