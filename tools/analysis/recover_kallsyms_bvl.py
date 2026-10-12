#!/usr/bin/env python3
# recover_kallsyms_bvl.py v2 - 锚定 token_index + relative_base, 不硬编码偏移
# 布局: offsets(s32) -> num_syms(u32) -> names(OLD压缩) -> markers(u32[])
#       -> token_table -> token_index(u16[256]) -> relative_base(u64)
import struct, sys

ROOT="D:/MEY-AN00-root-repro"
KERNEL=ROOT+"/firmware_bvl/bvl175_Image"
OUT=ROOT+"/analysis/output/kallsyms_bvl_6.1.157.txt"
ADDR_OUT=ROOT+"/analysis/output/kallsyms_bvl_key_syms.txt"
KEY_SYMS=["_text","_stext","_etext","commit_creds","prepare_creds",
          "posix_cpu_timers","posix_cpu_timer_del","run_posix_cpu_timers",
          "exit_itimers","itimerspec_to_ktime","init_cred","selinux_state",
          "kallsyms_lookup_name","security_hook_heads","tasklist_lock",
          "init_task","init_mm","__per_cpu_offset","runqueues","modprobe_path",
          "timer_delete","sys_timer_delete","do_exit","copy_process",
          "schedule","native_write_cr4","cpu_feature_matches"]

def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def s32(b,o): return struct.unpack_from("<i",b,o)[0]
def u64(b,o): return struct.unpack_from("<Q",b,o)[0]

def find_token_index(K):
    end=len(K)-512
    best=None
    for i in range(0,end,2):
        ok=True; prev=-1; mx=0; md=0
        for j in range(256):
            v=u16(K,i+j*2)
            if v<=prev or v>4096: ok=False; break
            d=v-prev
            if d>md: md=d
            prev=v
            if v>mx: mx=v
        if ok and md<32 and mx>200:   # 真实 token_table 一般 >200 字节
            # 记录最靠后的候选
            if best is None or i>best: best=i
    return best

def build_tokens(K, P, ts):
    tidx=[u16(K,P+j*2) for j in range(256)]
    tbl=K[ts:P]
    if any(t>=len(tbl) for t in tidx): return None
    token_str=[b'']*256
    for idx in range(256):
        j=tidx[idx]; k=j
        while k<len(tbl) and tbl[k]!=0: k+=1
        if k>=len(tbl): return None
        token_str[idx]=tbl[tidx[idx]:k]
    return token_str

def decode(K, token_str, pos):
    L=K[pos]; pos+=1
    out=bytearray(); end=pos+L; first=True
    while pos<end:
        b=K[pos]; pos+=1
        tok=token_str[b]
        if first: first=False; tok=tok[1:]
        out+=tok
    return bytes(out),pos

def main():
    K=open(KERNEL,"rb").read()
    print("image size",len(K))
    P=find_token_index(K)
    if P is None:
        print("FAIL: 未找到 token_index"); sys.exit(1)
    print("P_TOKEN_INDEX=%s"%hex(P))
    relbase=u64(K,P+512)
    print("relative_base@P+512=%s"%hex(relbase))
    if (relbase>>32)!=0xffffffc0:
        print("WARN: relative_base 非 0xffffffc0 前缀")

    # 找 offsets 数组: s32 严格递增长串, 且其后 u32 == 串长 (num_syms)
    n=len(K)//4
    best=None
    i=0
    while i<n:
        v=s32(K,i*4); j=i+1
        while j<n and s32(K,j*4)>s32(K,(j-1)*4): j+=1
        runlen=j-i
        if runlen>1000:
            E=(j-1)*4+4   # 段末字节之后
            nm=u32(K,E)
            if nm==runlen and (best is None or runlen>best[0]):
                best=(runlen, i*4, E)   # (N, S, E)
        i=j
    if best is None:
        print("FAIL: 未找到 offsets+num_syms 匹配"); sys.exit(1)
    N,S,E=best
    print("offsets: N=%d S=%s E=%s  num_syms==N 校验通过"%(N,hex(S),hex(E)))
    ns=E+4   # names 起点
    print("names 起点 ns=%s"%hex(ns))

    # 定 ts(token_table 起点): 扫描使解码首符号 == _text
    ts=None
    for tsc in range(P-256, P-8192, -1):
        tok=build_tokens(K,P,tsc)
        if tok is None: continue
        try:
            nm,_=decode(K,tok,ns)
        except Exception:
            continue
        if nm==b"_text":
            ts=tsc; break
    if ts is None:
        print("FAIL: 无法定 ts"); sys.exit(1)
    print("TS_TOKEN_TABLE=%s"%hex(ts))

    # 全量解码 names
    token_str=build_tokens(K,P,ts)
    pos=ns; names=[]
    ok=True
    for i in range(N):
        try:
            nm,pos=decode(K,token_str,pos)
        except Exception:
            ok=False; break
        names.append(nm)
    if not ok:
        print("FAIL: names 解码中断 @%d"%len(names)); sys.exit(1)
    total_names=pos-ns
    print("decoded N=%d total_names=%d"%(len(names),total_names))

    # markers 校验
    ms=ns+total_names
    mcnt=(ts-ms)//4
    if mcnt>0 and (ts-ms)%4==0:
        markers=[u32(K,ms+4*k) for k in range(mcnt)]
        if markers and markers[-1]==total_names:
            print("markers 校验通过 mcnt=%d ms=%s"%(mcnt,hex(ms)))
        else:
            print("WARN markers 末项=%s != total_names=%d"%(markers[-1] if markers else None,total_names))
    else:
        print("WARN markers 区间异常 ms=%s ts=%s"%(hex(ms),hex(ts)))

    offs=[s32(K,S+i*4) for i in range(N)]
    addrs=[(relbase+offs[i])&0xffffffffffffffff for i in range(N)]
    bad=sum(1 for nm in names if not all(32<=c<127 for c in nm))
    print("non-printable names:",bad)

    name2addr={}
    for a,nm in zip(addrs,names):
        if nm and nm not in name2addr: name2addr[nm]=a

    with open(OUT,"w") as f:
        for a,nm in zip(addrs,names):
            f.write("%016x %s\n"%(a,nm.decode('latin1')))
    print("wrote",OUT)
    with open(ADDR_OUT,"w") as f:
        f.write("# BVL-AN16 6.1.157 kallsyms (OLD pre-5.2, 锚定 token_index)\n")
        f.write("# S(offsets)=%s N=%d E=%s ns=%s P(tokidx)=%s ts(toktbl)=%s relbase=%s\n"
                %(hex(S),N,hex(E),hex(ns),hex(P),hex(ts),hex(relbase)))
        f.write("%-32s %s\n"%("symbol","vaddr"))
        for k in KEY_SYMS:
            if k in name2addr:
                f.write("%-32s 0x%016x\n"%(k,name2addr[k]))
            else:
                f.write("%-32s NOT FOUND\n"%k)
    print("wrote",ADDR_OUT)
    print(open(ADDR_OUT).read())

if __name__=="__main__":
    main()
