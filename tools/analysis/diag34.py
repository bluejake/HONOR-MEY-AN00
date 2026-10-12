#!/usr/bin/env python3
# diag34 - dump a broad set of exploit-relevant structs from BTF (byte offsets).
import struct
KERNEL="D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw"
OUT="D:/MEY-AN00-root-repro/analysis/output/btf_offsets_full.txt"
MAGIC=b"\x9f\xeb"
def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
kb=open(KERNEL,"rb").read()
def find_btf(kernel):
    cands=[]; start=0
    while True:
        i=kernel.find(MAGIC,start)
        if i<0: break
        if i+24<=len(kernel):
            version=kernel[i+2]; flags=kernel[i+3]; hdr_len=u32(kernel,i+4)
            type_off=u32(kernel,i+8); type_len=u32(kernel,i+12)
            str_off=u32(kernel,i+16); str_len=u32(kernel,i+20)
            if version==1 and (flags==0 or flags==1) and hdr_len>=8 and str_len>0:
                cands.append((i,hdr_len,type_off,type_len,str_off,str_len))
        start=i+2
    return cands
SKIP={3:4,6:8,13:8,14:4,15:12,19:12}
c=find_btf(kb)[0]
i,hdr_len,type_off,type_len,str_off,str_len=c
base=i+hdr_len
type_data=kb[base+type_off:base+type_off+type_len]
str_data=kb[base+str_off:base+str_off+str_len]
def get_str(off):
    e=str_data.find(b"\x00",off)
    if e<0:e=len(str_data)
    return str_data[off:e].decode("utf-8","replace")
types=[]; pos=0;n=len(type_data)
while pos+8<=n:
    name_off=u32(type_data,pos); info=u32(type_data,pos+4)
    kind=(info>>24)&0x1f; vlen=info&0xffff; sot=u32(type_data,pos+8)
    pos+=12
    if kind in (4,5):
        members=[]
        for _ in range(vlen):
            m_name=u32(type_data,pos); m_type=u32(type_data,pos+4); m_off=u32(type_data,pos+8)
            pos+=12
            members.append((get_str(m_name),m_off))
        types.append({"kind":kind,"name":get_str(name_off),"size":sot,"vlen":vlen,"members":members})
    else:
        if kind in SKIP: pos+=SKIP[kind]*vlen

def member_off_bytes(m_off):
    if m_off & (1<<31):
        return (m_off & 0x7fffffff)>>3, True
    return m_off>>3, False

want=["task_struct","cred","miscdevice","list_head","pid","pid_namespace","nsproxy",
      "mm_struct","file_operations","module","rt_mutex_waiter","thread_info",
      "super_block","inode","dentry","file","files_struct","fs_struct","seq_file",
      "avc_node","avc_cache","kmem_cache","vm_area_struct","spinlock","rwlock",
      "wait_queue_head","rw_semaphore","mutex","atomic_t","refcount_t","size_t"]
byname={}
for t in types:
    if t["name"] not in byname: byname[t["name"]]=t
lines=[]
for nm in want:
    t=byname.get(nm)
    if not t:
        lines.append(f"## {nm}: NOT FOUND"); continue
    lines.append(f"## struct {nm}  (size=0x{t['size']:x}  vlen={t['vlen']})")
    for mname,moff in t["members"]:
        boff,bf=member_off_bytes(moff)
        tag=" [bitfield]" if bf else ""
        lines.append(f"    {mname:34s} off=0x{boff:04x} ({boff}){tag}")
    lines.append("")
txt="\n".join(lines)
open(OUT,"w").write(txt)
print("wrote",OUT)
print("list_head present:", "list_head" in byname, " selinux_state present:", "selinux_state" in byname)
print(txt[:4000])
