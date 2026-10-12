#!/usr/bin/env python3
# diag33 - enumerate ALL structs/unions in the kernel BTF and check exploit-relevant ones.
import struct
KERNEL="D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw"
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
names=[]
pos=0;n=len(type_data)
while pos+8<=n:
    name_off=u32(type_data,pos); info=u32(type_data,pos+4)
    kind=(info>>24)&0x1f; vlen=info&0xffff; sot=u32(type_data,pos+8)
    pos+=12
    if kind in (4,5):
        names.append(get_str(name_off))
    else:
        if kind in SKIP: pos+=SKIP[kind]*vlen
print("total structs/unions:",len(names))
for q in ("selinux_state","miscdevice","list_head","selinux_avc","selinux_ss",
          "cred","task_struct","pid","pid_namespace","nsproxy","mm_struct",
          "super_block","inode","dentry","file","files_struct","fs_struct",
          "seq_file","avc_node","avc_cache","kmem_cache","page","vm_area_struct"):
    hits=[x for x in names if x==q]
    print(f"  {q:18s}: {'FOUND' if hits else 'missing'}")
print("---- sample of all names ----")
for x in names[:60]:
    print("   ",x)
