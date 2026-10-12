import sys, struct, os
sys.path.insert(0, 'analysis/scripts')
from arm64_disasm import dec

p = sys.argv[1]
want = sys.argv[2] if len(sys.argv)>2 else None
d = open(p,'rb').read()
e_shoff, = struct.unpack_from('<Q', d, 0x28)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', d, 0x3a)
secs=[]
for i in range(e_shnum):
    o = e_shoff + i*e_shentsize
    secs.append(struct.unpack_from('<IIQQQQIIQQ', d, o))
sh = secs[e_shstrndx]; strtab = d[sh[4]:sh[4]+sh[5]]
def nm(x):
    e = strtab.find(b'\x00', x); return strtab[x:e].decode('ascii','replace')
# find symtab
syms = []
for s in secs:
    if s[1]==2:
        off,size,link = s[4],s[5],s[6]
        stb = d[secs[link][4]:secs[link][4]+secs[link][5]]
        for i in range(size//24):
            o=off+i*24
            nameoff,info,other,shndx,value,ssz = struct.unpack_from('<IBBHQQ', d, o)
            e=stb.find(b'\x00',nameoff)
            syms.append((stb[nameoff:e].decode('ascii','replace'), value, ssz, shndx))
        break
# text section
for s in secs:
    if nm(s[0]) == '.text':
        text_off, text_addr_pass, text_size = s[4], s[3], s[5]
        break
targets = [x for x in syms if x[2]>0 and (want is None or want in x[0])]
for name, value, size, shndx in sorted(targets, key=lambda x:x[1]):
    print('\n=== %s  off=0x%x size=%d ===' % (name, value, size))
    fo = text_off + value
    for i in range(0, size, 4):
        w, = struct.unpack_from('<I', d, fo+i)
        print('  %05x: %08x  %s' % (value+i, w, dec(w, value+i)))
