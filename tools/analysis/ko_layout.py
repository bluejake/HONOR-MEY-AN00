import sys, struct, re
p = sys.argv[1]
d = open(p,'rb').read()
# ELF64 header
if d[:4] != b'\x7fELF':
    print('not ELF'); sys.exit(1)
e_shoff, = struct.unpack_from('<Q', d, 0x28)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', d, 0x3a)
print('sections=%d shstrndx=%d' % (e_shnum, e_shstrndx))
secs=[]
for i in range(e_shnum):
    o = e_shoff + i*e_shentsize
    name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from('<IIQQQQIIQQ', d, o)
    secs.append((name,typ,flags,addr,off,size,link,info,align,entsize))
# shstrtab
sh = secs[e_shstrndx]
strtab = d[sh[4]:sh[4]+sh[5]]
def nm(x):
    e = strtab.find(b'\x00', x)
    return strtab[x:e].decode('ascii','replace')
print('%-24s %-18s %10s %10s %10s' % ('NAME','TYPE','ADDR','OFF','SIZE'))
for s in secs:
    if s[5] == 0 and s[1] != 8: continue
    print('%-24s 0x%08x %10d %10d %10d' % (nm(s[0]), s[1], s[3], s[4], s[5]))
# symtab
for s in secs:
    if s[1] == 2:  # SYMTAB
        symtab_off, symtab_size, link = s[4], s[5], s[6]
        st = secs[link]
        stb = d[st[4]:st[4]+st[5]]
        n = symtab_size // 24
        # find symtab section index for names
        print('\n=== SYMBOLS (%d) with addrx != 0 ===' % n)
        for i in range(n):
            o = symtab_off + i*24
            nameoff, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', d, o)
            if value == 0: continue
            e = stb.find(b'\x00', nameoff)
            sname = stb[nameoff:e].decode('ascii','replace')
            print('  %-48s 0x%05x size=%-6d shndx=%d' % (sname, value, size, shndx))
        break
