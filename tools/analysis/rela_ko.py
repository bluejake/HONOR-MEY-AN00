import sys, struct
p = sys.argv[1]
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
# symtab
syms=[]
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
def symname(idx):
    if idx==0: return ''
    if idx < len(syms): return syms[idx][0]
    return '?'
# find target rela section by name
want = sys.argv[2] if len(sys.argv)>2 else '.rela.text'
sectidx = None
for i,s in enumerate(secs):
    if nm(s[0]) == want: sectidx=i; break
s = secs[sectidx]
rela_off, rela_size = s[4], s[5]
entry_sz = 24
print('== %s : %d relocs ==' % (want, rela_size//entry_sz))
R_TYPE = {257:'ABS64',258:'ABS32',259:'ABS16',260:'PREL32',261:'PREL64',
          263:'ADR_PREL_PG_HI21',275:'CALL26',276:'JUMP26',277:'CONDBR19',
          278:'ADR_PREL_LO21',279:'TSTBR14',280:'ADR_GOT_PAGE',311:'LD64_GOT_LO12_NC',
          312:'LD64_GOTPAGE_LO15',283:'MOVW_UABS_G0',284:'G1',285:'G2',286:'G3',
          273:'LD_PREL_LO19',274:'ADR_PREL_LO21'}
for i in range(rela_size//entry_sz):
    o = rela_off + i*entry_sz
    r_offset, r_info, r_addend = struct.unpack_from('<QQq', d, o)
    rtype = r_info & 0xffffffff
    rsym  = r_info >> 32
    print('  off=0x%05x type=%s(%d) sym=%s addend=%d' % (r_offset, R_TYPE.get(rtype, '?'), rtype, symname(rsym), r_addend))
