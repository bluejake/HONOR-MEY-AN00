import struct, sys

path = sys.argv[1]
pat = sys.argv[2] if len(sys.argv) > 2 else 'pselect'
data = open(path, 'rb').read()
e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]

def sh(i):
    o = e_shoff + i * e_shentsize
    return struct.unpack_from('<IIQQQQIIQQ', data, o)

shstr = sh(e_shstrndx)
shstro = shstr[4]

def nm(x, base):
    e = data.index(b'\0', base + x)
    return data[base + x:e].decode()

secs = {}
for i in range(e_shnum):
    n, t, f, a, o, sz, l, inf, al, es = sh(i)
    secs[nm(n, shstro)] = (a, o, sz, es)

symtab = secs['.symtab']
a, o, sz, es = symtab
sa, so, ssz, ses = secs['.strtab']
n = sz // es
for i in range(n):
    nameo, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', data, o + i * es)
    name = nm(nameo, so)
    if pat in name and size > 0:
        print(name, hex(value), 'size', size)
