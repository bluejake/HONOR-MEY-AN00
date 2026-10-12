import struct, sys

path = 'exploit-src/build/preload_canary.so'
data = open(path, 'rb').read()
e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
entsz = struct.unpack_from('<H', data, 0x3A)[0]
num = struct.unpack_from('<H', data, 0x3C)[0]
sidx = struct.unpack_from('<H', data, 0x3E)[0]

def sh(i):
    return struct.unpack_from('<IIQQQQIIQQ', data, e_shoff + i * entsz)

shstr = sh(sidx)
shstro = shstr[4]

def nm(x, base):
    e = data.index(b'\0', base + x)
    return data[base + x:e].decode()

secs = {}
for i in range(num):
    n, t, f, a, o, sz, l, inf, al, es = sh(i)
    secs[nm(n, shstro)] = (a, o, sz, es)

symtab = secs['.symtab']
a0, o0, sz0, es0 = symtab
sa, so, ssz, ses = secs['.strtab']

def sym(name):
    n = sz0 // es0
    for i in range(n):
        nameo, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', data, o0 + i * es0)
        if nm(nameo, so) == name:
            return value, size
    return None

try:
    import capstone
except ImportError:
    print('no capstone'); sys.exit(1)

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

def dis(name, limit=None):
    r = sym(name)
    if not r:
        print('sym not found', name); return
    va, size = r
    # file offset = vaddr - section addr + section off (.text)
    ta, to, tsz, _ = secs['.text']
    fo = to + (va - ta)
    code = data[fo:fo + size]
    print('==== %s @ %s size %d ====' % (name, hex(va), size))
    cnt = 0
    md.skipdata = True   # ★ 遇坏字节继续反汇编（否则中途静默停止，函数被截断）
    for ins in md.disasm(code, va):
        print('  0x%x:\t%s\t%s' % (ins.address, ins.mnemonic, ins.op_str))
        cnt += 1
        if limit and cnt >= limit:
            break

for nm_ in sys.argv[1:]:
    dis(nm_)
