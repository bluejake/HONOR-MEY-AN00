import struct, sys

data = open('exploit-src/build/preload_canary.so', 'rb').read()
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

TARGET = 0x29314  # slide_pselect_global_word.runtime_shift
for i in range(num):
    n, t, f, a, o, sz, l, inf, al, es = sh(i)
    if sz > 0 and a <= TARGET < a + sz:
        fo = o + (TARGET - a)
        v = struct.unpack_from('<i', data, fo)[0]
        print('section', nm(n, shstro), 'runtime_shift init =', v)
        break
