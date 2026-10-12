from capstone import *
data = open('D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw','rb').read()
BASE = 0xffffffc080000000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def dump(name, off, size):
    print(f"===== {name} @ {BASE+off:#x} =====")
    for i in md.disasm(data[off:off+size], BASE+off):
        print(f"  {i.address:#x}: {i.mnemonic:10s} {i.op_str}")

# walk: trylock(bl 0x81083238) 之后 → erase/insert 实参装载与调用
dump("walk 0x816c0-0x81730 (post-trylock / erase / insert)", 0x10816c0, 0x70)
# rb_erase 入口:分支结构 + case-1 写序列
dump("rb_erase 0x3a9d4-0x3aa40", 0x3a9d4, 0x6c)
# ____rb_insert 入口:第一读 + cbz 保护
dump("____rb_insert 0x3a860-0x3a960", 0x3a860, 0x100)
