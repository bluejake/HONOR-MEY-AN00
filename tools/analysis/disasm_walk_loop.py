from capstone import *
data = open('D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw','rb').read()
BASE = 0xffffffc080000000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
def dump(name, off, size):
    print(f"===== {name} @ {BASE+off:#x} =====")
    for i in md.disasm(data[off:off+size], BASE+off):
        print(f"  {i.address:#x}: {i.mnemonic:10s} {i.op_str}")
dump("walk entry 0x815d4-0x816e0 (args/sp8/w28 init)", 0x10815d4, 0x10c)
dump("walk 0x819e0-0x81a10 (MIN_CHAINWALK target)", 0x10819e0, 0x30)
dump("walk 0x81c58-0x81ca0 (0x81c64 owner==0 path)", 0x1081c58, 0x48)
