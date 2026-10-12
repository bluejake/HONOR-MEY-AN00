from capstone import *
data = open('D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw','rb').read()
BASE = 0xffffffc080000000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
def dump(name, off, size):
    print(f"===== {name} @ {BASE+off:#x} =====")
    for i in md.disasm(data[off:off+size], BASE+off):
        print(f"  {i.address:#x}: {i.mnemonic:10s} {i.op_str}")
# erase/insert 调用点实参装载
dump("walk 0x81730-0x817d0 (erase/insert callsites)", 0x1081730, 0xa0)
