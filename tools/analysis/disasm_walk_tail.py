from capstone import *
data = open('D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw','rb').read()
BASE = 0xffffffc080000000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
def dump(name, off, size):
    print(f"===== {name} @ {BASE+off:#x} =====")
    for i in md.disasm(data[off:off+size], BASE+off):
        print(f"  {i.address:#x}: {i.mnemonic:10s} {i.op_str}")
dump("walk tail 0x81d04-0x81d90 (post-insert tail)", 0x1081d04, 0x8c)
dump("walk bail 0x81980-0x819e0 (bail path)", 0x1081980, 0x60)
dump("wake paths 0x81a80-0x81af0 (0x81ad4 wake_up_state)", 0x1081a80, 0x70)
