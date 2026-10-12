from capstone import *
data = open('D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw','rb').read()
BASE = 0xffffffc080000000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
def dump(name, off, size):
    print(f"===== {name} @ {BASE+off:#x} =====")
    for i in md.disasm(data[off:off+size], BASE+off):
        print(f"  {i.address:#x}(+{i.address-BASE-0x1000000:#x}): {i.mnemonic:10s} {i.op_str}")
dump("after chk 0x818ec-0x81980 (x19 update / loop-back)", 0x10818ec, 0x94)
dump("bail target 0x81980-0x819c8", 0x1081980, 0x48)
dump("join 0x81d00-0x81d60", 0x1081d00, 0x60)
dump("0x81db8-0x81df0", 0x1081db8, 0x38)
