from capstone import *
data = open('D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw','rb').read()
BASE = 0xffffffc080000000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
for i in md.disasm(data[0x169380:0x169410], BASE+0x169380):
    print(f"  {i.address:#x}: {i.mnemonic:9s} {i.op_str}")
print("=== around 0x1692cc-0x169310 (body entry / queued check) ===")
for i in md.disasm(data[0x1692cc:0x169315], BASE+0x1692cc):
    print(f"  {i.address:#x}: {i.mnemonic:9s} {i.op_str}")
