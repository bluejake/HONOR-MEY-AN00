from capstone import *
data = open('D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw','rb').read()
BASE = 0xffffffc080000000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
for i in md.disasm(data[0x169294:0x169460], BASE+0x169294):
    tag = "  <<< X21 DEREF" if ("x21" in i.op_str and i.mnemonic.startswith(("ldr","ldur","ldrsw","ldrb","ldrsh"))) else ""
    print(f"  {i.address:#x}: {i.mnemonic:9s} {i.op_str}{tag}")
