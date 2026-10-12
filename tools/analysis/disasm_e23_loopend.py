from capstone import *
data = open('D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw','rb').read()
BASE = 0xffffffc080000000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def dump(name, off, size):
    print(f"===== {name} @ {BASE+off:#x} =====")
    for i in md.disasm(data[off:off+size], BASE+off):
        print(f"  {i.address:#x}(+{i.address-BASE-0x1000000:#x}): {i.mnemonic:10s} {i.op_str}")

# Q1/Q2: loop head — task 来源 & pi_blocked_on 读取
dump("loop head 0x81630-0x81670", 0x1081630, 0x40)
# Q4: re-insert 空/非空分支 (0x81798 RB_CLEAR / 0x81a8c descent)
dump("reinsert branch 0x81780-0x817c0", 0x1081780, 0x40)
# Q2/Q3: ring end — setprio(0x818a8) / pi_blocked_on 检查(0x818b8) / next task / depth
dump("ring end 0x81840-0x818f0", 0x1081840, 0xb0)
# loop-back 之后到循环头的 task 寄存器流转
dump("0x81b90-0x81bd8 (0x81b98/0x81ba0 region)", 0x1081b90, 0x48)
