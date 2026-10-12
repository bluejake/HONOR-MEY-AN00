from capstone import *
data = open('D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw','rb').read()
BASE = 0xffffffc080000000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
off, size = 0x169894, 0x16a5f4 - 0x169894
targets = {
    0x1081438: 'rt_mutex_adjust_pi',
    0x10815d4: 'rt_mutex_adjust_prio_chain',
    0x1691c8: 'rt_mutex_setprio',
}
print(f"===== __sched_setscheduler bl targets of interest ({size} bytes) =====")
found = 0
for i in md.disasm(data[off:off+size], BASE+off):
    if i.mnemonic == 'bl':
        try:
            tgt = int(i.op_str, 16)
        except ValueError:
            continue
        if tgt in targets:
            found += 1
            print(f"  CALL at {i.address:#x}: bl {targets[tgt]}")
print(f"total: {found}")
