import struct
data = open('D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw','rb').read()
print(f"image size = {len(data):#x}")
WALK = 0x10815d4
ADJPI = 0x1081438
walk_callers, adjpi_callers = [], []
for off in range(0, len(data) - 4, 4):
    w = struct.unpack_from('<I', data, off)[0]
    op = w >> 26
    if op == 0x25 or op == 0x05:  # BL or B
        imm = w & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        tgt = off + 4 + imm * 4
        if tgt == WALK:
            walk_callers.append((off, 'BL' if op == 0x25 else 'B'))
        elif tgt == ADJPI:
            adjpi_callers.append((off, 'BL' if op == 0x25 else 'B'))
print(f"rt_mutex_adjust_prio_chain callers ({len(walk_callers)}):")
for c, k in walk_callers:
    print(f"  {k} at {c:#x}")
print(f"rt_mutex_adjust_pi callers ({len(adjpi_callers)}):")
for c, k in adjpi_callers:
    print(f"  {k} at {c:#x}")
