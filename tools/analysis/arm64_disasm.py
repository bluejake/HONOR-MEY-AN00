# minimal AArch64 decoder for the subset we need
import sys, struct
def dec(w, addr):
    s = ''
    op = w >> 24
    # helper
    def R(n): return 'x%d'%n
    def Wr(n): return 'w%d'%n
    if (w & 0x7f800000) == 0x52800000:  # movz w
        hw = (w>>21)&3; imm=(w>>5)&0xffff; rd=w&0x1f
        return 'movz %s, #0x%x, lsl #%d' % (Wr(rd), imm, hw*16)
    if (w & 0xff800000) == 0xd2800000:  # movz x
        hw=(w>>21)&3; imm=(w>>5)&0xffff; rd=w&0x1f
        return 'movz %s, #0x%x, lsl #%d' % (R(rd), imm, hw*16)
    if (w & 0x7f800000) == 0x72800000:  # movk w
        hw=(w>>21)&3; imm=(w>>5)&0xffff; rd=w&0x1f
        return 'movk %s, #0x%x, lsl #%d' % (Wr(rd), imm, hw*16)
    if (w & 0xff800000) == 0xf2800000:  # movk x
        hw=(w>>21)&3; imm=(w>>5)&0xffff; rd=w&0x1f
        return 'movk %s, #0x%x, lsl #%d' % (R(rd), imm, hw*16)
    if (w & 0x7f800000) == 0x12800000:  # movn w
        hw=(w>>21)&3; imm=(w>>5)&0xffff; rd=w&0x1f
        return 'movn %s, #0x%x, lsl #%d' % (Wr(rd), imm, hw*16)
    if (w & 0xff800000) == 0x92800000:
        hw=(w>>21)&3; imm=(w>>5)&0xffff; rd=w&0x1f
        return 'movn %s, #0x%x, lsl #%d' % (R(rd), imm, hw*16)
    # ldr/str unsigned offset
    if (w & 0x3b000000) == 0x39000000:
        size=(w>>30)&3; opc=(w>>22)&3; imm12=(w>>10)&0xfff; rn=(w>>5)&0x1f; rt=w&0x1f
        sc = {0:1,1:2,2:4,3:8}[size]
        off = imm12*sc
        m = {0:'str',1:'ldr',2:'ldrs',3:'ldrs'}[opc]
        rr = R(rt) if size==3 else Wr(rt)
        return '%s %s, [%s, #0x%x]' % (m, rr, R(rn), off)
    # ldr/str unsigned offset (64-bit unsigned immediate, size=11)
    # STP/LDP
    if (w & 0x3a000000) == 0x28000000:
        opc=(w>>30)&3; v=(w>>26)&1; idx=(w>>23)&3; L=(w>>22)&1; imm7=(w>>15)&0x7f; rt2=(w>>10)&0x1f; rn=(w>>5)&0x1f; rt=w&0x1f
        sc = 4 if opc==0 else 8
        if opc==2: sc=4  # ldp 32
        off = (imm7 - (imm7 & 0x40)*2) * sc
        if opc==2: rr = R(rt); rr2=R(rt2)
        elif opc==0: rr=Wr(rt); rr2=Wr(rt2)
        else: rr=R(rt); rr2=R(rt2)
        m = 'ldp' if L else 'stp'
        return '%s %s, %s, [%s, #%d]' % (m, rr, rr2, R(rn), off)
    # add/sub immediate
    if (w & 0x1f000000) == 0x11000000:
        S=(w>>29)&1; sh=(w>>22)&1; imm12=(w>>10)&0xfff; rn=(w>>5)&0x1f; rd=w&0x1f
        sub = (w>>30)&1
        op='subs' if (sub and S) else ('sub' if sub else ('adds' if S else 'add'))
        imm = imm12<<(12 if sh else 0)
        return '%s %s, %s, #0x%x' % (op, R(rd), R(rn), imm)
    if (w & 0x1f000000) == 0x11000000:
        pass
    # orr immediate etc skip
    # br/blr
    if (w & 0xfffffc1f) == 0xd61f0000:
        rn=(w>>5)&0x1f; return 'br %s' % R(rn)
    if (w & 0xfffffc1f) == 0xd63f0000:
        rn=(w>>5)&0x1f; return 'blr %s' % R(rn)
    if (w & 0xfffffc1f) == 0xd65f0000:
        rn=(w>>5)&0x1f; return 'ret %s' % R(rn) if rn!=30 else 'ret'
    # b/bl
    if (w & 0x7c000000) == 0x14000000:
        op=(w>>31)&1; imm26=w&0x3ffffff
        if imm26 & 0x2000000: imm26 -= 0x4000000
        tgt = addr + imm26*4
        return '%s 0x%x' % ('bl' if op else 'b', tgt)
    # b.cond
    if (w & 0xff000010) == 0x54000000:
        imm19=(w>>5)&0x7ffff; cond=w&0xf
        if imm19 & 0x40000: imm19 -= 0x80000
        cn = ['eq','ne','cs','cc','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al','nv'][cond]
        return 'b.%s 0x%x' % (cn, addr + imm19*4)
    # cbz/cbnz
    if (w & 0x7e000000) == 0x34000000:
        op=(w>>24)&1; imm19=(w>>5)&0x7ffff; rt=w&0x1f
        if imm19 & 0x40000: imm19 -= 0x80000
        sz = (w>>31)&1
        rr = R(rt) if sz else Wr(rt)
        return '%s %s, 0x%x' % ('cbnz' if op else 'cbz', rr, addr+imm19*4)
    if (w & 0x7e000000) == 0x36000000:
        op=(w>>24)&1; b40=(w>>19)&0x1f; imm14=(w>>5)&0x3fff; rt=w&0x1f
        if imm14 & 0x2000: imm14 -= 0x4000
        rr = R(rt) if (w>>31)&1 else Wr(rt)
        return '%s %s, #%d, 0x%x' % ('tbnz' if op else 'tbz', rr, b40, addr+imm14*4)
    # mov reg
    if (w & 0xffe0ffe0) == 0xaa0003e0:
        rd=w&0x1f; rm=(w>>16)&0x1f
        return 'mov %s, %s' % (R(rd), R(rm))
    # ADD shifted register
    if (w & 0x7f200000) == 0x0b000000:
        sf=(w>>31)&1; op=(w>>30)&1; S=(w>>29)&1; shift=(w>>22)&3; rm=(w>>16)&0x1f; imm6=(w>>10)&0x3f; rn=(w>>5)&0x1f; rd=w&0x1f
        if S==0 and shift==0 and imm6==0:
            nm = 'add' if op==0 else 'sub'
            return '%s %s, %s, %s' % (nm, R(rd), R(rn), R(rm))
    # ORR shifted
    if (w & 0x7fe00000) == 0x2a000000:
        rm=(w>>16)&0x1f; rn=(w>>5)&0x1f; rd=w&0x1f
        if rn==31:
            return 'mov %s, %s' % (R(rd), R(rm))
    # NOP
    if w == 0xd503201f: return 'nop'
    if w == 0xd5033bbf: return 'dsb'
    # LDUR/STUR (unscaled)
    if (w & 0x3b200c00) == 0x38000000:
        size=(w>>30)&3; opc=(w>>22)&3; imm9=(w>>12)&0x1ff; rn=(w>>5)&0x1f; rt=w&0x1f
        if imm9 & 0x100: imm9 -= 0x200
        m = {0:'stur',1:'ldur',2:'ldurs',3:'ldurs'}[opc]
        rr = R(rt) if size==3 else Wr(rt)
        return '%s %s, [%s, #%d]' % (m, rr, R(rn), imm9)
    # adrp
    if (w & 0x9f000000) == 0x90000000:
        immlo=(w>>29)&3; immhi=(w>>5)&0x7ffff; rd=w&0x1f
        imm = (immhi<<2)|immlo
        if imm & (1<<20): imm -= (1<<21)
        page = (addr & ~0xfff) + (imm<<12)
        return 'adrp %s, 0x%x' % (R(rd), page)
    if (w & 0xff800000) == 0x91000000:
        sh=(w>>22)&1; imm12=(w>>10)&0xfff; rn=(w>>5)&0x1f; rd=w&0x1f
        return 'add %s, %s, #0x%x' % (R(rd), R(rn), imm12<<(12 if sh else 0))
    if (w & 0xff800000) == 0xd1000000:
        sh=(w>>22)&1; imm12=(w>>10)&0xfff; rn=(w>>5)&0x1f; rd=w&0x1f
        return 'sub %s, %s, #0x%x' % (R(rd), R(rn), imm12<<(12 if sh else 0))
    return '.word 0x%08x' % w
