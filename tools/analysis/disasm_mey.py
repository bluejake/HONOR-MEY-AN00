#!/usr/bin/env python3
"""Disassemble MEY kernel functions using kallsyms + kernel_mey_an00.raw (PE-wrapped arm64 Image).
Usage: disasm_mey.py <func1> [func2 ...] [-o out.txt] [-n bytes]
Maps vaddr -> file offset via _text = 0xffffffc080000000.
"""
import sys, struct, subprocess

KALLSYMS = "analysis/output/kallsyms_mey_an00.txt"
RAW = "analysis/output/kernel_mey_an00.raw"
TEXT = 0xffffffc080000000

def load_syms():
    name2addr = {}
    addr2name = {}
    with open(KALLSYMS) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            addr = int(parts[0], 16)
            typ = parts[1]
            name = parts[2]
            name2addr[name] = addr
            addr2name[addr] = (typ, name)
    return name2addr, addr2name

def main():
    args = sys.argv[1:]
    skip = False
    funcs = []
    out = None
    nbytes = 0x3000
    for i, a in enumerate(args):
        if skip:
            skip = False; continue
        if a == "-o":
            out = args[i+1]; skip = True; continue
        if a == "-n":
            nbytes = int(args[i+1], 0); skip = True; continue
        if a.startswith("-"):
            continue
        funcs.append(a)

    name2addr, addr2name = load_syms()
    with open(RAW, "rb") as f:
        raw = f.read()

    out_lines = []
    for fn in funcs:
        addr = name2addr.get(fn)
        if addr is None:
            # try partial match
            matches = [n for n in name2addr if fn in n]
            out_lines.append("=== '%s' not found. partial: %s" % (fn, matches[:10]))
            continue
        off = addr - TEXT
        code = raw[off:off+nbytes]
        out_lines.append("=== %s @ 0x%016x (file off 0x%x, %d bytes) ===" % (fn, addr, off, nbytes))
        try:
            import capstone
            md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            md.detail = False
            # ★ 2026-10-01 修复：capstone 的 md.disasm() 生成器遇到第一个无法
            #   解码的字节序就会整体停止 —— 大函数（如 __arm64_sys_rt_sigreturn
            #   含内联 restore_sigframe）中段的 PAC/BTILabel 混合编码会让输出
            #   在 ~0x180 处截断，导致后续 fpsimd 拷贝序列完全搜不到。
            #   改为逐条反汇编，失败处跳 4 字节继续。
            pc = addr
            end = addr + nbytes
            while pc < end:
                chunk = raw[pc - TEXT: pc - TEXT + 16]
                ins = None
                try:
                    ins = next(md.disasm(chunk, pc))
                except StopIteration:
                    ins = None
                except Exception:
                    ins = None
                if ins is None:
                    out_lines.append("  0x%016x:\t.bad" % pc)
                    pc += 4
                    continue
                out_lines.append("  0x%016x:\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))
                pc += ins.size
        except Exception as e:
            out_lines.append("  disasm error: %s" % e)

    text = "\n".join(out_lines)
    if out:
        with open(out, "w") as f:
            f.write(text)
        print("wrote", out, len(out_lines), "lines")
    else:
        print(text)

if __name__ == "__main__":
    main()
