#!/usr/bin/env python3
"""Dump the runtime string table (obf_strings.h + obf_data.h) to plaintext.

Read-only diagnostic. Mirrors _obf_dec():
    s[i] = k ^ SKEY((i+k)&0xFF) ^ (i*31)
    out[i] = b[i] ^ s[i]
"""
import re
import sys
from pathlib import Path

JNI = Path(__file__).resolve().parents[1] / "app" / "src" / "main" / "jni"


def load_bytes(path, name):
    txt = (JNI / path).read_text()
    m = re.search(re.escape(name) + r"\[(\d+)\]\s*=\s*\{(.*?)\}", txt, re.S)
    if not m:
        return None
    return bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(2)))


def main():
    sbox = load_bytes("obf_data.h", "_obf_sbox")
    mask = load_bytes("obf_data.h", "_obf_sbox_mask")
    if sbox is None or mask is None or len(sbox) != 256 or len(mask) != 256:
        sys.exit("bad sbox/mask")
    skey = bytes(sbox[i] ^ mask[i] for i in range(256))

    hdr = (JNI / "obf_strings.h").read_text()
    blobs = {}
    for m in re.finditer(r"_obf_b(\d+)\[(\d+)\]\s*=\s*\{(.*?)\}", hdr, re.S):
        blobs[int(m.group(1))] = bytes(
            int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(3)))

    rows = re.findall(r"\{\s*_obf_b(\d+),\s*(\d+),\s*0x([0-9a-fA-F]{2})\s*\}", hdr)
    if not rows:
        sys.exit("no table rows")
    only = None
    if len(sys.argv) > 1:
        only = set(int(x) for x in sys.argv[1:])
    for idx, (bid, ln, kv) in enumerate(rows):
        if only is not None and idx not in only:
            continue
        b = blobs[int(bid)]
        k = int(kv, 16)
        n = int(ln)
        out = bytearray(n)
        for i in range(n):
            s = (k ^ skey[(i + k) & 0xFF] ^ ((i * 31) & 0xFF)) & 0xFF
            out[i] = b[i] ^ s
        try:
            txt = out.decode("utf-8")
        except UnicodeDecodeError:
            txt = repr(bytes(out))
        print(f"{idx:3d}  {txt}")


if __name__ == "__main__":
    main()
