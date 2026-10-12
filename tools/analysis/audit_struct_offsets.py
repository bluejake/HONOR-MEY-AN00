# -*- coding: utf-8 -*-
"""
audit_struct_offsets.py
把 target_mey_an00.h 里的「结构体字段偏移」常量，拿去和设备内嵌 BTF 实测值比对。

之所以必须做：这类常量写错不会报错、不会崩，只会静默失效（exploit 走到一半卡住），
正是上一轮 KernelSnitch 64 次只中 1 次那类问题的温床。

用法: python audit_struct_offsets.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dump_btf as B  # 复用已验证的 libbpf 严格解析

ROOT = r"D:/MEY-AN00-root-repro"
TARGET = os.path.join(ROOT, "exploit-src", "target_mey_an00.h")
KERNEL = os.path.join(ROOT, "analysis", "output", "kernel_mey_an00.raw")

# (target.h 常量名, BTF 结构名, BTF 字段名[, 子字段链])
# 子字段链用于「结构体套结构体」的情况，例如 task->cred 里的某个字段
CHECKS = [
    # ---- task_struct ----
    ("TASK_REAL_CRED_OFF",    "task_struct", ("real_cred",)),
    ("TASK_CRED_OFF",         "task_struct", ("cred",)),
    ("TASK_COMM_OFF",         "task_struct", ("comm",)),
    ("TASK_PID_OFF",          "task_struct", ("pid",)),
    ("TASK_TGID_OFF",         "task_struct", ("tgid",)),
    ("TASK_TASKS_OFF",        "task_struct", ("tasks",)),
    ("TASK_PRIO_OFF",         "task_struct", ("prio",)),
    ("TASK_SE_OFF",           "task_struct", ("security",)),
    ("TASK_RT_OFF",           "task_struct", ("rt",)),
    ("TASK_PI_BLOCKED_ON_OFF","task_struct", ("pi_blocked_on",)),
    ("TASK_RQ_OFF",           "task_struct", ("rq",)),
    # ---- cred ----
    ("CRED_UID_OFF",          "cred", ("uid",)),
    ("CRED_GID_OFF",          "cred", ("gid",)),
    ("CRED_EUID_OFF",         "cred", ("euid",)),
    ("CRED_SECUREBITS_OFF",   "cred", ("securebits",)),
    ("CRED_CAPS_OFF",         "cred", ("cap_inheritable",)),
    ("CRED_SECURITY_OFF",     "cred", ("security",)),
    ("CRED_USAGE_OFF",        "cred", ("usage",)),
    # ---- rt_mutex_waiter ----
    ("FAKE_WAITER_TASK_OFF",  "rt_mutex_waiter", ("task",)),
    ("FAKE_WAITER_LOCK_OFF",  "rt_mutex_waiter", ("lock",)),
    ("FAKE_WAITER_WAKE_STATE_OFF", "rt_mutex_waiter", ("wake_state",)),
    ("FAKE_WAITER_WW_CTX_OFF","rt_mutex_waiter", ("ww_ctx",)),
    # ---- miscdevice ----
    ("MISC_LIST_OFF",         "miscdevice", ("list",)),
    ("MISC_NAME_OFF",         "miscdevice", ("name",)),
    ("MISC_FOPS_OFF",         "miscdevice", ("fops",)),
    # ---- file_operations ----
    ("FOPS_OWNER_OFF",        "file_operations", ("owner",)),
    ("FOPS_READ_ITER_OFF",    "file_operations", ("read_iter",)),
    ("FOPS_WRITE_ITER_OFF",   "file_operations", ("write_iter",)),
    ("FOPS_UNLOCKED_IOCTL_OFF","file_operations", ("unlocked_ioctl",)),
    ("FOPS_MMAP_OFF",         "file_operations", ("mmap",)),
    ("FOPS_OPEN_OFF",         "file_operations", ("open",)),
    ("FOPS_RELEASE_OFF",      "file_operations", ("release",)),
    # ---- file / inode ----
    ("FILE_F_OP_OFF",         "file", ("f_op",)),
    ("FILE_PRIVATE_DATA_OFF", "file", ("private_data",)),
    ("INODE_I_FOP_OFF",       "inode", ("i_fop",)),
    # ---- rq ----
    ("RQ_CURR_OFF",           "rq", ("curr",)),
    # ---- task_group ----
    ("TG_PARENT_OFF",         "task_group", ("parent",)),
]

DEF_RE = re.compile(r"^#define\s+([A-Za-z0-9_]+_OFF)\s+(\S+)")


def load_defs(path):
    raw, order = {}, []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = DEF_RE.match(line.rstrip())
            if m:
                raw[m.group(1)] = m.group(2)
                order.append(m.group(1))
    return raw, order


def to_int(expr, raw, depth=0):
    if depth > 8:
        return None
    if expr.lower().startswith("0x"):
        b = expr[2:]
        for s in ("ULL", "UL", "LL", "U", "L"):
            if b.upper().endswith(s):
                b = b[: -len(s)]
                break
        try:
            return int(b, 16)
        except ValueError:
            return None
    if expr.isdigit():
        return int(expr)
    if expr in raw:
        return to_int(raw[expr], raw, depth + 1)
    return None


def member_offset(types, struct, names):
    """沿 names 链解析嵌套字段的字节偏移"""
    t = B.by_name(types, struct) or B.resolve_typedef(types, struct)
    total = 0
    for i, n in enumerate(names):
        if t is None:
            return None
        found = None
        for mname, mtype, moff in t["members"]:
            if mname == n:
                found = (mtype, B.member_off_bytes(moff)[0])
                break
        if found is None:
            return None
        total += found[1]
        cur = types[found[0]] if found[0] < len(types) else None
        if i + 1 < len(names):
            # 下一级：如果是 struct/union 就继续；如果被 ptr/const/typedef 包着就剥
            seen = set()
            while cur is not None and cur["kind"] not in (B.K_STRUCT, B.K_UNION):
                if cur["kind"] in (8, 9, 10, 11, 18):
                    tid = cur["sot"]
                    if tid in seen:
                        cur = None
                        break
                    seen.add(tid)
                    cur = types[tid] if tid < len(types) else None
                else:
                    cur = None
            t = cur
    return total


def main():
    kernel = open(KERNEL, "rb").read()
    cands = B.find_btf(kernel)
    if not cands:
        print("找不到 BTF")
        return 1
    types, _str_data, _td = B.parse_btf(kernel, cands[0])

    raw, _ = load_defs(TARGET)

    ok, bad, miss = [], [], []
    for cname, struct, chain in CHECKS:
        if cname not in raw:
            continue
        val = to_int(raw[cname], raw)
        if val is None:
            continue
        exp = member_offset(types, struct, chain)
        if exp is None:
            miss.append((cname, struct, ".".join(chain), val))
        elif exp == val:
            ok.append((cname, struct, ".".join(chain), val))
        else:
            bad.append((cname, struct, ".".join(chain), val, exp))

    print("=" * 76)
    print("target_mey_an00.h 结构体字段偏移核对（对照设备内嵌 BTF）")
    print("=" * 76)
    print("一致 : %d   不一致 : %d   字段未找到 : %d" % (len(ok), len(bad), len(miss)))
    print()
    if bad:
        print("---- ★ 不一致（会静默失效，必须处理）----")
        for c, s, f, v, e in bad:
            print("  %-32s %s.%-16s target=0x%04x  btf=0x%04x  diff=%+d"
                  % (c, s, f, v, e, v - e))
        print()
    print("---- 一致 ----")
    for c, s, f, v in ok:
        print("  %-32s %s.%-16s 0x%04x" % (c, s, f, v))
    if miss:
        print()
        print("---- BTF 里没找到该字段（名字可能不对，需人工确认）----")
        for c, s, f, v in miss:
            print("  %-32s %s.%-16s target=0x%04x" % (c, s, f, v))
    return 0


if __name__ == "__main__":
    sys.exit(main())
