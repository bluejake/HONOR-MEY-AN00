#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
H12 同类变体穷举：rb_erase 写原语的几何变体矩阵
目标：找出所有能让 *(X) = Y 可控的 (pc, right, left) 组合，
      以及每条路径的"打错→崩"风险。
"""
def analyze(pc, right, left):
    """返回 dict: 路径 / 写入列表 / 崩溃风险"""
    W = []          # 写入 [(addr_expr, value_expr)]
    risk = []
    if left != 0:
        if right != 0:
            return dict(path="0x3aa1c 双子/后继", W=["（复杂，多写）"], risk=["后继查找依赖 child 链可读"])
        # left!=0 & right==0
        return dict(path="0x3ab04 单子(左)", W=["*(pc&~3 +0x10 或 +8) = 0", "*(0)=pc"],
                    risk=["0x3ab7c 后继 walk 读 child->left 链"])
    # left==0
    par = pc & ~3
    if par == 0:
        return dict(path="0x3aa00 空树", W=["*(root) = right"], risk=[])
    # 0x3a9f0 读 *(par+0x10)
    risk.append("★ 0x3a9f0 读 *(par+0x10) —— par 必须可读")
    if right != 0:
        W.append("*(par+0x10 或 +8) = right   [0x3aa00]")
        W.append("*(right) = pc              [0x3aa10]")
        return dict(path="0x3a9dc->0x3aa10 (本几何)", W=W, risk=risk)
    # right==0
    W.append("*(par+0x10 或 +8) = 0")
    if pc & 1:
        return dict(path="0x3aa78 rebalance", W=W, risk=risk+["RED+无子 -> 进 __rb_erase_color (复杂)"])
    return dict(path="0x3a9dc->0x3aa0c (B LACK)", W=W, risk=risk)

print("="*90)
print("H12 变体矩阵：rb_erase(node) 的 (pc, right, left) -> 路径/写序/风险")
print("="*90)
cases = [
  ("V1 现有: pc=EVEN, right!=0, left=0",  0xffffff802a29b090, 0xdead0000, 0),
  ("V2 pc=EVEN, right=0,   left=0",       0xffffff802a29b090, 0,          0),
  ("V3 pc=ODD,  right=0,   left=0",       0xffffff802a29b091, 0,          0),
  ("V4 pc=ODD,  right!=0,  left=0",       0xffffff802a29b091, 0xdead0000, 0),
  ("V5 pc=0,    right!=0,  left=0",       0,                  0xdead0000, 0),
  ("V6 pc=0,    right=0,   left=0",       0,                  0,          0),
  ("V7 pc=EVEN, right=0,   left!=0",      0xffffff802a29b090, 0,          0xbeef0000),
  ("V8 pc=EVEN, right!=0,  left!=0",      0xffffff802a29b090, 0xdead0000, 0xbeef0000),
]
for name, pc, r, l in cases:
    res = analyze(pc, r, l)
    print("\n[%s]" % name)
    print("  路径: %s" % res["path"])
    for w in res["W"]: print("    W: %s" % w)
    for x in res["risk"]: print("    ! %s" % x)

print("\n"+"="*90)
print("结论矩阵:")
print("  ✓ V1(现有)  写 *right=pc 与 *(par+8)=right —— 两处可控, 走 0x3aa10 直接 ret, 无 rebalance")
print("  ✓ V3(ODD+无子+无left) 进 rebalance —— 风险高, 不采用")
print("  ✓ V5(pc=0)  写 *root=right —— 等价 V1 但少依赖 par 可读")
print("  ✗ V2/V6    无子 BLACK -> 只摘链, 不产生跨结构写")
print("  ! V4(pc=ODD+right!=0) 写 *(right)=ODD指针 -> 奇数指针污染 => 后续解引用必崩")
print()
print("⇒ 现有 V1 是【最优几何】。唯一真实风险 = 0x3a9f0 对 par 的读 (par=c&~3 必须映射)。")
print("⇒ 因此 stageB 崩点不来自几何选择, 而来自【时序窗口过长】(exec_after_deleted=100)")
print("   使得 rb_erase 的 train 里混入大量其它 timerqueue 操作, 令 par 指向的页被改写/卸映射。")
print("="*90)
