# H237–H238 · 画布偏移公式修正 + 第 6/7 发

> 设备：MEY-AN00 · 会话 2026-10-06 续做
> 本会话真机开火 **7 发**（步 C 安全；步 D 系列 6 发 panic），设备 7 次自动重启后均健康
> 当前：`boot_id 024088a8-…`、`uid 2000`、`Enforcing`

---

## §0 结果速览

| 步 | 内容 | 结果 |
|---|---|---|
| **C** | 拓扑、不投画布 | ✅ 通过 |
| **D-2** | `tree.prio == task->prio == 121`（想走干净出口） | ❌ panic（`20261006103529`） |
| **D-3** | ★ **修正画布偏移公式**后同参数 | ❌ panic（`20261006103708`） |

---

## §1 ★★★ 本轮最重要的修正：画布偏移公式**反了**

### 1.1 正确推导

```
rt_sigreturn 把 512B 写到内核栈 (sp+0x10)
  sp = SP0 − 0x310  ⇒  拷贝区间 = [SP0−0x300, SP0−0x100)
⇒ 画布物理区间 = [S−0x300, S−0x100)，画布字节 C 对应绝对地址 S−0x300+C
waiter 基址 = 绝对深度 0x1F0   （H222/H219 汇编定稿）
⇒ waiter 基址在画布内的偏移 = 0x300 − 0x1F0 = 0x110
⇒ ★ 字段画布偏移 = 0x110 + 字段off        （off = 字段在 waiter 内的偏移）
```

### 1.2 我之前写错的地方

```c
/* h233–h237 用的（错）*/
#define COFF(d) ((d) - G_CANVAS)     /* d=0x1F0 ⇒ 0x1F0−0x300 = −0x110  ❌ 下溢 */
wr64(v + COFF(G_WAITER + 0x00), ...)
```
⇒ `v + (−0x110)` = 画布起点**之前** 0x110 字节 ⇒ **所有字段全写到画布【外面】了**
⇒ 内核读到的是**未初始化栈垃圾** ⇒ 6 发 panic 的**共同直接原因**。

> ⚠️ H222 文档里写的公式 `C = off + 0xF0`（= 0x110 + off，因 0xF0+0x20=0x110… 口径不同）
> 本身是对的 —— **是我的 C 代码实现反了**。这是纯实现错误，不是几何错误。

### 1.3 修正后的偏移自检（已跑，全部落界内）

| 字段 | 绝对深度 | 画布偏移 | 区间 | 判定 |
|---|---|---|---|---|
| `parent_color` | 0x1F0 | **0x110** | [0x110,0x118) | ✅ |
| `rb_right` | 0x1F8 | 0x118 | ✅ |
| `rb_left` | 0x200 | 0x120 | ✅ |
| `tree.prio` | 0x208 | 0x128 | ✅ |
| `task` | 0x240 | 0x160 | ✅ |
| `lock` | 0x248 | 0x168 | ✅ |
| `wake_state` | 0x250 | 0x170 | ✅ |
| **伪 lock** | 0x260 | **0x180** | [0x180,0x1A0) | ✅ |

⇒ 修正后 `h238` 的输出确认：`fakelock=…8f0`、`waiter=…960`、`canvas=…850`
（`fakelock = canvas + 0xA0` ✔、`waiter = canvas + 0x110` ✔）—— 自洽。

---

## §2 ⚠️ D-3 仍 panic ⇒ 根因**不止**偏移

```
[M] S=0x73f0225b50 waiter=0x73f0225960 canvas=0x73f0225850 fakelock=0x73f02258f0
  [W] delivering canvas ...
  [W] delivered=1 sig_hits=1
（此后无输出 ⇒ panic）
```
记录：`reason [page_request], time [20261006103708-52283171]`

⇒ 偏移修好后**仍然崩** ⇒ 说明还有**第二个独立问题**。

### 2.1 目前最强的假设：**消费 path 自己覆盖了画布**

`rt_mutex_adjust_pi` **读** `waiter->tree.prio` 时栈顶在 `0x1F0`（该函数 frame 下推前），
此时读到的应是画布值 121；但：

- `rt_mutex_adjust_prio_chain` 在 `0x815d8` 执行 **`sub sp,sp,#0x80`** ⇒
  其 frame 覆盖 **`[0x1F0, 0x270)`** —— **正好是 waiter 槽 `[0x1F0,0x260)`**！
- 一旦进入 chain，`waiter->lock`(+0x58 ⇒ 绝对 0x248) 等字段**已被 chain 自己的 frame 覆盖**；
- 后续 `0x816c0: ldr x24,[x25,#0x58]` 读到的是 **frame 垃圾** ⇒ `0x8170c` 解引用野指针 ⇒ `page_request`。

⇒ ★★★ **关键结构性冲突**：
`pi_blocked_on` 指向的 waiter 槽 `[0x1F0,0x260)` 与
`rt_mutex_adjust_prio_chain` 自己的 frame `[0x1F0,0x270)` **完全重叠**。
⇒ **链一进入就把我们要用的字段踩掉了。**

### 2.2 这可能才是项目历史的真正死结

项目 HANDOFF 记录过的「系统性 0 次干净 miss / 必然 panic」，以及本轮 7 发同签名 panic，
**都能被这一条解释**：无论画布多准、字段多对，
**只要 `rt_mutex_adjust_prio_chain` 被调用，它自己的 frame 就会先覆盖 waiter 槽。**

⇒ 除非：
- (a) 链在**读 waiter 字段之前**读到的是**已被 `sub sp` 之后的地址**里的值（即我的画布其实"更高"），
  或
- (b) 采用**不在 chain frame 覆盖范围内**的消费路径（例如 `remove_waiter`），
  或
- (c) 让 `pi_blocked_on` 指向**更深的槽**（不在任何消费 frame 的覆盖区）——
  但那需要 waiter 槽本身更深，而 waiter 位置由 futex 拓扑固定。

⇒ ★★ **下一发（也是唯一有意义的下一发）**：改用 **`remove_waiter` 消费路径**
（H106 §7.4 第 1 项；其 `rb_erase` 只用 `waiter+0x00/0x08/0x10`，
且它自己的 frame 是 `[0x1A0,0x1F0)`，**不覆盖 0x1F0 起的 waiter 槽**）。

---

## §3 本会话完整 panic 序列（7 发）

```
reason [page_request], 20261006101535   步 D      （固定写目标）
reason [page_request], 20261006101726   步 D'     （S 派生目标）
reason [page_request], 20261006101846   步 D'-gate（补 rb_leftmost/lock）
reason [page_request], 20261006102155   步 D-final（补 owner=init_task）
reason [page_request], 20261006103529   步 D-2    （tree.prio=121，走干净出口）
reason [page_request], 20261006103708   步 D-3    （★ 修正画布偏移后）
```
全部 **`page_request`**。

---

## §4 下一步（明确）

| 步 | 内容 | 理由 |
|---|---|---|
| **D-4** | 改用 **`remove_waiter`** 作消费器 | 其 frame `[0x1A0,0x1F0)` **不覆盖** waiter 槽 `[0x1F0,0x260)`（见 §2.1） |
| E | 写 `selinux_state.enforcing`（`0xffffffc0823ba418`，slide=0） | 终局判据 `getenforce` |

⚠️ **D-4 之前不要再跑 `sched_setattr` 路径** —— §2.1 的结构性冲突使其注定 panic。

---

## §5 铁律增补

| # | 铁律 |
|---|---|
| **㉚** | ★ **画布内偏移公式 = `0x110 + 字段off`**（= `0x300 − 0x1F0 + off`）。**绝不能写 `深度 − 0x300`**（会下溢到画布外） |
| **㉛** | ★★ **消费路径的 frame 不得与 waiter 槽重叠**：`rt_mutex_adjust_prio_chain` 的 `sub sp,#0x80` 覆盖 `[0x1F0,0x270)` ⊃ waiter 槽 `[0x1F0,0x260)` ⇒ **该消费器结构上不可用**；应改用 frame 更浅的 `remove_waiter` |
| **㉜** | 已 7 发同签名 panic：**在解决 ㉛ 之前，任何 `sched_setattr` 路径的开火都注定失败** |
