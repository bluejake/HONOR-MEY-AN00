# H107 · `/dev/uinput` 全量审计（MEY-AN00 三环闭环）

- 设备：MEY-AN00 · MagicOS 10.0.0.175(C00E170R201P2H1) · A16 · 内核 `6.6.118-android15-8-gf17133276a57-abogki518694926-4k`
- 上下文：`u:r:shell:s0` / uid=2000 / 组含 `1004(input)`、`3011(uhid)` · `getenforce=Enforcing`
- boot：`boot_id=f425d0ee-…`，全程同一 boot（uptime 4399s → 扫描结束时仍连续）
- 产物：`analysis/output/h107_uinput_full_audit.md`（本文）、`analysis/scratch/uinput_full.asm`（33 符号 2673 行）、
  `analysis/output/h107_uinput_scan_run1.txt`、`exploit-src/dc15/h107_uinput_{scan,lens,evdev}.c`

---

## 0. 裁定速览

| 项 | 结论 |
|---|---|
| **uinput 自身是否存在可利用内存破坏漏洞** | **否。** 设备侧 uinput 与上游 Linux 6.6 逐函数等价，10 个 bitmap 边界、2 处 request_id 边界、2 处 state 闸门、全部 `copy_*_user` 尺寸全部对齐上游，未发现厂商放宽或缺失的补丁 |
| **是否发现对本项目有推进价值的结构性事实** | **是，3 条**（见 §5） |
| **是否推翻旧结论** | **是，2 条**（见 §0.1） |
| 是否触发内核崩/重启 | 否，全程 0 次重启，`boot_id` 未变 |

### 0.1 被本次实测推翻的旧结论

| 旧结论 | 出处 | 推翻依据 |
|---|---|---|
| 「uinput 数据面只写不读，不能当判据通道」 | H158 | **错。** `UI_DEV_CREATE` 实测 **rc=0**；随后 `UI_GET_SYSNAME(64)` 返回真实 sysfs 名 `input26`/`input36`/`input38`/`input39`（rc=8）。H158 得到 ENOENT 是因为**没有先成功 `UI_DEV_SETUP` + `UI_DEV_CREATE`**，`udev->state` 未达 `UIST_CREATED(2)`，源码 `uinput_str_to_user` 前的 state 闸门直接返回 `-ENOENT` |
| `UI_DEV_CREATE` 两种形式都 EINVAL | H158 | **错。** 实测 `0x00005501` → rc=0。前置条件是 `UI_DEV_SETUP` 成功（`name[0] != 0`，`state 0/1 → 1`），之后 `state==1` 才能进 `UI_DEV_CREATE` |
| 「shell 域拿不到任何内核读回」 | MEMORY.md「真总闸门」 | **部分推翻。** 至少已有一条**跨驱动独立透镜**闭环：uinput 写 `name`/`input_id`，经 `/dev/input/eventN` 的 `EVIOCGNAME`/`EVIOCGID`（evdev 子系统）读回，见 §4.3 |

---

## 1. 环① 源码基线（`kernel_src/Code_Opensource/kernel/drivers/input/misc/uinput.c`，6.6）

### 1.1 ioctl 命令表（uapi 与设备汇编逐位一致）

| 命令 | nr | uapi 值 | 设备汇编比较值 | 备注 |
|---|---|---|---|---|
| `UI_DEV_CREATE` | 1 | `0x00005501` | `0x5501` | 需 `state==UIST_SETUP` |
| `UI_DEV_DESTROY` | 2 | `0x00005502` | `0x5502` | — |
| `UI_DEV_SETUP` | 3 | `0x405c5503` | `0x405c5503` | `sizeof(uinput_setup)=0x5c` ✓ |
| `UI_ABS_SETUP` | 4 | `0x401c/40205504` | **屏蔽 size** 后 `0x40005504` | 变长，走 `copy_struct_from_user` |
| `UI_SET_EVBIT`…`UI_SET_SWBIT` | 100…109 | `0x40045564`…`0x4004556d` | 逐个精确比较 | `UI_SET_PHYS`=nr108=`0x4008556c`（`char*`，size 8） |
| `UI_SET_PROPBIT` | 110 | `0x4004556e` | ✓ | — |
| `UI_BEGIN_FF_UPLOAD` | 200 | `0xc06855c8` | `0xc06855c8` | — |
| `UI_END_FF_UPLOAD` | 201 | `0x406855c9` | `0x406855c9` | **注意是 `_IOW` 不是 `_IOWR`** |
| `UI_BEGIN_FF_ERASE` | 202 | `0xc00c55ca` | `0xc00c55ca` | — |
| `UI_END_FF_ERASE` | 203 | `0x400c55cb` | `0x400c55cb` | — |
| `UI_GET_SYSNAME(len)` | 44 | `(len<<16)\|0x8000552c` | **屏蔽 size** 后 `0x8000552c` | 变长 |
| `UI_GET_VERSION` | 45 | `0x8004552d` | `0x8004552d` | 恒返回 5 |

> 汇编里出现的 `0x40045563`、`0x4008556b`、`0xc00c55c9`、`0xc06855c7` 等，都是编译器把 `>=` 优化成 `> (X-1)` 的**偏置常量**，非新命令。

### 1.2 用户可控输入 → 内核校验点（全表）

| 入口 | 用户可控量 | 内核校验 | 源码位置 |
|---|---|---|---|
| 10 个 `UI_SET_*BIT` | `arg`（unsigned long） | `udev->state==UIST_CREATED → EINVAL`；`arg > *_MAX → EINVAL`；否则 `set_bit` | `uinput_set_bit` 宏 |
| `UI_SET_PHYS` | 用户字符串 | state 闸门；`strndup_user(p,1024)`（≥1024 → `-EINVAL`）；`kfree` 旧的 `dev->phys` | `uinput_ioctl_handler` |
| `UI_DEV_SETUP` | `uinput_setup`(92B) | state 闸门；`copy_from_user(0x5c)`；`!name[0] → EINVAL`；`kstrndup(name,80,GFP_KERNEL)` | `uinput_dev_setup` |
| `UI_ABS_SETUP` | `uinput_abs_setup`(变长) | state 闸门；`copy_struct_from_user`（usize>ksize→`-E2BIG`，非整数倍→`-ERANGE`）；`code > ABS_MAX(0x3f) → EINVAL`；`uinput_validate_absinfo` | `uinput_abs_setup` |
| `UI_BEGIN/END_FF_UPLOAD`、`_ERASE` | `request_id`(u32) | `request_id > 0xf → EINVAL`；`req==NULL / req->code≠期望 / req->u.upload.effect==NULL → EINVAL` | `uinput_request_find` |
| `UI_GET_SYSNAME` | `len` | `state != UIST_CREATED → ENOENT`；`len==0 → EINVAL`（`uinput_str_to_user`） | `uinput_str_to_user` |
| `write()` | `uinput_user_dev`(0x45c) 或 `input_event`(0x18) | 尺寸必须**恰好** 0x45c（否则 EINVAL），或 0x18 的整数倍 | `uinput_write` |
| `read()` | 缓冲区 | `state != UIST_CREATED → ENOENT`；`size < sizeof(input_event) → EINVAL`；compat 用 0x10、native 用 0x18 | `uinput_read` |

---

## 2. 环② 反汇编（33 符号全量，`uinput_full.asm` 2673 行）

### 2.1 全部 `bl` 目标已解析（关键项）

| 地址 | 符号 | 含义 |
|---|---|---|
| `0x80195fc0` | `__arch_copy_from_user` | 用户拷贝（前后有 TTBR0/TTBR1 切换 = TSSO uaccess） |
| `0x80204480` | `__arch_copy_to_user` | 同上 |
| `0x80552d90` / `0x80552fc0` | **`memmove` / `memset`** | ⚠️ 早前误判为 copy_*_user，实为普通内存函数 |
| `0x80b16778` | **`fortify_panic`** | ⇒ **FORTIFY_SOURCE 已开** |
| `0x81071d44` | **`__stack_chk_fail`** | ⇒ 栈 canary（per-task，`current+0x620`） |
| `0x80053338` | **`__check_object_size`** | ⇒ **HARDENED_USERCOPY 已开** |
| `0x800a97c0` / `0x801f917c` | `strndup_user` / `kstrndup` | — |
| `0x807a9f94` | `memdup_user` | — |
| `0x804ea3fc` | `misc_open` | 见 §5.1（**关键**） |

另：所有函数均有 `paciasp`/`autiasp`（**PAC 已开**）；`uinput_open` 由 `kmalloc_trace(cache, GFP_KERNEL|__GFP_ZERO=0xdc0, 0x288)`。

### 2.2 `struct uinput_device` 权威布局（设备实测，`sizeof = 0x288`）

| 偏移 | 字段 | 证据 |
|---|---|---|
| `+0x000` | `dev`（`input_dev *`） | `ldr x8,[x21]` / `str x0,[x21]` |
| `+0x008` | `mutex`（0x30） | `add x19,x21,#8` → `mutex_lock_interruptible` |
| `+0x038` | `state` | `ldr w8,[x21,#0x38]; cmp w8,#2`（UIST_CREATED） |
| `+0x040` | `waitq`（0x18） | `__init_waitqueue_head(udev+0x40)` |
| `+0x058/0x059/0x05a` | `ready / head / tail` | `ldrb [x19,#0x59]`/`#0x5a` |
| `+0x060` | `buff[16]`（0x180） | stride `0x18`；`head=(head+1)&0xf` |
| `+0x1e0` | `ff_effects_max` | `str w8,[x19,#0x1e0]` |
| `+0x1e8` | `requests[16]`（0x80） | `ldr x8,[x8,#0x1e8]`；destroy 展开 0x1e8…0x260 |
| `+0x268` | `requests_waitq`（0x18） | `__init_waitqueue_head(udev+0x268)` |
| `+0x280` | `requests_lock`（spinlock） | `_raw_spin_lock(udev+0x280)` |

⇒ `0x280 + 8 = 0x288` ✓ 与 `kmalloc` 尺寸完全吻合。

### 2.3 `struct uinput_request` 权威布局（修正旧记录）

| 偏移 | 字段 |
|---|---|
| `+0x00` | `id`（`uinput_request_alloc_id` 写入槽位号） |
| `+0x04` | `code`（`UI_FF_UPLOAD=1` / `UI_FF_ERASE=2`） |
| `+0x08` | `retval` |
| `+0x10` | `done.done`（`struct completion`，size `0x20`） |
| `+0x18` | `done.wait` |
| `+0x30` | `u.upload.effect` |
| `+0x38` | `u.upload.old` |

> ⚠️ **旧记录「code@0 / retval@4」错误**，实际整体后移 4 字节（前面有 `id`）。

### 2.4 `struct input_dev` 关键偏移（设备实测）

| 偏移 | 字段 |
|---|---|
| `+0x00` `name`、`+0x08` `phys`、`+0x18` `id` | 字符串/ID |
| `+0x20` propbit、`+0x28` evbit、`+0x30` keybit(12 longs)、`+0x90` relbit、`+0x98` absbit、`+0xa0` mscbit、`+0xa8` ledbit、`+0xb0` sndbit、`+0xb8` ffbit(2 longs)、`+0xc8` swbit | 10 个能力位图 |
| `+0xf8` `ff`、`+0x158` `absinfo` | 力反馈 / 绝对轴数组 |
| `+0x1e8` `event`、`+0x1f0` `flush` | 回调 |
| **`+0x240` `dev.kobj.name`** | `UI_GET_SYSNAME` 回落源 |
| **`+0x2b0` `dev.init_name`** | `UI_GET_SYSNAME` 首选源 |
| **`+0x2d8` `driver_data` = `udev` 反向指针** | `uinput_dev_event`/`upload`/`erase` 均由此取 udev |

### 2.5 10 个 bitmap 边界逐条对照（**全部一致，无厂商放宽**）

| ioctl | 位图 | 偏移 | 设备 `cmp` | 源码 MAX | 一致 |
|---|---|---|---|---|---|
| `UI_SET_PROPBIT` | propbit | +0x20 | `#0x1f` | `INPUT_PROP_MAX=0x1f` | ✓ |
| `UI_SET_EVBIT` | evbit | +0x28 | `#0x1f` | `EV_MAX=0x1f` | ✓ |
| `UI_SET_KEYBIT` | keybit | +0x30 | `#0x2ff` | `KEY_MAX=0x2ff` | ✓ |
| `UI_SET_RELBIT` | relbit | +0x90 | `#0xf` | `REL_MAX=0xf` | ✓ |
| `UI_SET_ABSBIT` | absbit | +0x98 | `#0x3f` | `ABS_MAX=0x3f` | ✓ |
| `UI_SET_MSCBIT` | mscbit | +0xa0 | `#7` | `MSC_MAX=0x7` | ✓ |
| `UI_SET_LEDBIT` | ledbit | +0xa8 | `#0xf` | `LED_MAX=0xf` | ✓ |
| `UI_SET_SNDBIT` | sndbit | +0xb0 | `#7` | `SND_MAX=0x7` | ✓ |
| `UI_SET_FFBIT` | ffbit | +0xb8 | `#0x7f` | `FF_MAX=0x7f` | ✓ |
| `UI_SET_SWBIT` | swbit | +0xc8 | `#0x10` | `SW_MAX=0x10` | ✓ |

### 2.6 逐函数结论（33 个符号）

| 函数 | 结论 |
|---|---|
| `uinput_read` | 与上游一致；compat 用 0x10、native 用 0x18；`tail>=0x11 → brk #0x5512`（BUG_ON 守卫，不可触达） |
| `uinput_write` | 0x45c 旧式建设备路径 + 事件路径；`input_mt_init_slots(dev, absinfo[ABS_MT_SLOT].maximum+1, 0)`；无越界 |
| `uinput_poll` | kCFI hash `0x7db4acb9`；`head==tail` 判定 |
| `uinput_ioctl` | 纯转发（4 条指令） |
| `uinput_compat_ioctl` | 仅 3 个命令号重映射，无额外面 |
| `uinput_open` | `kzalloc(0x288)` + 3 个 `__init_waitqueue_head` + `stream_open` |
| `uinput_release` | `uinput_destroy_device` + `kfree(udev)` |
| `uinput_validate_absinfo` | `min>max` / `fuzz > max-min` / `ABS_MT_SLOT` 特判，与上游一致 |
| `uinput_ioctl_handler` | 192B 栈帧、栈 canary、跳转表分发；**全部分支与上游 6.6 逐条对齐** |
| `uinput_dev_setup` | `copy_from_user(0x5c)` → `!name[0]→EINVAL` → `kstrndup(name,0x50,0xcc0)` → `state=UIST_SETUP`；**逐行等价** |
| `uinput_abs_setup` | 变长 `copy_struct_from_user`（实测产出 `-E2BIG/-ERANGE`），边界齐全 |
| `uinput_create_device` | `state!=UIST_SETUP→EINVAL`；`EV_ABS`→`input_alloc_absinfo`+`input_mt_init_slots`；`ff_effects_max`→`input_ff_create`+5 个回调；`driver_data=udev`；`state=UIST_CREATED` |
| `uinput_destroy_device` | 16 个 request 展开 `retval=-ENODEV` + `complete()`；`input_unregister_device` + `kfree(name/phys)` |
| `uinput_ff_upload_{from,to}_user` | compat 分支存在，尺寸固定 |
| `uinput_str_to_user` | **`strlen(str)+1` 上限 `maxlen`；`maxlen==0→EINVAL`** |
| `uinput_dev_{event,upload_effect,erase_effect,playback,set_gain,set_autocenter,flush}` | 均先由 `dev+0x2d8` 取 udev，无越界 |
| `uinput_request_{submit,alloc_id}` | `requests_lock` 保护；`alloc_id` 线性扫 16 槽 |
| `uinput_misc_init/exit` | `misc_register(&uinput_misc)` |

---

## 3. 环③ 设备实测（shell 域）

### 3.1 P0 打开矩阵

| 方式 | 结果 |
|---|---|
| `O_RDWR` / `O_WRONLY` / `O_RDONLY` / `O_RDWR\|O_NONBLOCK` | **全部成功**，fd 正常返回 |

### 3.2 P1 原始 ioctl 全量扫（`nr 0..255 × dir 0..3 × size{0,4,8,0xc,0x10,0x20,0x5c,0x60,0x68,0x45c}` = **10240 次**）

非平庸结果 **24 条**，全部可归因：

| cmd | 结果 | 归因 |
|---|---|---|
| `0x00005502` | rc=0 | `UI_DEV_DESTROY` |
| `0x405c5503` | rc=0 | `UI_DEV_SETUP`（arg 为 0xa5 填充，`name[0]≠0` 通过） |
| `0x40005504` | rc=0 | `UI_ABS_SETUP` size=0 → `copy_struct_from_user` 补零，code=0 合法 |
| `0x4004/4008/400c/40105504` | **`-ERANGE`(34)** | `copy_struct_from_user` usize 非对齐 |
| `0x4020/405c/4060/4068/445c5504` | **`-E2BIG`(7)** | usize > ksize |
| `0x8000552c` + 10 种 size | `-ENOENT`(2) | `UI_GET_SYSNAME`，state≠UIST_CREATED |
| `0x8004552d` | rc=0 | `UI_GET_VERSION`，value=**5** |
| `0x4008556c` | rc=0 | `UI_SET_PHYS` |

⇒ **不存在任何「未知命令却返回成功/返回数据」的黑箱面**。

### 3.3 P2 状态机（**关键正面结果**）

| 步骤 | 结果 |
|---|---|
| `UI_GET_VERSION` | rc=0，value=**0x5** |
| 10 个 `UI_SET_*BIT` @ max | **rc=0** |
| 10 个 `UI_SET_*BIT` @ max+1 / huge | **-EINVAL** |
| `UI_SET_PHYS` len=0/1/80/1023 | **rc=0** |
| `UI_SET_PHYS` len=1024/4096 | **-EINVAL** |
| `UI_DEV_SETUP`(valid) | **rc=0** → `state=UIST_SETUP(1)` |
| `UI_DEV_SETUP`(name[0]=0) | -EINVAL |
| `UI_SET_KEYBIT` after SETUP | rc=0（state=1 允许） |
| `UI_GET_SYSNAME(64)` before CREATE | **-ENOENT** |
| **`UI_DEV_CREATE`** | **rc=0** ✅ |
| **`UI_GET_SYSNAME(64)` after CREATE** | **rc=8，str=`input26`** ✅ |
| `UI_GET_SYSNAME` len=16/32/48/64/80/96/112/128 | 全部 rc=8（=`strlen+1`，与 len 无关，符合源码） |
| `UI_GET_SYSNAME` len=0 | -EINVAL |
| `UI_SET_KEYBIT` after CREATE | -EINVAL（state=2 拒绝） |
| `UI_ABS_SETUP` code=0/0x3f/0x40 | -EINVAL（state=2 拒绝） |
| FF `BEGIN/END_UPLOAD/ERASE` id=0…17 | 全部 -EINVAL（无 pending request） |
| `read()`（O_NONBLOCK） | -EAGAIN |
| `poll()` timeout=0 | revents=0 |
| `UI_DEV_DESTROY` | rc=0 |
| **旧式 `write(uinput_user_dev)`，sizeof=1116(0x45c)** | **ret=1116** ✅ |
| 旧式 sizeof=1115 | -EINVAL |
| 旧式 `UI_DEV_CREATE` + `UI_GET_SYSNAME` | rc=0 + **str=`input27`** ✅ |

### 3.4 P3 多实例

**8 个并发 `open` 全部成功**，每个 fd 独立 `UI_SET_PHYS` 全部 rc=0 ⇒ 可从 shell 域同时持有 ≥8 个独立 `uinput_device`（每对象 `kzalloc(0x288)`，即 kmalloc-1024）。

### 3.5 P5 堆分配原语尺寸扫描（`UI_SET_PHYS`）

| len | rc |
|---|---|
| 1,2,7,8,15,16,31,32,63,64,100,127,128,255,256,511,512,1000,1022,1023 | **全部 rc=0** |
| 1024, 1025 | **-EINVAL** |

⇒ `kmalloc` 尺寸 **2 … 1024 字节**完全可控；同尺寸重复调用（200B × 5）全部 rc=0，即 **`kfree` 后紧接 `kmalloc` 的 churn 序列**可用。

---

## 4. 独立透镜（按项目铁律：判据必须走与写入不同的路径）

### 4.1 `/proc/bus/input/devices` —— **不可用**
shell 域 `Permission denied`（SELinux）。故进程内 `popen` 无输出。

### 4.2 sysfs 属性 `/sys/class/input/inputN/{name,phys}` —— **不可用（但存在性可用）**
- 读取全部 `-EACCES`(13)
- 但 `DEV_DESTROY` 后同一路径变为 **`-ENOENT`(2)** ⇒ 至少证明 inputN 条目被真实创建/销毁

### 4.3 ★ `/dev/input/eventN` 的 `EVIOCGNAME` / `EVIOCGID` —— **闭环成功**

```
写：ioctl(/dev/uinput, UI_DEV_SETUP)  name="H107EVDEV-1a2b3c4d"
                                      id ={bustype=0x0019, vendor=0x1070, product=0x1071, version=0x0007}
读：ioctl(/dev/input/event10, EVIOCGNAME) → rc=19, "H107EVDEV-1a2b3c4d"
    ioctl(/dev/input/event10, EVIOCGID)   → rc=0,  bustype=0x0019 vendor=0x1070 product=0x1071 version=0x0007
```

- 写路径：uinput `file_operations` → `kstrndup` → `input_dev->name/id`
- 读路径：**evdev** 子系统的 `file_operations` → `EVIOCGNAME/EVIOCGID`
- 两条路径不共享任何内核函数、不共享设备节点、不共享驱动

⇒ **用户可控数据确实落进内核对象，且可从 shell 域经两条互相独立的路径交叉验证。**

> 注：必须置至少一个 `EV_*` 位（本次用 `EV_MSC`+`MSC_SCAN`，无副作用）并等待 ~1s，ueventd 才会建出 `/dev/input/eventN` 节点。

---

## 5. 对本项目路线的价值（3 条结构性事实）

### 5.1 ★★★ `misc_open` 每次 open 现读 `miscdevice->fops` ⇒ `uinput_misc.fops` 是一等劫持目标（不碰 rodata）

`misc_open@0xffffffc0804ea3fc` 实测汇编：

```asm
0x4ea458: sub  x22, x24, #0x18      ; x22 = &miscdevice      (list 在 +0x18)
0x4ea45c: ldur x8,  [x24, #-8]      ; x8  = *(miscdev+0x10)  == c->fops
...
0x4ea508: str  x22, [x19, #0xd8]    ; file->private_data = miscdev
0x4ea518: str  x24, [x19, #0xc0]    ; file->f_op         = c->fops
0x4ea51c: ldr  x8,  [x24, #0x68]    ; fops->open
0x4ea52c: ldur w16, [x8, #-4]       ; kCFI 校验（hash 0x8f07ca55，原型 int(*)(inode*,file*)）
0x4ea544: blr  x8                   ; 立即调用 fops->open(inode, file)
```

关键符号地址：

| 符号 | 地址 | 段 | 可写 |
|---|---|---|---|
| `uinput_misc` | `0xffffffc0822c02c0` | **D(.data)** | **是** |
| └ `uinput_misc.fops`（+0x10） | **`0xffffffc0822c02d0`** | .data | **是** |
| └ `uinput_misc.minor`（+0x00）= 0xdf(223) | `0xffffffc0822c02c0` | .data | 是 |
| `uinput_fops` | `0xffffffc0812d3f98` | **R(rodata)** | 否 |

⇒ **链路**：任意写 → 改 `.data` 里的 `uinput_misc.fops`（`0x…822c02d0`）指向一块可写内核内存上的伪造 `file_operations` → 下一次 `open("/dev/uinput")` 时 `misc_open` 现读生效 → `fake_fops->open(inode,file)` 被调用。
比改 `uinput_fops`（rodata）**可行度高一档**（无需碰 RO 页，不会因写 RO 页直接 oops）。
**约束**：clang kCFI 会校验被调用者前 4 字节的原型 hash，`fake_fops->open` 只能是**真实的内核函数**（原型 `int(*)(struct inode*,struct file*)`）。

补充：`file_operations` 布局实测为 `read@0x10 / write@0x18 / poll@0x40 / unlocked_ioctl@0x48 / compat_ioctl@0x50 / mmap@0x58 / get_unmapped_area@0x60 / open@0x68 / flush@0x70 / release@0x78`。

### 5.2 ★★★ shell 域可达的「用户可控大小 + 用户可控内容 + fd 绑定生命周期」堆原语

| 手段 | 分配 | 尺寸 | 内容 | 生命周期 |
|---|---|---|---|---|
| `UI_SET_PHYS` | `strndup_user` → `kmalloc` | **2 … 1024 B** 精确可控（实测 1..1023 字符 rc=0，1024+ → EINVAL） | 任意非 NUL 字节 | `dev->phys`，`kfree` 于下一次 SET_PHYS 或 `uinput_destroy_device`/`close` |
| `UI_DEV_SETUP` | `kstrndup(name, 80, GFP_KERNEL)` | ≤ 80 B | 任意非 NUL 字节 | `dev->name`，同上 |
| `open` | `kzalloc(0x288)` | 固定 648 → **kmalloc-1024** | 部分可控 | fd 生命周期，可 ≥8 个并发 |

并支持 **free-then-alloc churn**（同尺寸重复 `UI_SET_PHYS`：先 `kfree` 旧块再 `kmalloc` 新块）。
⇒ 这是本项目此前缺失的**堆风水原语**（MEMORY.md 记「单 syscall 用户数据→内核栈原语不存在」；堆侧此前未系统探索）。

### 5.3 ★★ `UI_GET_SYSNAME` 是**条件性任意内核读回通道**

`uinput_str_to_user(p, str, maxlen)`：`copy_to_user(p, str, min(strlen(str)+1, maxlen))`，`maxlen = _IOC_SIZE(cmd)` 最大 16383。
`str` 取值链（实测）：`input_dev->dev.init_name`（`+0x2b0`）非空则用之，否则 `dev.kobj.name`（`+0x240`）。

⇒ **配合任意写原语把 `+0x2b0`（或 `+0x240`）改成任意内核地址，即可把该地址起始的字符串读回用户态**（长度受 `strlen` 限制，遇到 NUL 截断）。
前置：`udev->state == UIST_CREATED`（必须先成功 `UI_DEV_SETUP` + `UI_DEV_CREATE`，实测可行）。

---

## 6. 裁定

| 问题 | 裁定 |
|---|---|
| uinput 自身能否直接提权？ | **否。** 无内存破坏、无越界、无类型混淆、无 UAF；所有用户可控索引都有硬边界 |
| uinput 能否作为「写原语落点」？ | **能，且是优质落点**。`uinput_misc.fops@0x…822c02d0` 在可写 `.data`，由 `misc_open` 每次 open 现读 ⇒ 无需碰 rodata（§5.1） |
| uinput 能否作为「读回通道」？ | **条件性能**（需先用写原语改 `input_dev+0x2b0/0x240`，§5.3）；**不依赖写原语的独立读回**只有 `UI_GET_VERSION`(常量5) 与 `UI_GET_SYSNAME`(sysfs 名) 两个不可 steer 的量 |
| uinput 能否作为堆风水原语？ | **能，且是本项目目前最好的一个**（§5.2）：shell 域、尺寸 2..1024B 精确可控、内容可控、可 churn、可 ≥8 路并发 |
| 是否建议继续投入设备时间？ | **不建议把 uinput 当漏洞面继续挖**（三环已闭合、结论为负）。**建议把 uinput 当「原语/落点」纳入 L1 链**：写原语 → `uinput_misc.fops` → 控制流；以及用 `UI_SET_PHYS` 做堆占位 |

---

## 7. 本轮产物清单

| 文件 | 说明 |
|---|---|
| `analysis/scratch/h107_uinput_dis.py` | 33 符号全量 dump 脚本（capstone） |
| `analysis/scratch/uinput_full.asm` | 33 符号 × 2673 行全量反汇编 |
| `exploit-src/dc15/h107_uinput_scan.c` | 环③ 全量扫描器（P0–P3） |
| `exploit-src/dc15/h107_uinput_lens.c` | 透镜 + 堆尺寸扫描（P5） |
| `exploit-src/dc15/h107_uinput_evdev.c` | 跨驱动独立透镜（P6） |
| `analysis/output/h107_uinput_scan_run1.txt` | 扫描原始输出（152 行） |
| `analysis/output/h107_uinput_full_audit.md` | 本文 |

## 8. 待确认 / 下一步

1. **`uinput_abs_setup` 设备汇编尚未逐行读**（`uinput_full.asm` 2028–2172 行）。其实测行为（`copy_struct_from_user` 的 `-E2BIG/-ERANGE`）已与源码一致，但建议补一轮逐行对齐以彻底闭合。
2. **§5.1 的 fops 劫持链需要「可写内核内存里放伪造 fops」**，目前尚未确定一块地址已知且可写、且空闲的 .data 区域（`uinput_misc` 之后的 padding 是候选，需确认不与其它符号重叠）。
3. **kCFI 原型 hash 约束**：`fake_fops->open` 必须是真实内核函数。需要枚举 `int (*)(struct inode*, struct file*)` 原型的候选函数，评估哪一个能达到「提权」效果。
4. **§5.3 读回通道**依赖已有写原语；若 L1 写原语（rb_erase）落地，可立刻用 `UI_GET_SYSNAME` 做首次「任意内核地址读回」实证。
