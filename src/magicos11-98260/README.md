# magicOS11-98260-kit → `src/magicos11-98260/`

> **公开仓库说明**：本目录现在是交付包的**可执行部分**（文本 + 静态 payload + 上游源码）。
> 部署目录由 `run.sh` 自适应定位，不再硬编码 `/sdcard/ksu98260`；`onefire.sh`（PC 侧）会投到
> `/data/local/tmp/ksu98260/`。**不含任何 APK**（`.gitignore` 排除 `*.apk`，项目已决定不上传）。
> 源码来源与许可证归属见 [`upstream/SOURCE-NOTICE.txt`](upstream/SOURCE-NOTICE.txt)。
>
> **开箱程度：半开箱。** 仓库已提供可执行主体，仍需设备侧环境。
>
> | 仓库已提供 | 状态 |
> |---|---|
> | 静态非 PIE arm64 payload（462 KB，设备侧零动态依赖） | ✅ md5 `3e68cb01…` |
> | 上游 C 源码 + `build.sh`（NDK 27.0.12077973 实测字节级可复现） | ✅ |
> | `run.sh`（设备侧）+ `onefire.sh`（PC 侧投放器） | ✅ 但编排路径未真机验证 |
> | 本机偏移 / BTF 偏移 / GhostKey profile / 判据 / 成功证据 | ✅ |
>
> | 仍需自备（仓库无法提供） | 说明 |
> |---|---|
> | 目标设备 | MEY-AN00 + `uname -r` 精确匹配 + BL 锁定 |
> | shell(uid=2000) 域 | `adb shell` 或 Shizuku 终端；App 域必然 Permission denied |
> | KernelSU Manager | `fake` 成功后 `ksud late-load` 依赖其 `libksud.so` |
> | tracefs 可读、全新 boot | 98260 硬门槛；一 boot 一发 |
>
> **★ 置信度（务必看）**：payload 本身**已实测成功**（2026-11-02），但那次走的是
> GhostLock APK 经 **Shizuku UserService** 投放；`run.sh` + `onefire.sh` 这条编排
> **从未真机验证**，属 `[源码推断未验证]`。所以「半开箱」不等于「保证一键成功」。
>
> 一条命令（PC 侧，设备已开 USB 调试）：
> ```bash
> sh onefire.sh
> # 无 PC：把本目录拷到 /sdcard/ksu98260/，在 Shizuku 终端执行
> sh /sdcard/ksu98260/run.sh
> ```

荣耀 500（MEY-AN00）/ MagicOS **11.0.0.110** 的 CVE-2026-98260 临时 root 交付包。
目标内核 `6.6.118-android15-8-g554929766a0d-abogki544555896-4k`（BL 锁定，无需解锁）。

## 内容

| 文件 | 说明 | 校验 |
|---|---|---|
| `cve-2026-98260-uid0` | 98260 payload，**静态非 PIE arm64**（ELF `ET_EXEC`，无 `PT_INTERP`/`PT_DYNAMIC`），设备侧零动态依赖 | md5 `3e68cb01fba10447b0a34361b1326fac`<br>sha256 `7842ea6a96285f4ca3275776a9306f08b8c9404fb1eb99dd4cafcf362537ec80` |
| `run.sh` | 设备侧：环境自检 → 一 boot 一发门 → tracefs → KSU Manager → 哈希校验 → 只读自检 → 真打 → 独立透镜 | — |
| `onefire.sh` | PC 侧：机型门 → adb 投放 → `adb shell sh run.sh` → 取回日志 | — |
| `build.sh` | 字节级复现编译（**必须 NDK 27.0.12077973**），自动比对 md5/sha256 | — |
| `build-profiled.sh` | 编译 **profile 驱动版** payload（常量可在运行时被 profile 覆盖） | — |
| `profiled/cve-2026-98260-profiled.c` | 由 `upstream/` 改造：15 个常量变成默认值 + 启动时读 profile 覆盖 | — |
| `upstream/cve-2026-98260.c` | 上游 exploit 源码，单文件自包含，11 项本机常量已硬编码 | md5 `20f29282948a6e6a4760be7463ff139d` |
| `upstream/LICENSE-MIT.txt`、`SOURCE-NOTICE.txt` | MIT 全文 + 来源链 + 授权灰区说明 | — |
| `offsets_11.h`、`btf_offsets_11.json`、`profile/`、`key_symbols_11.txt` | 本机固件提取的文本基线 | — |

> `ksud` **不在本仓库**（6.4 MB，仅兜底）。2026-11-02 成功时实际用的是设备侧
> KernelSU Manager 自带的 `libksud.so`，所以必须装 Manager。

**payload 来源与可复现性（2026-11-07 实测修订）**：源码为 `upstream/cve-2026-98260.c`，
用 **NDK 27.0.12077973** 按上游 `build.sh` 的**原样 flags** 编译（`build.sh` 已封装）：

```bash
aarch64-linux-android35-clang -std=gnu11 -O2 -g -static -pthread -D_GNU_SOURCE \
  -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
  upstream/cve-2026-98260.c -o cve-2026-98260-uid0
llvm-strip --strip-all cve-2026-98260-uid0
```

实测产物 md5/sha256 与现役 payload **逐字节相同** ⇒ 可复现构建，证明二进制里的常量就是源码里那批
（已与本机符号表/BTF 对账过的 11 项，见下）。

⚠️ **NDK 版本必须锁定**：用 r27c（27.2.12479018）编译只差 6 字节，全部落在
`.note.android.ident` 的 NDK 版本串（`r27/12077973` ↔ `r27c/12479018`），代码体零差异。
早期文档写的简化命令（`-O2 -static`，无 `-std/-pthread/-D_GNU_SOURCE`）**不足以复现**，已废弃。

## profile 驱动版（可选）

`upstream/` 的常量是**编译期写死**的：换内核 build 就得改源码重编。`profiled/` 把其中 16 个值
改成"默认值 + 运行时覆盖"：

| 项 | 硬编码版 | profile 驱动版 |
|---|---|---|
| 常量来源 | `#define` 写死 | `#define` 作默认值，启动时读 profile 覆盖 |
| 换内核 | 改源码 + 重编 | 只改 profile 文件 |
| 无 profile 时 | — | **行为与硬编码版相同**（沿用默认值，静默） |
| 字节级可复现 | ✅ md5 `3e68cb01…` | ❌ 多了解析器代码 |

**查找顺序**：`$CVE98260_PROFILE` → `/data/local/tmp/98260-profile.conf` → 都没有则用默认值。

**可被覆盖的字段**（`offset { }` 块内）：

```
timer_link  cred_link  task_alloc_link  selinux_link  panic_on_warn
root_user   user_ns    ucounts          groups
task_cred   task_struct_size  cred_uid  cred_size
kitimer_node  kitimer_size
```

`*_link` 类字段是**链接期地址**，程序会自行取低 21 位（`& 0x1fffff`）用于 KASLR 站点匹配；
`task_cred` / `cred_uid` / `kitimer_*` 等是结构体偏移，按原值使用。

**编译**：

```bash
ANDROID_NDK_HOME=/path/to/ndk/27.0.12077973 sh build-profiled.sh
```

**生效判据**：日志出现 `[prof] /data/local/tmp/98260-profile.conf -> N field(s) applied`。
没有这一行 = 未找到 profile，走默认值。

**风险**：profile 写错会直接导致提权失败或 kernel panic —— 它是**写内核地址的输入**，不是提示信息。
建议先用 `check` 模式验证 tracefs 与基址解算，再开火。

## 已验证的 11 项常量（全部来自本机固件，零推断）

| 常量 | 值 | 来源 |
|---|---|---|
| `do_timer_create+0x94` | `ffffffc0803afcec` | 本机 kallsyms 符号表 |
| `selinux_state` | `ffffffc0823ba418` | 同上 |
| `panic_on_warn` | `ffffffc08216ae0c` | 同上 |
| `root_user` | `ffffffc08218f228` | 同上 |
| `init_user_ns` | `ffffffc08218ef98` | 同上 |
| `init_ucounts` | `ffffffc082190cf8` | 同上 |
| `init_groups` | `ffffffc082190788` | 同上 |
| `prepare_creds+0x20` low21 | `0x38458` | 符号地址 +0x20 推算 |
| `copy_process+0x144` low21 | `0x1cb240` | 符号地址 +0x144 推算 |
| `task_struct.cred` / `sizeof` | `0x820` / `0x12c0` | 本机 BTF `offsetof` |
| `k_itimer` / `it` / `cpu_timer.node` | `0x108` / `0x78` / `0x0` | 本机 BTF |

补丁状态：`posixtimer_exec` 在 111,074 个符号中**不存在**，`exit_itimers`/`posix_cpu_timers_exit` 存在 → 未修补。
（`grep -c posixtimer_exec /proc/kallsyms` 可在设备上二次证实，期望 0。）

## 部署

1. 把整个 `magicOS11-98260-kit` 目录放到手机 **`/sdcard/ksu98260/`**（脚本里的 `KIT` 路径写死为此）。
   ```
   /sdcard/ksu98260/cve-2026-98260-uid0
   /sdcard/ksu98260/ksud
   /sdcard/ksu98260/run.sh
   ```
   （`/sdcard` 是 noexec，不能直接在那里执行；脚本会把它拷到 `/data/local/tmp/`。）
2. 装 **Shizuku**（用无线调试方式启动，不要选 root 方式），在 Shizuku 终端里执行：
   ```sh
   sh /sdcard/ksu98260/run.sh
   ```
3. 首次建议先单独跑只读模式确认：
   ```sh
   cp /sdcard/ksu98260/cve-2026-98260-uid0 /data/local/tmp/ksu98260 && chmod 755 /data/local/tmp/ksu98260
   /data/local/tmp/ksu98260 check      # tracefs + 直接映射基址
   /data/local/tmp/ksu98260 leak       # 只泄漏 cred / task_struct，零写入
   /data/local/tmp/ksu98260 selftest   # 写原语打在自己进程页上
   ```
   三个都过了再跑 `fake`。

## 成功判据（独立透镜，禁止用 payload 自报）

```sh
id                              # uid=0(root) gid=0(root) context=u:r:ksu:s0
getenforce                      # Permissive（fake cred 路线置 0）
grep -w kernelsu /proc/modules  # 出现 kernelsu 行
su -c id                        # uid=0(root) ... context=u:r:ksu:s0
```

## 风险与回滚

- **不改任何分区** → 不会变砖；最坏是注入阶段 panic 重启（README 明示有此概率）。
- **回滚 = 重启**。root 是临时的，重启失效。
- BL 锁定 + `verifiedbootstate=green` → **持久化 root 物理上不可能**，每次重启都要重跑。
- 成功后进程驻留是**故意**的：那块页承载着活着的 `task->cred`，进程退出会把页还给 slab，
  随后 `cleanup_timerqueue()` 在陈旧 rb_node 上操作会 panic。**不要 kill，清理只能重启。**
- **一 boot 一发**。同 boot 反复打会累积破坏内核数据结构甚至 hang。

## 失败分支

| 观测 | 结论 | 下一步 |
|---|---|---|
| `id -u` 不是 2000 | 测错域（App 域） | 换 Shizuku 终端 / adb shell |
| `trace_pipe_raw: Permission denied` | 98260 + 64560 双堵 | 转 BPF（本机 `BPF_UNPRIV_DEFAULT_OFF` 未开 = 非特权 bpf 默认开放）→ perf（`perf_event_paranoid=-1`）→ io_uring |
| `check` 拿不到 direct map base | 环境不支持 | 看 `run.log` 定位 |
| fake 后设备重启 | 注入失败 | 确认 boot_id 变化后重跑；换 boot 再来 |

已排除：`USER_NS` 与 `NF_TABLES` 均 not set（unshare/CLONE_NEWUSER 与 nf_tables 类路线不可用）。

## 不要用的东西

- 本机 `lkm-aarch64-android15-6.6_kernelsu.ko`：vermagic 是 `6.6.127-4k-g46a034eca005-dirty`，
  **与本机 6.6.118 不匹配**，insmod 必失败。LKM 交给已安装的 KernelSU 管理器的 `ksud late-load --kmi android15-6.6`。
