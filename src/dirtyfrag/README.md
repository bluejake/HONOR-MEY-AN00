> [!IMPORTANT]
> If you want your own ksud binary, compile from diabl0w's fork of KernelSU: https://github.com/diabl0w/KernelSU

# CVE-2026-43284

## What's changed in this fork

- **OneUI-style UI** — OneUI-inspired card + custom-drawn OneUI switches, OneUI-style bottom fade, floating run button and a two-step progress bar (progress → verification) in the system-update style
- **Expert Mode** — autorun options are gated behind an Expert Mode toggle in the ⋮ menu (off by default)
- **Hardened autorun** — boot-time soft reboot is a separate toggle ("Auto reboot — soft reboots after root"), **off by default**; a failed boot-time run disables autorun instead of retry-looping (protection against the RescueParty boot-loop brick reported in the field); no hidden defaults anywhere
- **Share log button** — saves the log to `Downloads/dirtyfrag_log.txt` and opens the Downloads screen
- **APK shrunk 14.6 MB → ~6.2 MB** via R8 minification + resource shrinking (`proguard-rules.pro`)

Credits:
- DFRoot — base of this fork: https://github.com/diabl0w/DFRoot
- Original PoC and various code: https://github.com/lsposed/lspromise
- Selinux Permissive kernel modules and various code: https://github.com/polygraphene/DFReroot
- Unprivileged XFRM socket method: https://github.com/combeng6th/DirtyInit

## Usage

Install KernelSU (download "manager" file) from actions flow: https://github.com/tiann/KernelSU/actions/runs/35973514328

## Features

- Start on Boot
- Automatic soft reboot 
- RO Partition Protection
- Hide Selinux Modifications in KSU
- Shizuku not needed — regain root without WiFi!

> [!WARNING]
> I am not responsible for any damage to your device.

<img width="540" height="1170" alt="Screenshot_20261002_003005" src="https://github.com/user-attachments/assets/b3b13f16-8cf3-44ad-bf72-b623ca55b60e" />

## Supported Devices

Ephemeral root for Samsung devices (and possibly others) w/ locked bootloaders vulnerable to DirtyFrag (CVE-2026-43284) 

| KMI Version | Verified |
|---|---|
| android12-5.10 | Yes |
| android13-5.10 | Untested |
| android13-5.15 | Yes |
| android14-5.15 | Untested |
| android14-6.1 | Not working - accidental mitigation (see V4bel/dirtyfrag issue 23) |
| android15-6.6 | Yes |
| android16-6.12 | Yes |
| android17-6.18 | Untested |

## How it works

The Android kernel decrypts AES-CBC ESP packets directly into the page cache of files open for `splice()`. By crafting `IV = AES_ECB_DEC(key, current_content) ⊕ desired_content`, any 16-byte-aligned block in a mapped shared library can be overwritten without write permission and without copy-on-write.

The exploit uses this primitive to patch shellcode into `libc++.so` in the kernel's page cache. The next privileged call to the hooked function runs the shellcode, which loads our custom kernel module via `insmod`.

### Exploit chain

1. **IpSec transform** — App allocates a `UdpEncapsulationSocket` + SPI and builds an AES-CBC/HMAC-SHA256 ESP transform via `IpSecManager`.

2. **splicehelper → crash_dump64** — The splicehelper binary is spliced into `crash_dump64` via the CBC primitive. `crash_dump64` runs in the `crash_dump` SELinux domain (via exec label transition), which can open `vendor_file` labeled files (untrusted_app context cannot read these files so we need this bridge). The splicehelper serves two modes: splice mode (pipe a 16-byte page chunk out to the parent for write) and read mode (`argv[3]="r"`, write 16 bytes of file content to a pipe fd for IV computation).

3. **dirtyfrag.ko → vendor_file** — The kernel module is written via the crash_dump bridge (splicehelper splice mode) into a `vendor_file`-labeled file.

4. **libc++ hook** (fires in init, uid=0, tid=1) — Shellcode is patched into `libc++.so` at `std::ostream::sentry::sentry()`. Triggered by: `createOrphanProcess()` double-forks so the grandchild is adopted by PID 1 (init); when init reaps the orphan its main thread (tid=1) calls through the hooked function. The shellcode:
   - Checks `getuid()==0` and `gettid()==1`; returns immediately otherwise
   - Creates `/dev/df` as a one-shot mutex (O_CREAT|O_EXCL) to prevent re-entry
   - Clones a worker child (parent returns to init immediately)
   - Worker forks a grandchild; grandchild writes `u:r:vendor_modprobe:s0` to `/proc/self/attr/exec` then execs `/vendor/bin/insmod <ko_target>`

5. **dirtyfrag.ko init** (runs as `vendor_modprobe`, uid=0) — The KO is loaded by `insmod` in the `vendor_modprobe` SELinux domain:
   - Writes `false` to `selinux_state` (global permissive)
   - Bypasses DEFEX via kprobes
   - Calls `call_usermodehelper` to launch the `ksud` binary from our app's data dir
   - Module returns `-E2BIG` immediately after to self-unload



## Universal build (this fork)

One tap = SELinux permissive + KernelSU jailbreak, no adb staging, no rootd.

- `dirtyfrag.ko` UMH payload is `dfsh` (app-protected dir, same-length path swap)
- `dfsh` installs the paired `kernelsu-{kmi}.ko` + `ksud` by runtime uname KMI
  match, then runs `ksud late-load` — Manager shows jailbreak mode
- KSU artifacts are fetched from the latest tiann/KernelSU main-branch run
  (stable keystore: manager and all KMI modules mutually paired); CI
  re-triggers automatically when that run id moves (`check-upstream.yml`)

| KMI | Status |
|-----|--------|
| android12-5.10 | verified upstream |
| android13-5.10 | untested |
| android13-5.15 | verified upstream |
| android14-5.15 | untested |
| android14-6.1 | NOT SUPPORTED - accidental mitigation (the V4bel DirtyFrag repo, issue 23) |
| android15-6.6 | verified upstream |
| android16-6.12 | verified on-device (YLP-W00) |
| android17-6.18 | untested |

Local prep: `./scripts/fetch-ksu.sh` then `./build.sh`. Release keystore via
secrets `RELEASE_KEYSTORE_B64` / `RELEASE_KS_PASS` / `RELEASE_KEY_PASS`.
