import os, re
D = 'analysis/output/b_line/kos'
# 32 个 ogki hook 名（从 ogki_honor.h）
HOOKS = """audit_log_usercopy vmalloc_node_bypass vfree_bypass audit_log_setid audit_log_cfi
task_util uclamp_task_util get_task_tags get_task_rsum check_vip_status ogki_check_task_tags
ogki_async_psi_bypass ogki_tcp_ tcp_rtt tcp_ack tcp_cong tcp_retrans
ogki_f2fs_ f2fs_data f2fs_file f2fs_namei wb_pin
audit_log_module_sign ogki_""".split()
def strings(d):
    out = set()
    for m in re.finditer(rb'[\x20-\x7e]{6,}', d):
        out.add(m.group().decode('ascii'))
    return out
allsyms = {}
for fn in sorted(os.listdir(D)):
    p = os.path.join(D, fn)
    if not os.path.isfile(p): continue
    ss = strings(open(p,'rb').read())
    for s in ss:
        if 'android_' in s and 'ogki' in s:
            allsyms.setdefault(s, set()).add(fn)
        if 'register_trace_android' in s:
            allsyms.setdefault(s, set()).add(fn)
print('=== 所有 android_*ogki* 字符串 及其所在 ko ===')
for s in sorted(allsyms):
    print('%-70s %s' % (s, ','.join(sorted(allsyms[s]))))
