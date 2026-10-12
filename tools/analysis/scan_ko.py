import os, sys, re
D = 'analysis/output/b_line/kos'
pats = {
    b'register_trace_android_rvh_ogki': 'REG_RVH_OGKI',
    b'register_trace_android_vh_ogki':  'REG_VH_OGKI',
    b'android_rvh_ogki':                'RVH_OGKI',
    b'android_vh_ogki':                 'VH_OGKI',
    b'ogki':                            'OGKI_any',
    b'hn_kernel_stp':                   'STP',
    b'kernel_stp':                      'STP',
    b'is_hide_symbols':                 'HIDESYM',
    b'honor_scm':                       'SCM',
    b'honor_tsa':                       'TSA',
    b'commit_creds':                    'COMMIT_CREDS',
    b'prepare_kernel_cred':             'PREP_CRED',
}
hits = {}
for fn in sorted(os.listdir(D)):
    p = os.path.join(D, fn)
    if not os.path.isfile(p): continue
    d = open(p, 'rb').read()
    h = []
    for k, lab in pats.items():
        c = d.count(k)
        if c: h.append('%s=%d' % (lab, c))
    if h:
        hits[fn] = h
print('total ko scanned:', len([f for f in os.listdir(D) if os.path.isfile(os.path.join(D,f))]))
print()
for fn in sorted(hits):
    print('%-38s %s' % (fn, ' '.join(hits[fn])))
