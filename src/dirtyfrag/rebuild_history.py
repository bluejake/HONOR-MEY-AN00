#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rebuild_history.py - harden + rebuild every leaky historical APK.
For each version commit: checkout -> apply hardening patches (asset renames,
dynamic OBF ids for new strings, asset_name cases, R8 enable) -> build ->
overwrite the matching releases file -> restore HEAD. Serial (one gradle)."""
import subprocess, os, re, sys, glob, time

REPO = r'D:\MEY-AN00-root-repro\analysis\scratch\DirtyFrag'
os.chdir(REPO)
PY = sys.executable
HEAD = subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()

def log(s):
    print(f'[{time.strftime("%H:%M:%S")}] {s}', flush=True)

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)

# version -> (release filename, commit)
VERSIONS = [
    ('root-verified-ff1bf964.apk', '70194ac'),
    ('v9-su-waiter.apk', None),          # no commit found; skip if none
    ('v11-final.apk', '38a3235'),
    ('v12b-liquidglass.apk', '235b4ec'),
    ('v1.1-feedback.apk', '7614e0c'),
    ('v1.2-umhdiag.apk', '7223ed2'),
    ('v1.3-trace.apk', '8258725'),
    ('v1.4-mutexguard.apk', 'c4aff8f'),
    ('v1.5-obs.apk', '8cf9285'),
    ('v1.6-watchdog.apk', '01134d3'),
    ('v1.7-livenotify.apk', '88a74f6'),
    ('v1.7.1-notifperm.apk', 'fb291f9'),
    ('v1.7.2-sticky.apk', '1a04c80'),
    ('v1.8-autoboot.apk', 'f98b7d1'),
    ('v1.8.1-ticker.apk', '4f8b023'),
    ('v1.8.2-watchui.apk', '2b35991'),
    ('v1.9-final.apk', 'fde9737'),
    ('v1.9.1-clarity.apk', '027c7a6'),
    ('v1.9.2-busyui.apk', 'd1a86d1'),
    ('v1.9.3-diagpack.apk', '6448639'),
    ('v1.9.4-iobinit.apk', 'e6108fd'),
    ('v1.9.5-multiorphan.apk', '7d9e7a9'),
    ('v1.9.6-dualhook.apk', '9ac3e5b'),
    ('v1.9.7-safe.apk', '78b0093'),
    ('v2.0.0-beta1.apk', '9e5762c'),
    ('v2.1.0-beta1.apk', 'ca0a73e'),
    ('v2.2.0-beta1.adbfire.apk', 'bfa631e'),
]

results = []

def apply_hardening():
    """Apply hardening patches to the checked-out tree. Returns new obf ids
    (dict) or raises."""
    ids = {}

    # a) stage plaintext block in exp.c (file-end append, no anchor needed)
    p = 'app/src/main/jni/exp.c'
    s = open(p, encoding='utf-8').read()
    marker = '/* v220 obf additions */'
    if marker in s:
        # already applied (idempotent) - strip previous array if any
        i = s.find(marker); j = s.find('};', i)
        if j > 0 and 'g_v220_names' in s[i:j]:
            s = s[:i] + '/* v220 names in OBF table */' + s[j+2:]
            open(p, 'w', encoding='utf-8').write(s)
    else:
        block = '''
/* v220 obf additions */
static const char *g_v220_names_unused[] = { "O0O1l", "Ol1O0", "O1l0l",
    "payload.bin", "manager.apk", "zygisk-next.zip",
    "/vendor/lib64/libbinderdebug.so", "/vendor/lib64/libstagefrighthw.so",
    "/vendor/lib64/libstagefright_aidl_bufferpool2.so", "crash_dump64" };
'''
        s = s.rstrip() + '\n' + block
        open(p, 'w', encoding='utf-8').write(s)

    # b) OBF --append, parse new ids from obf_dump
    subprocess.run([PY, 'tools/obf_strings_gen.py', '--append',
                    'app/src/main/jni', 'exp.c'], capture_output=True, text=True)
    dump = run([PY, 'tools/obf_dump.py']).stdout
    want = ['O0O1l', 'Ol1O0', 'O1l0l', 'payload.bin', 'manager.apk',
            'zygisk-next.zip', '/vendor/lib64/libbinderdebug.so',
            '/vendor/lib64/libstagefrighthw.so',
            '/vendor/lib64/libstagefright_aidl_bufferpool2.so', 'crash_dump64',
            'hook_sym.txt']
    for w in want:
        m = re.search(rf'^\s*(\d+)\s+{re.escape(w)}\s*$', dump, re.M)
        if m:
            ids[w] = int(m.group(1))

    # c) asset_name cases for every new id
    p = 'app/src/main/jni/asset_names.c'
    s = open(p, encoding='utf-8').read()
    if 'case ' + str(ids.get('hook_sym.txt', 0)) not in s:
        cases = ''.join(f'        case {i}: return OBF({i});\n' for i in sorted(ids.values()))
        # insert before the switch's closing "    }\n    return NULL;" (first occurrence)
        m = re.search(r'(        case 38: return OBF\(71\);\n)', s)
        if m:
            s = s.replace(m.group(1), m.group(1) + cases, 1)
        else:
            # older layout: insert before first "    }\n    return NULL;"
            m = re.search(r'(\n    \}\n    return NULL;)', s)
            if not m:
                raise RuntimeError('asset_name table anchor missing')
            s = s.replace(m.group(1), '\n' + cases + '    }\n    return NULL;', 1)
        open(p, 'w', encoding='utf-8').write(s)

    # d) Java: assets rename + s() wiring (anchors optional - skip on miss)
    p = 'app/src/main/java/honor/root/ExploitRunner.java'
    if os.path.exists(p):
        s = open(p, encoding='utf-8').read()
        renames = [
            ('stageAsset(ctx, "payload.bin", new File(dpDir, "payload.bin"), false, reporter);',
             f'stageAsset(ctx, s({ids.get("payload.bin", 0)}), new File(dpDir, s({ids.get("payload.bin", 0)})), false, reporter);'),
            ('stageAsset(ctx, "manager.apk", new File(dpDir, "manager.apk"), false, reporter);',
             f'stageAsset(ctx, s({ids.get("manager.apk", 0)}), new File(dpDir, s({ids.get("manager.apk", 0)})), false, reporter);'),
            ('stageAsset(ctx, "zygisk-next.zip", new File(dpDir, "zygisk-next.zip"), false, reporter);',
             f'stageAsset(ctx, s({ids.get("zygisk-next.zip", 0)}), new File(dpDir, s({ids.get("zygisk-next.zip", 0)})), false, reporter);'),
        ]
        for old, new in renames:
            if old in s:
                s = s.replace(old, new, 1)
        s = s.replace('''        String[] candidates = {
            "/vendor/lib64/libbinderdebug.so",''',
                      f'''        String[] candidates = {{
            s({ids.get("/vendor/lib64/libbinderdebug.so", 0)}),''')
        s = s.replace('reporter.report("Could not find vendor_file target, falling back to libbinderdebug.so\\n");',
                      f'reporter.report("Could not find vendor_file target, falling back\\n");')
        open(p, 'w', encoding='utf-8').write(s)

    # e) assets physical rename
    a = 'app/src/main/assets'
    for old, new in [('payload.bin', 'O0O1l'), ('manager.apk', 'Ol1O0'),
                     ('zygisk-next.zip', 'O1l0l')]:
        src, dst = os.path.join(a, old), os.path.join(a, new)
        if os.path.exists(src):
            if os.path.exists(dst): os.remove(dst)
            os.rename(src, dst)

    # f) R8 enable (if not present)
    p = 'app/build.gradle.kts'
    s = open(p, encoding='utf-8').read()
    if 'isMinifyEnabled' not in s:
        m = re.search(r'(release \{\n)', s)
        if m:
            s = s.replace(m.group(1),
                          m.group(1) + '            isMinifyEnabled = true\n'
                          '            isShrinkResources = true\n'
                          '            proguardFiles(\n'
                          '                getDefaultProguardFile("proguard-android-optimize.txt"),\n'
                          '                "proguard-rules.pro")\n', 1)
        open(p, 'w', encoding='utf-8').write(s)

    # g) libbinderdebug/vendor path scrub in detectKoTarget report string
    p = 'app/src/main/java/honor/root/ExploitRunner.java'
    if os.path.exists(p):
        s = open(p, encoding='utf-8').read()
        s = s.replace('reporter.report("Could not find vendor_file target, falling back to libbinderdebug.so\\n");',
                      'reporter.report("Could not find vendor_file target, falling back\\n");')
        open(p, 'w', encoding='utf-8').write(s)

    return ids

results = []
for rel_name, commit in VERSIONS:
    if commit is None:
        results.append((rel_name, 'NO_COMMIT')); continue
    log(f'=== {rel_name} @ {commit} ===')
    # reset tree to the commit (force + clean untracked residue)
    run(['git', 'checkout', '-f', HEAD, '--', '.'])
    run(['git', 'clean', '-fd', 'app/src/main/assets', 'app/src/main/jni'])
    r = run(['git', 'checkout', '-f', commit])
    if r.returncode != 0:
        results.append((rel_name, 'CHECKOUT_FAIL')); continue
    try:
        ids = apply_hardening()
    except Exception as ex:
        results.append((rel_name, f'PATCH_FAIL:{ex}'))
        run(['git', 'checkout', '-f', HEAD, '--', '.']); continue
    # build
    env = {**os.environ, 'JAVA_HOME': r'<HOME>\.workbuddy\binaries\jdk\jdk-17.0.20.1+1',
           'PATH': r'<HOME>\.workbuddy\binaries\jdk\jdk-17.0.20.1+1\bin;' + os.environ['PATH']}
    r = run(['gradlew.bat', ':app:assembleRelease'], env=env)
    apk = 'app/build/outputs/apk/release/honor-root-tool.apk'
    if r.returncode != 0 or not os.path.exists(apk):
        err_tail = (r.stderr or r.stdout or '')[-300:]
        results.append((rel_name, 'BUILD_FAIL: ' + err_tail.replace(chr(10), ' | '))); continue
    dst = os.path.join('releases', f'honor-root-tool-{rel_name}')
    import shutil
    shutil.copyfile(apk, dst)
    results.append((rel_name, 'OK'))
    log(f'{rel_name}: OK -> overwritten')

# restore HEAD tree
run(['git', 'checkout', '-f', HEAD, '--', '.'])
run(['git', 'checkout', '-f', HEAD])

print('\n=== SUMMARY ===')
ok = sum(1 for _, st in results if st == 'OK')
for name, st in results:
    print(f'  {name}: {st}')
print(f'\n{ok}/{len(results)} hardened & overwritten')
