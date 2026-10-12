import sys, re, os
p = sys.argv[1]
d = open(p, 'rb').read()
# extract printable ascii runs >= 5
for m in re.finditer(rb'[\x20-\x7e]{5,}', d):
    s = m.group().decode('ascii')
    if len(sys.argv) > 2:
        if sys.argv[2].lower() in s.lower():
            print('%08x  %s' % (m.start(), s))
    else:
        print('%08x  %s' % (m.start(), s))
