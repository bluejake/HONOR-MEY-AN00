# -*- coding: utf-8 -*-
import sys, io

p = r"<HOME>\WorkBuddy\2026-09-26-09-04-37\.workbuddy\memory\MEMORY.md"
s = io.open(p, encoding='utf-8').read()

rep = [
 ('> **\u2461 \u2605\u2605\u2605\u2605\u2605\u2605\u2605 H13-a \u90e8\u5206\u8bc1\u4f2a\uff1a\u9636\u6bb5\u5206\u79bb\u3010\u4e0d\u89e3\u51b3 stageB\u3011**\uff08G2b3\uff0c608 \u6b21\u96f6\u65b9\u5dee\uff09',
  '> **\u2461 \u2605\u2605\u2605\u2605\u2605\u2605\u2605 H13-a \u90e8\u5206\u8bc1\u4f2a\uff1a\u9636\u6bb5\u5206\u79bb\u3010\u4e0d\u89e3\u51b3 stageB\u3011**\uff08G2b3\uff0c**1024 \u6b21\u96f6\u65b9\u5dee**\uff09'),
 ('`MISC_BRIDGE_MISS_VERIFY` 608/608 \u5168\u4e3a\uff1a',
  '`MISC_BRIDGE_MISS_VERIFY` **1024/1024** \u5168\u4e3a\uff1a'),
 ('> \u4f46**\u5d29\u6e83\u786e\u5b9e\u88ab\u6d88\u9664**\uff1aH13 G1(ead=1000) \u5d29 1/3\u3001G2(ead=8000) \u5d29 0/3\uff1b\u5bf9\u6bd4 ead=100 \u5d29 4/5\u3002',
  '> \u4f46**\u5d29\u6e83\u786e\u5b9e\u88ab\u6d88\u9664**\uff1aG1(1000) \u5d29 1/3\u3001G2(8000) \u5d29 0/3\u3001G3(54000) \u5d29 0/3\uff089 boots \u5408\u8ba1 1/9\uff09\uff1b\u5bf9\u6bd4 ead=100 \u5d29 4/5\u3002'),
 ('> | 1000 | 3 | 1/3=33% | 318 |\n> | 8000 | 3 | 0/3=0% | 384 |\n> | 54000 | 1 | 0/1=0% | 128 |',
  '> | 1000 | 3 | 1/3=33% | 318 |\n> | 8000 | 3 | 0/3=0% | 384 |\n> | 54000 | 4 | 0/4=0% | 512 |'),
 ('\u2605 H13 \u5b9e\u6d4b\u6700\u4f18\u533a\u95f4\uff1a**ead=1000~8000**\uff08\u4f4e\u5d29\u6e83 0~33% \u4e14\u4fdd\u7559 stage0 \u547d\u4e2d attempt=69\uff09',
  '\u2605 H13 \u5b9e\u6d4b\u6700\u4f18\u533a\u95f4\uff1a**ead0 \u2265 8000**\uff08\u96f6\u5d29\u6e83\u4e14\u4fdd\u7559 stage0 \u547d\u4e2d attempt=69\uff09\uff1b**ead0=1000 \u5f15\u5165\u5d29\u6e83\u98ce\u9669**\uff08G1b3 \u5d29 @62\uff09'),
 ('- **H13 \u4e94\u9636\u6bb5**\uff1a\u96f6\u2705 \u4e00\u2705 \u4e8c\u2705 \u4e09\u23f3\uff08G3 \u5f85\u8dd1\uff09 \u56db\u2705\uff08\u672c\u6587\u4ef6\u5199\u56de\uff09',
  '- **H13 \u4e94\u9636\u6bb5**\uff1a\u96f6\u2705 \u4e00\u2705 \u4e8c\u2705 \u4e09\u2705\uff089 boots \u5168\u8dd1\u5b8c\uff09 \u56db\u2705'),
]

n = 0
for a, b in rep:
    if a in s:
        s = s.replace(a, b); n += 1
    else:
        print('MISS:', a[:60])
io.open(p, 'w', encoding='utf-8').write(s)
print('MEMORY.md replaced:', n)
