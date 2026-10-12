# 文档索引

| 路径 | 内容 |
|---|---|
| [`../README.md`](../README.md) | 项目总览、技术路线、设备矩阵、构建方式 |
| [`../REFERENCES.md`](../REFERENCES.md) | 上游参考与署名（DirtyFrag 血统链） |
| [`../NOTICE`](../NOTICE) | 第三方声明与「不包含内容」清单 |
| [`../SECURITY.md`](../SECURITY.md) | 安全研究说明、负责任使用与披露 |
| [`../firmware/README.md`](../firmware/README.md) | 固件获取说明（镜像不入库） |
| [`00-project-README.md`](00-project-README.md) | 原始项目说明（工作区 README 原样） |
| [`01-HANDOFF.md`](01-HANDOFF.md) | 完整研究交接记录（时间线最全） |
| [`methodology/`](methodology/) | 研究方法论：操作纪律、反汇编纪律、补丁判定 |
| [`success-cases/`](success-cases/) | 成功案例矩阵（脱敏）与失败/判死案例 |
| [`research/`](research/) | 100 份研究报告，见下 |
| [`handover/`](handover/) | 方法论补充文档（SOP、分析路径） |

## research/ 研究报告

命名规律：

- **`R0`–`R11`** —— 路线探寻系列（攻击面盘点、漏洞候选、参考 PoC 盘点、补丁状态裁决等）
- **`H25x`** —— 具体裁决与自查报告（如 `H258_PPG-AN00_DirtyFrag裁决.md`）
- **`BVL-*`** —— BVL-AN16（6.1.157）专项
- **`RE_*`** —— 机理逆向分析（如 `RE_rb_erase_mechanism_*.md`）
- **`SESSION-SUMMARY-*`** —— 阶段性会话总结

建议阅读顺序：`R0`（总览）→ `R2`（漏洞候选）→ `R9`（补丁状态裁决）→ 具体机型的 `H*`/`BVL*` 报告。
