# template_qa — 模板语义去重、家族归并与质量评分

只读分析工具，不修改任何模板文件，与现有模板格式、签名/checksum 工作流完全兼容。
仅依赖 Python 3.9+ 标准库与 PyYAML。

## 用法

```bash
cd .github/scripts/template_qa

# 语义去重 + 家族归并（全库）
python3 -m template_qa dedup --root ../../.. --out dedup-report.json

# 确定性抽样 1000 个模板（验收用）
python3 -m template_qa dedup --root ../../.. --limit 1000 --seed 20261127

# 质量评分
python3 -m template_qa score --root ../../.. --out scores.json
```

## 家族归并（dedup）

两个确定性阶段（并查集）：

1. **精确归并**：相同 `classification.cve-id` 的模板无条件归入同一家族
   （同一 CVE 即同一漏洞，例如 CVE-2021-44228 的 44 个跨厂商变体）。
2. **相似归并**：对规范化 token 集合（模板名 + 请求路径 + matcher 条件）
   计算 Jaccard 相似度，阈值 0.80，并施加防误并护栏。

规范化：路径中的 `{{变量}}`、hex/数字段、查询串均被归一，matcher 顺序无关。

**防误并护栏**（任一侧定义了该字段且不一致则不合并）：
CVE、CWE 集合、vendor、product、漏洞类型、severity；此外相似归并还要求
协议交集非空、token 集合最小规模 4，且：

- 两侧各自独有 token → 拒绝（描述的是不同对象，如 key-creation vs key-upload）；
- 单侧独有的是身份 token（名称/路径）→ 拒绝（防止泛化模板成为"枢纽"
  吸收所有具体模板，如 woocommerce 吸收全部插件检测）；
- 单侧仅多出 matcher token → 允许（同一漏洞的强弱变体）。

每个家族选出 canonical 代表：质量分最高者，并列时取 id 字典序最小者。

## 质量评分（score）

总分 0–100，三个分量，权重与版本号固定在 `score.py`（`SCORING_VERSION`）：

| 分量 | 权重 | 说明 |
| --- | --- | --- |
| 请求效率 | 30 | 请求数越少越高（`metadata.max-request` 优先，否则按协议块计数） |
| 误报韧性 | 50 | 1 − 误报风险：dsl/regex/多 matcher `and`/负向 matcher/extractor/verified 降风险；仅状态码、仅通用词（admin/login/...）、无 matcher 升风险 |
| 元数据完整性 | 20 | description / reference / classification / impact|remediation / tags+vendor |

## 可复现性

- 评分为模板内容的纯函数：无随机、无时间戳、无环境依赖；
- 抽样使用固定 seed 对排序后的文件列表采样；
- 所有迭代均按排序顺序，输出 `sort_keys=True` 的 JSON；
- 相同输入两次运行输出逐字节一致（验收测试覆盖）。

## 验收测试

```bash
cd .github/scripts/template_qa
python3 -m unittest discover -s tests -v
```

覆盖：1000 模板确定性样本中所有 CVE 重复组完整归并、无跨 CVE/CWE/厂商/
产品/漏洞类型误并、评分跨运行与跨输入顺序可复现、合成变体必合并、
不同漏洞（同产品不同 CVE/CWE/漏洞类型）不合并。
