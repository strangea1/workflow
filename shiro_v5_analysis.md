# Shiro v5 运行结果分析报告

**运行时间**：2026-05-21  
**代码版本**：v4（含 CVSS 提取 + 不可达 CVE 置零两项新功能）  
**运行命令**：
```bash
python workflow_unified.py \
  --projects-excel app_githuburl.xlsx \
  --cve-excel DATA.xlsx \
  --output-excel result_shiro.xlsx \
  --skip-matching --run-eval --vote 2
```

---

## 一、任务规模

| 维度 | 数量 |
|---|---|
| 总任务数 | 56 |
| 可达 CVE（Reachable=True） | 29 |
| 不可达 CVE（Reachable=False） | 27 |
| success | 44 |
| skipped（module locator 为空） | 12 |

v4 之前仅处理可达 CVE，本轮新增了 27 条不可达 CVE 的评估记录（FBusiness 全部强制置 0）。

---

## 二、风险等级分布

### 与修改前对比

| RiskLevel | 修改前（17 条） | v5（43 条有等级） |
|---|---|---|
| 高危 | 15 条（88%） | 11 条（**26%**） |
| 中危 | 2 条（12%） | 4 条（9%） |
| 低危 | 0 条（0%） | **27 条（63%）** |
| 未取得共识 | 0 条 | 1 条（2%） |

修改前高危主导（88%），v5 后分布接近正三角形（低危 > 高危 > 中危），与实际安全评估中大多数漏洞不可达、业务影响有限的现实更为吻合。

### 分组分布

**可达 CVE（29 条，其中 16 条 success / 12 条 skipped / 1 条无 NVD）**：

| RiskLevel | 条数 |
|---|---|
| 高危 | 11 |
| 中危 | 4 |
| 未取得共识 | 1 |
| 无等级（skipped） | 12 |

**不可达 CVE（27 条，全部 success）**：

| RiskLevel | 条数 |
|---|---|
| 低危 | 27（100%） |
| FBusiness | 全部为 0.0 |

---

## 三、因子分析（可达 CVE，16 条 success）

| 因子 | 均值 | 最小值 | 最大值 |
|---|---|---|---|
| FVuln | 3.62 | 3.20 | 4.00 |
| FThreat | 1.90 | 1.80 | 2.40 |
| FBusiness | 2.68 | 2.00 | 3.00 |

### CVSS 与 RiskLevel 对照

| CVE | CVSS | RiskLevel | FVuln | FThreat | FBusiness |
|---|---|---|---|---|---|
| CVE-2020-17510 | 9.8 | 高危 | 3.80 | 1.80 | 2.80 |
| CVE-2022-32532 | 9.8 | 高危 | 3.80 | 1.80 | 2.80 |
| CVE-2020-11989 | 9.8 | 高危 | 3.80 | 1.80 | 2.80 |
| CVE-2024-50379 | 9.8 | 高危 | 3.75 | 1.80 | 2.90 |
| CVE-2025-48734 | 8.8 | 高危 | 4.00 | 1.80 | 3.00 |
| CVE-2020-13933 | 7.5 | 高危 | 3.80 | 1.80 | 2.80 |
| CVE-2014-0074 | 7.5 | 高危 | 3.80 | 2.40 | 2.55 |
| CVE-2019-12422 | 7.5 | 高危 | 3.55 | 1.80 | 2.80 |
| CVE-2025-48988 | 7.5 | 高危 | 3.30 | 1.80 | 3.00 |
| CVE-2025-48989 | 7.5 | 未取得共识 | 3.30 | 1.80 | 2.75 |
| CVE-2023-41080 | 6.1 | 中危 | 3.50 | 1.80 | 2.30 |
| CVE-2024-8980 | 6.1 | 中危 | 3.20 | 1.80 | 2.00 |
| CVE-2024-54677 | 5.3 | 中危 | 3.30 | 1.80 | 2.50 |
| **CVE-2023-42795** | **5.3** | **高危** | 3.50 | 1.80 | 2.80 |
| **CVE-2010-3863** | **5.0** | **高危** | 3.80 | 2.30 | 2.80 |
| CVE-2023-41900 | 4.3 | 中危 | 3.70 | 2.25 | 2.30 |

**加粗行**为 CVSS 与 RiskLevel 明显不符的案例（CVSS 5.x 被评为高危），根本原因见下节。

---

## 四、仍存在的问题

### 问题 1：module_locator 覆盖率不足（12 条 skipped）

**现象**：12 条可达 CVE 的 `Status = "skipped"`，原因均为 `module locator returned empty component`。其中 4 条 CVSS 9.8 漏洞（CVE-2016-4437、CVE-2020-1957、CVE-2025-24813、CVE-2025-31651）完全没有风险等级，是当前数据集最大的缺口。

**根因**：vfind 定位的触发点（函数名 + 文件路径）落在拦截器、过滤器、通用工具类等横切代码中，这类代码不属于 CodeWiki 任何具体业务模块，module_locator 无法映射，返回空 component。

**改进方向**：增加两级回退策略：
1. 回退一：用 `task.component`（依赖名）作为组件名，调用 `run_component_summarizer` 搜索最近似的模块文档
2. 回退二：读取 `overview.md` 构造最小业务上下文，跳过 summarizer 直接进入风险评估

两级回退均可泛化到其他项目（只需 CodeWiki 已运行）。

---

### 问题 2：FVuln 系统性虚高

**现象**：16 条可达 CVE 的 FVuln 均值高达 3.62/4.0（满分）。CVSS 5.3 的漏洞（CVE-2023-42795）FVuln 打到 3.50，最终被评为高危。

**根因**：LLM 看到"触发点可达"后，几乎无差别地将 `vuln_type / reachability / required_privilege / exploit_complexity` 四个子因子全部打高分，没有将 CVSS 作为参考锚点。实际上 FVuln 的四个子因子与 CVSS v3 的评分维度高度重叠（AC、PR、UI 等），两者应有强相关性。

**改进方向**：在每次 vote 结果出来后，施加基于 CVSS 的后置上限约束（新增 `_cap_fvuln_by_cvss` 函数）：

```
CVSS < 4.0  → FVuln ≤ 1.5
CVSS 4.0–6.9 → FVuln ≤ 2.5
CVSS 7.0–8.9 → FVuln ≤ 3.5
CVSS ≥ 9.0  → 不限制（LLM 评分全部保留）
```

超出上限时等比压缩子因子，保持内部相对权重不变。此规则对所有有 CVSS 数据的 CVE 均可生效，无 CVSS 时跳过约束。

---

### 问题 3：FThreat 区分度低（长期问题）

**现象**：16 条可达 CVE 中 14 条的 FThreat 固定为 1.80，说明 LLM 在没有真实威胁情报输入时给出"均值"应答。

**根因**：当前传入 LLM 的威胁情报字段仅有 `vul_patch_available`（布尔）和 `vul_poc_available`（布尔），信息量严重不足，无法区分"已被 APT 组织在野利用"与"仅有学术 PoC"两种截然不同的场景。

**改进方向（按接入成本排序）**：

| 数据源 | 解决的子因子 | 接入方式 |
|---|---|---|
| CISA KEV（已知被利用漏洞目录） | `exploit_status` / `related_threat_activity` | 下载免费 JSON，本地匹配 CVE 编号 |
| NVD EPSS 分数 | `intel_confidence` | NVD API v2 已有字段，直接读取 |
| CVE 发布年龄 | `patch_status` 时间维度 | 已有 `published` 字段，计算天数即可 |

CISA KEV 优先级最高：直接告诉 LLM 此 CVE 是否已被在野利用，把 `exploit_status` 从"猜测"变成"事实"，预计可将 FThreat 的方差从接近 0 提升到有实际区分度的水平。

---

### 问题 4：不可达 CVE 的 CVSS 列为空

**现象**：27 条不可达 CVE 中 25 条 CVSS 为空，因为这些 CVE 在 `--run-nvd` 阶段不在 `non_empty_sinks.json` 中，未被拉取 NVD 数据。

**改进方向**：在 `--run-nvd` 阶段，将所有匹配到的 CVE（不论可达与否）均纳入 NVD 拉取范围，而不是仅拉取有 sink 的 CVE。这样不可达 CVE 也能获得 CVSS、CWE、patch_status 等字段，未来若需要对不可达 CVE 做更精细的评估（而非统一低危），这些数据是必要前提。

---

## 五、后续开发优先级

| 优先级 | 改进项 | 预期收益 | 实施成本 |
|---|---|---|---|
| P1 | module_locator 两级回退 | 补全 12 条（含 4 条 CVSS 9.8）的缺口 | 低 |
| P2 | CVSS 分段 FVuln 上限（`_cap_fvuln_by_cvss`） | 修正 CVSS 5.x 被高估的问题 | 低 |
| P3 | CISA KEV 接入 | FThreat 从均值 1.80 变为有区分度 | 中 |
| P4 | 不可达 CVE 纳入 NVD 拉取范围 | 补全 CVSS 列，为后续精细评估做铺垫 | 低 |
