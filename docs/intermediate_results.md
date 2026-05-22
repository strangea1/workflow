# 中间结果保存说明

## 一、总览

workflow 在运行过程中会将各阶段的中间结果持久化到两个主要目录：

| 目录 | 用途 |
|---|---|
| `debug_output/` | 流程级汇总文件，便于整体排查 |
| `workflow_output/eval_runs/<project>/<tag>/<CVE>/` | 每个 CVE 的详细中间结果 |

此外还有：

| 目录 | 用途 |
|---|---|
| `workflow_output/nvd/` | NVD API 原始响应（每个 CVE 一个 JSON） |
| `workflow_output/vfind/<project>/` | vfind 可达性分析原始结果 |
| `workflow_cache/github_raw/` | GitHub 原始文件缓存（按 owner/repo/tag/path 组织） |

---

## 二、`debug_output/` — 流程级汇总

运行参数 `--debug-dir`（默认 `debug_output/`）指定。

| 文件 | 写入时机 | 内容 |
|---|---|---|
| `debug.log` | 全程追加 | 各阶段文字日志 |
| `projects_loaded.xlsx` | 项目加载后 | 从 Excel 读取的项目列表 |
| `all_crawled_rows.xlsx` | 爬取完成后 | 所有 Java 文件行数据 |
| `codewiki_runs.xlsx` | CodeWiki 完成后 | CodeWiki 运行记录 |
| `cve_loaded.xlsx` | vfind 完成后 | vfind 识别的 CVE 任务列表 |
| `vfind_cvelist.xlsx` | vfind 完成后 | vfind 输出的 CVE 列表 |
| `nvd_results.xlsx` | NVD 抓取完成后 | NVD 抓取成功结果摘要 |
| `nvd_failed.xlsx` | NVD 抓取完成后 | NVD 抓取失败的 CVE 列表 |
| `eval_tasks.xlsx` | eval 开始前 | eval 阶段的任务列表 |
| `eval_results.xlsx` | eval 完成后 | eval 阶段各 CVE 评分汇总 |
| `final_result_debug.xlsx` | 全流程结束后 | 最终结果调试表 |

---

## 三、`workflow_output/eval_runs/<project>/<tag>/<CVE>/` — 每个 CVE 的详细结果

每个 CVE 独立一个目录，保存该 CVE 的全部分析过程产物。

| 文件 | 内容 |
|---|---|
| `trigger_analysis.json` | vfind 可达性分析结果：触发点函数名、文件路径、是否可达 |
| `module_locator_result.json` | 模块定位结果：漏洞触发点 → CodeWiki 模块/组件映射 |
| `component_summary.json` | **组件业务信息摘要**（见第四节） |
| `risk_assessment_vote{N}.json` | 第 N 次投票的 LLM 评分结果，含三因子详细评分与 sub_factors |
| `risk_assessment_all_votes.json` | 所有投票结果合集（`--vote > 1` 时才生成） |
| `final_record.json` | **最终汇总记录**（见下表） |

`final_record.json` 的顶层结构：

```json
{
  "task": { ... },               // AnalysisTask 的全部字段
  "vfind": { ... },              // trigger_analysis 内容
  "module_locator": { ... },     // module_locator_result 内容
  "component_summary": { ... },  // component_summary 内容
  "risk_assessment": { ... },    // 投票聚合后的最终评分
  "vote_n": 2,
  "vote_results": [ ... ]        // 每次投票的原始结果
}
```

---

## 四、喂给 LLM 的信息来源与保存位置

eval 阶段每次调用 LLM 时，`prepare_assessment_input` 函数将以下两类信息填入 prompt 模板后发送。

### 4.1 漏洞威胁情报（来自 NVD）

从 `workflow_output/nvd/<CVE>_nvd.json`（NVD API v2 原始响应）中解析，字段对应关系如下：

| Prompt 字段 | 数据来源 |
|---|---|
| `vul_name` | CVE 编号本身 |
| `vul_id` | CVE 编号 |
| `vul_cvss_score` | NVD `metrics` → `cvssMetricV31/V30/V2` → `baseScore`（优先取 Primary） |
| `vul_type` | NVD `weaknesses` → `description.value`（CWE 列表，去重合并） |
| `vul_risk` | NVD `descriptions` → `lang=en` 的描述文本 |
| `vul_reason` | 同上（与 `vul_risk` 使用相同文本） |
| `vul_trigger_condition` | 同上（与 `vul_risk` 使用相同文本） |
| `vul_patch_available` | NVD `references` 中是否含 `Patch` tag 或 `Vendor Advisory` |
| `vul_poc_available` | NVD `references` 中是否含 `Exploit` tag |
| `vul_fix_suggestion` | 固定文本："参考官方补丁、升级版本或规避方案。" |

**保存位置**：`workflow_output/nvd/<CVE>_nvd.json`（NVD 原始响应），解析后的结构体同时写入 `final_record.json` → `vfind` 字段（间接包含）。

### 4.2 业务信息（来自 CodeWiki + 组件摘要）

从 `run_component_summarizer` 的输出构建，保存在 `component_summary.json`。字段对应关系如下：

| Prompt 字段 | 数据来源（`component_summary.json` 路径） |
|---|---|
| `project_name` | `project.name` |
| `project_overall_role` | `project.overall_role` |
| `project_description` | `project.description` |
| `business_importance_analysis` | `project.business_importance_analysis` |
| `data_sensitivity_analysis` | `project.data_sensitivity_analysis` |
| `exposure_analysis` | `project.exposure_analysis` |
| `component_name` | `component.name` |
| `component_role` | `component.role_in_project` |
| `component_importance` | `component.importance_analysis` |
| `component_data_sensitivity` | `component.data_sensitivity_analysis` |
| `component_attack_surface` | `component.attack_surface_analysis` |
| `service_availability` | `component.impact_analysis.service_availability` |
| `data_security` | `component.impact_analysis.data_security` |
| `compliance_impact` | `component.impact_analysis.compliance_impact` |

**保存位置**：`workflow_output/eval_runs/<project>/<tag>/<CVE>/component_summary.json`

### 4.3 可达性信息

| Prompt 字段 | 来源 |
|---|---|
| `reachability_info` | `trigger_analysis.json` → `reachability` 字段（字符串，如"可达"/"不可达"） |

**保存位置**：`workflow_output/eval_runs/<project>/<tag>/<CVE>/trigger_analysis.json`

---

## 五、未保存的内容

**填充后的完整 prompt 文本不会写入磁盘。** LLM 每次调用的完整输入是将上述字段填入 `RISK_ASSESSMENT_HUMAN_PROMPT` 模板后在内存中拼接，直接发给 API，不持久化。

如需复现某次 LLM 调用，可从以下文件手动还原所有输入：

```
component_summary.json        # 业务信息
trigger_analysis.json         # 可达性
workflow_output/nvd/<CVE>_nvd.json  # 漏洞情报
eval/final_result_system_prompt/<prompt_file>.md  # system prompt 模板
```
