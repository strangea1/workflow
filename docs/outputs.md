# 输出文件参考

## 主结果文件

| 路径 | 内容 |
|---|---|
| `result.xlsx` | 爬取 + CVE 匹配结果（Project / Tag / Component / Version / CVE） |
| `workflow_output/final_assessment.xlsx` | eval 完成后的风险评估汇总表 |

`final_assessment.xlsx` 列说明（v4 起新增 CVSS 列；v6 起 RiskLevel 改为高危/非高危）：

| 列名 | 说明 |
|---|---|
| Project / Tag / Component / Version / CVE | 任务来源 |
| **CVSS** | NVD 官方 CVSS 基础分（无 NVD 数据时为空） |
| Reachable | vfind 判断触发点是否可达（True/False） |
| Trigger / FilePath | vfind 定位的触发函数与文件 |
| Module / LocatedComponent | module_locator 映射结果；`fallback_overview` 表示由 overview.md 兜底，`fallback_component` 表示由依赖名回退 |
| RiskLevel | 风险等级：**高危 / 非高危 / 未取得共识**（v6 起取消中危/低危） |
| FVuln / FThreat / FBusiness | 三因子分值；不可达 CVE 的 FBusiness 恒为 0.0；FVuln 受 CVSS 分段上限约束 |
| Status | success / skipped / failed |
| Error | skipped/failed 原因 |
| VoteN | 实际投票次数 |

## debug_output/（软链接 → /data/sdb/hqs/debug_output）

| 文件 | 内容 |
|---|---|
| `projects_loaded.xlsx` | 加载的项目列表 |
| `cve_loaded.xlsx` | 加载的 CVE 库 |
| `<项目>_<语言>_crawl.xlsx` | 各项目各 tag 爬取到的组件版本 |
| `all_crawled_rows.xlsx` | 所有项目爬取结果汇总 |
| `final_result_debug.xlsx` | 最终 CVE 匹配结果（同 result.xlsx） |
| `eval_tasks.xlsx` | eval 阶段任务列表（tag × CVE 组合，去重后） |
| `eval_results.xlsx` | eval 完成后的评估结果（同 final_assessment.xlsx） |
| `vfind_cvelist.xlsx` | vfind 阶段使用的 CVE 列表 |
| `nvd_results.xlsx` | NVD 抓取成功的 CVE 列表 |
| `nvd_failed.xlsx` | NVD 抓取失败的 CVE 列表 |
| `codewiki_runs.xlsx` | CodeWiki 各项目执行状态 |
| `debug.log` | 运行时附加调试日志 |

## workflow_output/（软链接 → /data/sdb/hqs/workflow_output）

### eval 过程文件

| 路径 | 内容 |
|---|---|
| `eval_runs/<项目>/<tag>/<CVE>/final_record.json` | 单任务完整记录（task + vfind + module_locator + risk） |
| `eval_runs/<项目>/<tag>/<CVE>/risk_assessment_vote{N}.json` | 第 N 次投票的风险评分原始结果 |
| `eval_runs/<项目>/<tag>/<CVE>/risk_assessment_all_votes.json` | 所有投票汇总 |
| `eval_runs/<项目>/<tag>/<CVE>/module_locator_result.json` | 模块定位结果（mapped / unmapped） |
| `eval_runs/<项目>/<tag>/<CVE>/component_summary.json` | 组件业务摘要（FBusiness 输入） |
| `eval_runs/<项目>/<tag>/<CVE>/trigger_analysis.json` | vfind 触发点分析 |

### 其他输出

| 路径 | 内容 |
|---|---|
| `vfind/<项目>/` | vfind 原始输出 JSON |
| `nvd/shiro_<CVE>_nvd.json` | NVD 原始 JSON 缓存（命名规则：`<项目>_<CVE>_nvd.json`） |
| `kev_catalog.json` | CISA KEV 本地缓存（首次运行时下载，后续直接读取） |
| `recon/` | 仓库侦查结果（文件结构 / 依赖树） |
| `cvelist/` | vfind 使用的 CVE 列表 |

## CodeWiki 文档

| 路径 | 内容 |
|---|---|
| `target_repo/<项目>/docs/overview.md` | 项目总览文档 |
| `target_repo/<项目>/docs/<模块>.md` | 各模块文档（module_locator 的查找依据） |

## final_record.json 结构说明

```json
{
  "task": { "project", "tag", "cve", "component", "version", ... },
  "vfind": { ... },
  "module_locator": { "status": "mapped|unmapped", "module_name", "component_name", "rationale" },
  "component_summary": { ... },
  "risk_assessment": {
    "project_name", "project_description",
    "vulnerability": { "vul_name", "vul_id", "vul_cvss_score", "vul_type" },
    "scoring_factors": {
      "f_vuln": { "score", "sub_factors", "details" },
      "f_threat": { "score", "sub_factors", "details" },
      "f_business": { "score", "sub_factors", "details" }
    },
    "final_result": { "risk_level": "高危|非高危|未取得共识" },
    "aggregation": { ... }
  },
  "vote_n": 2,
  "vote_results": [ ... ]
}
```
