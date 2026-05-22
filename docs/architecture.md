# 项目结构与流程说明

## 目录结构

```
workflow/
├── workflow_unified.py          # 主入口，统一调度全部流程
├── run_codewiki_pipline.py      # CodeWiki 子流程：clone/清洗/生成文档
├── generate_vfind_tasks.py      # 生成 vfind 分析任务列表
├── nvd_api.py                   # 从 NVD 拉取 CVE 详情
│
├── eval/                        # 风险评估子模块
│   ├── main.py                  # 评估入口：module_locator / summarizer / risk_assessment
│   ├── src/
│   │   ├── module_locator.py               # 将漏洞触发点映射到 CodeWiki 模块
│   │   ├── component_module_summarizer.py  # 生成组件业务摘要
│   │   └── risk_asssignment.py             # 计算 FVuln/FThreat/FBusiness 并给出风险等级
│   ├── final_result_system_prompt/         # LLM 风险评估 prompt（prompt1.md / prompt2.md）
│   ├── cve_data/                           # 每个 CVE 的漏洞信息与业务因子数据
│   └── data_sort.xlsx                      # 风险评估辅助 Excel
│
├── VulnTriage/                  # vfind 漏洞触发点定位子系统
│   └── src/
│       ├── commands/vfind.py        # vfind 主命令
│       ├── vfinder/                 # 触发点查找核心逻辑
│       ├── recon/                   # 仓库侦查（文件结构/依赖树）
│       └── utils/agent_runtime.py   # LLM agent 运行时
│
├── app_githuburl.xlsx           # 输入：项目列表（Project / URL / language）
├── DATA.xlsx                    # 输入：CVE 库（软件名 / CVE编号 / 描述）
├── docs/                        # 项目文档
│
├── target_repo/                 # CodeWiki clone 的目标仓库（运行时生成）
├── workflow_cache/              # GitHub Raw 文件本地缓存
│
├── debug_output  -> /data/sdb/hqs/debug_output    # 软链接，指向大容量盘
└── workflow_output -> /data/sdb/hqs/workflow_output  # 软链接，指向大容量盘
```

## 流程阶段

| 阶段 | 触发参数 | 说明 |
|---|---|---|
| 爬取 / CVE 匹配 | 始终执行（或 `--skip-matching` 跳过） | 从 GitHub 按 tag 拉取各版本依赖，与 CVE 库匹配，输出 `result.xlsx` |
| CodeWiki | `--run-codewiki` | clone 仓库，生成模块级文档至 `target_repo/<项目>/docs/` |
| vfind | `--run-vfind` | 对每个命中 CVE 定位漏洞触发点，输出 JSON |
| NVD | `--run-nvd` | 从 NVD API v2 抓取 CVSS / CWE / 补丁状态等官方数据 |
| eval | `--run-eval` | 结合 CodeWiki 文档和 vfind 结果，做模块定位、业务摘要、三因子风险评估 |

## eval 三因子评分说明

| 因子 | 子因子 | 说明 |
|---|---|---|
| FVuln | vuln_type / reachability / required_privilege / exploit_complexity | 漏洞本身属性 |
| FThreat | exploit_status / intel_confidence / patch_status / related_threat_activity | 威胁情报状态 |
| FBusiness | system_criticality / business_impact / impact_scope | 业务影响 |

风险等级由三因子加权综合决定：高危 / 中危 / 低危。VoteN≥2 时多票取共识，分歧则标记"未取得共识"。

## 注意事项

- `debug_output` 和 `workflow_output` 软链接到 `/data/sdb/hqs/`，避免根目录空间不足
- CodeWiki 阶段耗时较长（shiro 约 30 分钟，storm 约 60 分钟）；docs 已生成时去掉 `--run-codewiki`
- eval 每个任务约 120 秒（LLM 调用），任务数 = 匹配 CVE × tag 数；storm top-80 约 2400 条需 2 天
- eval 每个任务完成后立即写入独立 JSON，中途中断不丢数据
