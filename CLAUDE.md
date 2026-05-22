# workflow — EVA-Pro 漏洞风险评估流水线

## 快速开始

```bash
nohup python workflow_unified.py \
  --projects-excel app_githuburl.xlsx \
  --cve-excel DATA.xlsx \
  --output-excel result.xlsx \
  --debug-dir debug_output \
  --top-tags 40 \
  --openai-base-url "$OPENAI_BASE_URL" \
  --openai-api-key "$OPENAI_API_KEY" \
  --openai-model "gpt-5-mini" \
  --run-vfind --run-nvd --run-eval --vote 2 \
  > workflow_run.log 2>&1 &
```

首次运行加 `--run-codewiki`；docs 已存在时去掉该参数。

## 文档索引

| 文件 | 内容 |
|---|---|
| [docs/architecture.md](docs/architecture.md) | 目录结构、流程阶段、三因子评分说明 |
| [docs/usage.md](docs/usage.md) | 完整运行命令、参数说明、中断恢复脚本 |
| [docs/outputs.md](docs/outputs.md) | 输出文件路径参考、final_record.json 结构 |
| [docs/changelog.md](docs/changelog.md) | 历次代码修复记录（v1–v6）与待改进项 |
| [docs/shiro_v5_analysis.md](docs/shiro_v5_analysis.md) | Shiro v5 运行结果分析（CVSS 提取 + 不可达置零效果） |
| [docs/shiro_v6_analysis.md](docs/shiro_v6_analysis.md) | Shiro v6 运行结果分析（CISA KEV + FVuln上限 + module回退效果） |

## 主要入口文件

| 文件 | 说明 |
|---|---|
| `workflow_unified.py` | 主入口，统一调度全部流程 |
| `run_codewiki_pipline.py` | CodeWiki 子流程（含 `<OVERVIEW>` 防崩溃补丁） |
| `eval/src/risk_asssignment.py` | 三因子风险评估（FVuln / FThreat / FBusiness） |
| `eval/src/module_locator.py` | 漏洞触发点 → CodeWiki 模块映射 |
| `nvd_api.py` | NVD API v2 数据拉取 |
