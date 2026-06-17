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

## ⚠️ CodeWiki 文档保护

CodeWiki 生成的模块文档（`target_repo/<project>/docs/*.md`）是最耗时、最昂贵的产出物。重新运行项目前必须先检查已有结果：

1. **检查 docs 目录**：`ls target_repo/<project>/docs/` 确认是否有已生成的模块文档（非 `module_tree.json`）
2. **不要随意删除**：`module_tree.json` 和 `docs/*.md` 是 CodeWiki 的核心产出，删除后需要数小时重新生成
3. **谨慎使用 `--run-codewiki`**：仅在确认 docs 目录为空或明确需要重新生成时才加此参数；已有文档时去掉该参数可跳过 CodeWiki 阶段
4. **注意 workflow 行为**：CodeWiki 会检查 `module_tree.json` 是否存在来决定是否跳过；如果上次运行中途失败留下了不完整的 `module_tree.json`，需要手动删除后重新运行，否则会被跳过

## 文档索引

| 文件 | 内容 |
|---|---|
| [docs/architecture.md](docs/architecture.md) | 目录结构、流程阶段、三因子评分说明 |
| [docs/usage.md](docs/usage.md) | 完整运行命令、参数说明、中断恢复脚本 |
| [docs/outputs.md](docs/outputs.md) | 输出文件路径参考、final_record.json 结构 |
| [docs/changelog.md](docs/changelog.md) | 历次代码修复记录（v1–v7）与待改进项 |
| [docs/radp.md](docs/radp.md) | RADP数据打包术语说明、脚本使用、数据结构 |
| [shiro_v5_analysis.md](shiro_v5_analysis.md) | Shiro v5 运行结果分析（CVSS 提取 + 不可达置零效果） |
| [shiro_v6_analysis.md](shiro_v6_analysis.md) | Shiro v6 运行结果分析（CISA KEV + FVuln上限 + module回退效果） |

## 主要入口文件

| 文件 | 说明 |
|---|---|
| `workflow_unified.py` | 主入口，统一调度全部流程 |
| `run_codewiki_pipline.py` | CodeWiki 子流程（含 `<OVERVIEW>` 防崩溃补丁） |
| `eval/src/risk_asssignment.py` | 三因子风险评估（FVuln / FThreat / FBusiness） |
| `eval/src/module_locator.py` | 漏洞触发点 → CodeWiki 模块映射 |
| `nvd_api.py` | NVD API v2 数据拉取 |
| `scripts/package_risk_dataset.sh` | RADP打包脚本，将eval结果打包为标准化数据集 |

## 常用术语

| 术语 | 全称 | 说明 |
|---|---|---|
| **RADP** | Risk Assessment Dataset Package | 将eval结果打包为标准化机器学习数据集的过程 |
