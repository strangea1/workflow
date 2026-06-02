# 使用方式与参数说明

## 常用命令

### 完整流程（首次运行）

```bash
nohup python workflow_unified.py \
  --projects-excel app_githuburl.xlsx \
  --cve-excel DATA.xlsx \
  --output-excel result.xlsx \
  --debug-dir debug_output \
  --top-tags 80 \
  --github-token "$GITHUB_TOKEN" \
  --openai-base-url "$OPENAI_BASE_URL" \
  --openai-api-key "$OPENAI_API_KEY" \
  --openai-model "gpt-5-mini" \
  --run-codewiki \
  --run-vfind \
  --run-nvd \
  --run-eval \
  > workflow_run.log 2>&1 &
```

### 跳过 CodeWiki（docs 已生成时）

```bash
nohup python workflow_unified.py \
  --projects-excel app_githuburl.xlsx \
  --cve-excel DATA.xlsx \
  --output-excel result.xlsx \
  --debug-dir debug_output \
  --top-tags 80 \
  --openai-base-url "$OPENAI_BASE_URL" \
  --openai-api-key "$OPENAI_API_KEY" \
  --openai-model "gpt-5-mini" \
  --run-vfind \
  --run-nvd \
  --run-eval \
  > workflow_run.log 2>&1 &
```

### 仅重跑 eval（result.xlsx 和 vfind/nvd 结果均存在）

```bash
# 清除上一轮 eval 输出
rm -rf /data/sdb/hqs/workflow_output/eval_runs/<项目>/
rm -f debug_output/eval_results.xlsx debug_output/eval_tasks.xlsx

nohup python workflow_unified.py \
  --projects-excel app_githuburl.xlsx \
  --cve-excel DATA.xlsx \
  --output-excel result_<项目>.xlsx \
  --debug-dir debug_output \
  --top-tags 40 \
  --openai-base-url "$OPENAI_BASE_URL" \
  --openai-api-key "$OPENAI_API_KEY" \
  --openai-model "gpt-5-mini" \
  --skip-matching \
  --run-eval --vote 2 \
  > workflow_run_v3.log 2>&1 &
```

## 参数说明

| 参数 | 说明 |
|---|---|
| `--projects-excel` | 项目列表 Excel，需含 Project / URL / language 列 |
| `--cve-excel` | CVE 库 Excel，需含 软件名 / CVE编号 / 描述 列 |
| `--output-excel` | 爬取+匹配结果输出路径，默认 result.xlsx |
| `--debug-dir` | 中间调试文件输出目录，默认 debug_output |
| `--top-tags` | 每个项目爬取最近 N 个 tag，默认 10；storm 建议 80 |
| `--github-token` | 可选 GitHub Token，用于提升 API 额度 |
| `--run-codewiki` | 启用 CodeWiki 阶段（clone 仓库并生成模块文档） |
| `--run-vfind` | 启用 vfind 阶段（漏洞触发点定位） |
| `--run-nvd` | 启用 NVD 抓取阶段 |
| `--run-eval` | 启用风险评估阶段（模块定位 + 业务摘要 + 风险打分） |
| `--skip-matching` | 跳过爬取/CVE 匹配，直接复用已有 result.xlsx |
| `--vote N` | 风险评估向 LLM 发起 N 次投票，默认 1；建议关键项用 2 或 3 |
| `--eval-risk-verbose` | 输出风险评估阶段详细调试信息 |
| `--nvd-output-dir` | NVD JSON 缓存目录，默认 `workflow_output/nvd` |
| `--eval-output-dir` | eval 中间文件根目录，默认 `workflow_output/eval_runs` |
| `--eval-prompt-dir` | 风险评估 prompt 模板目录，默认 `eval/final_result_system_prompt` |
| `--eval-prompt-filename` | prompt 文件名，默认 `prompt2.md` |
| `--eval-excel-path` | 风险评估辅助 Excel，默认 `eval/data_sort.xlsx` |

## 中途中断后导出已完成结果

```bash
python3 - << 'EOF'
import json, pandas as pd
from pathlib import Path

rows = []
for f in sorted(Path("workflow_output/eval_runs").rglob("final_record.json")):
    d = json.loads(f.read_text(encoding="utf-8"))
    task = d.get("task", {})
    risk = d.get("risk_assessment") or {}
    final = (risk.get("final_result") or {}) if risk else {}
    rows.append({
        "project": task.get("project"),
        "tag": task.get("tag"),
        "cve": task.get("cve"),
        "version": task.get("version"),
        "RiskLevel": final.get("risk_level"),
    })

pd.DataFrame(rows).to_excel("partial_results.xlsx", index=False)
print(f"导出 {len(rows)} 条")
EOF
```
