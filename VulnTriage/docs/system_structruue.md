# 系统 CLI 接口与实现策略

## 目标
- 提供统一、可组合的命令行入口，贯穿 Recon → VFinder → Calltrace Mapper → Verification Agent 全流程。
- 支持单模块独立运行与端到端流水线，具备可配置、可观测与可扩展特性。

## 命令概览
- `recon`：扫描仓库配置、依赖、路由/控制器、导出接口，输出标准化清单。
- `vfind`：将漏洞需求包标准化为签名，在仓库中定位候选 sink 并打分。
- `map`：构建入口到 sink 的调用链，评估可达性并排序。
- `verify`：围绕调用链进行静态推理与（可选）轻量动态验证，给出结论与证据。
- `all`：端到端执行上述流水线，产出最终报告与中间产物。

## 参数与用法（建议）
### 通用选项（所有命令可共享）
- `--repo <path>`：目标代码仓库根路径（必填）。
- `--lang <auto|py|java>`：语言选择，默认 `auto`。
- `--config <file>`：外部 YAML 配置文件（可覆盖所有参数）。
- `--log-level <info|debug|warn|error>`：日志级别，默认 `info`。
- `--out <file>`：结果输出文件（默认 stdout，按各命令默认格式）。
- `--format <json|jsonl|sqlite>`：输出格式（按命令支持情况）。
- `--workers <int>`：并发工作线程数，默认依据 CPU。

### recon
- `cli recon --repo ./proj --lang auto --out recon.jsonl --format jsonl`
- 额外选项：
  - `--include-k8s`：启用 k8s 清单解析。
  - `--max-file-size <MB>` / `--ignore <glob>`：性能与过滤。

### vfind
- `cli vfind --repo ./proj --bundle cve_bundle.yaml --recon recon.jsonl --out sinks.jsonl`
- 额外选项：
  - `--similarity <tfidf|vector|off>`：片段相似度策略，默认 `tfidf`。
  - `--api-fuzzy <0-1>`：API 模糊匹配阈值，默认 0.8。
  - `--dep-only`：仅依据依赖命中输出候选。

### map
- `cli map --repo ./proj --recon recon.jsonl --sinks sinks.jsonl --out traces.jsonl`
- 额外选项：
  - `--use-codeql <bool>`：启用 CodeQL（默认 false）。
  - `--max-depth <N>`：路径搜索最大深度，默认 12。
  - `--max-paths <N>`：每入口最大路径数，默认 50。

### verify
- `cli verify --repo ./proj --traces traces.jsonl --poc poc.yaml --out verdict.json`
- 额外选项：
  - `--dynamic <bool>`：是否启用轻量动态探测（默认 false）。
  - `--timeout <sec>`：动态探测超时，默认 30。
  - `--http-only-get`：限制为幂等 GET 探测，默认开启。

### all
- `cli all --repo ./proj --bundle cve_bundle.yaml --out report.json`
- 透传常见参数：`--lang`、`--workers`、`--use-codeql`、`--dynamic`、`--format` 等。
- 输出：聚合报告（包含中间产物路径索引）。

## 配置优先级与环境变量
- 优先级：CLI 参数 > 环境变量 > 配置文件（YAML）。
- 默认配置文件：`.exploiteval.yaml`（位于仓库根或当前工作目录）。
- 环境变量前缀：`EXPVAL_`（如 `EXPVAL_LOG_LEVEL=debug`）。

## 输出与退出码
- 标准输出：结构化 JSON/JSONL；`--out` 指定输出文件时仍打印关键信息到 stderr。
- 退出码：
  - `0`：成功；
  - `2`：输入/参数错误；
  - `3`：解析/分析失败（部分步骤降级）；
  - `4`：外部依赖失败（如 CodeQL 不可用）。

## 日志与可观测性
- `--log-level` 控制控制台日志；支持 `--log-json` 输出 JSON 结构化日志。
- 命令执行摘要：入口数量、sink 命中数、路径数、结论分布等指标汇总。

## 实现逻辑与分层
- CLI 层仅做参数解析与调度，不包含业务逻辑。
- 服务层（各模块）提供纯函数式接口，便于单测与复用。
- 存储层统一 Writer/Reader（JSON/JSONL/SQLite），输出 schema 稳定。
- 错误模型：统一异常类型与错误码映射，保证一致的失败语义。

## 代码结构组织（建议）
```
src/
  cli.py                # 顶层命令分发（click/argparse）
  commands/
    __init__.py
    recon.py            # 解析参数 → 调用 recon 服务 → 写出
    vfind.py            # 解析参数 → 调用 vfinder 服务 → 写出
    map.py              # 解析参数 → 调用 callmap 服务 → 写出
    verify.py           # 解析参数 → 调用 verify 服务 → 写出
    all.py              # 串联执行并产出聚合报告
  core/
    config.py           # YAML/Env/CLI 合并与校验
    logging.py          # 结构化日志初始化
    errors.py           # 统一异常与退出码
    cli_common.py       # 通用选项装饰器/参数校验
  recon/                # 模块实现（见 docs/recon.md）
  vfinder/              # 模块实现（见 docs/vfinder.md）
  callmap/              # 模块实现（见 docs/calltrace_mapper.md）
  verify/               # 模块实现（见 docs/verification_agent.md）
  storage/
    writer.py           # JSON/JSONL/SQLite 写出
    reader.py           # 读取/合并
```

## 解析与调度（伪代码）
```python
# src/cli.py
import click
from commands import recon as cmd_recon, vfind as cmd_vfind, map as cmd_map, verify as cmd_verify, all as cmd_all

@click.group()
@click.option('--log-level', default='info')
@click.option('--config', type=click.Path(exists=True))
@click.pass_context
def cli(ctx, log_level, config):
    ctx.obj = load_config(log_level, config)  # core.config

@cli.command()
@click.option('--repo', required=True, type=click.Path(exists=True))
@click.option('--lang', default='auto')
@click.option('--out', type=click.Path())
@click.option('--format', type=click.Choice(['json','jsonl','sqlite']), default='jsonl')
@click.pass_obj
def recon(obj, **kwargs):
    result = cmd_recon.run(obj, **kwargs)
    write_out(result, kwargs.get('out'), fmt=kwargs.get('format'))
```

## all 流水线编排（简要）
1. `recon`：产出 `recon.jsonl`
2. `vfind`：读取 Recon 清单与需求包，产出 `sinks.jsonl`
3. `map`：读取 Recon 与 Sinks，产出 `traces.jsonl`
4. `verify`：读取 Traces 与 PoC，产出 `verdict.json`
5. 聚合：生成 `report.json`（包含上述文件路径、统计与结论）。

## 性能与可靠性
- 文件/目录忽略与大小限制，避免扫描爆炸。
- 并行化与分块处理（读取/解析/匹配流水线化）。
- 可重试与降级（CodeQL 不可用时回退 AST）。

## 测试与发布
- CLI 单测：`click.testing.CliRunner`/`pytest` 覆盖参数解析与错误路径。
- 冒烟测试：在示例 FastAPI/Spring 项目跑 `all` 命令校验产物。
- 包装与发布：`pyproject.toml` 声明 `console_scripts` 入口（如 `expval=src.cli:cli`）。

## 示例命令
```bash
# 端到端执行
expval all --repo ./demo --bundle ./requirements/cve.yaml --use-codeql false --dynamic false --out ./out/report.json

# 单独阶段执行
expval recon --repo ./demo -o recon.jsonl
expval vfind --repo ./demo --bundle cve.yaml --recon recon.jsonl -o sinks.jsonl
expval map --repo ./demo --recon recon.jsonl --sinks sinks.jsonl -o traces.jsonl
expval verify --repo ./demo --traces traces.jsonl --poc poc.yaml -o verdict.json --dynamic false
```
