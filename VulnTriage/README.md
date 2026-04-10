# VulnTriage

本仓库对应漏洞评级项目中的可利用性分析部分，旨在针对 Python 以及 Java 语言下项目级与库级别的源码仓库，结合漏洞报告与源码文件，实现对目标源码的配置文件定位与摘要、库依赖提取以及代码层面的可利用约束分析。最终综合上述信息，构建智能体实现自动化的漏洞可利用性评估系统。

---

## Install

最简安装（项目根目录执行）：

```bash
# 1. 创建虚拟环境
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 2. 可编辑安装（依赖由 pyproject.toml 拉取，无需单独 pip install -r requirement.txt）
pip install -e .

# 3. 直接调用命令
vuln_reach_analysis list
```

可选（按需使用对应功能时再装）：

- **Python LSP（recon/trace 引用查询）**：`pip install pyright`，保证 `pyright-langserver` 在 PATH。
- **Java LSP（Java 仓库的 trace 引用）**：下载 [Eclipse JDT LS](https://download.eclipse.org/jdtls/snapshots/) 解压到 `.jdtls`，设置 `JDTLS_HOME=$PWD/.jdtls`；当前快照需 **Java 21+**，设置 `JAVA_HOME` 指向 JDK 21。

---

## Usage

安装后可直接使用命令 `vuln_reach_analysis`（无需设置 `PYTHONPATH`）：

```bash
vuln_reach_analysis <command> [options]
```

| 命令 | 说明 |
|------|------|
| `list` | 列出所有可用子命令。 |
| `recon` | 项目侦察：语言检测、技术栈匹配、入口/端点/配置等模式匹配。 |
| `vfind` | 基于漏洞 bundle 与 recon 结果，用智能体定位漏洞相关 sink。 |
| `trace` | LSP 与调用链：列出语言、启动 LSP、查引用、从 sink 回溯 call trace。 |
| `verify` | 利用轨迹与可选 PoC 做可利用性验证（含占位实现）。 |
| `all` | 端到端流水线：recon → vfind → trace → verify（占位编排）。 |
| `shell-exec` / `file-read` / `recon-symbol-match` | 供智能体调用的工具子命令，也可单独在 CLI 中测试。 |

### recon（侦察）

对目标仓库做语言检测、技术栈匹配和 YAML 规则匹配（入口、端点、sink、配置等），输出结构化 recon 结果。

```bash
vuln_reach_analysis recon --repo /path/to/repo [--lang auto|py|java] [--out out/recon.jsonl] [--format json|jsonl|sqlite]
```

- `--repo`：目标源码根目录。
- `--lang`：`auto`（自动检测）、`py`、`java`。
- `--out`：输出文件路径（不写则打印到 stdout）。
- `--format`：`json` / `jsonl` / `sqlite`。

### vfind（漏洞 sink 发现）

读取漏洞材料目录（bundle）与 recon 结果，通过 LangChain、Codex 或 OpenCode 智能体在仓库中定位与漏洞相关的 sink。

```bash
vuln_reach_analysis vfind --repo /path/to/repo --bundle /path/to/vuln_bundle --recon out/recon.jsonl [--out out/sinks.jsonl] [--format json|jsonl|sqlite] [--agent-mode langchain|codex|opencode]
```

- `--bundle`：漏洞材料目录（含 CVE 描述、补丁等）。
- `--recon`：recon 命令输出的文件路径。
- `--agent-mode`：`langchain`（默认）、`codex`（需安装 Codex CLI），或 `opencode`（需安装 [OpenCode](https://opencode.ai) CLI，可选环境变量 `OPENCODE_CMD`、`OPENCODE_MODEL`、`OPENCODE_AGENT`、`OPENCODE_RUN_FORMAT=json`）。
- 可选：`--similarity`、`--api-fuzzy`、`--dep-only` 等。

### trace（多 backend 调用链）

- **列出支持的语言**：`vuln_reach_analysis trace lsp list`
- **检查 LSP 是否可用**：`vuln_reach_analysis trace lsp start --repo /path/to/repo --lang py|java`
- **查询某位置的引用（测 LSP）**：  
  `vuln_reach_analysis trace lsp refs --repo /path/to/repo --file src/foo.py --line 10 [--character 4] --lang py [--include-declaration] [--json]`
- **从 sink 文件回溯调用链**：  
  `vuln_reach_analysis trace find --repo /path/to/repo --sinks out/sinks.jsonl --recon out/recon.jsonl [--lang auto] [--out out/traces.json] [--format json|jsonl|sqlite]`

- **指定 backend（LSP / CodeQL）**：  
  `vuln_reach_analysis trace find --repo /path/to/repo --sinks out/sinks.json --recon out/recon.json --backend lsp|codeql`

- **CodeQL backend（Java）**：
  - 可显式指定：`--codeql-db <db_path> --codeql-image <image_tag>`
  - 若未提供，系统会尝试通过 `fix-compile` 自动构建可复用 image 与 database。
  - 可用 `--no-codeql-fallback-lsp` 禁止降级到 LSP。

Java 使用 trace 前需配置好 jdtls（见 Install 可选部分）；`--character` 为符号所在列（0-based），用于准确定位要查引用的标识符。

> 当前 `codeql` backend 仅支持 Java；Python 建议使用 `lsp` backend。

### verify（验证）

根据 trace 结果与可选 PoC 做可利用性判断（当前为占位逻辑）。

```bash
vuln_reach_analysis verify --repo /path/to/repo --traces out/traces.json [--poc /path/to/poc] [--out out/verdict.json] [--dynamic] [--timeout 30]
```

### all（端到端）

一次性跑 recon、vfind、trace、verify（trace/verify 当前多为占位或依赖前序输出格式）。

```bash
vuln_reach_analysis all --repo /path/to/repo --bundle /path/to/vuln_bundle [--lang auto] [--out out/report.json] [--use-codeql] [--dynamic]
```

### 工具子命令（供 agent 或手动测试）

- `vuln_reach_analysis shell-exec -c "ls -la" [--cwd /path]`：执行 shell 命令。
- `vuln_reach_analysis file-read -p /path/to/file [--start-line 1] [--end-line 100]`：读文件或行范围。
- `vuln_reach_analysis recon-symbol-match -s "SymbolName" [--recon-file recon_output.json]`：在 recon 结果中搜索符号/API。
