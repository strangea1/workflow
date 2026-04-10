# 环境变量参考（LLM 三后端与编排）

本文档汇总 **LangChain / Codex / OpenCode** 三种 Agent 后端各自依赖或可配置的环境变量，以及 **Codex、OpenCode 子进程**中由本仓库注入的变量，便于后续调整与排障。

---

## 1. LangChain 后端（`--agent-mode langchain`）

用于 **`vfind`**、**`verify`** 内嵌的 `ChatOpenAI` + LangChain Agent。模型与网关均由下列变量控制。

| 变量 | 必填 | 默认值 / 行为 |
|------|------|----------------|
| **`OPENAI_API_KEY`** | 是 | 无；未设置时运行 LangChain 模式会报错 |
| **`OPENAI_MODEL`** | 否 | `gpt-5-mini` |
| **`OPENAI_BASE_URL`** | 否 | 不设置则走 SDK 默认（OpenAI 官方）；设置后用于兼容网关 / 自建 OpenAI 兼容服务 |

**LangChain 读文件工具根目录**（`ReadFileTool` 的 `root_dir`，影响可列出的绝对路径范围）：

| 变量 | 必填 | 默认值 / 行为 |
|------|------|----------------|
| **`VFINDER_READ_FILE_ROOT`** | 否 | 优先使用；非空则作为读文件根 |
| **`VERIFY_READ_FILE_ROOT`** | 否 | 若未设置 `VFINDER_READ_FILE_ROOT` 则尝试；仍为空时：Windows 为 `%SystemDrive%\`，Unix 为 `/` |

实现：`src/utils/agent_runtime.read_file_tool_root()`；`src/vfinder/agent.py`、`src/verify/agent.py` 的 LangChain 工具链。

---

## 2. Codex 后端（`--agent-mode codex`）

本仓库 **不** 通过环境变量指定 Codex 所用 **模型**。实际模型由 **Codex CLI 自身配置**（账号、项目配置、默认模型等）决定。

编排侧 **可读写的环境变量**：

| 变量 | 必填 | 行为 |
|------|------|------|
| **`CODEX_EXEC_ADD_DIR`** | 否 | 逗号分隔的**绝对路径**，会逐个追加为 `codex exec` 的 `--add-dir`。在 `OUTPUT_PATH` 落在 `-C` 工作区外时，与代码自动追加的目录**叠加**使用 |

**说明**：`codex exec` 使用 `-C <repo>` 与 `--full-auto`。若 `--out` 指向仓库外的目录，代码会自动对输出文件**父目录**追加 `--add-dir`；仍不够时用 `CODEX_EXEC_ADD_DIR` 扩展。

---

## 3. OpenCode 后端（`--agent-mode opencode`）

| 变量 | 必填 | 默认值 / 行为 |
|------|------|----------------|
| **`OPENCODE_CMD`** | 否 | `opencode`（需在 `PATH` 中或可执行绝对路径） |
| **`OPENCODE_MODEL`** | 否 | 若**非空**，则传给 CLI：`-m <值>`；**空**则由 OpenCode 默认/项目配置决定模型 |
| **`OPENCODE_AGENT`** | 否 | 若**非空**，则传 `--agent <值>` |
| **`OPENCODE_RUN_FORMAT`** | 否 | 仅当取值为 `json` 或 `default`（大小写不敏感）时，追加 `--format <值>` |

实现：`src/vfinder/agent.py`、`src/verify/agent.py` 中 `_run_opencode_mode`。

---

## 4. Codex / OpenCode 子进程中的注入变量（继承 + 覆盖）

调用 **`build_llm_cli_env`**（`src/utils/agent_runtime.py`）时，在 **当前进程 `os.environ` 副本** 上写入下列键（供 `AGENTS.md` 与外部 Agent 引用）：

| 变量 | 说明 |
|------|------|
| **`VULN_DIR`** | `--bundle`（漏洞资料目录）解析后的绝对路径；可为空字符串 |
| **`PROJECT_DIR`** | 目标仓库根（`--repo`）绝对路径 |
| **`RECON_FILE`** | `--recon` 解析后的绝对路径；可为空 |
| **`OUTPUT_PATH`** | `--out` 最终 JSON 的绝对路径（仅当指定了输出路径时设置） |

**仅 `verify` 额外注入**（在 `OUTPUT_PATH` 等之上，见 `src/verify/agent._verify_cli_env`）：

| 变量 | 说明 |
|------|------|
| **`TRACES_FILE`** | `--traces` 解析后的绝对路径 |
| **`VERIFY_OUTPUT_PATH`** | 与 **`OUTPUT_PATH`** 相同的绝对路径（便于文档/脚本统一引用） |
| **`POC_PATH`** | 仅当提供了 `--poc` 时设置，为解析后的绝对路径 |

以上注入变量**不是**你必须在 shell 里预先 export 的；但若你在自定义 `AGENTS.md` 或包装脚本里依赖它们，需与 CLI 参数一致。

---

## 5. 与三后端无关、流水线其它环节（可选查阅）

| 变量 | 模块 | 说明 |
|------|------|------|
| **`JDTLS_HOME`** | trace / LSP | Java 语言服务根目录 |
| **`JAVA_HOME`** | trace / LSP | 运行 jdtls 的 JDK（建议 21+） |
| **`VULN_LSP_PYRIGHT_CMD`** | LSP | 覆盖 Pyright 启动命令（空格分隔参数） |
| **`VULN_LSP_JDTLS_CMD`** | LSP | 覆盖 JDT LS 启动命令 |
| **`VULN_LSP_REQUEST_TIMEOUT`** | LSP | 单次 JSON-RPC 读超时秒数，默认 `120`；`0`/`none`/`off`/`inf` 等可关闭（不推荐） |

---

## 6. 修改本文档时

若新增或重命名环境变量，请同步更新：

- `src/vfinder/agent.py`
- `src/verify/agent.py`
- `src/utils/agent_runtime.py`（若与 CLI 子进程 / ReadFile 根目录相关）

并在本节或对应小节追加表格行。
