# Verification Agent 设计说明

本文档描述流水线末段 **verify** 阶段的实现设计：与 **VFinder** 一样，本质是 **LLM Agent**，并 **复用同一套三种 LLM 后端**（LangChain 内嵌、Codex CLI、OpenCode CLI）。实现时应优先对齐 `src/vfinder/agent.py` 中已验证的编排方式，再按本模块的输入输出与 `agents.md` 工作流做差异化。

---

## 1. 定位与目标

| 维度 | 说明 |
|------|------|
| **在系统中的位置** | Recon → VFind（sinks）→ Trace/Map（调用链）→ **Verify（可利用性结论）** |
| **与 VFinder 的关系** | 同源架构：**同一类 Agent + 三种 `mode`**，共用「`agents.md` 模板 + 外部 CLI 写盘交付」模式 |
| **核心任务** | 结合 **漏洞上下文**、**调用链（traces）**、可选 **PoC**，推理是否可利用（Yes / No / Uncertain），给出 **理由、证据、建议验证命令** |
| **非目标（首版可后置）** | 重推理、轻执行：可选 **动态探测**（HTTP/进程）作为 **独立子模块 + 显式开关**，不阻塞三后端 Agent 主线 |

---

## 2. 与 VFinder 后端对齐（必须一致的行为）

以下与 `VulnerabilityAnalystAgent`（`src/vfinder/agent.py`）保持一致，便于维护与文档统一。

### 2.1 三种 `mode`

| `mode` | 实现要点 |
|--------|----------|
| **`langchain`** | `ChatOpenAI` + `create_agent` + 工具；`system_prompt` = `agents.md` 正文 + LangChain 专用后缀（写盘须用 `terminal` 等） |
| **`codex`** | `codex exec -C <repo> --full-auto`；同步 **`AGENTS.md`** 到 `--repo` 根目录；`OUTPUT_PATH` / `--add-dir` 规则与 vfind 相同 |
| **`opencode`** | `opencode run --dir <repo>`；同样依赖 **`AGENTS.md`**；`OPENCODE_CMD` / `OPENCODE_MODEL` / `OPENCODE_AGENT` 等与 vfind 一致 |

### 2.2 环境变量约定（Verify 专用前缀）

为与 VFinder 区分，Verify 侧建议使用 **`VERIFY_`** 前缀；若与 vfind 共用逻辑（例如仅换模板路径），实现时可通过参数注入，避免硬编码。

| 变量 | 用途 |
|------|------|
| `VERIFY_OUTPUT_PATH` | 与 vfind 的 `OUTPUT_PATH` 语义一致：Codex/OpenCode 写最终 JSON 的绝对路径（由 CLI 设置） |
| `VULN_DIR` / `PROJECT_DIR` / `RECON_FILE` | 可与 vfind 共用语义：`--bundle`→漏洞资料目录，`--repo`→目标仓库，`--recon`→recon JSON（verify 强烈建议保留 **recon** 供符号/路由对照） |
| `TRACES_FILE`（建议新增） | **verify 特有**：当前分析的 traces 文件绝对路径，供 `agents.md` 与工具读取 |
| `POC_PATH`（可选） | PoC 文件或目录，未提供则省略 |

**Codex 写权限**：与 vfinder 相同——若 `--out` 落在 `codex exec -C` 工作区外，编排器须自动追加 `--add-dir <输出父目录>`；可继续支持 `CODEX_EXEC_ADD_DIR`。

### 2.3 交付物

- 最终 **机器可读 JSON** 必须写入 **`--out`** 指定路径（与 vfind 一致），**不能**仅依赖对话输出。
- LangChain：在 `agents.md` STEP 末尾明确要求用 **`terminal`**（如 `python3 -c`）写入 `VERIFY_OUTPUT_PATH` / `OUTPUT_PATH`。
- Codex / OpenCode：依赖项目根 **`AGENTS.md`**（由 `verify/agents.md` 模板生成并同步）。

---

## 3. 推荐目录结构（含可选公共抽取）

### 3.1 最小方案（与现有一致）

在 **`src/verify/`** 下镜像 vfinder 布局：

```
src/verify/
├── __init__.py           # 导出 VerificationAgent 等
├── agent.py              # VerificationAgent：run(mode=...) 与 _run_*_mode
├── agents.md             # Verify 专用工作流与输出 schema 占位符
└── tools/                # 可选：verify 专用工具
    └── ...               # 例如 traces 摘要、仅读聚合等（见 §5）
```

CLI：**`src/commands/verify.py`** 对标 `vfind.py`：解析 `--repo`、`--traces`、`--bundle`、`--recon`、`--poc`、`--out`、**`--agent-mode langchain|codex|opencode`**（需在 `vulntriage_cli.py` 中补充参数）、备份完整轨迹等。

### 3.2 推荐演进（减少与 vfinder 重复）

将「与子进程 CLI 交互、写日志、Codex add-dir」等抽成公共模块，**vfinder 与 verify 共用**：

```
src/core/
└── agent_cli_backend.py   # 例如：stream_subprocess_to_log、codex_cmd_build、opencode_cmd_build、cli_env 合并

src/vfinder/agent.py       # 调用 core 中函数
src/verify/agent.py        # 调用 core 中函数
```

抽取时机：实现 verify 时若复制粘贴超过 ~80 行与 vfinder 相同的子进程逻辑，即应下沉到 `core`。文档阶段仅作约定，不强制第一步就重构 vfinder。

---

## 4. 输入与输出

### 4.1 CLI 输入（与 `system_structruue.md` 对齐并扩展）

| 参数 | 必填 | 说明 |
|------|------|------|
| `--repo` | 是 | 目标仓库根 |
| `--traces` | 是 | trace/find 产物（JSON 或 JSONL，与现有 trace 输出一致） |
| `--bundle` | 建议 | 漏洞资料目录（与 vfind 同源，便于对照 CVE 描述） |
| `--recon` | 建议 | recon JSON，用于路由/符号与链上节点对照 |
| `--poc` | 否 | PoC 文件或目录 |
| `--out` | 否 | 默认可仿 vfind：`out/verify_verdict.json` |
| `--agent-mode` | 否 | `langchain`（默认）\| `codex` \| `opencode` |
| `--dynamic` | 否 | 是否启用动态探测子流程（首版可仍为占位） |
| `--timeout` / `--http-only-get` | 否 | 仅当 `--dynamic` 生效时使用 |

### 4.2 输出 JSON Schema（建议字段）

根对象建议包含（可与实现迭代微调）：

- `verdict`：`"Yes"` \| `"No"` \| `"Uncertain"`
- `confidence`：`high` \| `medium` \| `low`（可选）
- `reason`：人类可读结论依据
- `evidence`：列表，如引用文件路径、调用链摘要、PoC 对齐说明
- `used_traces`：参与推理的 trace 标识或路径索引
- `suggested_commands`：建议的 curl / httpx / mvn test 等（字符串列表）
- `vulnerability_type` / `analysis_notes`：与 vfind 风格统一时可与 sinks 报告对齐
- `dynamic_probe`：若启用动态探测，嵌套 `attempted`、`success`、`log` 等（可选）

**硬性要求**：根对象须含可被 CLI 校验的字段（类似 vfind 校验 `sinks`），例如固定 **`verdict`** + **`reason`**，以便非 Agent 降级或测试桩也通过同一校验逻辑。

---

## 5. 工具集（LangChain）

| 工具 | 来源 | 说明 |
|------|------|------|
| Shell（`terminal`） | `langchain_community` | 与 vfinder 一致；用于列目录、grep、写 JSON |
| Read file（`read_file`） | `langchain_community` | 读 repo、bundle、traces、PoC；`root_dir` 可与 vfinder 共用 **`VFINDER_READ_FILE_ROOT`** 或新增 **`VERIFY_READ_FILE_ROOT`**（实现二选一并文档化） |
| `recon_symbol_match` | `vfinder.tools` | **直接复用**：对照链上符号与 recon |
| （可选）`traces_summarize` | verify.tools | 对超大 traces 做截断摘要，避免撑爆上下文 |

Codex / OpenCode **不注册 LangChain 工具**，仅靠 AGENTS.md + 终端能力完成同等步骤。

---

## 6. `agents.md` 工作流（Verify 专用模板）

`src/verify/agents.md` 建议采用与 vfinder 相同的占位符，并增加 trace 相关变量：

- `{vuln_dir}` / `{project_dir}` / `{recon_file}` / `{output_path}`：与 vfinder 一致
- `{traces_file}`：**traces 绝对路径**（由编排器替换）
- `{poc_path}`：可选

**步骤建议（示例）**

1. **理解漏洞与 PoC**：阅读 bundle（及 PoC 若存在）
2. **理解调用链**：阅读 `traces_file`，识别入口 → sink 的路径与关键函数
3. **对照 recon**：对链上关键符号使用 `recon_symbol_match`（LangChain）或 CLI 查询 recon（外部 Agent）
4. **代码级核对**：读相关文件，判断鉴权、校验、数据流是否阻断利用
5. **结论与写盘**：输出符合 §4.2 的 JSON 至 `{output_path}` / `VERIFY_OUTPUT_PATH`

LangChain 运行时后缀：明确写盘方式与 vfinder `agent.py` 中 `_run_langchain_mode` 的 `lc_suffix` 同构。

---

## 7. `VerificationAgent` API 形状（与 VFinder 对称）

建议类名：**`ExploitabilityVerificationAgent`**（或 `VerificationAgent`），提供：

- `role()` / `task_description()`：角色与任务一句话，供返回包装与日志
- `run(user_input, vuln_dir, project_dir, recon_file, mode=..., output_path=..., traces_file=..., poc_path=...) -> dict`
- 内部：` _run_langchain_mode` / `_run_codex_mode` / `_run_opencode_mode`
- `_sync_agents_md`：将 `verify/agents.md` 同步到 `project_dir/AGENTS.md`（勿覆盖 vfinder 若同 repo 连续运行——实现上可用 **文件名区分** 如 `VERIFY_AGENTS.md` **或** 每次运行前按当前子命令覆盖；**推荐**：verify 使用 **`AGENTS.md`** 与 vfinder 相同文件名时，**同一工作区不要交错跑两个子命令而不刷新**；或在文档中约定 **先 vfind 后 verify** 时由 verify **覆盖** AGENTS.md）

**AGENTS.md 冲突说明（重要）**：若用户在同一 `repo` 根目录先后执行 vfind 与 verify，后执行的子命令会覆盖 `AGENTS.md`。实现可在 verify 启动时打日志提醒，或后续改为 `VULN_TRIAGE_AGENTS.md` + 各 CLI 指定规则；首版在本文档中 **明确约定覆盖行为** 即可。

---

## 8. 动态探测（可选，与 Agent 解耦）

- **默认关闭**（`--dynamic` 不传则为 false）
- 建议实现为 **`src/verify/harness_*.py`** 或 **`src/verify/dynamic.py`**，由 **`commands/verify.py`** 在 Agent 产出静态 verdict **之后**（或之前按产品决策）可选调用
- Agent 输出中的 `suggested_commands` 可与 harness 输入对齐，但 **不必** 在首版让 LLM 直接执行网络请求

---

## 9. 测试与里程碑

| 阶段 | 内容 |
|------|------|
| M1 | `VerificationAgent` + 三后端打通；`agents.md` + CLI `--agent-mode`；输出 schema 与写盘校验 |
| M2 | 与真实 `traces` + fixture bundle 集成测试；Codex/OpenCode 的 `OUTPUT_PATH` 与 add-dir 回归 |
| M3 | 可选：`recon_symbol_match` + traces 大文件策略；公共 `core/agent_cli_backend` 抽取 |
| M4 | 可选：`--dynamic` 与 Python/Java 轻量 harness |

---

## 10. 风险与缓解

| 风险 | 缓解 |
|------|------|
| `AGENTS.md` 与 vfind 互覆盖 | 文档约定执行顺序；日志提示；后续可改为独立文件名 |
| traces 过大导致上下文溢出 | 工具侧摘要 + 只传 Top-K 路径 |
| Codex 沙箱写盘失败 | 与 vfinder 相同 `--add-dir` / `CODEX_EXEC_ADD_DIR` |
| 结论幻觉 | schema 中要求 `evidence` 引用具体文件与行；强提示「不得编造路径」 |

---

## 11. 参考代码路径

- VFinder Agent：`src/vfinder/agent.py`
- VFinder 工作流模板：`src/vfinder/agents.md`
- VFinder CLI：`src/commands/vfind.py`
- Verify CLI（占位）：`src/commands/verify.py`
- 顶层入口：`src/vulntriage_cli.py`（verify 子命令需补充 `--agent-mode` 等）

---

*文档版本：与三后端 LLM 实现对齐的重设计稿；实现以仓库代码为准。*
