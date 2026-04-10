# VFinder 模块实现说明

本文档描述 VFinder 模块的当前实现，包括核心功能、架构设计、CLI 集成和已知问题。

## 概述
VFinder 是基于 LangChain Agent 的漏洞定位工具，通过结合漏洞描述、项目代码和 recon 索引，自动定位潜在漏洞触发点（sinks）。

## 模块结构
```
src/vfinder/
├── __init__.py          # 公共 API 导出
├── agent.py             # 核心 Agent 实现
└── tools/               # 自定义工具（其余由 LangChain 社区工具承担）
    └── recon_symbol_match.py  # recon 索引查询
```

## 核心组件

### 1. VulnerabilityAnalystAgent
- **位置**：`src/vfinder/agent.py`
- **功能**：LLM 驱动的漏洞分析 Agent，遵循结构化 5-step workflow
- **技术栈**：LangChain + ChatOpenAI（gpt-5-mini，temperature=0）
- **递归限制**：recursion_limit=1000（允许复杂分析场景）

#### Codex CLI（`codex exec`）
- 默认 **`--full-auto`** 对应沙箱 **`workspace-write`**：模型通过 shell 写入的文件必须在 **`-C` 工作区**（以及 Codex 允许的路径如 `/tmp`）内。
- 若 **`OUTPUT_PATH` / `vfind --out`** 落在工作区**之外**（例如 workdir 为 `tests/fixtures/python_vulnerable_app`，而输出在 `tests/out/…`），Codex 会报 **`PermissionError: Operation not permitted`**。编排器会在检测到这种情况时自动追加官方参数 **`--add-dir <输出文件所在目录>`**。
- 若仍需更多可写目录，可设置 **`CODEX_EXEC_ADD_DIR`**（逗号分隔的绝对路径）。若仍不足，只能在 Codex 侧改用更宽沙箱（如 **`codex exec -s danger-full-access`**）或自行包装 CLI（本仓库默认不开启）。

### 2. 工具集

#### LangChain 模式（内嵌 Agent）
- **`langchain_community` 的 `ShellTool` / `ReadFileTool`**：在 Agent 中注册为 **`terminal`**（参数 `commands`）与 **`read_file`**（参数 `file_path`）。读文件根目录可通过环境变量 **`VFINDER_READ_FILE_ROOT`** 覆盖（默认 Unix 为 `/`，Windows 为系统盘符）。
- 依赖 **`langchain-experimental`**（`ShellTool` 内部使用）。

#### CLI 调试子命令（非 LangChain 工具）
- **`vuln_reach_analysis shell-exec`** / **`file-read`**：在 `src/commands/tools.py` 中内联实现（与旧工具相同的安全截断策略），便于单独测试。

#### recon_symbol_match
- **功能**：在 recon 输出中查询符号信息
- **匹配策略**：
  1. 优先精确匹配 `symbol` 字段
  2. 回退到子串搜索（在所有字段中）
- **返回范围**：每类最多 5 条（exports/endpoints/sinks/sanitizers）
- **输出截断**：2000 字符

## 工作流程

### 工作流程（`agents.md`）
三种后端（LangChain / Codex / OpenCode）共用 **`src/vfinder/agents.md`** 模板；Codex 与 OpenCode 会同步为项目根 **`AGENTS.md`**。LangChain 模式将同一份正文（加少量运行时说明）作为 **system prompt**。步骤概览：

1. **理解漏洞**：列出并阅读漏洞资料目录中的所有文档
2. **提取符号**：从漏洞描述中提取关键符号（类名、方法名、函数名）
3. **定位代码**：使用 recon_symbol_match 在项目中定位相关符号
4. **分析确认**：读取定位到的文件，分析上下文确认漏洞位置
5. **输出结果**：生成结构化 JSON 报告

### 输出格式
最终 JSON 包含以下字段：
- `vulnerability_name`：漏洞名称
- `vulnerability_type`：漏洞类型
- `root_cause`：根本原因描述
- `key_symbols_searched`：搜索的关键符号列表
- `dangerous_functions`：危险函数列表
- `sinks`：漏洞触发点列表（每个包含 file/line/function/code_snippet/confidence/reason）
- `total_sinks_found`：总计发现的 sinks 数量
- `analysis_notes`：分析备注

## CLI 集成

### 命令格式
```bash
python src/cli.py vfind \
  --repo <项目路径> \
  --bundle <漏洞资料目录> \
  --recon <recon输出文件> \
  --out <输出文件路径> \
  [--format json|jsonl]
```

### 参数说明
- `--repo`：待分析项目的根目录（必需）
- `--bundle`：漏洞描述文档目录（必需）
- `--recon`：recon 命令生成的索引文件（必需）
- `--out`：分析结果输出路径（可选，默认 stdout）
- `--format`：输出格式（可选，默认 jsonl）

### 输出机制
1. **主输出文件**（如 `out/result.json`）：
   - 仅包含最终漏洞分析 JSON
   - 自动从 Agent 消息中提取最后一条 LLM 输出
   - 格式干净，便于后续处理

2. **完整轨迹备份**（如 `out/.vfind_full_<timestamp>.json`）：
   - 包含所有 Agent 执行轨迹
   - 记录每一步工具调用和中间结果
   - 用于调试和分析优化

### 示例
```bash
# 分析 ruoyi-vue-pro 路径遍历漏洞
python src/cli.py vfind \
  --repo /tmp/security-agent/ruoyi-vue-pro/ \
  --bundle ./examples/vulns/ruoyi_path_travel/ \
  --recon ./out/ruoyi_recon.json \
  --out ./out/ruoyi_vfinder.json \
  --format json
```

## 编程接口

### 直接使用 Agent
```python
from vfinder import VulnerabilityAnalystAgent

# 创建 Agent 实例
agent = VulnerabilityAnalystAgent()

# 运行分析
result = agent.run(
    user_input="Analyze the path traversal vulnerability",
    vuln_dir="./examples/vulns/ruoyi_path_travel/",
    project_dir="/tmp/security-agent/ruoyi-vue-pro/",
    recon_file="./out/ruoyi_recon.json",
    verbose=False
)

# 结果包含完整执行轨迹
print(result["output"]["messages"][-1])  # 最后一条消息为最终分析结果
```

### 导出的类和工具
- `VulnerabilityAnalystAgent`：主 Agent 类
- 别名：`VFinderAgent`、`DemoAgent`
- 工具：`recon_symbol_match`（包内导出）；LangChain 运行时另注册社区 shell/读文件工具

## 成功案例

### ruoyi-vue-pro 路径遍历漏洞
- **漏洞类型**：未授权路径遍历（Unauthenticated Path Traversal）
- **分析结果**：
  - 识别 8 个 sinks（含高/中置信度）
  - 完整调用链：FileController.getFileContent → FileServiceImpl → LocalFileClient
  - 根本原因：路径拼接未做规范化和边界检查
- **产物**：
  - 主输出：`out/ruoyi_vfinder.json`（干净的 JSON 分析报告）
  - 备份轨迹：`out/.vfind_full_*.json`（完整 Agent 执行记录）

## 已知问题与限制

### 1. 效率问题
- **工具调用次数偏多**：Agent 可能多次查询相同或相似符号
- **缺乏缓存机制**：重复查询无法复用结果
- **递归深度较大**：recursion_limit=1000 可能导致长时间运行

### 2. 匹配策略问题
- **recon_symbol_match 回退策略过宽**：子串搜索可能返回大量无关结果
- **缺少上下文过滤**：无法根据已获取信息智能筛选
- **截断可能丢失关键信息**：2000/3000 字符限制在大型结果中可能不足

### 3. 用户体验问题
- **终端输出冗长**：每次工具调用都输出详细日志
- **进度不明确**：用户难以判断分析进展
- **错误提示不友好**：失败时缺少清晰的诊断信息

### 4. Agent 行为问题
- **5-step workflow 较机械**：有时会跳步或重复执行
- **system prompt 约束不足**：Agent 可能偏离预期流程
- **JSON 输出格式不稳定**：偶尔会输出不符合 schema 的结果

## 优化方向

### 高优先级
1. **优化 system prompt**：
   - 更清晰的任务约束和步骤定义
   - 添加输出格式示例和验证要求
   - 限制工具调用次数和范围

2. **改进 recon_symbol_match**：
   - 增加查询缓存机制
   - 优化匹配策略（限制子串搜索范围）
   - 支持批量查询减少调用次数

3. **简化终端输出**：
   - 仅显示关键进度信息（step 1/5: 理解漏洞...）
   - 隐藏详细工具调用日志（或使用 --verbose 控制）
   - 增加进度百分比或时间估计

### 中优先级
4. **调整 recursion_limit**：测试不同值对效率和完整性的影响
5. **增加重试机制**：对失败的工具调用自动重试
6. **输出格式验证**：使用 Pydantic 校验最终 JSON 结构

### 低优先级
7. **并行化工具调用**：对独立查询支持并发执行
8. **增量分析支持**：基于已有结果继续分析
9. **多模型支持**：允许配置不同 LLM 后端

## 依赖项
- LangChain >= 0.1.0
- OpenAI Python SDK
- Python 3.10+
- 环境变量：`OPENAI_API_KEY`、`OPENAI_BASE_URL`（可选）

## 参考文档
- [PLAN.md](../PLAN.md)：总体架构设计
- [status.md](./status.md)：项目当前状态
- [recon.md](./recon.md)：Recon 模块说明