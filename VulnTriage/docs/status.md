# 当前实施状态

## 已完成
- 制定总体方案：[PLAN.md](PLAN.md)（端到端流程、模块设计、目录规划、里程碑）。
- 输出四大模块的实施计划与代码结构建议：Recon、VFinder、Calltrace Mapper、Verification Agent（见 [docs/](.)）。
- CLI 骨架与子命令框架：
	- 主入口与命令注册：[src/cli.py](../src/cli.py)
	- 子命令占位：
		- [src/commands/recon.py](src/commands/recon.py)
		- [src/commands/vfind.py](src/commands/vfind.py)
		- [src/commands/map.py](src/commands/map.py)
		- [src/commands/verify.py](src/commands/verify.py)
		- [src/commands/all.py](src/commands/all.py)
	- 支撑模块占位：
		- [src/core/config.py](src/core/config.py)
		- [src/core/logging.py](src/core/logging.py)
		- [src/core/errors.py](src/core/errors.py)
		- [src/core/cli_common.py](src/core/cli_common.py)
		- [src/storage/writer.py](src/storage/writer.py)
		- [src/storage/reader.py](src/storage/reader.py)

- Recon 核心实现（Python）：
	- 模式与匹配：新增 patterns 目录（YAML），实现通用匹配引擎与 Python 专用匹配器。
		- 模式：见 [patterns/python](patterns/python) 与 [patterns/tech_stack](patterns/tech_stack)。
		- 引擎与匹配器：见 [src/recon/matcher.py](src/recon/matcher.py)、[src/recon/matcher_py.py](src/recon/matcher_py.py)。
		- 数据模型：见 [src/recon/models.py](src/recon/models.py)。
		- 语言检测：见 [src/recon/detect_lang.py](src/recon/detect_lang.py)。
		- CLI 集成：更新 [src/commands/recon.py](src/commands/recon.py) 调用实际扫描逻辑并输出结构化结果。
	- Bug 修复：支持 ast.AsyncFunctionDef 装饰器解析，正确识别 FastAPI 异步路由。
	
- Recon 核心实现（Java）：
	- 模式与匹配：新增 patterns/java 目录（YAML），实现 Java 专用匹配器。
		- 模式：见 [patterns/java](patterns/java)（entry.yaml, sanitizer.yaml, sink.yaml, config.yaml）。
		- 匹配器：见 [src/recon/matcher_java.py](src/recon/matcher_java.py)（基于正则表达式的静态分析）。
	- CLI 集成：更新 [src/commands/recon.py](../src/commands/recon.py) 支持 Java 语言路由。
	- 注解解析：支持 Spring（@RestController/@GetMapping 等）、JAX-RS（@Path/@GET 等）、Servlet（@WebServlet）。
	- 校验注解：支持 Spring Security（@PreAuthorize 等）、Bean Validation（@Valid/@NotNull 等）。
	- 敏感调用：支持命令注入（Runtime.exec）、代码注入（反射）、文件操作、SQL、反序列化等。
	- 依赖解析：支持 Maven（pom.xml）、Gradle（build.gradle）。
	
- VFinder 核心实现（Java）：
	- Agent 框架：基于 LangChain 实现 5-step 工作流（理解漏洞 → 提取符号 → recon 定位 → 读取代码 → 输出 JSON）。
	- 工具集成：
		- shell_exec：安全的 shell 命令执行（有白名单保护、超时控制）。
		- file_read：文件内容读取（支持行范围、长度截断）。
		- recon_symbol_match：基于 recon 输出的符号查询（优先精确匹配，回退子串搜索）。
	- CLI 集成：[src/commands/vfind.py](src/commands/vfind.py) 支持 --repo、--bundle、--recon、--out 参数。
	- 输出优化：
		- 完整轨迹备份至 .vfind_full_*.json（包含所有 agent 消息和工具调用）。
		- 主输出文件仅保存最终 JSON 分析结果（自动提取最后一条消息内容）。
	- 成功案例：ruoyi-vue-pro 路径遍历漏洞分析（识别 8 个 sinks，包含完整调用链）。
	- 产物：见 [out/ruoyi_vfinder.json](out/ruoyi_vfinder.json)、[out/.vfind_full_*.json](out/)。

## 进行中/待优化

### ✅ 已实现模块
- **Recon（Python & Java）**：
	- ✅ 核心扫描逻辑已完整实现并通过示例验证。
	- ⚠️ **存在问题**：匹配模式仍需迭代优化，当前存在一定误报率。
	- 🔄 **优化方向**：
		- 精细化 patterns 规则，减少误报（特别是 sink 和 entrypoint 匹配）。
		- 改进上下文分析逻辑，提高匹配准确率。
		- 增加过滤机制，排除测试代码和第三方库干扰。
- **VFinder（基于 LangChain Agent）**：
	- ✅ 核心 Agent 实现已完成（见 [src/vfinder/agent.py](src/vfinder/agent.py)）。
	- ✅ CLI 集成完成（见 [src/commands/vfind.py](src/commands/vfind.py)）。
	- ✅ 工具实现：shell_exec、file_read、recon_symbol_match（见 [src/vfinder/tools/](src/vfinder/tools/)）。
	- ✅ 输出优化：支持完整轨迹备份（.vfind_full_*.json）+ 干净结果提取。
	- ⚠️ **存在问题**：
		- Agent 任务与角色设定需要优化，当前 5-step workflow 较为机械。
		- 分析效率有待提升，工具调用次数偏多。
		- 终端显示输出冗长，影响用户体验。
	- 🔄 **优化方向**：
		- 优化 Agent system prompt，提供更清晰的任务引导和约束。
		- 改进 recon_symbol_match 匹配策略，减少无效查询。
		- 简化终端输出，仅显示关键进度和结果摘要。
		- 引入缓存机制，避免重复查询相同符号。
		- 调整 recursion_limit，平衡效率与完整性。

### 🔄 待实现/待启动
- pattern 拓展
- AI API env 拆分，以 env.template 格式存储
- callmap（调用链追踪）核心逻辑待落地
- verify（验证 Agent）核心逻辑待落地
- 数据模型与 SQLite 存储实现待定（当前 JSONL/JSON 已支持，SQLite 为占位）。
- CLI 配置合并优化（已有占位 core 模块）
	- 进展：基础结构化日志已接入，后续增加 JSON 日志与字段化（command/repo/duration）。
- 测试样例与集成用例待准备

## 风险与关注点
- **匹配准确性**：不同框架/注解/装饰器的多样性可能带来解析误差，当前 recon 模式存在误报需优化。
- **性能与效率**：
	- 大型仓库的扫描性能与资源消耗需在实现中优化。
	- VFinder Agent 工具调用次数偏多，分析效率待提升。
- **用户体验**：VFinder 终端输出冗长，影响交互体验，需简化显示逻辑。
- **动态探测风险**：可能存在环境依赖与副作用，需要安全开关与超时控制。

## 建议的下一步

### 高优先级（优化现有功能）
1. **Recon 模式优化**：
	- 精细化 patterns/python 和 patterns/java 的匹配规则。
	- 增加上下文分析和过滤机制，减少误报。
	- 补充单测和基线数据验证。
2. **VFinder 效率与体验优化**：
	- 重构 Agent system prompt，明确任务约束和输出格式。
	- 优化 recon_symbol_match 匹配策略（增加缓存、减少模糊查询）。
	- 简化终端输出，仅显示进度关键信息。
	- 调整工具参数和 recursion_limit，平衡完整性与效率。

- **Callmap / Trace（LSP + CodeQL 多 backend）**：
	- ✅ `trace find` 支持 `--backend lsp|codeql`。
	- ✅ 抽象层已落地：`TraceBackend` / `LspTraceBackend` / `CodeQLTraceBackend`。
	- ✅ `CodeQL` 模式支持 `--codeql-db`、`--codeql-image` 参数。
	- ✅ 未提供 image/db 时可尝试通过 `fix-compile` 自动生成可复用 CodeQL image + database。
	- ✅ backend 初始化失败语义已统一：返回 `ok=false` + 明确 `error`。
	- ⚠️ **当前限制**：`codeql` backend 的 caller 查询适配尚未完成；目前主要完成环境构建与流程接线。

### 中优先级（完善现有模块）
3. 增强日志：支持 JSON 结构化日志与统一字段（command、repo、duration、status）。
4. 完善存储层：定义并固化 JSONL/SQLite schema；扩展 writer 的 SQLite 写入能力。
5. 扩展 Recon：实现 tech_stack 更全面解析（Docker/compose/k8s）。

### 低优先级（新模块开发）
6. 推进 Calltrace：构建 AST 调用图与路径评分；与 Recon/VFinder 协同输出。
7. 完成 Verification Agent 的静态推理闭环；动态探测作为可选增强后置接入。
