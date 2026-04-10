# Calltrace Mapper 模块实施计划（已更新）

## 目标与范围
- 构建入口（路由/控制器）到候选 sink 的调用链，评估可达性与鉴权/边界检查。
- 结合 AST 定位与可插拔 caller backend（LSP / CodeQL）。

## 输入输出
- 输入：Recon 入口清单、VFinder sink 列表、repo_root。
- 输出：入口列表、sink 列表、调用链（有序节点、文件/行、守卫注记、评分）。

## 当前代码结构（摘要）
- `src/callmap/trace.py`：TraceExtractor 与 DFS 路径提取
- `src/callmap/ast/`：单文件符号定位（tree-sitter）
- `src/callmap/lsp/`：LSP 服务器生命周期与引用查询
- `src/callmap/codeql/runner.py`：fix-compile 驱动的 CodeQL image/db 构建与查询
- `src/callmap/backends/`：多 backend 抽象与实现
  - `base.py`：`TraceBackend`
  - `lsp_backend.py`：`LspTraceBackend`
  - `codeql_backend.py`：`CodeQLTraceBackend`

## 实现策略
- 调用图构建：
  - Python：AST 收集函数/方法定义、调用；处理装饰器、类方法、自引用；可选 networkx 存图。
  - Java：javaparser/spoon 解析类与方法调用；基础类型解析与简单分派；必要时基于类路径补全。
- 入口到 sink 搜索：
  - 从 sink 反向 DFS 查找 callers，限制深度；记录路径节点。
  - callers 来源由 backend 决定（LSP 或 CodeQL）。
- 守卫检测：
  - Python：常见装饰器（login_required、dependency 注入检查等）、参数校验。
  - Java：@PreAuthorize/@Secured/@RolesAllowed，常见校验调用（Objects.requireNonNull 等）。
- 评分：
  - 路径长度、守卫强度（有无鉴权/校验）、sink 置信度综合打分。
- 性能：缓存解析结果；忽略大文件/生成文件；可配置最大节点/路径数。

## CLI（当前）
- `vuln_reach_analysis trace find --repo <path> --sinks <sinks.json> --recon <recon.json> [--backend lsp|codeql]`
- CodeQL 可选参数：`--codeql-db`, `--codeql-image`, `--no-codeql-fallback-lsp`

## 测试
- 单测：AST 边提取、守卫识别、路径搜索与评分。
- 集成：在示例 FastAPI/Spring 项目上生成调用链，校验预期路径与评分顺序。

## 里程碑（更新）
1) LSP + AST 反向调用链提取完成。
2) 多 backend 抽象完成（`lsp` / `codeql`）。
3) CodeQL 自动构建路径完成（未提供 image/db 时尝试 fix-compile 生成）。
4) 待完成：CodeQL caller query adapter（当前 backend 中该部分为占位）。

## 风险与缓解
- 解析不全：提供忽略/跳过并记录告警；深度限制避免爆炸。
- 守卫误判：白名单+黑名单可配置，允许标注覆盖。
- CodeQL 依赖环境：通过开关控制，缺失时降级为纯 AST。

## 当前实现边界
- AST 负责单文件“位置 -> 所在符号”定位。
- LSP 负责跨文件引用查询。
- CodeQL backend 当前完成了环境构建与接线，caller 查询适配仍在开发中。