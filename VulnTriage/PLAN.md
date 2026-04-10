# 漏洞可利用性评估系统实施方案

## 目标
- 针对 Python 与 Java 仓库，自动化完成信息收集、漏洞定位、调用链映射与验证评估。
- 支持多仓库与三方库扫描，输出标准化结果便于后续分析与报告。

## 端到端流程
1) 输入：仓库路径与漏洞描述/PoC 需求包。
2) Recon：扫描配置、技术栈、路由/控制器、库的对外接口，生成规范化清单并存储。
3) VFinder：依据漏洞特征（API、模式、PoC）匹配代码，输出候选 sink 及上下文。
4) Calltrace Mapper：基于 AST/可选 CodeQL 构建入口-出口调用链，输出排序后的调用路径。
5) Verification Agent：围绕调用链进行推理（静态优先，可选轻量动态探测），产出可利用性结论与证据。
6) 持久化 JSON 结果并生成报告。

## 模块输入输出设计
- 通用输入：repo_root，语言（自动检测可覆盖），需求包（漏洞描述、CVE、PoC、易受攻击的 API/模式、版本范围）。

- Recon（项目信息）
	- 输入：repo_root
	- 处理：识别配置（Dockerfile/docker-compose/k8s/env），包管理工具（pip/poetry/pipenv；maven/gradle），框架路由模式（FastAPI/Flask/Django；Spring MVC/Boot 控制器），三方库导出接口（Python __init__.py，Java public 方法/注解）
	- 输出（JSONL/SQLite）：tech_stack、configs、services、routers/controllers、exported APIs 清单。

- VFinder（漏洞定位）
	- 输入：repo_root，需求包，Recon 清单
	- 处理：漏洞规格标准化→签名（API 名、包名、版本、代码模式、PoC 请求）；通过 AST/grep、依赖匹配、相似度检索进行查找
	- 输出：候选 sink（文件/行）、匹配的签名、置信度、周边代码片段。

- Calltrace Mapper
	- 输入：入口 Recon 清单、VFinder sink、repo_root
	- 处理：AST 调用图；可选 CodeQL；将入口（router/controller）映射到 sink；计算调用链并按可达性、鉴权/边界检查打分
	- 输出：入口列表、sink 列表、调用链（有序调用+位置+守卫信息）。

- Verification Agent
	- 输入：调用链、PoC（如有）、漏洞描述、repo_root
	- 处理：围绕调用链的推理循环；构造/模拟请求路径；可选轻量动态探测（如 httpx 调 FastAPI、mock Spring MVC）；给出结论与证据
	- 输出：可利用性结论（Yes/No/Uncertain）、理由、验证链路、测试指令（curl/httpx、mvn/pip）。

## 实施阶段与代码结构
目录规划：
- /src/
	- core/（数据模型、日志、配置）
	- recon/（配置探测、框架扫描、API 导出提取）
	- vfinder/（签名构建、匹配器、相似度检索）
	- callmap/（调用图构建、入口到 sink 映射）
	- verify/（验证代理循环、探测适配器）
	- cli.py（命令入口）
	- storage/（JSONL/SQLite 存储）
	- utils/（文件、语言检测、AST 工具）
- /requirements/（示例漏洞需求包）
- /tests/（单测/集成测试）

### Recon 实现计划
- 语言检测：基于文件特征识别 py/java，可手动覆盖。
- 配置探测：扫描 Dockerfile/compose/k8s/env，解析端口、服务、环境变量。
- 依赖信息：解析 pyproject/requirements.txt/pipfile；pom.xml/gradle，记录依赖与版本。
- 路由/控制器识别：
	- Python：AST 解析 FastAPI/Flask 路由装饰器；Django urls.py；记录 method/path/handler。
	- Java：解析注解 @RestController/@Controller/@RequestMapping/@GetMapping 等；记录 path/method/class。
- 库导出 API：
	- Python：遍历 __init__.py、模块级函数/类、__all__。
	- Java：src/main/java 中 public 类/方法，尤其带注解或接口实现。
- 存储：标准化模型（entrypoint/export/config/dep），落盘 JSONL/SQLite。

### VFinder 实现计划
- 签名构建：从漏洞规格提取 API、包名、版本、代码片段、PoC HTTP 目标。
- 匹配策略：
	- 依赖匹配：比对漏洞包/版本与 manifest/lock。
	- API 名匹配：AST 搜索符号名，支持模糊与命名空间匹配。
	- 片段/相似度：对漏洞代码/PoC trace 做向量或 TF-IDF，检索相似文件片段。
	- URL 线索：PoC URL 映射到 Recon 路由。
- 输出格式：文件、行号、片段、匹配签名、置信度。

### Calltrace Mapper 实现计划
- 调用图：
	- Python：AST 调用边，networkx 可选；识别装饰器与依赖注入。
	- Java：javaparser 或 spoon；方法调用边；简易 classpath 解析。
- 入口到 sink：从 router/controller 起，遍历到候选 sink，限制深度，标记鉴权检查（中间件或 @PreAuthorize 等）。
- CodeQL（可选）：运行预置数据流查询，合并结果。
- 输出：排序调用链，附守卫/鉴权/污点信息。

### Verification Agent 实现计划
- 输入：排序调用链 + PoC。
- 推理循环：选 Top 调用链，展开参数需求，检查守卫，生成假设请求。
- 动态探测（可选，开关控制）：
	- FastAPI/Flask：若可运行则起服务，用 httpx 发送构造请求。
	- Spring：尝试 mvn test 或嵌入式 Tomcat；否则走纯静态结论。
- 结论逻辑：可达且无有效阻断、PoC/构造请求成功则 Yes；证据不足为 Uncertain；不可达或已缓解为 No。
- 输出：结论、理由、使用的调用链、建议命令（curl/httpx、mvn/pip）。

## 集成与 CLI
- 命令：
	- recon：生成清单
	- vfind：基于需求包定位候选 sink
	- map：构建调用链
	- verify：运行验证代理
	- all：端到端流水线
- 配置：yaml/env；日志支持结构化 JSON。

## 测试策略
- 单测：探测器（路由/注解解析）、签名匹配、调用边提取。
- 集成：在示例 FastAPI 与 Spring 项目上跑全流程，含已知漏洞依赖。
- 回归基线：需求包与预期匹配结果、调用链快照。

## 里程碑
1) 框架骨架 + 数据模型 + CLI stub。
2) Recon（Python/Java 基础）输出清单。
3) VFinder 依赖/API 匹配与置信度。
4) Calltrace AST 图与排序。
5) Verification Agent（静态推理）+ 可选动态探测。
6) 集成测试 + 文档 + 示例。
