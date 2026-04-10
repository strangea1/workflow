# Recon 模块实施计划

## 目标与范围
- 发现并结构化仓库的技术栈、配置、路由/控制器、库的对外导出接口。
- 支持 Python 与 Java，兼容多服务/多模块项目。

## 输入输出
- 输入：repo_root，语言（可自动检测/手动指定）。
- 输出：JSONL/SQLite 清单（tech_stack、configs、services、routers/controllers、exports、deps）。

## 代码结构（建议）
- src/recon/__init__.py
- src/recon/detect_lang.py（语言检测）
- src/recon/config_scan.py（Dockerfile、compose、k8s、.env，借助tech_stack模式）
- src/recon/matcher.py（核心静态模式匹配引擎，加载 YAML 模式并执行匹配）
- src/recon/matcher_py.py
    - Python entry解析，使用 matcher + patterns
    - Python sanitizer解析，使用 matcher + patterns
    - Python sink解析，使用 matcher + patterns
    - Python库API列表解析，__init__.py / __all__ / 
    - Python配置文件解析，requirements.txt, setup.py, pyproject.toml
- src/recon/matcher_java.py
    - Java entry解析，使用 matcher + patterns
    - Java sanitizer解析，使用 matcher + patterns
    - Java sink解析，使用 matcher + patterns
    - Java库API列表解析，public 类/方法，注解过滤
    - Java配置文件解析，application.properties, application.yml）
- src/recon/models.py（EntryPoint, Export, Config, Dep, Service）
- src/recon/writer.py（JSONL/SQLite 持久化）
- patterns/（预定义模式目录，YAML 格式维护）
  - python/
    - entry.yaml（入口模式：FastAPI/Flask/Django 路由装饰器）
    - sanitizer.yaml（清洗/校验函数模式）
    - sink.yaml（敏感调用 sink 模式，如 eval/exec/subprocess）
    - config.yaml（配置文件模式，如requirements.txt）
  - java/
    - entry.yaml（入口模式：@RestController/@GetMapping 等注解）
    - sanitizer.yaml（校验/过滤模式：@PreAuthorize/@Validated 等）
    - sink.yaml（敏感调用模式：Runtime.exec/ProcessBuilder 等）
    - config.yaml (配置文件模式，如application.properties/application.yml)
  - tech_stack/
    - tech_stack.yaml（技术栈识别模式，如Docker,Kubernetes等）
- tests/recon/...

## 实现策略
- 语言检测：基于文件分布与标志文件（pyproject.toml、pom.xml 等）；允许 CLI 覆盖。
- 配置扫描：
  - Dockerfile：解析 EXPOSE、CMD/ENTRYPOINT、ENV。
  - docker-compose/k8s：解析服务名、端口、镜像、环境变量。
  - .env/环境变量文件：键值存储。
- 依赖解析：
  - Python：pyproject/requirements/pipfile；记录包名、版本约束；可选读取 lock。
  - Java：pom.xml（maven）、build.gradle；解析 groupId/artifactId/version。
- **预定义模式目录（patterns/）：**
  - 按语言分子目录（python/、java/）及通用目录（tech_stack/）。
  - 每个语言目录包含 YAML 模式文件：
    - `entry.yaml`：入口模式（路由/控制器/HTTP endpoint 标志）。
    - `sanitizer.yaml`：清洗/校验/鉴权模式（中间件/装饰器/注解）。
    - `sink.yaml`：敏感调用模式（命令执行/文件操作/反序列化等）。
    - `config.yaml`：配置文件模式（requirements.txt/pyproject.toml；application.properties/application.yml）。
  - tech_stack/ 目录：
    - `tech_stack.yaml`：技术栈识别模式（Docker/Kubernetes/容器编排等）。
  - YAML 结构示例（以 Python entry 为例）：
    ```yaml
    patterns:
      - type: decorator
        names: ["app.route", "app.get", "app.post", "router.get", "router.post"]
        framework: flask/fastapi
        extract:
          - path: first_arg  # @app.get("/foo")
          - method: decorator_name  # get/post
      - type: function_call
        names: ["path", "re_path"]
        framework: django
        extract:
          - pattern: first_arg
          - view: second_arg
    ```
- **静态匹配引擎（matcher.py）：**
  - 核心匹配引擎，提供通用的 YAML 加载与 AST 遍历匹配能力。
  - 遍历 AST（Python：ast 模块；Java：javaparser/tree-sitter），根据模式定义匹配节点。
  - 匹配逻辑：
    - 装饰器/注解名称匹配（精确或正则）。
    - 函数调用名称匹配（含命名空间）。
    - 提取关联上下文（路径/HTTP method/参数）。
  - 输出统一结构：`{type, matched_pattern, file, line, context}`。
- **语言专用匹配器：**
  - `matcher_py.py`：
    - 调用 `matcher.py` 加载 `patterns/python/*.yaml`。
    - 集成 Python entry/sanitizer/sink 解析（装饰器/函数调用匹配）。
    - 库 API 列表解析（__init__.py 中的 __all__、from x import y；模块级函数/类）。
    - 配置文件解析（requirements.txt/setup.py/pyproject.toml）。
  - `matcher_java.py`：
    - 调用 `matcher.py` 加载 `patterns/java/*.yaml`。
    - 集成 Java entry/sanitizer/sink 解析（注解匹配与提取）。
    - 库 API 列表解析（public 类/方法，注解过滤）。
    - 配置文件解析（application.properties/application.yml）。
- **技术栈扫描（config_scan.py）：**
  - 借助 `patterns/tech_stack/tech_stack.yaml` 模式识别技术栈。
  - Dockerfile：解析 EXPOSE、CMD/ENTRYPOINT、ENV。
  - docker-compose/k8s：解析服务名、端口、镜像、环境变量。
  - .env/环境变量文件：键值存储。
- 数据模型：统一使用 pydantic/dataclasses，便于序列化。
- 存储：writer 支持 JSONL 和 SQLite（以表分 schema），CLI 选择输出路径。

## CLI
- cli recon --repo <path> --lang <auto|py|java> --out <file> --format <jsonl|sqlite>

## 测试
- 单测：
  - 语言检测、技术栈识别（基于 tech_stack.yaml 模式）。
  - matcher.py 核心引擎：装饰器/注解/函数调用匹配逻辑。
  - matcher_py.py：Python entry/sanitizer/sink/库 API/配置文件解析。
  - matcher_java.py：Java entry/sanitizer/sink/库 API/配置文件解析。
  - 依赖解析（pyproject/pom/gradle）。
- 集成：对示例 FastAPI 与 Spring 项目跑一次 recon，校验输出 schema（含 entry/sanitizer/sink/exports/deps）。

## 里程碑
1) 模型与存储层落地，语言检测与依赖解析完成。
2) 预定义模式目录（patterns/）搭建，Python/Java/tech_stack 的 YAML 基线模式落地（entry/sanitizer/sink/config/tech_stack）。
3) 核心匹配引擎（matcher.py）实现并完成单测（装饰器/注解/函数调用匹配）。
4) matcher_py.py 实现 Python 全场景解析（entry/sanitizer/sink/库 API/配置）；tech_stack 扫描（config_scan.py）。
5) matcher_java.py 实现 Java 全场景解析（entry/sanitizer/sink/库 API/配置）。
6) CLI 与输出格式稳定，集成测试通过（含模式扩展与覆盖验证）。

## 风险与缓解
- 框架变体多：通过 YAML 模式文件可配置，支持用户追加自定义模式（`--extra-patterns` 或环境变量）。
- 模式维护成本：初期提供基线覆盖（FastAPI/Flask/Django/Spring），社区贡献或自动学习扩展。
- 大仓库性能：目录过滤、并行扫描、结果缓存；模式匹配可增量执行。
- 非标准 build 脚本：提供跳过/忽略列表，记录告警。
- 静态匹配精度：部分动态路由/反射调用难以覆盖，标记为低置信度或通过 CodeQL 补充。