# Pattern 文件字段说明

## 标准模式（entry/sink/sanitizer）

**type**: 模式类型（annotation/method_call/decorator/function_call/file）

**names**: 匹配名称列表，支持通配符

**framework**: 框架标识

**scope**: 作用域（class/method/class_or_method/field_or_parameter/parameter/method_or_class）

**category**: 分类标识

**severity**: 严重程度（high/medium/low）

**standalone**: 是否可独立工作（boolean）

**extract**: 上下文提取规则列表
  - 列表项为对象，key为提取目标（path/method/pattern/view/methods），value为source值
  - source值: value/first_arg/second_arg/annotation_name/decorator_name/urlPatterns/kwarg_methods

**method_mapping**: 注解名到HTTP方法的映射表
  - 对象格式，key为注解名，value为HTTP方法

**method_extract**: 从参数提取HTTP方法的规则
  - **source**: 提取源（通常为params）
  - **pattern**: 正则表达式模式
  - **default**: 默认值

---

## Tech Stack 模式（tech_stack.yaml）

**说明**: 使用标准模式格式（与 entry/sink/sanitizer 一致）

**字段**:
  - **type**: file
  - **names**: 文件名列表，支持通配符
  - **framework**: 技术栈类型（container/maven/gradle/pip等）
  - **category**: tech_stack

---

## Config 模式（config.yaml，当前未使用）

**说明**: 这两个文件被加载但未在代码中使用，依赖解析逻辑为硬编码。**Java 和 Python 使用统一的标准模式格式。**

**字段**:
  - **type**: file
  - **names**: 文件名列表，支持通配符
  - **framework**: 框架标识
  - **category**: 分类标识（dependency/config）

**Java config.yaml**: 定义配置文件和依赖文件识别模式
  - 对应内容: Spring Boot配置、Maven/Gradle依赖文件、日志配置、Servlet配置

**Python config.yaml**: 定义依赖文件识别模式
  - 对应内容: requirements.txt、pyproject.toml、setup.py、Pipfile、poetry.lock等依赖文件
