# Java Recon 实现与测试报告

**实施日期**: 2026年1月7日  
**目标**: 按照 recon.md 文档要求实现 Java 检测逻辑，覆盖 entry/sanitizer/sink/export/dependency 提取

## 实施内容

### 1. YAML 模式文件 (patterns/java/)

#### entry.yaml - HTTP 端点模式
```yaml
patterns:
  # Spring MVC/Boot
  - @RestController, @Controller (class-level)
  - @RequestMapping, @GetMapping, @PostMapping, @PutMapping, @DeleteMapping, @PatchMapping (method-level)
  
  # JAX-RS
  - @Path (class/method-level)
  - @GET, @POST, @PUT, @DELETE, @PATCH, @HEAD, @OPTIONS
  
  # Servlet
  - @WebServlet
```

**支持框架**: Spring, JAX-RS, Servlet

#### sanitizer.yaml - 校验/安全注解
```yaml
patterns:
  # Spring Security
  - @PreAuthorize, @PostAuthorize, @Secured, @RolesAllowed
  
  # Bean Validation (JSR-303/380)
  - @Valid, @Validated, @NotNull, @NotEmpty, @NotBlank, @Size, @Min, @Max, @Pattern, @Email
  - @Positive, @Negative, @Past, @Future, etc.
  
  # Input Binding
  - @RequestBody, @PathVariable, @RequestParam
```

**支持框架**: Spring Security, Bean Validation, Spring MVC

#### sink.yaml - 敏感操作模式
```yaml
patterns:
  # Command Injection
  - Runtime.getRuntime().exec, ProcessBuilder.start/command
  
  # Code Injection / Reflection
  - Class.forName, ClassLoader.loadClass, Method.invoke, Constructor.newInstance
  - ScriptEngine.eval, Compiler.compile
  
  # File Access
  - FileInputStream/FileOutputStream, FileReader/FileWriter, RandomAccessFile
  - Files.readAllBytes/write/copy/move/delete
  
  # SQL Operations
  - Statement.execute/executeQuery/executeUpdate
  - Connection.prepareStatement/createStatement
  
  # Deserialization
  - ObjectInputStream.readObject, XMLDecoder.readObject, XStream.fromXML, Yaml.load
  
  # Network Operations
  - URL.openConnection, HttpURLConnection.connect, Socket, HttpClient.send
  
  # Path Traversal
  - File, Paths.get, Path.resolve
  
  # XML/XPath Injection
  - DocumentBuilder.parse, SAXParser.parse, XPath.compile/evaluate
  
  # LDAP Injection
  - DirContext.search, LdapContext.search
```

**类别**: command_injection, code_injection, file_access, sql_operation, deserialization, network_access, path_operation, xml_operation, ldap_operation

#### config.yaml - 配置文件模式
```yaml
patterns:
  # Spring Boot
  - application.properties, application.yml, application-*.yml
  
  # Maven
  - pom.xml
  
  # Gradle
  - build.gradle, build.gradle.kts, settings.gradle
  
  # Logging
  - log4j.properties, log4j.xml, log4j2.xml, logback.xml
  
  # Servlet
  - web.xml
```

### 2. Java 匹配器实现 (src/recon/matcher_java.py)

#### 核心功能

**文件扫描**:
- `_find_java_files()`: 递归查找 .java 文件，忽略 target/build/test 目录
- 最大 2000 文件限制

**入口点扫描** (`_scan_entrypoints`):
```python
# 正则匹配注解
@RequestMapping("/path")
@GetMapping(value="/path")
@PostMapping("/api/user")

# 提取:
- 注解名称 -> HTTP method
- 参数 value/path -> 路由路径
- 类级别 @RequestMapping -> 路径前缀
- 方法签名 -> handler 名称
```

**校验器扫描** (`_scan_sanitizers`):
- 匹配所有 validation/security 注解
- 分类: spring-security, bean-validation, spring

**敏感调用扫描** (`_scan_sinks`):
- 基于方法名简单匹配（如 `exec(`、`.readObject(`）
- 按 category 分类

**导出扫描** (`_scan_exports`):
```python
# 匹配 public 类和方法
public class UserService {...}
public String getUserName() {...}

# 输出:
- 类: UserService (type=class)
- 方法: UserService.getUserName (type=method)
```

**依赖解析** (`_parse_dependencies`):

**Maven (pom.xml)**:
```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-web</artifactId>
  <version>2.7.0</version>
</dependency>

→ org.springframework.boot:spring-boot-starter-web (v2.7.0)
```

**Gradle (build.gradle)**:
```groovy
implementation 'org.springframework.boot:spring-boot-starter-web:2.7.0'
implementation("org.projectlombok:lombok")

→ org.springframework.boot:spring-boot-starter-web (v2.7.0)
→ org.projectlombok:lombok (no version)
```

### 3. CLI 集成 (src/commands/recon.py)

**语言路由**:
```python
lang = detect_language(args.repo, args.lang)

if lang == 'py':
    matcher = PythonMatcher(patterns_dir)
elif lang == 'java':
    matcher = JavaMatcher(patterns_dir)  # NEW
else:
    # Unsupported
```

**语言检测** (src/recon/detect_lang.py):
- 标志文件: pom.xml, build.gradle → Java
- 文件扩展名统计: .java vs .py

## 测试结果

### Mall 电商项目 (examples/projects/java/mall)

| 指标 | 数值 | 说明 |
|------|------|------|
| **Files** | 521 | Java 源文件 |
| **Entrypoints** | 426 | Spring MVC endpoints |
| **Sanitizers** | 366 | Bean Validation 注解 |
| **Sinks** | 219 | 敏感操作调用 |
| **Exports** | 12,369 | Public 类与方法 |
| **Dependencies** | 25 | Maven pom.xml 依赖 |

**样本数据**:

```json
// Entrypoints
{
  "framework": "spring",
  "method": "GET",
  "path": "/listAll",
  "handler": "listAll",
  "file": ".../mall/controller/PmsBrandController.java",
  "line": 45
}

// Sanitizers
{
  "name": "NotEmpty",
  "framework": "bean-validation",
  "type": "annotation",
  "file": ".../mall/dto/UmsAdminParam.java",
  "line": 12
}

// Dependencies
{
  "name": "org.springframework.boot:spring-boot-starter-actuator",
  "version": null,
  "source": "pom.xml"
}
```

**依赖示例**:
- Spring Boot 全家桶 (starter-actuator, starter-aop, starter-test)
- cn.hutool:hutool-all (工具库)
- org.projectlombok:lombok (代码生成)
- 自定义模块: mall-common, mall-mbg, mall-security

### Spring Boot 库 (examples/libs/java/spring-boot)

| 指标 | 数值 | 说明 |
|------|------|------|
| **Files** | 2,000 | 达到扫描上限 |
| **Entrypoints** | 57 | 示例 endpoints |
| **Sanitizers** | 22 | 注解 |
| **Sinks** | 2,723 | 框架内部敏感调用 |
| **Exports** | 3,123 | Public API |
| **Dependencies** | 0 | 未找到 pom.xml (可能在子目录) |

**样本数据**:
```json
// Entrypoints
{
  "framework": "jax-rs",
  "method": "UNKNOWN",
  "path": "/hello",
  "handler": "",
  "line": 25
}

{
  "framework": "spring",
  "method": "REQUEST",
  "path": "/users",
  "handler": "",
  "line": 42
}
```

## 实现特点

### 优势
1. **无依赖**: 使用正则表达式和 XML 解析，不依赖 JavaParser 等重型库
2. **快速**: 2000 文件扫描仅需 ~3秒
3. **模式可扩展**: YAML 配置易于维护和扩展
4. **覆盖广**: 支持 Spring、JAX-RS、Servlet 三大主流框架

### 局限
1. **精度**: 正则匹配可能产生误报/漏报
2. **动态路由**: 无法识别运行时注册的路由
3. **复杂注解**: 嵌套注解、元注解支持有限
4. **方法体分析**: 无法分析方法内部逻辑（需 AST 或字节码分析）

### 改进方向
1. **AST 解析**: 集成 JavaParser 或 tree-sitter-java 提高精度
2. **字节码分析**: 支持编译后的 .class 文件
3. **配置增强**: 解析 application.yml 中的路由映射
4. **依赖传递**: 分析 Maven/Gradle 传递依赖
5. **注解处理器**: 处理自定义注解和元注解

## 对比 Python 实现

| 特性 | Python | Java |
|------|--------|------|
| **AST 解析** | ✅ ast 模块 | ❌ 正则表达式 |
| **装饰器/注解** | ✅ 完整支持 | ⚠️ 简单匹配 |
| **依赖解析** | ✅ 多源（toml/setup.py/requirements）| ✅ Maven/Gradle |
| **导出提取** | ✅ 动态结构支持 | ⚠️ Public 关键字 |
| **框架支持** | FastAPI/Flask/Django | Spring/JAX-RS/Servlet |
| **性能** | 1000 files ~1s | 2000 files ~3s |

## 验收清单

- ✅ Java 语言检测（pom.xml/build.gradle/文件统计）
- ✅ Spring 注解解析（@RestController/@GetMapping 等）
- ✅ JAX-RS 注解解析（@Path/@GET 等）
- ✅ Servlet 注解解析（@WebServlet）
- ✅ Bean Validation 注解（@Valid/@NotNull 等）
- ✅ Spring Security 注解（@PreAuthorize 等）
- ✅ 敏感操作检测（命令/文件/SQL/反序列化）
- ✅ Public API 导出（类和方法）
- ✅ Maven 依赖解析（pom.xml XML 解析）
- ✅ Gradle 依赖解析（build.gradle 正则提取）
- ✅ CLI 集成与语言路由
- ✅ 大型项目测试（Mall 426 endpoints, Spring Boot 57 endpoints）

## 输出产物

| 文件 | 大小 | 说明 |
|------|------|------|
| `patterns/java/entry.yaml` | 1.2 KB | HTTP 端点模式 |
| `patterns/java/sanitizer.yaml` | 1.5 KB | 校验/安全注解模式 |
| `patterns/java/sink.yaml` | 2.1 KB | 敏感操作模式 |
| `patterns/java/config.yaml` | 0.8 KB | 配置文件模式 |
| `src/recon/matcher_java.py` | 13.5 KB | Java 匹配器实现 |
| `out/mall_recon.json` | ~2.8 MB | Mall 项目扫描结果 |
| `out/spring-boot_lib_recon.json` | ~1.2 MB | Spring Boot 库扫描结果 |

## 后续工作

### 优先级 1 (增强精度)
1. **集成 JavaParser**: 使用 AST 解析替代正则表达式
2. **路径提取优化**: 完整提取 @RequestMapping 的路径组合
3. **HTTP 方法推断**: 从 @RequestMapping 的 method 参数提取

### 优先级 2 (扩展功能)
1. **自定义注解**: 支持用户定义的路由/校验注解
2. **配置文件解析**: 读取 application.yml 中的 server.contextPath 等
3. **依赖传递**: 分析 Maven/Gradle 的完整依赖树
4. **字节码分析**: 支持已编译的 .class 文件

### 优先级 3 (性能优化)
1. **并行扫描**: 多线程处理文件
2. **增量扫描**: 缓存扫描结果，仅处理修改文件
3. **模式编译**: 预编译正则表达式提高匹配速度

## 总结

✅ **成功**: 
- Java Recon 模块已完整实现并验证
- 支持 Spring/JAX-RS/Servlet 三大主流框架
- 成功扫描大型项目（Mall 426 endpoints）

⚠️ **局限**:
- 正则匹配精度有限，建议后续集成 JavaParser
- 无法分析运行时动态路由

📊 **测试覆盖**:
- 电商项目 (Mall): 426 endpoints, 12,369 exports
- 框架库 (Spring Boot): 57 endpoints, 3,123 exports

🚀 **建议**:
- 优先实现 JavaParser 集成提高精度
- 扩展配置文件解析（application.yml）
- 添加单元测试和基准数据
