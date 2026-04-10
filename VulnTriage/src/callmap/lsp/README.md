# LSP 运行方式、与 Trace 的交互及可提取信息

## 配置与命令行测试

- **Python (Pyright)**：安装 `pip install pyright` 或 `npm install -g pyright`，确保 `pyright-langserver` 在 PATH 中。  
测试引用：  
`vuln_reach_analysis trace lsp refs --repo <repo> --file <path> --line <N> [--character <col>] --lang py`  
其中 `--line` 为 1-based 行号，`--character` 为该行内列偏移（0-based），需指向符号（如函数名）所在列。
- **Java (jdtls)**：下载 [Eclipse JDT LS](https://download.eclipse.org/jdtls/snapshots/) 并解压，设置环境变量 `JDTLS_HOME` 指向解压目录。**当前快照需 Java 21+**（部分 bundle 要求 JavaSE 21），请设置 `JAVA_HOME` 指向 JDK 21 再运行。  
测试引用：  
`vuln_reach_analysis trace lsp refs --repo <repo> --file <path> --line <N> --character <col> --lang java`

---

## 1. 运行方式：如何“指定 repo 并监听”

LSP 本身**不是“监听目录”的常驻服务**，而是**按会话工作**：

- 客户端（我们）**启动** LSP 进程（如 `pyright-langserver --stdio` 或 jdtls 的 JAR）。
- 通过 **stdio**（标准输入/输出）或 **socket** 与服务器用 **JSON-RPC** 通信。
- **工作区（repo path）** 在 **初始化阶段** 由客户端发给服务器，而不是命令行参数。

### 指定 repo path

在 LSP 的 `**initialize`** 请求里传入：

- `**rootUri**`：工作区根目录的 URI，例如 `file:///path/to/repo`
- 或 `**workspaceFolders**`：多根时用 `[{ uri: "file:///path/to/repo", name: "repo" }]`

服务器会把这个目录当作“当前项目”，在此范围内做索引、解析、查找引用等。**不是**服务器自己去“监听文件系统”，而是：

- 客户端可发 `**textDocument/didOpen`** 打开文件，让服务器解析；
- 或服务器在收到请求时按需从磁盘读文件（多数实现如此）；
- 文件变更可由客户端用 `**textDocument/didChange` / `didSave**` 或 `**workspace/didChangeWatchedFiles**` 通知服务器。

所以：**“指定 repo path” = 在 initialize 时传 `rootUri` / `workspaceFolders`，之后所有请求都在这个工作区内生效。**

### Python：Pyright

- **安装**：`pip install pyright` 或 `npm install -g pyright`；LSP 入口多为 `**pyright-langserver`**（随 pyright 包一并提供）。
- **运行**：`pyright-langserver --stdio`（无其他参数）。工作区由客户端在 **initialize** 里传 `rootUri`（repo 的 `file://` URI）。
- **通信**：stdin/stdout，JSON-RPC 2.0，每条消息前有 `Content-Length` 头。

### Java：Eclipse JDT LS (jdtls)

- **获取**：从 [Eclipse jdtls](https://download.eclipse.org/jdtls/snapshots/) 或 Maven `org.eclipse.jdt.ls` 取 JAR 与配置。
- **运行**：  
`java -jar org.eclipse.equinox.launcher_*.jar -configuration <config> -data <data_dir>`  
常用 **stdio** 或 socket；工作区同样在客户端 **initialize** 时通过 `**rootUri` / `workspaceFolders`** 传入。
- **通信**：同上，JSON-RPC over stdio 或 socket。

---

## 2. 如何与其交互以获取 reference 结果

### 方式一：`textDocument/references`（最通用）

- **含义**：在某个 **文档 + 位置** 上，查“所有引用该符号”的位置（谁在调用、谁在引用）。
- **请求**：  
  - `textDocument/references`  
  - 参数：`textDocument: { uri }, position: { line, character }`，可选 `context: { includeDeclaration: true/false }`
- **返回**：`Location[]`，每个为 `{ uri, range: { start, end } }`，即引用发生的文件与行号范围。

**典型用法（用于引用回溯）**：  
从 sink 所在 (file, line) 出发 → 解析该位置“符号”（如函数/方法名）→ 对该符号所在位置发 **references** → 得到所有引用点（调用方）→ 再对每个调用点取“所在函数”并递归，直到没有引用。

### 方式二：Call Hierarchy（若服务器支持）

- `**textDocument/prepareCallHierarchy`**：在给定位置返回一个 **CallHierarchyItem**（表示该符号）。
- `**callHierarchy/incomingCalls`**：传入该 item，返回 **“谁调用了它”** 的列表（CallHierarchyIncomingCall[]），每个包含 caller 与 fromRanges。
- `**callHierarchy/outgoingCalls`**：该符号“调用了谁”。

**用于 trace**：  
对 sink 位置先 **prepareCallHierarchy**，再 **incomingCalls**，得到直接调用方；对每个调用方递归 **incomingCalls**，即可建“从 sink 往上的调用链”。  
注意：不是所有 LSP 都实现 call hierarchy（Pyright/jdtls 需查各自文档）。

### 交互流程小结

1. 启动 LSP 进程（stdio），发 **initialize**（带 `rootUri` = repo 的 file URI）。
2. 发 **initialized** 通知。
3. （可选）对关心的文件发 **textDocument/didOpen**，或依赖服务器按需读文件。
4. 对 sink 所在 (file, line) 发 **textDocument/references**（或 prepareCallHierarchy + incomingCalls）。
5. 根据返回的 Location 列表继续对“调用方”递归，直到无引用或达到入口。

---

## 3. LSP 还能支持哪些信息提取（与 trace 相关）

除 references 外，常用且与“溯源 / 理解代码”相关的能力包括：


| 能力        | 请求                                            | 用途                             |
| --------- | --------------------------------------------- | ------------------------------ |
| **定义**    | `textDocument/definition`                     | 从引用跳到定义，确定“当前符号”的规范位置          |
| **声明**    | `textDocument/declaration`                    | 声明位置（与 definition 可能不同）        |
| **类型定义**  | `textDocument/typeDefinition`                 | 跳到类型定义，辅助理解调用链中的类型             |
| **实现**    | `textDocument/implementation`                 | 查接口/抽象方法的实现，补全调用图              |
| **悬停**    | `textDocument/hover`                          | 当前符号的文档/类型摘要，辅助判断是否 sink/entry |
| **文档符号**  | `textDocument/documentSymbol`                 | 单文件内符号树（类/函数/变量），用于“该行属于哪个函数”  |
| **工作区符号** | `workspace/symbol`                            | 按名称在工作区搜索符号，辅助从 recon 名称反查位置   |
| **引用**    | `textDocument/references`                     | 已述，回溯“谁引用/调用了这里”               |
| **调用层级**  | `callHierarchy/incomingCalls`、`outgoingCalls` | 直接“谁调谁”，若实现则比 references 更省事   |


不同服务器对上述支持不一，需在 **initialize** 返回的 **ServerCapabilities** 里查看（如 `referencesProvider`、`callHierarchyProvider` 等）。

---

## 4. 小结

- **运行方式**：用 **stdio** 启动 Pyright/jdtls，**不**在命令行传 repo；repo 通过 **initialize** 的 `**rootUri` / `workspaceFolders`** 指定，服务器在该工作区内做索引与查询。
- **获取 reference**：对 sink 位置发 `**textDocument/references`**（或 **prepareCallHierarchy + incomingCalls**），用返回的 Location 做递归回溯。
- **其他信息**：definition、hover、documentSymbol、workspace/symbol、call hierarchy 等均可用于辅助定位与过滤，具体以各 LSP 的 capabilities 为准。

