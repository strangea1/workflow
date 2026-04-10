# 漏洞分析流水线

该仓库实现了一个由三个阶段组成的漏洞分析流水线，分别负责：

1. **模块定位（Module Locator）**
   - 加载 `docs/module_tree.json`，理解项目的模块与组件树结构。
   - 通过 LangChain + LLM 构造提示，把 CVE 触发信息映射到具体的模块与组件。
   - 校验模型输出，生成带 confidence/rationale 的结构化 JSON 结果。

2. **组件摘要（Component Summarizer）**
   - 将**模块定位**得到的组件名映射到 `docs` 下的文档（`overview.md` 和模块 `.md` 文件），调用 LLM 生成包含项目层与组件层业务信息的结构化摘要。
   - 确保输出是有效的 JSON，描述项目重要性、数据敏感性、组件攻击面与影响分析，供后续风险评估使用。

3. **风险评估（Risk Assessment）**
   - 汇总 CVE 元数据、业务因子（business factors）、可达性分析以及 prompt 模板，构建风险评估输入。
   - 使用 LangChain + LLM，按照指定格式填充风险因子（FVuln/FThreat/FBusiness）并生成整体风险等级。
   - 解析输出、重新计算分数、打印报告并将结构化结果写入 JSON。

## 目录结构一览
- `src/`：包含 `module_locator.py`、`component_module_summarizer.py`、`risk_asssignment.py` 
- `cve_data/`：放置漏洞/业务数据、供风险评估模块读取。
- `final_result_system_prompt/`：风险评估阶段使用的系统提示词模板。
- `artifacts/`：默认输出目录，由 `main.py` 按时间戳创建，用于保存每个阶段的 JSON 结果： `module_locator_result.json`、`component_summary.json`、`risk_assessment.json`。

## 运行方式
### 主控脚本
`main.py` 是整段流水线的入口，依次运行模块定位、组件摘要、风险评估。常用命令示例：

```bash
python main.py \
  --docs ./proj/ofbiz-framework/docs \
  --trigger "JSON.java:return mapper.readValue(jsonString, targetClass) // Jackson 反序列化 sink" \
  --repo ofbiz-framework-release24.09.05 \
  --cve CVE-2025-49128 \
  --api-key <API_KEY> \
  --base-url https://api.bianxie.ai/v1 \
  --output-dir ./artifacts
```

这个命令将：
1. 使用 `module_locator.py` 定位目标模块与组件，并输出 `module_locator_result.json`。
2. 调用 `component_module_summarizer.py`，生成组件摘要 `component_summary.json`。
3. 读取 CVE 数据与业务因子，运行 `risk_asssignment.py` 输出最终风险评估 `risk_assessment.json`。

### CLI 参数说明
`main.py` 支持以下常用参数（更多说明可查看脚本顶部）：
- `--trigger` / `--target`：漏洞触发文本或类名。
- `--repo`：仓库/项目名称，用于 prompt 上下文。
- `--cve`：CVE 编号（必须），贯穿所有阶段并用来定位业务因子文件。
- `--snippet-size`：向 LLM 提供的 module tree 上下文数量，设为 `-1` 可包含全部模块。
- `--api-key` / `--base-url`：LLM 认证信息。
- `--output-dir`：指定 artifacts 输出目录，默认当前路径。
- `--risk-verbose`：风控阶段打印更多 LLM 配置日志。

## 输出说明
- `module_locator_result.json`：包含定位出的 `module`、`component`、`confidence`、`rationale`、LLM 使用的 `module_context_snippet` 以及 `cli_context`。
- `component_summary.json`：LLM 输出的项目 + 组件业务摘要，包含 `project` 与 `component` 信息（如敏感性、影响、合规分析）。
- `risk_assessment.json`：最终风险结果，表述项目、漏洞信息、评分因子（FVuln/FThreat/FBusiness）以及评估过程、风险等级。