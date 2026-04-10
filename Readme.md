# 漏洞分析全流程自动化工具

本项目将开源项目版本爬取、CVE 匹配、CodeWiki 模块分析以及风险评估整合为一套完整的流水线，入口为 workflow_unified.py。

## 依赖的外部项目

- VulnTriage: 提供漏洞触发点扫描能力，判断目标项目是否调用了危险函数
  https://github.com/xzhxzw/VulnTriage
- CodeWiki: 对目标仓库生成模块树与文档，供后半段业务信息提取使用
  需在 target_repo/<项目名>/docs/ 下产出文档

请先按各项目自身 README 完成安装与配置，再运行本脚本。

## 环境要求

- Python 3.10+
- 建议使用独立虚拟环境（conda 或 venv）
- 需要访问 OpenAI 兼容接口（如 opencode、Azure OpenAI、第三方中转服务）

## 模型接口配置

CLI 参数（也可设置对应环境变量）：
  --openai-base-url   OPENAI_BASE_URL   接口 Base URL
  --openai-api-key    OPENAI_API_KEY    API Key
  --openai-model      OPENAI_MODEL      模型名，例如 gpt-4o-mini

若不传模型参数，CVE 匹配与 eval 后半段的 LLM 调用会被跳过，前半段爬取仍可正常运行。

## 安装依赖

  pip install -r eval/requirements.txt
  pip install pandas openpyxl requests

## 运行流程

各阶段及对应 flag:
  版本爬取 + CVE 匹配  默认运行
  CodeWiki 分析        --run-codewiki
  vfind 任务生成        --run-vfind
  NVD 信息抓取         --run-nvd
  eval 后半段          --run-eval
  N次投票              --vote N

## 完整流程命令

  python workflow_unified.py \\
    --projects-excel app_githuburl.xlsx \\
    --cve-excel DATA.xlsx \\
    --output-excel result.xlsx \\
    --debug-dir debug_output \\
    --top-tags 10 \\
    --github-token <YOUR_GITHUB_TOKEN> \\
    --openai-base-url <YOUR_BASE_URL> \\
    --openai-api-key <YOUR_API_KEY> \\
    --openai-model gpt-4o-mini \\
    --run-codewiki \\
    --run-vfind \\
    --run-nvd \\
    --run-eval
    --vote N


## 输入文件格式

app_githuburl.xlsx 列: Project / URL / language（python 或 java）
DATA.xlsx 列: 软件名 / CVE编号 / 描述

## 输出文件说明

  result.xlsx                          各项目各 tag 下目标组件版本及匹配到的 CVE
  workflow_output/nvd/*.json           NVD API 返回的 CVE 详情
  workflow_output/eval_runs/           eval 各阶段 JSON 产出
  workflow_output/final_assessment.xlsx 最终风险评估汇总表
  debug_output/                        中间调试文件及 debug.log

## 常见问题

1.需要先安装并配置opencode，可参考网上教程配置中转api，参考链接：https://zhuanlan.zhihu.com/p/1992957270024283486

2.需要下载并配置codewiki

3.需要安装VulnTriage，进入VulnTriage文件夹下使用命令：
pip install -e .

注意：
VulnTriage\src\vfinder\agent.py中将r"C:\Users\A\scoop\apps\nodejs\current\bin\opencode.CMD"替换为自己的opencode的位置
