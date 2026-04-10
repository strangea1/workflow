#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
改进版组件模块功能总结工具
- 新文件：component_module_summarizer.py（不修改原 component_finder.py）
- 基于 LangChain，将 overview.md 与对应模块的 .md 文档一并送入大模型，总结模块功能

使用示例：
    python component_module_summarizer.py "java-sec-code-master.src.main.java.org.joychou.security.WebSecurityConfig.WebSecurityConfig" \
        --docs "./java-sec-code-master/docs" --model "gpt-4o-mini"

依赖：
    pip install langchain langchain-openai
    并在环境中配置 OPENAI_API_KEY 或使用 --api_key 传入
"""

import argparse
import json
import os
from pathlib import Path
from typing import Dict, List, Optional

# LangChain imports
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import SystemMessage, HumanMessage


class ModuleSummarizer:
    """模块功能总结器：解析 module_tree.json，定位模块及其文档，调用大模型生成总结"""

    def __init__(self, docs_dir: str, model: str, api_key: Optional[str] = None, base_url: Optional[str] = None,
                 language: str = "zh"):
        self.docs_dir = Path(docs_dir)
        self.module_tree_file = self.docs_dir / "module_tree.json"
        self.overview_file = self.docs_dir / "overview.md"
        self.language = language

        # 初始化 LLM
        api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("缺少 API Key：请设置环境变量 OPENAI_API_KEY 或通过 --api_key 参数传入")
        self.llm = ChatOpenAI(model=model, api_key=api_key, base_url=base_url)

        # 读取模块树
        self.module_tree = self._load_module_tree()
        self.component_to_modules = self._build_component_map()

    def _load_module_tree(self) -> dict:
        if not self.module_tree_file.exists():
            raise FileNotFoundError(f"找不到模块树文件：{self.module_tree_file}")
        with open(self.module_tree_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def _build_component_map(self) -> Dict[str, List[str]]:
        """构建 component -> 所有模块路径 的映射"""
        mapping: Dict[str, List[str]] = {}

        def traverse(mods: dict, parent: str = ""):
            for module_name, info in mods.items():
                full_path = f"{parent}.{module_name}" if parent else module_name
                for comp in info.get("components", []):
                    mapping.setdefault(comp, []).append(full_path)
                children = info.get("children", {})
                if children:
                    traverse(children, full_path)

        traverse(self.module_tree)
        return mapping

    def _get_module_info(self, module_path: str) -> Optional[dict]:
        parts = module_path.split(".")
        current = self.module_tree
        for p in parts:
            if p in current:
                current = current[p]
            else:
                return None
        return current

    def _read_text_file(self, path: Path) -> Optional[str]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def _find_module_md(self, module_name: str) -> Optional[Path]:
        """根据模块键名尝试找到对应的 .md 文档：优先尝试 <module_name>.md；找不到时做有限的启发式搜索"""
        direct = self.docs_dir / f"{module_name}.md"
        if direct.exists():
            return direct
        # 启发式：尝试大小写或短横线变体（非常保守，避免错误匹配）
        candidates = [
            self.docs_dir / f"{module_name.lower()}.md",
            self.docs_dir / f"{module_name.replace('.', '_')}.md",
        ]
        for c in candidates:
            if c.exists():
                return c
        return None

    def summarize_module(self, component_name: str) -> Optional[str]:
        """对给定组件所属的模块进行总结，返回 Markdown 文本"""
        module_paths = self.component_to_modules.get(component_name)
        if not module_paths:
            return None

        # 读取 overview.md
        overview_text = self._read_text_file(self.overview_file)
        if not overview_text:
            overview_text = "(未找到或无法读取 overview.md)"

        summaries = []
        for module_name in module_paths:
            info = self._get_module_info(module_name) or {}
            module_md_path = self._find_module_md(module_name)
            module_md_text = self._read_text_file(module_md_path) if module_md_path else None
            if not module_md_text:
                module_md_text = f"(未找到 {module_name}.md 文档)"

            # 组织提示词
            system_prompt = """你是一个安全分析专家，需要从代码文档中提取业务信息并生成结构化的 JSON 输出。

请仔细分析提供的文档内容，提取以下信息：

1. **项目级别信息**：
   - 项目名称
   - 项目在公司中的定位与作用
   - 项目功能、服务对象、流程与关键模块
   - 项目的重要性及故障造成的业务影响
   - 项目涉及的敏感数据及泄露后果
   - 项目部署环境与对外暴露情况

2. **组件级别信息**（基于找到的模块）：
   - 组件名称
   - 组件在项目中的功能
   - 组件在整体逻辑中的地位
   - 组件涉及的敏感数据
   - 组件作为输入入口的情况
   - 漏洞触发条件与可达性
   - 漏洞触发后的服务影响
   - 漏洞导致的数据风险
   - 漏洞引发的合规风险
   - 漏洞造成的业务损失与声誉影响

**重要**：你必须严格按照以下 JSON 格式输出，不要添加任何额外的说明文字：

{
  "project": {
    "name": "项目名称",
    "overall_role": "项目在公司中的定位与作用。",
    "description": "项目功能、服务对象、流程与关键模块。",
    "business_importance_analysis": "项目的重要性及故障造成的业务影响。",
    "data_sensitivity_analysis": "项目涉及的敏感数据及泄露后果。",
    "exposure_analysis": "项目部署环境与对外暴露情况。"
  },
  "component": {
    "name": "组件名称",
    "role_in_project": "组件功能。",
    "importance_analysis": "组件在整体逻辑中的地位。",
    "data_sensitivity_analysis": "组件涉及的敏感数据。",
    "attack_surface_analysis": "组件作为输入入口的情况。",
    "reachability_analysis": "漏洞触发条件与可达性。",
    "impact_analysis": {
      "service_availability": "漏洞触发后的服务影响。",
      "data_security": "漏洞导致的数据风险。",
      "compliance_impact": "漏洞引发的合规风险。",
      "financial_and_reputation_impact": "漏洞造成的业务损失与声誉影响。"
    }
  }
}

注意：
1.字段名为英文，内容为中文。
2.请确保输出是有效的 JSON 格式，可以直接被解析。"""

            # 新的 prompt 强制要求中文 JSON 输出，因此忽略 language 参数
            system_msg = system_prompt

            prompt = ChatPromptTemplate.from_messages([
                SystemMessage(content=system_msg),
                HumanMessage(content=(
                    f"模块名称: {module_name}\n"
                    f"组件名称: {component_name}\n\n"
                    f"=== 仓库 overview.md 内容 ===\n{overview_text}\n\n"
                    f"=== 模块 {module_name} 的 .md 文档内容 ===\n{module_md_text}\n\n"
                    f"请根据以上文档内容，提取信息并生成 JSON。\n"
                ))
            ])

            chain = prompt | self.llm
            result = chain.invoke({})
            text = result.content if hasattr(result, "content") else str(result)

            # 尝试提取 LLM 输出中的 JSON 部分并验证
            try:
                # LLM 可能在 JSON 前后添加 ```json ... ``` 或其他说明
                json_start = text.find('{')
                json_end = text.rfind('}') + 1
                if json_start != -1 and json_end != 0:
                    json_part = text[json_start:json_end]
                    # 验证它是否是有效的 JSON
                    json.loads(json_part)
                    summaries.append(json_part)
                else:
                    raise json.JSONDecodeError("No JSON object found in output", text, 0)
            except json.JSONDecodeError:
                # 如果不是有效的 JSON，则将原始文本作为错误信息记录
                error_summary = {"error": "Failed to parse LLM output as JSON", "module": module_name, "output": text}
                summaries.append(json.dumps(error_summary, ensure_ascii=False))

        # 将所有模块的 JSON 总结合并为一个 JSON 数组
        if not summaries:
            return None

        # 将字符串列表解析为对象列表，然后再统一序列化为格式化的 JSON 字符串
        all_summaries = [json.loads(s) for s in summaries]
        return json.dumps(all_summaries, indent=2, ensure_ascii=False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="组件所属模块功能总结（LangChain）")
    parser.add_argument("component", help="组件名称（从 docs/module_tree.json 的 components 中完整复制）")
    parser.add_argument("--docs", dest="docs", default="./docs", help="文档目录（包含 module_tree.json 与 overview.md）")
    parser.add_argument("--model", dest="model", default=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"), help="大模型名称")
    parser.add_argument("--api_key", dest="api_key", default=None, help="API Key（缺省读取 OPENAI_API_KEY 环境变量）")
    parser.add_argument("--base_url", dest="base_url", default=os.environ.get("OPENAI_BASE_URL"), help="OpenAI 兼容 Base URL（可选）")
    parser.add_argument("--lang", dest="lang", default="zh", choices=["zh", "en"], help="输出语言：zh 或 en")
    return parser.parse_args()


def main():
    args = parse_args()
    summarizer = ModuleSummarizer(docs_dir=args.docs, model=args.model, api_key=args.api_key, base_url=args.base_url,
                                  language=args.lang)

    summary = summarizer.summarize_module(args.component)
    if summary:
        print(summary)
    else:
        print(f"未找到组件所属模块：{args.component}")
        print("请确认组件名来自 docs/module_tree.json 的 components 列表，并与 --docs 指定目录一致。")


if __name__ == "__main__":
    main()