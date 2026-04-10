#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Module locator that reads module_tree.json and maps triggers/targets to structured module info."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.exceptions import OutputParserException
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field, ValidationError
from typing_extensions import Literal

from .module_tree_utils import (
    build_component_map,
    flatten_module_tree,
    get_module_info,
    load_module_tree,
)


LOG = logging.getLogger(__name__)


class ModuleLocatorResult(BaseModel):
    module: Optional[str]
    component: Optional[str]
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    status: Literal["mapped", "unmapped"]


class ModuleLocator:
    MAX_VALIDATE_ATTEMPTS = 10

    def __init__(
        self,
        module_tree_path: Path,
        model: str,
        api_key: Optional[str],
        base_url: Optional[str],
        trigger: Optional[str],
        target: Optional[str],
        cve: Optional[str],
        filepath: Optional[str],
        repo: Optional[str],
        snippet_size: int,
    ):
        self.module_tree_path = module_tree_path
        self.module_tree = load_module_tree(module_tree_path)
        self.flattened = flatten_module_tree(self.module_tree)
        self.component_to_modules = build_component_map(self.module_tree)
        self.trigger = (trigger or "").strip()
        self.target = (target or "").strip()
        self.cve = cve
        self.filepath = filepath
        self.repo = (repo or "").strip()
        self.snippet_size = snippet_size
        self.prompt_parser = PydanticOutputParser(pydantic_object=ModuleLocatorResult)

        api_key = api_key or os.environ.get("OPENAI_API_KEY")
        base_url = base_url or os.environ.get("OPENAI_BASE_URL")
        self.llm = ChatOpenAI(model=model, api_key=api_key, base_url=base_url) if api_key else None

    def build_module_context_snippet(self, limit: Optional[int] = None) -> Tuple[str, List[Dict[str, object]]]:
        entries: List[Dict[str, object]] = []
        lines: List[str] = []
        if limit is None:
            limit = self.snippet_size
        if limit < 0:
            modules_to_include = self.flattened
        else:
            modules_to_include = self.flattened[:limit]
        for module_path, info in modules_to_include:
            desc = (info.get("description") or "").strip() or "(无描述)"
            components = info.get("components", [])
            entries.append({
                "path": module_path,
                "description": desc,
                "components": components,
            })
            components_text = ", ".join(components) if components else "N/A"
            lines.append(f"{module_path}: {desc} (components: {components_text})")
        snippet_text = "\n".join(lines) if lines else "(module tree is empty)"
        return snippet_text, entries

    def locate(self) -> Dict[str, object]:
        context_text, context_modules = self.build_module_context_snippet(self.snippet_size)
        result: Optional[ModuleLocatorResult] = None
        parser_error: Optional[str] = None
        attempts = 0

        if self.llm:
            while attempts < self.MAX_VALIDATE_ATTEMPTS:
                try:
                    result = self._call_llm(context_text)
                    attempts += 1
                    if result.status != "mapped":
                        parser_error = parser_error or f"LLM result status {result.status}"
                        break
                    validated = self._validate_llm_result(result)
                    if validated.status == "mapped":
                        result = validated
                        break
                    parser_error = parser_error or validated.rationale
                    result = validated
                except (OutputParserException, ValidationError) as exc:
                    parser_error = f"LLM parser error: {exc}"
                    LOG.warning(parser_error)
                    attempts += 1
            else:
                LOG.warning("Reached max validation retries (%d)", self.MAX_VALIDATE_ATTEMPTS)

        if not result:
            result = self._keyword_fallback(parser_error)

        payload = result.dict()
        payload["module_context_snippet"] = {"text": context_text, "modules": context_modules}
        payload["cli_context"] = {
            "trigger": self.trigger,
            "target": self.target,
            "repo": self.repo,
            "cve": self.cve,
            "filepath": self.filepath,
        }
        return payload

    def _call_llm(self, module_context: str) -> ModuleLocatorResult:
        system_prompt = (
            "你是 CodeWiki 结构分析师，负责将漏洞触发上下文映射到 module_tree.json 中的模块/组件。"
            "使用结构化 JSON 以便 downstream 风险评估能消费。confidence 要在 0 到 1 之间。"
            "如果无法映射，请设置 status 为 \"unmapped\" 并解释原因。"
        )
        human_template = (
            "漏洞{cve}在仓库{repo}被触发的位置是：\n"
            "{trigger}\n"
            # "文件路径：{filepath}\n"
            "请你确定这个触发位置属于codewiki划分的哪个模块和组件（ofbiz-framework-release24.09.05\docs-1.0）"
            "重点是模块名和组件名要在module_tree.json中有对应."
            "举个例子，\"components\":[\"framework.webapp.src.main.java.org.apache.ofbiz.webapp.SeoConfigUtil.SeoConfigUtil\"]中的framework.webapp.src.main.java.org.apache.ofbiz.webapp.SeoConfigUtil.SeoConfigUtil就是我要找的组件名"
            "请参考以下模块上下文信息：\n{module_context}\n"
            "{format_instructions}"
        )
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("human", human_template),
        ])
        prompt_inputs = {
            "trigger": self.trigger or "",
            "target": self.target or "",
            "repo": self.repo or "N/A",
            "cve": self.cve or "N/A",
            "filepath": self.filepath or "N/A",
            "module_context": module_context,
            "format_instructions": self.prompt_parser.get_format_instructions(),
        }
        try:
            prompt_value = prompt.format_prompt(**prompt_inputs)
            for msg in prompt_value.to_messages():
                LOG.info("LLM prompt (%s): %s", msg.type, msg.content)

        except Exception as log_exc:
            LOG.warning("无法格式化 prompt 用于记录: %s", log_exc)
        response = (prompt | self.llm).invoke(prompt_inputs)
        content = getattr(response, "content", str(response))

        # print("LLM response content:", content) # 后续还会有分析
        return self.prompt_parser.parse(content)

    def _validate_llm_result(self, result: ModuleLocatorResult) -> ModuleLocatorResult:
        data = result.dict()

        missing = not data.get("module") or not data.get("component")
        if missing:
            return ModuleLocatorResult(
                module=None,
                component=None,
                confidence=0.0,
                rationale="LLM 输出缺少 module 或 component 字段",
                status="unmapped",
            )

        module_info = get_module_info(self.module_tree, data["module"])
        if not module_info:
            return ModuleLocatorResult(
                module=data["module"],
                component=data["component"],
                confidence=0.0,
                rationale="LLM 所选模块不在 module_tree 中",
                status="unmapped",
            )

        if data["component"] not in module_info.get("components", []):
            return ModuleLocatorResult(
                module=data["module"],
                component=data["component"],
                confidence=0.0,
                rationale="LLM 输出的 component 不属于所选 module",
                status="unmapped",
            )

        return ModuleLocatorResult(
            module=data["module"],
            component=data["component"],
            confidence=max(0.0, min(1.0, data.get("confidence", 0.0))),
            rationale=data.get("rationale", "").strip() or "LLM 映射成功",
            status="mapped",
        )

    def _keyword_fallback(self, reason: Optional[str]) -> ModuleLocatorResult:
        matches = self._find_matches(self.target or self.trigger or "")
        if matches:
            score, module_path, component = matches[0]
        else:
            score = 0
            module_path = None
            component = None

        module_info = get_module_info(self.module_tree, module_path) if module_path else {}
        confidence = min(1.0, score / 10) if score else 0.3
        fallback_rationale = reason or "仅靠关键词匹配，未能提供结构化信息"
        return ModuleLocatorResult(
            module=module_path,
            component=component,
            confidence=confidence,
            rationale=fallback_rationale,
            status="unmapped",
        )

    def _find_matches(self, target: str) -> List[Tuple[int, str, str]]:
        results: List[Tuple[int, str, str]] = []
        if not target.strip():
            return results
        target = target.lower()
        for module_path, info in self.flattened:
            components = info.get("components", [])
            for component in components:
                score = self._score_component(component, target)
                if score > 0:
                    results.append((score, module_path, component))
        return sorted(results, key=lambda item: item[0], reverse=True)

    @staticmethod
    def _score_component(component: str, target: str) -> int:
        comp = component.lower()
        tgt = target.lower().strip()
        if not tgt:
            return 0
        if comp == tgt:
            return len(tgt) * 5
        if tgt in comp:
            return len(tgt) * 3
        chunks = [chunk for chunk in re.split(r"[.\\/\\s_-]+", tgt) if chunk]
        score = 0
        for chunk in chunks:
            if chunk in comp:
                score = max(score, len(chunk))
        return score


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Module locator that maps text to module_tree.json")
    parser.add_argument("--docs", default="./docs", help="Docs directory containing module_tree.json")
    parser.add_argument("--module-tree", help="Explicit module_tree.json path (overrides --docs)")
    parser.add_argument("--trigger", help="Trigger text used in CVE/vulnerability contexts")
    parser.add_argument("--target", help="Primary class name or snippet to match")
    parser.add_argument("--repo", help="Repository or project name for prompt context")
    parser.add_argument("--cve", help="CVE identifier to inject into prompts")
    parser.add_argument("--filepath", help="File path associated with the trigger")
    parser.add_argument("--snippet-size", type=int, default=10, help="Number of modules to synthesize into the context snippet (-1 for all)")
    parser.add_argument("--output", help="Output path for JSON result (stdout if omitted)")
    parser.add_argument("--model", default=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"), help="LLM model name")
    parser.add_argument("--api-key", help="OpenAI/Anthropic API key (default uses OPENAI_API_KEY env)")
    parser.add_argument("--base-url", help="OpenAI-compatible base URL (default uses OPENAI_BASE_URL env)")

    args = parser.parse_args()
    if not args.trigger and not args.target:
        parser.error("At least one of --trigger or --target must be provided")
    return args


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    docs_path = Path(args.docs)
    tree_path = Path(args.module_tree) if args.module_tree else docs_path / "module_tree.json"
    locator = ModuleLocator(
        module_tree_path=tree_path,
        model=args.model,
        api_key=args.api_key,
        base_url=args.base_url,
        trigger=args.trigger,
        target=args.target,
        cve=args.cve,
        filepath=args.filepath,
        repo=args.repo,
        snippet_size=args.snippet_size,
    )
    result = locator.locate()
    output_json = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(output_json, encoding="utf-8")
    print(f"Output: {output_json}")

    component = result.get("component")
    module = result.get("module")

    print(f"component: {component}")
    print(f"module: {module}")


if __name__ == "__main__":
    main()
