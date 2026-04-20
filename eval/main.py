#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Orchestrate module locating, summarization, and risk assessment.

Each stage writes a JSON payload under artifacts/:
  - artifacts/module_locator_result.json
  - artifacts/component_summary.json
  - artifacts/risk_assessment.json
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import ChatPromptTemplate

from src.component_module_summarizer import ModuleSummarizer
from src.module_locator import ModuleLocator
from src.risk_asssignment import (
    RISK_ASSESSMENT_HUMAN_PROMPT,
    RiskAssessmentResult,
    create_llm,
    load_business_factors,
    load_prompt,
    load_vulnerability_info,
    prepare_assessment_input,
    process_llm_response,
)

import logging

logger = logging.getLogger(__name__)

# 命名为当前时间
import datetime
OUTPUT_DIR_NAME = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
MODULE_LOCATOR_OUT = "module_locator_result.json"
COMPONENT_SUMMARY_OUT = "component_summary.json"
RISK_ASSESSMENT_OUT = "risk_assessment.json"


def build_output_dir(base: Path) -> Path:
    output_dir = base / OUTPUT_DIR_NAME
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def run_module_locator(
    module_tree_path: Path,
    docs_path: Path,
    trigger: Optional[str],
    target: Optional[str],
    repo: Optional[str],
    cve: Optional[str],
    filepath: Optional[str],
    snippet_size: int,
    model: str,
    api_key: Optional[str],
    base_url: Optional[str],
) -> Dict[str, Any]:
    locator = ModuleLocator(
        module_tree_path=module_tree_path,
        model=model,
        api_key=api_key,
        base_url=base_url,
        trigger=trigger,
        target=target,
        cve=cve,
        filepath=filepath,
        repo=repo,
        snippet_size=snippet_size,
    )
    result = locator.locate()
    return result


def run_component_summarizer(
    component: str,
    docs_dir: Path,
    model: str,
    api_key: Optional[str],
    base_url: Optional[str],
    language: str,
) -> Any:
    summarizer = ModuleSummarizer(
        docs_dir=str(docs_dir),
        model=model,
        api_key=api_key,
        base_url=base_url,
        language=language,
    )
    summary_text = summarizer.summarize_module(component)
    if not summary_text:
        raise RuntimeError(f"组件 {component} 没有对应的模块摘要。")
    try:
        return json.loads(summary_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError("模块摘要无法解析成 JSON") from exc


def run_risk_assessment(
    prompt_filename: str,
    cve_id: str,
    prompt_dir: Path,
    vulnerability_dir: Path,
    vulnerability_info: Optional[Dict[str, Any]],
    business_dir: Path,
    business_factors: Optional[Dict[str, Any]],
    excel_path: Path,
    reachability: Dict[str, str],
    model: str,
    api_key: str,
    api_base: Optional[str],
    verbose: bool,
) -> RiskAssessmentResult:
    prompt_text = load_prompt(prompt_dir, prompt_filename)
    if not vulnerability_info or not isinstance(vulnerability_info, dict):
        print("未提供有效的 vulnerability_info 参数，正在从目录中读取历史数据...")
        vulnerability_info = load_vulnerability_info(vulnerability_dir, cve_id, excel_path)
    if not business_factors or not isinstance(business_factors, dict):
        print("未提供有效的 business_factors 参数，正在从目录中读取历史数据...")
        business_factors = load_business_factors(business_dir, cve_id)

    chat_llm = create_llm(model, api_key, api_base, verbose, "cli", "cli", "cli")
    risk_assessment_parser = PydanticOutputParser(pydantic_object=RiskAssessmentResult)
    prompt_template = ChatPromptTemplate.from_messages([
        ("system", prompt_text),
        ("human", RISK_ASSESSMENT_HUMAN_PROMPT),
    ])
    risk_assessment_chain = prompt_template | chat_llm | risk_assessment_parser

    assessment_input = prepare_assessment_input(
        vulnerability_info,
        reachability,
        business_factors,
        risk_assessment_parser,
    )

    logging.info("输入数据已准备完成，开始风险评估...")
    logging.info("正在调用 LLM 进行风险评估，请稍候...")

    # 重试与确定性回退（以子因子之和覆盖声明总分）
    MAX_RETRIES = 3
    attempt = 1
    last_candidate = None
    last_exception = None

    while attempt <= MAX_RETRIES:
        try:
            if attempt == 1:
                print(f"调用 LLM 风险评估（尝试 {attempt}/{MAX_RETRIES}）")
                candidate = risk_assessment_chain.invoke(assessment_input)
            else:
                print(f"请求 LLM 对上次输出进行修正（尝试 {attempt}/{MAX_RETRIES}）")
                fix_instructions = (
                    "上次返回的 JSON 中存在因子 score 与其 sub_factors 之和不一致的问题。\n"
                    "请仅返回修正后的完整 JSON，确保每个 factor 包含 score/details/sub_factors，且 score 等于子因子之和。"
                    "不要输出额外文本。"
                )

                prev_str = None
                if last_candidate is not None:
                    try:
                        prev_str = last_candidate.json(ensure_ascii=False)
                    except Exception:
                        try:
                            prev_str = json.dumps(last_candidate, ensure_ascii=False)
                        except Exception:
                            prev_str = str(last_candidate)

                fix_prompt = ChatPromptTemplate.from_messages([
                    ("system", "请修正以下 JSON 输出中的不一致，并只输出修正后的 JSON，严格遵守 format_instructions。"),
                    ("human", "{previous_output}\n\n{fix_instructions}\n\n{format_instructions}"),
                ])
                fix_chain = fix_prompt | chat_llm | risk_assessment_parser
                candidate = fix_chain.invoke(
                    {
                        "previous_output": prev_str or "",
                        "fix_instructions": fix_instructions,
                        "format_instructions": risk_assessment_parser.get_format_instructions(),
                    }
                )

            # 验证并展示（包含 validate_result）
            process_llm_response(candidate)
            return candidate

        except Exception as exc:
            print(f"尝试 {attempt} 失败: {exc}")
            last_exception = exc
            last_candidate = candidate if 'candidate' in locals() else None
            attempt += 1

    # 达到重试上限，采用回退
    print("达到重试上限，采用确定性回退（以子因子之和覆盖声明总分）并记录警告")
    if last_candidate is None:
        raise RuntimeError("未能从 LLM 获得任何候选结果")

    try:
        payload = last_candidate.dict() if hasattr(last_candidate, "dict") else last_candidate
    except Exception:
        raise RuntimeError(f"无法解析最后一次 LLM 输出以用于回退: {last_candidate}")

    for fk in ("f_vuln", "f_threat", "f_business"):
        f = payload.get(fk)
        if isinstance(f, dict):
            sf = f.get("sub_factors") or {}
            total = 0.0
            for v in sf.values():
                if isinstance(v, dict):
                    total += float(v.get("score", 0))
                else:
                    total += float(getattr(v, "score", 0))
            f["score"] = total

    payload["_warning"] = "验证失败，已采用确定性回退：子因子之和覆盖声明总分（重试次数已达上限）"

    try:
        risk_result = RiskAssessmentResult.parse_obj(payload)
    except Exception as exc:
        raise RuntimeError(f"回退后无法解析为 RiskAssessmentResult: {exc}")

    process_llm_response(risk_result)
    return risk_result


def build_risk_payload(risk_result: RiskAssessmentResult) -> Dict[str, Any]:
    def factor_to_payload(factor: Factor) -> Dict[str, Any]:
        # factor is expected to be the new structured Factor (pydantic) with score/details/sub_factors
        sf_dict: Dict[str, Dict[str, float]] = {}
        for k, v in factor.sub_factors.items():
            sf_dict[k] = {"label": v.label, "score": v.score}
        return {"score": factor.score, "details": factor.details, "sub_factors": sf_dict}

    return {
        "project_name": risk_result.project_name,
        "project_description": risk_result.project_description,
        "vulnerability": {
            "vul_name": risk_result.vul_name,
            "vul_id": risk_result.vul_id,
            "vul_cvss_score": risk_result.vul_cvss_score,
            "vul_type": risk_result.vul_type,
        },
        "scoring_factors": {
            "f_vuln": factor_to_payload(risk_result.f_vuln),
            "f_threat": factor_to_payload(risk_result.f_threat),
            "f_business": factor_to_payload(risk_result.f_business),
        },
        "final_result": {
            "risk_level": risk_result.risk_level,
            "assessment_process": risk_result.risk_assessment_process,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="连接 module_locator、component_module_summarizer 与 risk_asssignment 的协同脚本")
    parser.add_argument("--docs", default="./docs", help="文档目录（包含 module_tree.json ）")
    parser.add_argument("--module-tree", help="显式 module_tree.json 路径，优先于 --docs")
    parser.add_argument("--trigger", help="Trigger 文本")
    parser.add_argument("--target", help="Target class 或关键字")
    parser.add_argument("--repo", help="仓库/项目名，用于提示词上下文")
    parser.add_argument("--cve", required=True, help="CVE 编号，用于 module locator 和 risk_assessment")
    parser.add_argument("--filepath", help="文件路径上下文")
    parser.add_argument("--snippet-size", type=int, default=10, help="module tree 上下文数量，-1 代表所有")
    parser.add_argument(
        "--model",
        default=os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    )
    parser.add_argument("--api-key", help="LLM API Key（module_locator + summarizer 默认使用）")
    parser.add_argument("--base-url", help="LLM Base URL（module_locator + summarizer 默认使用）")
    parser.add_argument("--component-lang", default="zh", choices=["zh", "en"], help="组件摘要语言")
    # risk_assessment 相关参数
    parser.add_argument("--prompt-dir", default=Path(__file__).resolve().parent / "final_result_system_prompt", help="risk_asssignment 的 prompt 文件路径")
    parser.add_argument("--prompt-filename", default="prompt2.md", help="risk_asssignment 的 prompt 文件名")
    parser.add_argument("--vulnerability-dir", default=Path(__file__).resolve().parent / "cve_data", help="漏洞数据目录")
    parser.add_argument("--business-dir", default=Path(__file__).resolve().parent / "cve_data", help="业务数据目录")
    parser.add_argument("--excel-path", default=Path(__file__).resolve().parent / "data_sort.xlsx", help="辅助 Excel 路径")
    parser.add_argument("--risk-verbose", action="store_true", help="开启后将输出风险评估阶段的模型配置信息便于调试")
    parser.add_argument("--output-dir", default=".", help="输出目录，默认当前目录")
    args = parser.parse_args()
    if not args.trigger and not args.target:
        parser.error("需要提供 --trigger 或 --target 中的至少一个")
    return args


def main() -> None:
    args = parse_args()
    output_dir = build_output_dir(Path(args.output_dir))

    module_tree_path = Path(args.module_tree) if args.module_tree else Path(args.docs or "./docs") / "module_tree.json"
    if not module_tree_path.is_file():
        raise FileNotFoundError(f"module_tree.json 未找到: {module_tree_path}")

    shared_api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
    shared_base_url = args.base_url or os.environ.get("OPENAI_BASE_URL")

    module_locator_result = run_module_locator(
        module_tree_path=module_tree_path,
        docs_path=Path(args.docs),
        trigger=args.trigger,
        target=args.target,
        repo=args.repo,
        cve=args.cve,
        filepath=args.filepath,
        snippet_size=args.snippet_size,
        model=args.model,
        api_key=shared_api_key,
        base_url=shared_base_url,
    )
    module_locator_path = output_dir / MODULE_LOCATOR_OUT
    module_locator_path.write_text(json.dumps(module_locator_result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Module locator result saved to {module_locator_path}")

    component = module_locator_result.get("component")
    if not component:
        raise RuntimeError("Module locator 未返回 component，无法继续执行 component_module_summarizer")

    component_summary = run_component_summarizer(
        component=component,
        docs_dir=Path(args.docs),
        model=args.model,
        api_key=shared_api_key,
        base_url=shared_base_url,
        language=args.component_lang,
    )
    component_summary_path = output_dir / COMPONENT_SUMMARY_OUT
    component_summary_path.write_text(json.dumps(component_summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Component summary saved to {component_summary_path}")

    print(type(component_summary), type(component_summary[0]))  # 调试输出，确认 component_summary 的结构

    # 更新 business_factors
    reachability_info = {"reachability": "可达"}
    risk_result = run_risk_assessment(
        prompt_filename=args.prompt_filename,
        cve_id=args.cve,
        prompt_dir=Path(args.prompt_dir),
        vulnerability_dir=Path(args.vulnerability_dir), 
        vulnerability_info=None, # TODO：从之前的步骤传递参数
        business_dir=Path(args.business_dir),
        business_factors=component_summary[0], # 优先使用当前传入的 component_summary 作为 business_factors
        excel_path=Path(args.excel_path),
        reachability=reachability_info,
        model=args.model,
        api_key=shared_api_key,
        api_base=shared_base_url,
        verbose=args.risk_verbose,
    )
    risk_payload = build_risk_payload(risk_result)
    risk_path = output_dir / RISK_ASSESSMENT_OUT
    risk_path.write_text(json.dumps(risk_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Risk assessment result saved to {risk_path}")


if __name__ == "__main__":
    main()