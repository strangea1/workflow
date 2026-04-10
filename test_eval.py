#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
独立测试脚本：跳过 module_locator / component_summarizer 前置流程，
直接使用 workflow_output/eval_runs 中已有的中间结果（business_factors JSON）
以及 eval/cve_data/vulnerability_info 中的漏洞数据，直接运行 risk_assessment。

输出结果写入 workflow_output/eval_runs/<project>/<version>/<cve_id>/risk_assessment.json
同时将完整 JSON payload 写入 workflow_output/test_eval_result.json 便于汇总查看。

用法示例（在 workflow 目录下执行）：
    python test_eval.py --cve CVE-2025-32434 --business eval/cve_data/business_factors/CVE-2025-41249.business.json
    python test_eval.py --cve CVE-2025-41249
    python test_eval.py --list-cves          # 列出 eval/cve_data 中可用的 CVE
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# ---- 把 eval/ 加入 sys.path，使 eval/src 下的模块可直接 import ----
EVAL_DIR = Path(__file__).resolve().parent / "eval"
sys.path.insert(0, str(EVAL_DIR))

from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import ChatPromptTemplate

from src.risk_asssignment import (
    RISK_ASSESSMENT_HUMAN_PROMPT,
    RiskAssessmentResult,
    _BUSINESS_SUBFACTOR_KEYS,
    _THREAT_SUBFACTOR_KEYS,
    _VULN_SUBFACTOR_KEYS,
    _extract_sub_factors,
    create_llm,
    load_business_factors,
    load_prompt,
    load_vulnerability_info,
    prepare_assessment_input,
    process_llm_response,
)

WORKFLOW_OUTPUT = Path(__file__).resolve().parent / "workflow_output"
EVAL_CVE_DATA = EVAL_DIR / "cve_data"
EVAL_PROMPT_DIR = EVAL_DIR / "final_result_system_prompt"
EVAL_EXCEL = EVAL_DIR / "data_sort.xlsx"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def list_available_cves() -> None:
    vul_dir = EVAL_CVE_DATA / "vulnerability_info"
    biz_dir = EVAL_CVE_DATA / "business_factors"
    vul_ids = {p.name.replace(".normalized.json", "") for p in vul_dir.glob("CVE-*.normalized.json")}
    biz_ids = {p.name.replace(".business.json", "") for p in biz_dir.glob("CVE-*.business.json")}
    both = vul_ids & biz_ids
    only_vul = vul_ids - biz_ids
    only_biz = biz_ids - vul_ids

    print("=" * 60)
    print("可用 CVE（漏洞信息 + 业务因子 均有）:")
    for c in sorted(both):
        print(f"  {c}")
    if only_vul:
        print("\n仅有漏洞信息（缺少业务因子）:")
        for c in sorted(only_vul):
            print(f"  {c}")
    if only_biz:
        print("\n仅有业务因子（缺少漏洞信息）:")
        for c in sorted(only_biz):
            print(f"  {c}")
    print("=" * 60)


def build_risk_payload(risk_result: RiskAssessmentResult) -> dict:
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
            "f_vuln": {
                "score": risk_result.f_vuln,
                "details": risk_result.f_vuln_details,
                "sub_factors": _extract_sub_factors(risk_result.f_vuln_details, _VULN_SUBFACTOR_KEYS),
            },
            "f_threat": {
                "score": risk_result.f_threat,
                "details": risk_result.f_threat_details,
                "sub_factors": _extract_sub_factors(risk_result.f_threat_details, _THREAT_SUBFACTOR_KEYS),
            },
            "f_business": {
                "score": risk_result.f_business,
                "details": risk_result.f_business_details,
                "sub_factors": _extract_sub_factors(risk_result.f_business_details, _BUSINESS_SUBFACTOR_KEYS),
            },
        },
        "final_result": {
            "risk_level": risk_result.risk_level,
            "assessment_process": risk_result.risk_assessment_process,
        },
    }


# ---------------------------------------------------------------------------
# main logic
# ---------------------------------------------------------------------------

def run_eval(
    cve_id: str,
    business_json: Path | None,
    prompt_filename: str,
    reachability: str,
    model: str,
    api_key: str,
    api_base: str | None,
    verbose: bool,
    output_dir: Path,
) -> dict:
    # 1. 加载 prompt
    prompt_text = load_prompt(EVAL_PROMPT_DIR, prompt_filename)
    print(f"[✓] Prompt 加载完成: {EVAL_PROMPT_DIR / prompt_filename}")

    # 2. 加载漏洞信息
    vulnerability_info = load_vulnerability_info(EVAL_CVE_DATA, cve_id, EVAL_EXCEL)
    print(f"[✓] 漏洞信息加载完成: {cve_id}")

    # 3. 加载业务因子
    if business_json is not None:
        with open(business_json, "r", encoding="utf-8") as f:
            raw = json.load(f)
        business_factors = raw[0] if isinstance(raw, list) and raw else raw
        print(f"[✓] 业务因子加载完成（自定义文件）: {business_json}")
    else:
        business_factors = load_business_factors(EVAL_CVE_DATA, cve_id)
        print(f"[✓] 业务因子加载完成（eval/cve_data）: {cve_id}")

    # 4. 构建 LLM & chain
    llm = create_llm(model, api_key, api_base, verbose, "env", "env", "env")
    parser = PydanticOutputParser(pydantic_object=RiskAssessmentResult)
    prompt_template = ChatPromptTemplate.from_messages([
        ("system", prompt_text),
        ("human", RISK_ASSESSMENT_HUMAN_PROMPT),
    ])
    chain = prompt_template | llm | parser

    reachability_info = {"reachability": reachability}
    assessment_input = prepare_assessment_input(
        vulnerability_info,
        reachability_info,
        business_factors,
        parser,
    )

    print(f"\n[→] 正在调用 LLM 进行风险评估，请稍候...")
    risk_result = chain.invoke(assessment_input)
    process_llm_response(risk_result)

    # 5. 构建并保存输出
    payload = build_risk_payload(risk_result)

    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / f"{cve_id}_risk_assessment.json"
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[✓] 结果已保存: {out_path}")

    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="直接测试 eval risk_assessment 模块（跳过前置流程）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--list-cves", action="store_true",
        help="列出 eval/cve_data 中可用的 CVE 编号后退出",
    )
    parser.add_argument(
        "--cve", default=None,
        help="CVE 编号，例如 CVE-2025-41249",
    )
    parser.add_argument(
        "--business", default=None,
        help="自定义 business_factors JSON 文件路径（不指定则从 eval/cve_data/business_factors/ 自动读取）",
    )
    parser.add_argument(
        "--prompt", default="prompt2.md",
        help="Prompt 文件名（位于 eval/final_result_system_prompt/），默认 prompt2.md",
    )
    parser.add_argument(
        "--reachability", default="可达",
        help="可达性状态（默认：可达）",
    )
    parser.add_argument(
        "--model", default=None,
        help="LLM 模型名，默认读取 OPENAI_MODEL 或 gpt-4o-mini",
    )
    parser.add_argument(
        "--api-key", default=None, dest="api_key",
        help="API Key，默认读取 OPENAI_API_KEY 环境变量",
    )
    parser.add_argument(
        "--api-base", default=None, dest="api_base",
        help="API Base URL，默认读取 OPENAI_API_BASE 环境变量",
    )
    parser.add_argument(
        "--output-dir", default=None, dest="output_dir",
        help="结果输出目录，默认 workflow_output/test_eval_results/",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="显示 LLM 配置详细信息",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.list_cves:
        list_available_cves()
        return

    if not args.cve:
        print("[错误] 请通过 --cve 指定 CVE 编号，或使用 --list-cves 查看可用 CVE。")
        sys.exit(1)

    model = args.model or os.environ.get("OPENAI_MODEL") or "gpt-4o-mini"
    api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
    api_base = args.api_base or os.environ.get("OPENAI_API_BASE")

    if not api_key:
        print("[错误] 缺少 API Key，请通过 --api-key 或环境变量 OPENAI_API_KEY 提供。")
        sys.exit(1)

    output_dir = (
        Path(args.output_dir)
        if args.output_dir
        else WORKFLOW_OUTPUT / "test_eval_results"
    )

    business_json = Path(args.business) if args.business else None

    print("=" * 60)
    print(f"CVE        : {args.cve}")
    print(f"Prompt     : {args.prompt}")
    print(f"Model      : {model}")
    print(f"Reachability: {args.reachability}")
    print(f"Output Dir : {output_dir}")
    print("=" * 60)

    run_eval(
        cve_id=args.cve,
        business_json=business_json,
        prompt_filename=args.prompt,
        reachability=args.reachability,
        model=model,
        api_key=api_key,
        api_base=api_base,
        verbose=args.verbose,
        output_dir=output_dir,
    )


if __name__ == "__main__":
    main()
