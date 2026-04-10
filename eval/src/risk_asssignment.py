import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Dict

import pandas as pd
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field


def print_nested(data: Any, indent: int = 0) -> None:
    prefix = "   " * indent

    if isinstance(data, dict):
        max_key_len = max(len(str(k)) for k in data.keys()) if data else 0

        for k, v in data.items():
            key_str = f"{k:<{max_key_len}}"

            if isinstance(v, dict):
                print(f"{prefix}{key_str}:")
                print_nested(v, indent + 1)
            elif isinstance(v, list):
                print(f"{prefix}{key_str}: [")
                print_nested(v, indent + 1)
                print(f"{prefix}{' ' * max_key_len}]")
            else:
                print(f"{prefix}{key_str}: {v}")

    elif isinstance(data, list):
        for item in data:
            print_nested(item, indent)

    else:
        print(f"{prefix}{data}")


def _clean_vul_name(name: Any) -> str:
    if not isinstance(name, str):
        return ""
    s = re.sub(r"（.*?）", "", name)
    s = re.sub(r"\(.*?\)", "", s)
    return s.strip()


def _extract_subfactor_scores(details: str, max_count: int | None = None) -> list[float]:
    """从 details 文本中提取各子因子分值列表。

    支持三种格式（优先级从高到低）：
    格式1(列表-分值): - 因子名称：xxx；分值 X.XX 或 分值=X.XX
    格式2(列表-括号): - 因子名称：标签（X.XX），说明（每行只取第一个括号值）
    格式3(散文-括号): 因子名称为标签（X.XX），... 无列表标记的散文，提取每个括号数值
    """
    # 格式1：列表行中含「分值 X.XX」或「分值=X.XX」
    line_scores: list[float] = []
    for line in details.splitlines():
        s = line.strip()
        if not (s.startswith("-") or s.startswith("*")):
            continue
        m = re.search(r"分值[=\s]+([0-9]+(?:\.[0-9]+)?)", s)
        if m:
            line_scores.append(float(m.group(1)))
    if line_scores:
        if max_count is not None and max_count > 0 and len(line_scores) > max_count:
            return line_scores[-max_count:]
        return line_scores

    # 格式2：列表行中含括号分值「（X.XX）」，每行只取第一个
    bracket_line_scores: list[float] = []
    for line in details.splitlines():
        s = line.strip()
        if not (s.startswith("-") or s.startswith("*")):
            continue
        m = re.search(r"[（(]([0-9]+(?:\.[0-9]+)?)[)）]", s)
        if m:
            bracket_line_scores.append(float(m.group(1)))
    if bracket_line_scores:
        if max_count is not None and max_count > 0 and len(bracket_line_scores) > max_count:
            return bracket_line_scores[-max_count:]
        return bracket_line_scores

    # 格式3：散文格式，按句号/逗号分割，每句只取第一个括号数值
    # 先按句子边界切分（。或换行），对每段提取第一个括号数值
    prose_scores: list[float] = []
    # 以「。」「\n」分句，也支持以「，」分割的情况（如「xxx（0.80），yyy（1.00）」）
    # 改用贪心策略：扫描文本，找到「为xxx（X.XX）」模式，提取每个「为/选/是」后的括号分值
    sentence_iter = re.finditer(
        r"(?:为|选|是)[^。\n（(]{0,20}[（(]([0-9]+(?:\.[0-9]+)?)[)）]",
        details,
    )
    for m in sentence_iter:
        prose_scores.append(float(m.group(1)))
    if prose_scores:
        if max_count is not None and max_count > 0 and len(prose_scores) > max_count:
            return prose_scores[-max_count:]
        return prose_scores

    # fallback：全文所有括号数值（去掉综合/总体得分行）
    clean = re.sub(r"综合得分[^。\n]*。?", "", details)
    clean = re.sub(r"总体得分[^。\n]*。?", "", clean)
    matches = re.findall(r"[（(]([0-9]+(?:\.[0-9]+)?)[)）]", clean)
    scores = [float(m) for m in matches]
    if max_count is not None and max_count > 0 and len(scores) > max_count:
        return scores[-max_count:]
    return scores


# 子因子 key 映射表
_VULN_SUBFACTOR_KEYS = ["vuln_type", "reachability", "required_privilege", "exploit_complexity"]
_THREAT_SUBFACTOR_KEYS = ["exploit_status", "intel_confidence", "patch_status", "related_threat_activity"]
_BUSINESS_SUBFACTOR_KEYS = ["system_criticality", "business_impact", "impact_scope"]


def _extract_sub_factors(details: str, keys: list[str]) -> dict:
    """从 details 文本中按行提取子因子标签和分值，返回结构化字典。

    支持多种 LLM 输出格式：
    1. (列表-分值) - 因子名称：标签；分值 X.XX。判断依据：...
    2. (列表-档位) - 因子名称：xxx；档位=标签，分值=X.XX。
    3. (列表-括号) - 因子名称：标签（X.XX），补充说明。
    4. (散文-括号) 因子名称为标签（X.XX），补充说明。（无列表行前缀）
    """
    result = {}
    entries = []

    # --- 先尝试列表格式（- 或 * 开头的行）---
    for line in details.splitlines():
        stripped = line.strip()
        if not (stripped.startswith("-") or stripped.startswith("*")):
            continue

        # 提取分值
        score_match = re.search(r"分值[=\s]+([0-9]+(?:\.[0-9]+)?)", stripped)
        use_bracket = False
        if not score_match:
            score_match = re.search(r"[（(]([0-9]+(?:\.[0-9]+)?)[)）]", stripped)
            use_bracket = score_match is not None
        if not score_match:
            continue
        score = float(score_match.group(1))

        # 提取标签
        tier_match = re.search(r"档位[=\s]*([^，,；;。\n\uff08(]+)", stripped)
        if tier_match:
            label = tier_match.group(1).strip()
        elif use_bracket:
            colon_match = re.search(r"[\uff1a:]\s*([^\uff08(\n]+?)[\uff08(]", stripped)
            label = colon_match.group(1).strip().rstrip("，,") if colon_match else ""
        else:
            colon_match = re.search(r"[\uff1a:]\s*([^\uff1b;\n]+)[\uff1b;]", stripped)
            label = colon_match.group(1).strip().rstrip("，,") if colon_match else ""
        entries.append((label, score))

    # --- 若列表格式未命中，改用散文格式（按「为/选/是」关键词定位）---
    if not entries:
        # 策略：按「。」或「\n」将散文分句，从每句中提取「标签（X.XX）」
        # 每句只取第一个「xxx（X.XX）」，其中 xxx 为紧接括号前的非括号短文本
        sentences = re.split(r"[。\n]", details)
        for sent in sentences:
            sent = sent.strip()
            if not sent:
                continue
            # 跳过汇总句（综合得分/总体得分等）
            if re.search(r"综合得分|总体得分", sent):
                continue
            # 在每句中找第一个「(X.XX)」
            m_score = re.search(r"[（(]([0-9]+(?:\.[0-9]+)?)[)）]", sent)
            if not m_score:
                continue
            score = float(m_score.group(1))
            # 取括号前紧邻的非括号文本（最多20字）作为标签
            before = sent[:m_score.start()]
            # 去掉冒号及之前的因子名称前缀，只保留最后一段
            label_match = re.search(r"(?:为|是|选择?)[^，,、为是选（(]{0,20}$", before)
            if label_match:
                # 去掉「为/是/选/选择」前导词
                raw = label_match.group(0)
                raw = re.sub(r"^(?:为|是|选择?)", "", raw)
                label = raw.strip().strip("，,")
            else:
                # fallback：取最后一段非标点文本
                label = re.sub(r".*[，,、]", "", before).strip()
            entries.append((label, score))

    for i, (label, score) in enumerate(entries):
        key = keys[i] if i < len(keys) else f"sub_factor_{i}"
        result[key] = {"label": label, "score": score}
    return result


def _update_factor_total(details: str, total: float) -> str:
    pattern = r"(总体得分为)\s*[0-9]+(?:\.[0-9]+)?"

    def _repl(match: re.Match) -> str:
        prefix = match.group(1)
        return f"{prefix}{total:.1f}"

    updated = re.sub(pattern, _repl, details)
    if updated != details:
        return updated
    if total <= 0:
        return details
    base = details.rstrip()
    if base and not base.endswith("。"):
        base += "。"
    return f"{base}\n总体得分为{total:.1f}。"


def _update_summary_scores(process: str, f_vuln: float, f_threat: float, f_business: float) -> str:
    def _repl(pattern: str, text: str, value: float) -> str:
        return re.sub(
            pattern,
            lambda m: f"{m.group(1)}{value:.1f}",
            text,
        )

    process = _repl(r"(漏洞属性因子（FVuln）得分为)\s*[0-9]+(?:\.[0-9]+)?", process, f_vuln)
    process = _repl(r"(威胁情报因子（FThreat）得分为)\s*[0-9]+(?:\.[0-9]+)?", process, f_threat)
    process = _repl(r"(业务属性因子（FBusiness）得分为)\s*[0-9]+(?:\.[0-9]+)?", process, f_business)
    return process


def load_prompt(prompt_dir: Path, prompt_filename: str) -> str:
    if not prompt_dir.is_dir():
        raise FileNotFoundError(f"Prompt directory not found: {prompt_dir}")
    prompt_path = prompt_dir / prompt_filename
    if not prompt_path.is_file():
        raise FileNotFoundError(f"Prompt file not found: {prompt_path}")
    return prompt_path.read_text(encoding="utf-8")


def load_vulnerability_info(vul_dir: Path, cve_id: str, excel_path: Path) -> Dict[str, Any]:
    info_path = vul_dir / "vulnerability_info" / f"{cve_id}.normalized.json"
    if not info_path.is_file():
        raise FileNotFoundError(f"Vulnerability info missing: {info_path}")

    with open(info_path, "r", encoding="utf-8") as f:
        raw_vul = json.load(f)

    base_info = raw_vul.get("漏洞基础信息", {})
    risk_eval = raw_vul.get("漏洞风险评估", {})
    risk_sources = risk_eval.get("来源明细", {})
    ti_info = raw_vul.get("威胁情报相关", {})

    vul_name = _clean_vul_name(base_info.get("中文名称", ""))
    vul_id = base_info.get("CVE编号", "")

    cvss3 = risk_sources.get("cvss3", "")
    vul_cvss_score = ""
    if isinstance(cvss3, str) and cvss3.strip():
        vul_cvss_score = cvss3.strip().split()[0]

    vul_type_value = base_info.get("威胁类型", "")
    if isinstance(vul_type_value, list) and vul_type_value:
        vul_type = str(vul_type_value[0])
    elif isinstance(vul_type_value, str):
        vul_type = vul_type_value
    else:
        vul_type = ""

    cwe_type = ""
    if excel_path.is_file():
        try:
            df = pd.read_excel(excel_path, sheet_name="原始数据表")
            if "cve编号" in df.columns and "cwe编号" in df.columns and vul_id:
                row = df.loc[df["cve编号"] == vul_id]
                if not row.empty:
                    value = row["cwe编号"].iloc[0]
                    cwe_type = "" if pd.isna(value) else str(value)
        except Exception:
            cwe_type = ""

    vul_risk = base_info.get("触发场景", "")
    vul_fix_suggestion = ti_info.get("修复方案", "")
    vul_reason = base_info.get("漏洞描述", "")
    vul_trigger_condition = base_info.get("触发条件", "")
    vul_patch_available = bool(ti_info.get("补丁"))
    poc_field = ti_info.get("POC/EXP", "")
    vul_poc_available = isinstance(poc_field, str) and poc_field.strip() == "有"

    return {
        "vul_name": vul_name,
        "vul_id": vul_id,
        "vul_cvss_score": vul_cvss_score,
        "vul_type": vul_type,
        "vul_cwe_type": cwe_type,
        "vul_risk": vul_risk,
        "vul_fix_suggestion": vul_fix_suggestion,
        "vul_reason": vul_reason,
        "vul_trigger_condition": vul_trigger_condition,
        "vul_patch_available": vul_patch_available,
        "vul_poc_available": vul_poc_available,
    }


def load_business_factors(business_dir: Path, cve_id: str) -> Dict[str, Any]:
    business_path = business_dir / "business_factors" / f"{cve_id}.business.json"
    if not business_path.is_file():
        raise FileNotFoundError(f"Business factors file missing: {business_path}")

    with open(business_path, "r", encoding="utf-8") as f:
        raw_business = json.load(f)

    if isinstance(raw_business, list) and raw_business:
        return raw_business[0]
    return raw_business


def prepare_assessment_input(
    vulnerability_info: Dict[str, Any],
    reachability_info: Dict[str, str],
    business_factors: Dict[str, Any],
    parser: PydanticOutputParser,
) -> Dict[str, Any]:
    return {
        "vul_name": vulnerability_info["vul_name"],
        "vul_id": vulnerability_info["vul_id"],
        "vul_cvss_score": vulnerability_info["vul_cvss_score"],
        "vul_type": vulnerability_info["vul_type"],
        "vul_risk": vulnerability_info["vul_risk"],
        "vul_reason": vulnerability_info["vul_reason"],
        "vul_trigger_condition": vulnerability_info["vul_trigger_condition"],
        "vul_patch_available": "是" if vulnerability_info["vul_patch_available"] else "否",
        "vul_poc_available": "是" if vulnerability_info["vul_poc_available"] else "否",
        "vul_fix_suggestion": vulnerability_info["vul_fix_suggestion"],
        "reachability_info": f"可达性状态: {reachability_info['reachability']}",
        "project_name": business_factors["project"]["name"],
        "project_overall_role": business_factors["project"]["overall_role"],
        "project_description": business_factors["project"]["description"],
        "business_importance_analysis": business_factors["project"]["business_importance_analysis"],
        "data_sensitivity_analysis": business_factors["project"]["data_sensitivity_analysis"],
        "exposure_analysis": business_factors["project"]["exposure_analysis"],
        "component_name": business_factors["component"]["name"],
        "component_role": business_factors["component"]["role_in_project"],
        "component_importance": business_factors["component"]["importance_analysis"],
        "component_data_sensitivity": business_factors["component"]["data_sensitivity_analysis"],
        "component_attack_surface": business_factors["component"]["attack_surface_analysis"],
        "service_availability": business_factors["component"]["impact_analysis"]["service_availability"],
        "data_security": business_factors["component"]["impact_analysis"]["data_security"],
        "compliance_impact": business_factors["component"]["impact_analysis"]["compliance_impact"],
        "format_instructions": parser.get_format_instructions(),
    }


def process_llm_response(risk_result: "RiskAssessmentResult") -> None:
    risk_result.vul_name = _clean_vul_name(risk_result.vul_name)

    vuln_scores = _extract_subfactor_scores(risk_result.f_vuln_details, max_count=4)
    threat_scores = _extract_subfactor_scores(risk_result.f_threat_details, max_count=4)
    business_scores = _extract_subfactor_scores(risk_result.f_business_details, max_count=3)

    f_vuln_score = sum(vuln_scores) if vuln_scores else 0.0
    f_threat_score = sum(threat_scores) if threat_scores else 0.0
    f_business_score = sum(business_scores) if business_scores else 0.0

    risk_result.f_vuln = f_vuln_score
    risk_result.f_threat = f_threat_score
    risk_result.f_business = f_business_score

    risk_result.f_vuln_details = _update_factor_total(risk_result.f_vuln_details, f_vuln_score)
    risk_result.f_threat_details = _update_factor_total(risk_result.f_threat_details, f_threat_score)
    risk_result.f_business_details = _update_factor_total(risk_result.f_business_details, f_business_score)

    risk_result.risk_assessment_process = _update_summary_scores(
        risk_result.risk_assessment_process,
        f_vuln_score,
        f_threat_score,
        f_business_score,
    )

    print("风险评估完成！\n")
    print("=" * 80)
    print("漏洞风险评估结果")
    print("=" * 80)
    print(f"\n项目名称: {risk_result.project_name}")
    print(f"项目描述: {risk_result.project_description}")
    print(f"\n漏洞信息:")
    print(f"  漏洞名称: {risk_result.vul_name}")
    print(f"  漏洞编号: {risk_result.vul_id}")
    print(f"  CVSS评分: {risk_result.vul_cvss_score}")
    print(f"  漏洞类型: {risk_result.vul_type}")

    print(f"\n评分因子:")
    print(f"  漏洞属性因子 (FVuln): {risk_result.f_vuln:.2f}")
    print(f"    详细说明: {risk_result.f_vuln_details}")
    print(f"\n  威胁情报因子 (FThreat): {risk_result.f_threat:.2f}")
    print(f"    详细说明: {risk_result.f_threat_details}")
    print(f"\n  业务属性因子 (FBusiness): {risk_result.f_business:.2f}")
    print(f"    详细说明: {risk_result.f_business_details}")

    print(f"\n最终评估结果:")
    print(f"  风险等级: {risk_result.risk_level}")
    print(f"\n  评估过程:")
    print(f"    {risk_result.risk_assessment_process}")

    print("=" * 80)
    print("\n" + "=" * 80)
    print("结构化风险评估结果")
    print("=" * 80)

    result_dict = {
        "project_name": risk_result.project_name,
        "project_description": risk_result.project_description,
        "vulnerability": {
            "vul_name": risk_result.vul_name,
            "vul_id": risk_result.vul_id,
            "vul_cvss_score": risk_result.vul_cvss_score,
            "vul_type": risk_result.vul_type,
        },
        "scoring_factors": {
            "fvuln": {
                "score": risk_result.f_vuln,
                "sub_factors": _extract_sub_factors(risk_result.f_vuln_details, _VULN_SUBFACTOR_KEYS),
            },
            "fthreat": {
                "score": risk_result.f_threat,
                "sub_factors": _extract_sub_factors(risk_result.f_threat_details, _THREAT_SUBFACTOR_KEYS),
            },
            "fbusiness": {
                "score": risk_result.f_business,
                "sub_factors": _extract_sub_factors(risk_result.f_business_details, _BUSINESS_SUBFACTOR_KEYS),
            },
        },
        "final_result": {
            "risk_level": risk_result.risk_level,
        },
    }

    print_nested(result_dict)


class RiskAssessmentResult(BaseModel):
    project_name: str = Field(description="项目名称")
    project_description: str = Field(description="项目描述")
    vul_name: str = Field(description="漏洞名称")
    vul_id: str = Field(description="漏洞编号")
    vul_cvss_score: str = Field(description="漏洞CVSS评分")
    vul_type: str = Field(description="漏洞类型")
    f_vuln: float = Field(description="漏洞属性因子得分（子因子之和）")
    f_threat: float = Field(description="威胁情报因子得分（子因子之和）")
    f_business: float = Field(description="业务属性因子得分（子因子之和）")
    f_vuln_details: str = Field(description="漏洞属性因子详细评分说明")
    f_threat_details: str = Field(description="威胁情报因子详细评分说明")
    f_business_details: str = Field(description="业务属性因子详细评分说明")
    risk_level: str = Field(description="风险等级：高危/中危/低危")
    risk_assessment_process: str = Field(description="风险评估过程详细说明")


RISK_ASSESSMENT_HUMAN_PROMPT = """
**漏洞信息**
漏洞名称: {vul_name}
漏洞编号: {vul_id}
漏洞CVSS评分: {vul_cvss_score}
漏洞类型: {vul_type}

漏洞风险描述: {vul_risk}
漏洞产生原因: {vul_reason}
漏洞触发条件: {vul_trigger_condition}
是否存在补丁: {vul_patch_available}
是否存在POC: {vul_poc_available}
漏洞修复建议: {vul_fix_suggestion}

**可达性分析**
{reachability_info}

**项目业务信息**
项目名称: {project_name}
项目整体角色: {project_overall_role}
项目描述: {project_description}
业务重要性分析: {business_importance_analysis}
数据敏感性分析: {data_sensitivity_analysis}
暴露面分析: {exposure_analysis}

**组件信息**
组件名称: {component_name}
组件在项目中的角色: {component_role}
组件重要性分析: {component_importance}
组件数据敏感性分析: {component_data_sensitivity}
组件攻击面分析: {component_attack_surface}
组件影响分析:
  - 服务可用性: {service_availability}
  - 数据安全: {data_security}
  - 合规影响: {compliance_impact}

请根据以上信息，按照评分规则进行全面的风险评估。

**[输出格式]**
{format_instructions}
"""


def parse_args(script_dir: Path) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "基于风险评估系统提示词和 CVE 元数据执行漏洞风险评估。"
            "prompt 文件默认放在 src/final_result_system_prompt/ 下，CVE 数据位于 src/cve_data/ 的相关子目录。"
        )
    )
    parser.add_argument("prompt_filename", help="Prompt 文件名（在 prompt-dir 中查找，例如 prompt1.md）")
    parser.add_argument("cve_id", help="CVE 编号（用于加载 cve_data/{vulnerability,business}/{cve}.json）")
    parser.add_argument(
        "--prompt-dir",
        dest="prompt_dir",
        default=None,
        help="Prompt 目录，默认 src/final_result_system_prompt",
    )
    parser.add_argument(
        "--vulnerability-dir",
        dest="vulnerability_dir",
        default=None,
        help="漏洞数据根目录，默认 src/cve_data",
    )
    parser.add_argument(
        "--business-dir",
        dest="business_dir",
        default=None,
        help="业务数据根目录，默认 src/cve_data",
    )
    parser.add_argument(
        "--excel-path",
        dest="excel_path",
        default=None,
        help="辅助的 data_sort.xlsx 路径，用于查找 CWE，默认 src/data_sort.xlsx",
    )
    parser.add_argument(
        "--model",
        dest="model",
        default=None,
        help="LLM 模型名称，默认读取 OPENAI_MODEL 或 gpt-4",
    )
    parser.add_argument(
        "--api-key",
        dest="api_key",
        default=None,
        help="OpenAI API Key（默认读取 OPENAI_API_KEY）",
    )
    parser.add_argument(
        "--api-base",
        dest="api_base",
        default=None,
        help="OpenAI 兼容 Base URL（默认读取 OPENAI_API_BASE）",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="启用详细信息输出，用于查看已解析的 LLM 配置来源",
    )

    args = parser.parse_args()

    args.prompt_dir = Path(args.prompt_dir) if args.prompt_dir else script_dir / "final_result_system_prompt"
    args.vulnerability_dir = (
        Path(args.vulnerability_dir) if args.vulnerability_dir else script_dir / "cve_data"
    )
    args.business_dir = Path(args.business_dir) if args.business_dir else script_dir / "cve_data"
    args.excel_path = Path(args.excel_path) if args.excel_path else script_dir / "data_sort.xlsx"

    if not args.prompt_dir.is_dir():
        parser.error(f"Prompt 目录不存在: {args.prompt_dir}")
    if not args.vulnerability_dir.is_dir():
        parser.error(f"漏洞数据目录不存在: {args.vulnerability_dir}")
    if not args.business_dir.is_dir():
        parser.error(f"业务数据目录不存在: {args.business_dir}")
    if not args.excel_path.is_file():
        parser.error(f"辅助 Excel 文件不存在: {args.excel_path}")

    return args


def create_llm(
    model: str,
    api_key: str,
    api_base: str | None,
    verbose: bool,
    api_key_source: str,
    api_base_source: str,
    model_source: str,
) -> ChatOpenAI:
    if verbose:
        base_desc = f"{api_base} ({api_base_source})" if api_base else f"默认 OpenAI Base ({api_base_source})"
        print(
            "[Verbose] 使用 LLM 配置：",
            f"model={model} ({model_source})",
            f"api_key source={api_key_source}",
            f"api_base={base_desc}",
        )

    return ChatOpenAI(
        model=model,
        temperature=0,
        max_tokens=None,
        api_key=api_key,
        base_url=api_base,
    )


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    args = parse_args(script_dir)

    prompt_text = load_prompt(args.prompt_dir, args.prompt_filename)
    vulnerability_info = load_vulnerability_info(args.vulnerability_dir, args.cve_id, args.excel_path)
    business_factors = load_business_factors(args.business_dir, args.cve_id)
    reachability_analysis = {"reachability": "可达"}

    print_nested(vulnerability_info)
    print_nested(reachability_analysis)
    print_nested(business_factors)

    model_env = os.environ.get("OPENAI_MODEL")
    model = args.model or model_env or "gpt-4"
    model_source = "cli" if args.model else ("env" if model_env else "default gpt-4")

    api_key_env = os.environ.get("OPENAI_API_KEY")
    api_key = args.api_key or api_key_env
    api_key_source = "cli" if args.api_key else ("env" if api_key_env else "missing")

    api_base_env = os.environ.get("OPENAI_API_BASE")
    api_base = args.api_base or api_base_env
    api_base_source = "cli" if args.api_base else ("env" if api_base_env else "default")

    if not api_key:
        raise RuntimeError("缺少 OpenAI API Key，请通过 --api-key 或环境变量 OPENAI_API_KEY 提供")

    chat_llm = create_llm(model, api_key, api_base, args.verbose, api_key_source, api_base_source, model_source)

    risk_assessment_parser = PydanticOutputParser(pydantic_object=RiskAssessmentResult)
    human_prompt = ChatPromptTemplate.from_messages([
        ("system", prompt_text),
        ("human", RISK_ASSESSMENT_HUMAN_PROMPT),
    ])
    risk_assessment_chain = human_prompt | chat_llm | risk_assessment_parser

    assessment_input = prepare_assessment_input(
        vulnerability_info,
        reachability_analysis,
        business_factors,
        risk_assessment_parser,
    )

    print("输入数据已准备完成，开始风险评估...")
    print("正在调用 LLM 进行风险评估，请稍候...")
    risk_result = risk_assessment_chain.invoke(assessment_input)
    process_llm_response(risk_result)


if __name__ == "__main__":
    main()
