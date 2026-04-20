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
import logging

logger = logging.getLogger(__name__)

# =========================
# 数据结构定义
# =========================

class SubFactor(BaseModel):
    label: str = Field(description="子因子标签，如：权限提升")
    score: float = Field(description="子因子分值（0~1）")


class Factor(BaseModel):
    score: float = Field(description="因子总分（等于所有子因子之和）")
    sub_factors: Dict[str, SubFactor] = Field(description="子因子结构化评分")
    details: str = Field(description="评分解释说明")

class RiskAssessmentResult(BaseModel):
    project_name: str = Field(description="项目名称")
    project_description: str = Field(description="项目描述")
    
    vul_name: str = Field(description="漏洞名称")
    vul_id: str = Field(description="漏洞编号")
    vul_cvss_score: str = Field(description="漏洞CVSS评分")
    vul_type: str = Field(description="漏洞类型")
    
    f_vuln: Factor
    f_threat: Factor
    f_business: Factor
    
    risk_level: str = Field(description="风险等级：高危/中危/低危")
    risk_assessment_process: str = Field(description="风险评估过程详细说明")


# =========================
# 校验逻辑
# =========================

def validate_factor(name: str, factor: Factor):
    # 严格要求新形态：factor 必须为 Factor（pydantic）对象或可被解析成 Factor。
    if not isinstance(factor, Factor):
        # 尝试解析 dict 到 Factor，便于 pydantic 反序列化场景
        if isinstance(factor, dict):
            try:
                factor = Factor.parse_obj(factor)
            except Exception:
                raise ValueError(f"{name} 必须为 Factor 格式，无法解析传入的 dict")
        else:
            raise ValueError(f"{name} 必须为 Factor 类型，收到 {type(factor)}")

    logging.info(f"Validating {name} with score {factor.score} and sub_factors {factor.sub_factors}")
    
    calc = sum(sf.score for sf in factor.sub_factors.values())
    if abs(calc - factor.score) > 0.01:
        raise ValueError(f"{name} 分数不一致: 声明={factor.score}, 实际={calc}")


def validate_result(result: RiskAssessmentResult):
    validate_factor("f_vuln", result.f_vuln)
    validate_factor("f_threat", result.f_threat)
    validate_factor("f_business", result.f_business)




# =========================
# 输出展示
# =========================

def print_factor(name: str, factor: Factor):
    logger.info(f"\n{name}: {factor.score:.2f}")

    for k, v in factor.sub_factors.items():
        logger.info(f"  - {k}: {v.label} ({v.score})")

    logger.info(f"  说明: {factor.details}")


def process_llm_response(result: RiskAssessmentResult):
    validate_result(result)

    
    logger.info("\n==============================")
    logger.info("漏洞风险评估结果")
    logger.info("==============================")

    logger.info(f"\n项目名称: {result.project_name}")
    logger.info(f"项目描述: {result.project_description}")

    logger.info(f"\n漏洞: {result.vul_name} ({result.vul_id})")
    logger.info(f"CVSS: {result.vul_cvss_score}")
    logger.info(f"类型: {result.vul_type}")

    print_factor("漏洞属性因子", result.f_vuln)
    print_factor("威胁情报因子", result.f_threat)
    print_factor("业务属性因子", result.f_business)

    logger.info(f"\n风险等级: {result.risk_level}")
    logger.info("\n评估过程:")
    logger.info(result.risk_assessment_process)


# =========================
# Prompt（保留格式化变量）
# =========================

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

请根据以上信息进行风险评估，并严格按照 JSON 格式输出。

【强制规则】
1. 每个评分因子必须包含：
   - score
   - sub_factors
   - details

2. sub_factors key 必须如下：

f_vuln:
- vuln_type
- reachability
- required_privilege
- exploit_complexity

f_threat:
- exploit_status
- intel_confidence
- patch_status
- related_threat_activity

f_business:
- system_criticality
- business_impact
- impact_scope

3. 每个子因子必须包含：
   - label
   - score（0~1）

4. 必须满足：
   score = 所有 sub_factors.score 之和

5. 禁止：
   - 缺失 sub_factors
   - 在 details 中写唯一分数
   - 输出额外字段
   - 输出非 JSON 内容

**[输出格式]**
{format_instructions}
"""


# =========================
# LLM 初始化
# =========================


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




def load_prompt(prompt_dir: Path, prompt_filename: str) -> str:
    if not prompt_dir.is_dir():
        raise FileNotFoundError(f"Prompt directory not found: {prompt_dir}")
    prompt_path = prompt_dir / prompt_filename
    if not prompt_path.is_file():
        raise FileNotFoundError(f"Prompt file not found: {prompt_path}")
    return prompt_path.read_text(encoding="utf-8")


def _clean_vul_name(name: Any) -> str:
    if not isinstance(name, str):
        return ""
    s = re.sub(r"（.*?）", "", name)
    s = re.sub(r"\(.*?\)", "", s)
    return s.strip()


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

    # 重试与确定性回退逻辑
    MAX_RETRIES = 3
    attempt = 1
    last_exception = None
    last_candidate = None
    risk_result = None

    while attempt <= MAX_RETRIES:
        try:
            if attempt == 1:
                logger.info("调用 LLM 风险评估（尝试 %d/%d）", attempt, MAX_RETRIES)
                candidate = risk_assessment_chain.invoke(assessment_input)
            else:
                # 构造修正提示并请求 LLM 返回修正后的 JSON（只含 JSON）
                logger.info("请求 LLM 对上次输出进行修正（尝试 %d/%d）", attempt, MAX_RETRIES)
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

            # 验证并展示
            process_llm_response(candidate)  # 包含 validate_result
            risk_result = candidate
            break

        except Exception as exc:
            logger.warning("尝试 %d 失败: %s", attempt, exc)
            last_exception = exc
            last_candidate = candidate
            attempt += 1

    if risk_result is None:
        logger.warning("达到重试上限，采用确定性回退（以子因子之和覆盖声明总分）并记录警告")
        # 解析最后一次候选为 dict
        if last_candidate is None:
            raise RuntimeError("未能从 LLM 获得任何候选结果")

        try:
            payload = last_candidate.dict() if hasattr(last_candidate, "dict") else last_candidate
        except Exception:
            # 无法转成 dict，则转字符串并抛错
            raise RuntimeError(f"无法解析最后一次 LLM 输出以用于回退: {last_candidate}")

        # 对每个因子按 sub_factors 之和修正 score
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

        # 尝试把 payload 解析为 RiskAssessmentResult
        try:
            risk_result = RiskAssessmentResult.parse_obj(payload)
        except Exception as exc:
            raise RuntimeError(f"回退后无法解析为 RiskAssessmentResult: {exc}")

        # 最终校验（此时应当通过）
        process_llm_response(risk_result)


if __name__ == "__main__":
    main()
