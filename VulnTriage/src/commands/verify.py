import json
import logging
import os
from datetime import datetime
from pathlib import Path

from verify.agent import ExploitabilityVerificationAgent


def _verify_result_path(args) -> str:
    raw = getattr(args, "out", None)
    if not raw:
        os.makedirs("out", exist_ok=True)
        raw = os.path.join("out", "verify_verdict.json")
    p = Path(raw)
    if p.is_absolute():
        return str(p.resolve())
    return str((Path.cwd() / p).resolve())


def run(args):
    logging.info(
        "verify_start repo=%s traces=%s bundle=%s recon=%s poc=%s dynamic=%s agent_mode=%s",
        args.repo,
        args.traces,
        getattr(args, "bundle", None),
        getattr(args, "recon", None),
        getattr(args, "poc", None),
        getattr(args, "dynamic", False),
        getattr(args, "agent_mode", "langchain"),
    )

    verdict_path = _verify_result_path(args)
    Path(verdict_path).parent.mkdir(parents=True, exist_ok=True)

    bundle = getattr(args, "bundle", None) or ""
    recon = getattr(args, "recon", None) or ""
    poc = getattr(args, "poc", None) or None
    agent_mode = getattr(args, "agent_mode", "langchain")

    user_input = (
        f"Verify exploitability for the target repository using the trace/find output. "
        f"Traces file: {args.traces}. "
        f"Use vulnerability materials from bundle directory when provided. "
        f"Use recon index when provided for symbol/route cross-check."
    )

    agent = ExploitabilityVerificationAgent()
    result = agent.run(
        user_input=user_input,
        vuln_dir=bundle,
        project_dir=args.repo,
        recon_file=recon,
        traces_file=args.traces,
        poc_path=poc,
        verbose=False,
        mode=agent_mode,
        output_path=verdict_path,
    )

    try:
        out_dir = os.path.dirname(verdict_path)
        os.makedirs(out_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(out_dir, f".verify_full_{ts}.json")
        with open(backup_file, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2, default=str)
        logging.info("verify_backup full_result=%s", backup_file)
    except Exception as e:
        logging.warning("verify_backup_failed %s", e)

    agent_mode = result.get("mode", "langchain")
    log_file = ""
    if agent_mode in ("codex", "opencode"):
        log_file = result.get("output", {}).get("log_file", "")

    try:
        with open(verdict_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("root JSON value is not an object")
        if "verdict" not in data:
            raise ValueError("missing 'verdict' field")
        if "reason" not in data:
            raise ValueError("missing 'reason' field")
        logging.info("verify_read_ok path=%s keys=%s", verdict_path, list(data.keys()))
        if getattr(args, "dynamic", False):
            logging.info("verify_option dynamic=true timeout=%s (not implemented)", getattr(args, "timeout", None))
        return data
    except FileNotFoundError:
        logging.warning("verify_read_failed missing_file path=%s mode=%s", verdict_path, agent_mode)
    except (json.JSONDecodeError, ValueError) as e:
        logging.warning("verify_read_failed path=%s err=%s", verdict_path, e)

    return {
        "verdict": "Uncertain",
        "reason": "verify: output file missing or invalid; see analysis_notes",
        "confidence": "low",
        "evidence": [],
        "used_traces": "",
        "suggested_commands": [],
        "analysis_mode": agent_mode,
        "output_path": verdict_path,
        "log_file": log_file,
        "analysis_notes": (
            f"Expected verdict JSON at {verdict_path} per verify/agents.md STEP 5. "
            "Check agent log or .verify_full_*.json backup."
        ),
    }
