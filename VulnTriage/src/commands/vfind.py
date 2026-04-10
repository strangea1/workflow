import json
import logging
import os
from datetime import datetime
from pathlib import Path

from vfinder.agent import VulnerabilityAnalystAgent


def _vfind_result_path(args) -> str:
    """Absolute path where the agent must write the final JSON (default under ./out/)."""
    raw = getattr(args, "out", None)
    if not raw:
        os.makedirs("out", exist_ok=True)
        raw = os.path.join("out", "vfind_sinks.json")
    p = Path(raw)
    if p.is_absolute():
        return str(p.resolve())
    return str((Path.cwd() / p).resolve())


def run(args):
    logging.info("vfind_start repo=%s bundle=%s recon=%s", args.repo, args.bundle, args.recon)

    if getattr(args, "dep_only", False):
        logging.info("vfind_mode dep_only=true (note: current agent ignores this flag)")

    agent_mode = getattr(args, "agent_mode", "langchain")
    logging.info("vfind_agent_mode=%s", agent_mode)

    sink_path = _vfind_result_path(args)
    Path(sink_path).parent.mkdir(parents=True, exist_ok=True)

    user_input = f"Analyze vulnerability materials in {args.bundle} and locate sinks in {args.repo}. Use recon index {args.recon}."

    agent = VulnerabilityAnalystAgent()
    result = agent.run(
        user_input=user_input,
        vuln_dir=args.bundle,
        project_dir=args.repo,
        recon_file=args.recon,
        verbose=False,
        mode=agent_mode,
        output_path=sink_path,
    )

    try:
        out_dir = os.path.dirname(args.out) if args.out else "out"
        os.makedirs(out_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(out_dir, f".vfind_full_{ts}.json")
        with open(backup_file, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2, default=str)
        logging.info("vfind_backup full_result=%s", backup_file)
    except Exception as e:
        logging.warning("vfind_backup_failed %s", e)

    agent_mode = result.get("mode", "langchain")
    log_file = ""
    if agent_mode in ("codex", "opencode"):
        log_file = result.get("output", {}).get("log_file", "")

    try:
        with open(sink_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("root JSON value is not an object")
        if "sinks" not in data or not isinstance(data["sinks"], list):
            raise ValueError("missing or invalid 'sinks' list")
        logging.info("vfind_read_ok path=%s keys=%s", sink_path, list(data.keys()))
        return data
    except FileNotFoundError:
        logging.warning("vfind_read_failed missing_file path=%s mode=%s", sink_path, agent_mode)
    except (json.JSONDecodeError, ValueError) as e:
        logging.warning("vfind_read_failed path=%s err=%s", sink_path, e)

    return {
        "vulnerability_name": "vfind: output file missing or invalid",
        "vulnerability_type": "Unknown",
        "analysis_mode": agent_mode,
        "output_path": sink_path,
        "log_file": log_file,
        "sinks": [],
        "analysis_notes": (
            f"Expected a JSON file at {sink_path} written per AGENTS.md STEP 5. "
            "Open the agent log or full trace backup for details."
        ),
    }
