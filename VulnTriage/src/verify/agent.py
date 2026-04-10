"""Exploitability verification agent: LangChain, Codex CLI, or OpenCode CLI.

Shares subprocess/env helpers with vfinder via ``utils.agent_runtime``.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from langchain_openai import ChatOpenAI
from langchain.agents import create_agent

from utils.agent_runtime import (
    build_llm_cli_env,
    cli_executable_exists,
    llm_cli_parent_dirs_outside_project,
    merge_opencode_external_directory_allow,
    read_file_tool_root,
    resolve_path_for_cli_env,
    stream_subprocess_to_log,
)
from vfinder.tools.recon_symbol_match import recon_symbol_match


def _get_llm():
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY not set. Copy env.template to .env and add your key.")
    return ChatOpenAI(
        model=os.environ.get("OPENAI_MODEL", "gpt-5-mini"),
        temperature=0,
        api_key=api_key,
        base_url=os.environ.get("OPENAI_BASE_URL") or None,
    )


@dataclass
class ExploitabilityVerificationAgent:
    """LLM agent: assess exploitability from traces + vuln context + optional PoC."""

    @classmethod
    def role(cls) -> str:
        return "Professional Security Analyst — Exploitability Verifier"

    @classmethod
    def task_description(cls) -> str:
        return (
            "Assess whether the vulnerability is exploitable given call traces, "
            "vulnerability materials, recon, and optional PoC; output structured verdict JSON"
        )

    def _agents_md_text(
        self,
        vuln_dir: Optional[str],
        project_path: Path,
        recon_file: Optional[str],
        traces_file: Optional[str],
        poc_path: Optional[str],
        output_path: Optional[str] = None,
    ) -> str:
        agents_source = Path(__file__).parent / "agents.md"
        if not agents_source.exists():
            raise FileNotFoundError(f"Agents file not found: {agents_source}")
        text = agents_source.read_text(encoding="utf-8")
        vuln_disp = resolve_path_for_cli_env(vuln_dir) if vuln_dir else ""
        recon_disp = resolve_path_for_cli_env(recon_file) if recon_file else ""
        traces_disp = resolve_path_for_cli_env(traces_file) if traces_file else ""
        poc_disp = resolve_path_for_cli_env(poc_path) if poc_path else ""
        out_disp = resolve_path_for_cli_env(output_path) if output_path else ""
        text = text.replace("{vuln_dir}", vuln_disp if vuln_disp else "{vuln_dir}")
        text = text.replace("{project_dir}", str(project_path.resolve()))
        text = text.replace("{recon_file}", recon_disp if recon_disp else "{recon_file}")
        text = text.replace("{traces_file}", traces_disp if traces_disp else "{traces_file}")
        text = text.replace("{poc_path}", poc_disp if poc_disp else "")
        text = text.replace("{output_path}", out_disp if out_disp else "{output_path}")
        return text

    def _sync_agents_md(
        self,
        vuln_dir: str,
        project_path: Path,
        recon_file: str,
        traces_file: str,
        poc_path: Optional[str],
        output_path: Optional[str] = None,
    ) -> Path:
        agents_target = project_path / "AGENTS.md"
        agents_target.write_text(
            self._agents_md_text(
                vuln_dir, project_path, recon_file, traces_file, poc_path, output_path
            ),
            encoding="utf-8",
        )
        return agents_target

    @staticmethod
    def _build_langchain_tools() -> List:
        from langchain_community.tools.file_management.read import ReadFileTool
        from langchain_community.tools.shell.tool import ShellTool

        return [
            ShellTool(),
            ReadFileTool(root_dir=read_file_tool_root()),
            recon_symbol_match,
        ]

    def run(
        self,
        user_input: str,
        *,
        vuln_dir: str = "",
        project_dir: str = "",
        recon_file: str = "",
        traces_file: str = "",
        poc_path: Optional[str] = None,
        verbose: bool = False,
        mode: str = "langchain",
        output_path: Optional[str] = None,
    ) -> dict:
        project_dir = project_dir or "/tmp/target_project"
        traces_file = traces_file or ""
        if mode == "codex":
            return self._run_codex_mode(
                user_input, vuln_dir, project_dir, recon_file, traces_file, poc_path, verbose, output_path
            )
        if mode == "opencode":
            return self._run_opencode_mode(
                user_input, vuln_dir, project_dir, recon_file, traces_file, poc_path, verbose, output_path
            )
        return self._run_langchain_mode(
            user_input, vuln_dir, project_dir, recon_file, traces_file, poc_path, verbose, output_path
        )

    def _verify_cli_env(
        self,
        project_path: Path,
        vuln_dir: str,
        recon_file: str,
        output_path: Optional[str],
        traces_file: str,
        poc_path: Optional[str],
    ) -> Dict[str, str]:
        out_abs = ""
        if output_path:
            p = Path(output_path)
            if not p.is_absolute():
                p = Path.cwd() / p
            out_abs = str(p.resolve())
        extra: Dict[str, str] = {
            "TRACES_FILE": resolve_path_for_cli_env(traces_file) if traces_file else "",
            "VERIFY_OUTPUT_PATH": out_abs,
        }
        if poc_path:
            extra["POC_PATH"] = resolve_path_for_cli_env(poc_path)
        return build_llm_cli_env(
            project_path,
            vuln_dir=vuln_dir,
            recon_file=recon_file,
            output_path=output_path,
            extra=extra,
        )

    def _run_codex_mode(
        self,
        user_input: str,
        vuln_dir: str,
        project_dir: str,
        recon_file: str,
        traces_file: str,
        poc_path: Optional[str],
        verbose: bool,
        output_path: Optional[str],
    ) -> dict:
        from datetime import datetime

        project_path = Path(project_dir).resolve()
        agents_target = self._sync_agents_md(
            vuln_dir, project_path, recon_file, traces_file, poc_path, output_path
        )
        logging.info("Synced AGENTS.md to %s", agents_target)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = project_path / f"verify_codex_{timestamp}.log"
        user_prompt = f"""Perform the following exploitability verification task:

{user_input}

Follow AGENTS.md. When finished, the verdict JSON must exist on disk at the path documented in AGENTS.md (output_path / OUTPUT_PATH / VERIFY_OUTPUT_PATH), not only in chat."""
        cmd: List[str] = ["codex", "exec", "-C", str(project_path), "--full-auto"]
        for d in llm_cli_parent_dirs_outside_project(project_path, [output_path]):
            cmd.extend(["--add-dir", d])
        for extra in (os.environ.get("CODEX_EXEC_ADD_DIR") or "").split(","):
            e = extra.strip()
            if e:
                cmd.extend(["--add-dir", e])
        cmd.append(user_prompt)
        env = self._verify_cli_env(project_path, vuln_dir, recon_file, output_path, traces_file, poc_path)
        logging.info("Running verify (codex) in %s, log=%s", project_path, log_file)
        try:
            exit_code, output_lines = stream_subprocess_to_log(
                cmd,
                cwd=project_path,
                env=env,
                log_file=log_file,
                verbose=verbose,
                log_heading="Verify — Codex Log",
            )
        except FileNotFoundError:
            raise RuntimeError("codex not found. Install Codex CLI and ensure it is on PATH.") from None
        return {
            "role": self.role(),
            "task": self.task_description(),
            "input": user_input,
            "vuln_dir": vuln_dir,
            "project_dir": project_dir,
            "recon_file": recon_file,
            "traces_file": traces_file,
            "poc_path": poc_path or "",
            "mode": "codex",
            "output": {
                "exit_code": exit_code,
                "output": "\n".join(output_lines),
                "log_file": str(log_file),
            },
        }

    def _run_opencode_mode(
        self,
        user_input: str,
        vuln_dir: str,
        project_dir: str,
        recon_file: str,
        traces_file: str,
        poc_path: Optional[str],
        verbose: bool,
        output_path: Optional[str],
    ) -> dict:
        from datetime import datetime

        project_path = Path(project_dir).resolve()
        agents_target = self._sync_agents_md(
            vuln_dir, project_path, recon_file, traces_file, poc_path, output_path
        )
        logging.info("Synced AGENTS.md to %s", agents_target)

        opencode_cmd = os.environ.get("OPENCODE_CMD", "opencode")
        if not cli_executable_exists(opencode_cmd):
            raise RuntimeError(
                f"OpenCode CLI not found ({opencode_cmd!r}). Set OPENCODE_CMD or install OpenCode."
            )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = project_path / f"verify_opencode_{timestamp}.log"
        user_prompt = f"""Perform the following exploitability verification task:

{user_input}

Follow AGENTS.md. When finished, the verdict JSON must exist on disk at the path documented in AGENTS.md, not only in chat."""

        paths_for_opencode = [output_path, vuln_dir, recon_file, traces_file]
        if poc_path:
            paths_for_opencode.append(poc_path)
        merge_opencode_external_directory_allow(
            project_path,
            llm_cli_parent_dirs_outside_project(project_path, paths_for_opencode),
        )

        cmd: List[str] = [opencode_cmd, "run", "--dir", str(project_path)]
        model = os.environ.get("OPENCODE_MODEL", "").strip()
        if model:
            cmd.extend(["-m", model])
        agent_name = os.environ.get("OPENCODE_AGENT", "").strip()
        if agent_name:
            cmd.extend(["--agent", agent_name])
        fmt = os.environ.get("OPENCODE_RUN_FORMAT", "").strip().lower()
        if fmt in ("json", "default"):
            cmd.extend(["--format", fmt])
        cmd.append(user_prompt)

        env = self._verify_cli_env(project_path, vuln_dir, recon_file, output_path, traces_file, poc_path)
        logging.info("Running verify (opencode) in %s, log=%s", project_path, log_file)
        try:
            exit_code, output_lines = stream_subprocess_to_log(
                cmd,
                cwd=project_path,
                env=env,
                log_file=log_file,
                verbose=verbose,
                log_heading="Verify — OpenCode Log",
            )
        except FileNotFoundError:
            raise RuntimeError(f"OpenCode executable not found ({opencode_cmd!r}).") from None
        return {
            "role": self.role(),
            "task": self.task_description(),
            "input": user_input,
            "vuln_dir": vuln_dir,
            "project_dir": project_dir,
            "recon_file": recon_file,
            "traces_file": traces_file,
            "poc_path": poc_path or "",
            "mode": "opencode",
            "output": {
                "exit_code": exit_code,
                "output": "\n".join(output_lines),
                "log_file": str(log_file),
            },
        }

    def _run_langchain_mode(
        self,
        user_input: str,
        vuln_dir: str,
        project_dir: str,
        recon_file: str,
        traces_file: str,
        poc_path: Optional[str],
        verbose: bool,
        output_path: Optional[str],
    ) -> dict:
        project_path = Path(project_dir).resolve()
        vuln_r = resolve_path_for_cli_env(vuln_dir) if vuln_dir else vuln_dir
        recon_r = resolve_path_for_cli_env(recon_file) if recon_file else recon_file
        traces_r = resolve_path_for_cli_env(traces_file) if traces_file else traces_file
        poc_r = resolve_path_for_cli_env(poc_path) if poc_path else ""
        out_r = resolve_path_for_cli_env(output_path) if output_path else ""
        body = self._agents_md_text(
            vuln_dir, project_path, recon_file, traces_file, poc_path, output_path
        )
        out_hint = out_r or output_path or "(see AGENTS.md)"
        lc_suffix = f"""

## LangChain runtime (this session)
- Tool **`terminal`**: pass shell input in the **`commands`** argument (one string).
- Tool **`read_file`**: pass **`file_path`** (prefer absolute paths).
- Tool **`recon_symbol_match`**: unchanged.
- **Deliverable:** write the verdict JSON object to **`{out_hint}`** using **`terminal`**, as in AGENTS.md STEP 5. Required fields: **`verdict`**, **`reason`**.
"""
        system_prompt = body + lc_suffix
        llm = _get_llm()
        tools = self._build_langchain_tools()
        agent = create_agent(model=llm, tools=tools, system_prompt=system_prompt, debug=verbose)

        full_request = f"""
**Exploitability verification task:**
{user_input}

**Resolved paths:**
- Vulnerability bundle: {vuln_r or vuln_dir}
- Target repo: {project_path}
- Recon JSON: {recon_r or recon_file}
- Traces file: {traces_r or traces_file}
- PoC (optional): {poc_r or "(none)"}
- Final JSON output (must create/overwrite): {out_hint}

Follow AGENTS.md. Start by reading the traces file with **`read_file`** or **`terminal`**.
"""

        result = agent.invoke(
            {"messages": [{"role": "user", "content": full_request}]},
            config={"recursion_limit": 1000},
        )

        return {
            "role": self.role(),
            "task": self.task_description(),
            "input": user_input,
            "vuln_dir": vuln_dir,
            "project_dir": project_dir,
            "recon_file": recon_file,
            "traces_file": traces_file,
            "poc_path": poc_path or "",
            "mode": "langchain",
            "output": result,
        }


VerificationAgent = ExploitabilityVerificationAgent
