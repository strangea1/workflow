"""Security vulnerability analysis agent.

Autonomous security analyst that identifies vulnerability sink locations in source code.
Supports LangChain, OpenAI Codex CLI, and OpenCode CLI agent modes.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict, Any, List

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

from .tools.recon_symbol_match import recon_symbol_match


def _get_llm():
    """Create OpenAI chat model."""
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
class VulnerabilityAnalystAgent:
    """Professional security analyst for vulnerability code location."""

    @classmethod
    def role(cls) -> str:
        return "Professional Security Analyst - Vulnerability Localization Expert"

    @classmethod
    def task_description(cls) -> str:
        return "Analyze vulnerability info, locate sink positions in target project, output JSON with all possible vulnerability trigger locations"

    def _agents_md_text(
        self,
        vuln_dir: Optional[str],
        project_path: Path,
        recon_file: Optional[str],
        output_path: Optional[str] = None,
    ) -> str:
        """Load ``agents.md`` with path placeholders substituted."""
        agents_source = Path(__file__).parent / "agents.md"
        if not agents_source.exists():
            raise FileNotFoundError(f"Agents file not found: {agents_source}")
        agents_content = agents_source.read_text(encoding="utf-8")
        vuln_disp = resolve_path_for_cli_env(vuln_dir) if vuln_dir else ""
        recon_disp = resolve_path_for_cli_env(recon_file) if recon_file else ""
        out_disp = resolve_path_for_cli_env(output_path) if output_path else ""
        agents_content = agents_content.replace(
            "{vuln_dir}", vuln_disp if vuln_disp else "{vuln_dir}"
        )
        agents_content = agents_content.replace("{project_dir}", str(project_path.resolve()))
        agents_content = agents_content.replace(
            "{recon_file}", recon_disp if recon_disp else "{recon_file}"
        )
        agents_content = agents_content.replace(
            "{output_path}", out_disp if out_disp else "{output_path}"
        )
        return agents_content

    def _sync_agents_md(
        self,
        vuln_dir: str,
        project_path: Path,
        recon_file: str,
        output_path: Optional[str] = None,
    ) -> Path:
        """Write vfinder/agents.md into project root as AGENTS.md (Codex / OpenCode pick this up)."""
        agents_target = project_path / "AGENTS.md"
        agents_target.write_text(
            self._agents_md_text(vuln_dir, project_path, recon_file, output_path),
            encoding="utf-8",
        )
        return agents_target

    @staticmethod
    def _build_langchain_tools() -> List:
        """LangChain tools: community shell + read file + recon symbol match."""
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
        vuln_dir: str = None, 
        project_dir: str = None, 
        recon_file: str = None, 
        verbose: bool = False,
        mode: str = "langchain",
        output_path: str = None
    ) -> dict:
        """
        Run vulnerability analysis workflow.
        
        Args:
            user_input: Vulnerability analysis request
            vuln_dir: Directory containing vulnerability reports/PoCs (placeholder: /tmp/vuln_info)
            project_dir: Target project directory to analyze (placeholder: /tmp/target_project)
            recon_file: Path to recon output JSON (placeholder: recon_output.json)
            verbose: Enable verbose logging
            mode: Agent mode - "langchain" (default), "codex", or "opencode"
            output_path: Absolute or CWD-relative path for the final analysis JSON (all modes; also sets OUTPUT_PATH for CLI env)
        
        Returns:
            Analysis result with identified sink positions as JSON
        """
        # Use placeholders if not provided
        vuln_dir = vuln_dir or "/tmp/vuln_info"
        project_dir = project_dir or "/tmp/target_project"
        recon_file = recon_file or "recon_output.json"
        
        # Route to appropriate implementation based on mode
        if mode == "codex":
            return self._run_codex_mode(user_input, vuln_dir, project_dir, recon_file, verbose, output_path)
        if mode == "opencode":
            return self._run_opencode_mode(user_input, vuln_dir, project_dir, recon_file, verbose, output_path)
        return self._run_langchain_mode(
            user_input, vuln_dir, project_dir, recon_file, verbose, output_path
        )

    def _run_codex_mode(
        self,
        user_input: str,
        vuln_dir: str,
        project_dir: str,
        recon_file: str,
        verbose: bool,
        output_path: str = None,
    ) -> dict:
        """Run analysis using Codex CLI (`codex exec`)."""
        from datetime import datetime

        project_path = Path(project_dir).resolve()
        agents_target = self._sync_agents_md(vuln_dir, project_path, recon_file, output_path)
        logging.info("Synced AGENTS.md to %s", agents_target)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = project_path / f"codex_analysis_{timestamp}.log"
        user_prompt = f"""Perform the following vulnerability analysis task:

{user_input}

Follow AGENTS.md. When finished, the vulnerability analysis JSON must exist on disk at the path documented in AGENTS.md (output_path / OUTPUT_PATH), not only in chat."""
        cmd: List[str] = ["codex", "exec", "-C", str(project_path), "--full-auto"]
        for d in llm_cli_parent_dirs_outside_project(project_path, [output_path]):
            cmd.extend(["--add-dir", d])
        for extra in (os.environ.get("CODEX_EXEC_ADD_DIR") or "").split(","):
            extra = extra.strip()
            if extra:
                cmd.extend(["--add-dir", extra])
        cmd.append(user_prompt)
        env = build_llm_cli_env(project_path, vuln_dir=vuln_dir, recon_file=recon_file, output_path=output_path)
        logging.info("Running codex in %s, log=%s", project_path, log_file)
        try:
            exit_code, output_lines = stream_subprocess_to_log(
                cmd,
                cwd=project_path,
                env=env,
                log_file=log_file,
                verbose=verbose,
                log_heading="Codex Analysis Log",
            )
        except FileNotFoundError:
            msg = "codex not found. Install Codex CLI and ensure it is on PATH."
            logging.error(msg)
            raise RuntimeError(msg) from None
        logging.info("Codex finished with exit code %s", exit_code)
        return {
            "role": self.role(),
            "task": self.task_description(),
            "input": user_input,
            "vuln_dir": vuln_dir,
            "project_dir": project_dir,
            "recon_file": recon_file,
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
        verbose: bool,
        output_path: str = None,
    ) -> dict:
        """Run analysis using OpenCode CLI (`opencode run`, non-interactive)."""
        from datetime import datetime

        project_path = Path(project_dir).resolve()
        agents_target = self._sync_agents_md(vuln_dir, project_path, recon_file, output_path)
        logging.info("Synced AGENTS.md to %s", agents_target)

        opencode_cmd = os.environ.get(
            "OPENCODE_CMD",
            r"C:\Users\A\scoop\apps\nodejs\current\bin\opencode.CMD"
        )
        if not cli_executable_exists(opencode_cmd):
            raise RuntimeError(
                f"OpenCode CLI not found or not executable ({opencode_cmd!r}). Install from https://opencode.ai "
                "or set OPENCODE_CMD to a valid path."
            )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = project_path / f"opencode_analysis_{timestamp}.log"
        user_prompt = f"""Perform the following vulnerability analysis task:

{user_input}

Follow AGENTS.md. When finished, the vulnerability analysis JSON must exist on disk at the path documented in AGENTS.md (output_path / OUTPUT_PATH), not only in chat."""

        merge_opencode_external_directory_allow(
            project_path,
            llm_cli_parent_dirs_outside_project(
                project_path, [output_path, vuln_dir, recon_file]
            ),
        )
        # --dir: project root for config/AGENTS.md; complements subprocess cwd (needed when using
        # e.g. --attach, where the child cwd may not define OpenCode's project context).
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

        env = build_llm_cli_env(project_path, vuln_dir=vuln_dir, recon_file=recon_file, output_path=output_path)
        logging.info("Running opencode in %s, log=%s", project_path, log_file)
        try:
            exit_code, output_lines = stream_subprocess_to_log(
                cmd,
                cwd=project_path,
                env=env,
                log_file=log_file,
                verbose=verbose,
                log_heading="OpenCode Analysis Log",
            )
        except FileNotFoundError:
            msg = f"OpenCode executable not found ({opencode_cmd!r})."
            logging.error(msg)
            raise RuntimeError(msg) from None
        logging.info("OpenCode finished with exit code %s", exit_code)
        return {
            "role": self.role(),
            "task": self.task_description(),
            "input": user_input,
            "vuln_dir": vuln_dir,
            "project_dir": project_dir,
            "recon_file": recon_file,
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
        verbose: bool,
        output_path: Optional[str] = None,
    ) -> dict:
        """Run analysis using LangChain agent mode (community ShellTool + ReadFileTool + recon)."""
        project_path = Path(project_dir).resolve()
        vuln_resolved = resolve_path_for_cli_env(vuln_dir) if vuln_dir else vuln_dir
        recon_resolved = resolve_path_for_cli_env(recon_file) if recon_file else recon_file
        out_resolved = resolve_path_for_cli_env(output_path) if output_path else ""
        agents_body = self._agents_md_text(vuln_dir, project_path, recon_file, output_path)
        out_hint = out_resolved or output_path or "(see AGENTS.md if output path is unset)"
        lc_suffix = f"""

## LangChain runtime (this session)
- Tool **`terminal`**: pass shell input in the **`commands`** argument (one string).
- Tool **`read_file`**: pass **`file_path`** (prefer absolute paths under `{vuln_resolved or vuln_dir}` / `{project_path}`).
- Tool **`recon_symbol_match`**: unchanged.
- **Deliverable:** write the final JSON object to **`{out_hint}`** using **`terminal`** (e.g. `python3 -c` or a heredoc), as described in AGENTS.md STEP 5. Do not treat chat-only text as the deliverable.
"""
        system_prompt = agents_body + lc_suffix

        llm = _get_llm()
        tools = self._build_langchain_tools()
        agent = create_agent(model=llm, tools=tools, system_prompt=system_prompt, debug=verbose)

        full_request = f"""
**Vulnerability Analysis Task:**
{user_input}

**Resolved paths (use these in tool calls):**
- Vulnerability info directory: {vuln_resolved or vuln_dir}
- Target project directory: {project_path}
- Recon database file: {recon_resolved or recon_file}
- Final JSON output file (must create/overwrite): {out_hint}

Follow the workflow in your system instructions. Start by listing the vulnerability directory with **`terminal`**.
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
            "mode": "langchain",
            "output": result,
        }


# Legacy alias for compatibility
VFinderAgent = VulnerabilityAnalystAgent

