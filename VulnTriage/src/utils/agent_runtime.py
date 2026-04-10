"""
Runtime helpers shared by vfinder and verify agents:
CLI env merging, Codex ``--add-dir`` / OpenCode ``external_directory`` merge, subprocess streaming.
"""
from __future__ import annotations

import json
import logging
import os
import platform
import queue
import shutil
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


def resolve_path_for_cli_env(path_str: str) -> str:
    """Resolve a CLI-supplied path for subprocess env vars.

    Relative paths are resolved from the **current working directory** of the
    invoking process, not ``--repo``. Absolute paths are normalized with
    ``resolve()`` only.
    """
    if not path_str:
        return ""
    p = Path(path_str)
    if p.is_absolute():
        return str(p.resolve())
    return str((Path.cwd() / p).resolve())


def cli_executable_exists(cmd: str) -> bool:
    """True if ``cmd`` names an existing, executable file (PATH or absolute path)."""
    if not cmd:
        return False
    p = Path(cmd)
    looks_like_path = p.is_absolute() or "/" in cmd or (os.name == "nt" and "\\" in cmd)
    if looks_like_path:
        try:
            return p.is_file() and os.access(p, os.X_OK)
        except OSError:
            return False
    return shutil.which(cmd) is not None


def llm_cli_parent_dirs_outside_project(
    project_path: Path,
    paths: Sequence[Optional[str]],
) -> List[str]:
    """Directory paths that must be whitelisted when tools run with ``--repo``/``-C`` = ``project_path``.

    For each non-empty path: resolve (using CWD for relative paths, same rules as
    ``resolve_path_for_cli_env``). If the path is **outside** ``project_path``:
    - existing **directory** → include that directory;
    - otherwise → include **parent** of the path (file or non-existent leaf).

    Used for:
    - **Codex** ``--add-dir`` (typically pass ``[output_path]`` only — write target);
    - **OpenCode** ``permission.external_directory`` (pass output, traces, recon, bundle, …).
    """
    proj = project_path.resolve()
    seen: set[str] = set()
    out: List[str] = []
    for raw in paths:
        if not raw or not str(raw).strip():
            continue
        rp = resolve_path_for_cli_env(str(raw).strip())
        if not rp:
            continue
        try:
            p = Path(rp).resolve(strict=False)
        except OSError:
            continue
        try:
            p.relative_to(proj)
            continue
        except ValueError:
            pass
        if p.exists() and p.is_dir():
            d = str(p)
        else:
            d = str(p.parent)
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def merge_opencode_external_directory_allow(project_path: Path, parent_dirs: List[str]) -> None:
    """Merge ``permission.external_directory`` globs into ``<project>/.opencode/opencode.json``.

    Non-interactive ``opencode run`` treats ``external_directory: ask`` as auto-reject; without
    this, reads/writes under e.g. ``--out`` outside the repo fail.

    Skips merge if ``external_directory`` is already the string ``\"allow\"``. If it is any other
    string (e.g. ``\"ask\"``), logs a warning and skips to avoid clobbering user config.
    """
    if not parent_dirs:
        return
    oc_dir = project_path / ".opencode"
    cfg_path = oc_dir / "opencode.json"
    data: Dict[str, Any] = {}
    if cfg_path.exists():
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logging.warning("OpenCode config unreadable %s: %s; skip permission merge", cfg_path, e)
            return
    perm = data.setdefault("permission", {})
    ext = perm.get("external_directory")
    if ext == "allow":
        logging.debug("OpenCode external_directory is global allow; skip merge")
        return
    if isinstance(ext, str):
        logging.warning(
            "OpenCode permission.external_directory is %r (string); skip auto-merge. "
            "Use a dict form or set to \"allow\", or add paths manually.",
            ext,
        )
        return
    if not isinstance(ext, dict):
        ext = {}
    perm["external_directory"] = ext
    for d in parent_dirs:
        pattern = f"{Path(d).resolve().as_posix()}/**"
        ext[pattern] = "allow"
        logging.info("OpenCode permission merge: external_directory[%s] = allow", pattern)
    try:
        oc_dir.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except OSError as e:
        logging.warning("OpenCode config write failed %s: %s", cfg_path, e)


def read_file_tool_root(
    primary_env: str = "VFINDER_READ_FILE_ROOT",
    fallback_env: str = "VERIFY_READ_FILE_ROOT",
) -> str:
    """Root for LangChain ReadFileTool so absolute paths under the FS work."""
    for key in (primary_env, fallback_env):
        r = os.environ.get(key, "").strip()
        if r:
            return r
    if platform.system() == "Windows":
        return os.environ.get("SystemDrive", "C:") + "\\"
    return "/"


def build_llm_cli_env(
    project_path: Path,
    *,
    vuln_dir: str = "",
    recon_file: str = "",
    output_path: Optional[str] = None,
    extra: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Build env dict for Codex / OpenCode subprocess (VULN_DIR, PROJECT_DIR, RECON_FILE, OUTPUT_PATH, +extra)."""
    env = os.environ.copy()
    env["VULN_DIR"] = resolve_path_for_cli_env(vuln_dir or "")
    env["PROJECT_DIR"] = str(project_path)
    env["RECON_FILE"] = resolve_path_for_cli_env(recon_file or "")
    if output_path:
        output_path_abs = Path(output_path)
        if not output_path_abs.is_absolute():
            output_path_abs = Path.cwd() / output_path_abs
        output_path_abs = output_path_abs.resolve()
        env["OUTPUT_PATH"] = str(output_path_abs)
        logging.info("LLM CLI output path set: %s", output_path_abs)
    if extra:
        for k, v in extra.items():
            if v is not None:
                env[k] = v
    return env


def stream_subprocess_to_log(
    cmd: List[str],
    cwd: Path,
    env: Dict[str, str],
    log_file: Path,
    verbose: bool,
    log_heading: str,
    max_wait_time: int = 600,
) -> Tuple[int, List[str]]:
    """Run a CLI process, stream stdout to log file, return (exit_code, lines)."""
    output_lines: List[str] = []
    exit_code = -1
    with open(log_file, "w", encoding="utf-8") as log_f:
        log_f.write(f"{log_heading}\n")
        log_f.write(f"Timestamp: {datetime.now().isoformat()}\n")
        log_f.write(f"Command: {' '.join(cmd)}\n")
        log_f.write(f"Working Directory: {cwd}\n")
        log_f.write(f"{'=' * 80}\n\n")
        log_f.flush()
        try:
            process = subprocess.Popen(
                cmd,
                cwd=str(cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                text=True,
                bufsize=1,
                encoding="utf-8",   # 👈 关键
                errors="ignore"     # 👈 防止崩
            )
            output_queue: queue.Queue[str] = queue.Queue()
            read_done = threading.Event()

            def read_output() -> None:
                try:
                    assert process.stdout is not None
                    for line in process.stdout:
                        output_queue.put(line.rstrip())
                    read_done.set()
                except Exception as e:
                    logging.error("Error reading CLI stdout: %s", e)
                    read_done.set()

            reader_thread = threading.Thread(target=read_output, daemon=True)
            reader_thread.start()
            start_time = datetime.now()
            while not read_done.is_set() or not output_queue.empty():
                elapsed = (datetime.now() - start_time).total_seconds()
                if elapsed > max_wait_time:
                    logging.warning("CLI process timeout after %ss, terminating", max_wait_time)
                    process.terminate()
                    try:
                        exit_code = process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        exit_code = -1
                    log_f.write(f"\n[TIMEOUT] Process terminated after {max_wait_time}s\n")
                    break
                if process.poll() is not None:
                    exit_code = process.returncode
                    time.sleep(0.5)
                try:
                    while True:
                        line = output_queue.get_nowait()
                        output_lines.append(line)
                        log_f.write(f"{line}\n")
                        log_f.flush()
                        if verbose or "error" in line.lower() or "warning" in line.lower():
                            logging.info("CLI: %s", line[:200])
                except queue.Empty:
                    pass
                time.sleep(0.1)
            if process.poll() is None:
                try:
                    exit_code = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    exit_code = -1
            if exit_code == -1 and process.poll() is not None:
                exit_code = process.returncode
            while True:
                try:
                    line = output_queue.get_nowait()
                    output_lines.append(line)
                    log_f.write(f"{line}\n")
                    log_f.flush()
                except queue.Empty:
                    break
            log_f.write(f"\n{'=' * 80}\n")
            log_f.write(f"Exit Code: {exit_code}\n")
            log_f.write(f"Completed: {datetime.now().isoformat()}\n")
        except FileNotFoundError:
            raise
        except Exception as e:
            log_f.write(f"[ERROR] {e}\n")
            logging.exception("CLI subprocess failed")
            raise
    return exit_code, output_lines
