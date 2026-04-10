"""
LSP: get_server(lang) returns LSPClient; list_languages / start_server / query_references for CLI.

Supports persistent server management for index reuse across invocations.
"""
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .client import LSPClient, path_to_uri, uri_to_path, _is_process_running
from .config import get_lsp_command, get_workspace_data_dir

# Language id -> { display name, lsp identifier }
SUPPORTED_LANGUAGES: Dict[str, Dict[str, str]] = {
    "py": {"name": "Python", "lsp": "pyright"},
    "java": {"name": "Java", "lsp": "jdtls"},
}

# Global server registry: repo_path -> LSPClient
_server_registry: Dict[str, LSPClient] = {}


def _get_server_info_path(data_dir: Path) -> Path:
    """Get path to server info file."""
    return data_dir / "lsp_server_info.json"


def _save_server_info(data_dir: Path, pid: int, repo_path: str, lang: str) -> None:
    """Save server info to file for later reuse."""
    info = {
        "pid": pid,
        "repo_path": repo_path,
        "lang": lang,
        "started_at": time.time(),
    }
    info_path = _get_server_info_path(data_dir)
    try:
        with open(info_path, "w", encoding="utf-8") as f:
            json.dump(info, f)
    except Exception as e:
        logging.warning("Failed to save server info: %s", e)


def _load_server_info(data_dir: Path) -> Optional[Dict[str, Any]]:
    """Load server info from file."""
    info_path = _get_server_info_path(data_dir)
    if not info_path.exists():
        return None
    try:
        with open(info_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logging.warning("Failed to load server info: %s", e)
        return None


def _clear_server_info(data_dir: Path) -> None:
    """Clear server info file."""
    info_path = _get_server_info_path(data_dir)
    try:
        if info_path.exists():
            info_path.unlink()
    except Exception:
        pass


def get_server(lang: str, data_dir: Optional[Path] = None) -> Optional[LSPClient]:
    """Return an LSP client for the given language, or None if unsupported/unavailable."""
    if lang not in SUPPORTED_LANGUAGES:
        return None
    cmd = get_lsp_command(lang, data_dir)
    if not cmd:
        return None
    return LSPClient(cmd)


def get_registered_server(repo_path: str) -> Optional[LSPClient]:
    """Get a registered (already running) server for a repo."""
    repo_key = str(Path(repo_path).resolve())
    server = _server_registry.get(repo_key)
    if server and server.is_initialized():
        return server
    if server:
        del _server_registry[repo_key]
    return None


def register_server(repo_path: str, server: LSPClient) -> None:
    """Register a server for a repo."""
    repo_key = str(Path(repo_path).resolve())
    _server_registry[repo_key] = server


def unregister_server(repo_path: str) -> Optional[LSPClient]:
    """Unregister and return a server for a repo."""
    repo_key = str(Path(repo_path).resolve())
    return _server_registry.pop(repo_key, None)


def list_languages() -> List[Dict[str, str]]:
    """Return list of supported languages for LSP-based trace finding."""
    return [
        {"id": lang_id, "name": info["name"], "lsp": info["lsp"]}
        for lang_id, info in SUPPORTED_LANGUAGES.items()
    ]


def start_server(repo: str, lang: str) -> Dict[str, Any]:
    """
    Check that LSP command for the language is available (no process started).
    Returns ok + message for CLI compatibility.
    """
    repo_path = Path(repo).resolve()
    if not repo_path.is_dir():
        return {"ok": False, "error": f"Repo not found or not a directory: {repo}"}
    if lang not in SUPPORTED_LANGUAGES:
        return {"ok": False, "error": f"Unsupported language: {lang}"}
    cmd = get_lsp_command(lang)
    if not cmd:
        return {"ok": False, "error": f"No LSP command for {lang}. Install pyright or set JDTLS_HOME for Java."}
    logging.info("lsp_start repo=%s lang=%s cmd=%s", repo, lang, cmd[0])
    return {
        "ok": True,
        "repo": str(repo_path),
        "lang": lang,
        "command": cmd[0],
        "message": f"LSP command: {' '.join(cmd)[:80]}... Use 'trace lsp refs' to test references.",
    }


def start_server_persistent(
    repo: str,
    lang: str,
    cache_dir: Optional[str] = None,
    wait_for_index: bool = True,
    index_timeout: int = 0,
) -> Dict[str, Any]:
    """
    Start LSP server persistently with index caching.
    
    This function:
    1. Creates a workspace-specific data directory for index storage
    2. Starts the LSP server with the data directory
    3. Initializes the server and waits for indexing to complete
    4. Keeps the server running for later reuse
    
    Args:
        repo: Path to repository root
        lang: Language id ("py" or "java")
        cache_dir: Optional custom cache directory for index storage
        wait_for_index: If True, wait for initial indexing to complete
        index_timeout: Maximum seconds to wait for indexing (0 = no timeout, wait until done)
    
    Returns:
        Dict with ok, pid, data_dir, message, etc.
    """
    repo_path = Path(repo).resolve()
    if not repo_path.is_dir():
        return {"ok": False, "error": f"Repo not found or not a directory: {repo}"}
    if lang not in SUPPORTED_LANGUAGES:
        return {"ok": False, "error": f"Unsupported language: {lang}"}
    
    # Check if server already registered and running
    existing = get_registered_server(str(repo_path))
    if existing and existing.is_initialized():
        return {
            "ok": True,
            "repo": str(repo_path),
            "lang": lang,
            "pid": existing.get_pid(),
            "data_dir": None,
            "message": "LSP server already running.",
            "reused": True,
        }
    
    # Get workspace data directory (language-specific)
    data_dir = get_workspace_data_dir(str(repo_path), cache_dir, lang)
    
    # Check if there's an existing server process we can reuse index from
    server_info = _load_server_info(data_dir)
    if server_info:
        old_pid = server_info.get("pid")
        if old_pid and _is_process_running(old_pid):
            logging.info("Found existing server process PID=%d, but cannot reuse stdio connection", old_pid)
    
    # Get LSP command with custom data directory
    cmd = get_lsp_command(lang, data_dir)
    if not cmd:
        return {"ok": False, "error": f"No LSP command for {lang}. Install pyright or set JDTLS_HOME for Java."}
    
    logging.info("Starting LSP server: repo=%s lang=%s data_dir=%s", repo, lang, data_dir)
    
    # Create and start server
    server = LSPClient(cmd, cwd=str(repo_path))
    root_uri = path_to_uri(str(repo_path))
    
    start_time = time.time()
    if not server.initialize(root_uri):
        stderr = getattr(server, "_stderr_lines", [])
        err_msg = "LSP initialize failed"
        if stderr:
            err_msg += ". Server stderr (last 15): " + " | ".join(stderr[-15:])
        server.close()
        return {"ok": False, "error": err_msg}
    
    init_time = time.time() - start_time
    pid = server.get_pid()
    
    # Save server info and register
    if pid:
        _save_server_info(data_dir, pid, str(repo_path), lang)
    register_server(str(repo_path), server)
    
    logging.info("LSP server started: PID=%s, init_time=%.2fs", pid, init_time)
    
    # Wait for indexing if requested (JDT LS only; Pyright has no .metadata/.log)
    indexing_time = 0.0
    if wait_for_index:
        if lang == "java":
            logging.info("Waiting for JDT LS indexing to complete...")
            index_start = time.time()
            if server.wait_for_indexing(timeout=index_timeout, data_dir=str(data_dir)):
                indexing_time = time.time() - index_start
                logging.info("Indexing completed in %.1fs", indexing_time)
            else:
                indexing_time = time.time() - index_start
                logging.warning("Indexing may not be complete (waited %.1fs)", indexing_time)
        else:
            logging.info(
                "Skipping Eclipse-style indexing wait for lang=%s (not applicable to Pyright)",
                lang,
            )
    
    return {
        "ok": True,
        "repo": str(repo_path),
        "lang": lang,
        "pid": pid,
        "data_dir": str(data_dir),
        "init_time_seconds": round(init_time, 2),
        "indexing_time_seconds": round(indexing_time, 2) if wait_for_index else None,
        "message": f"LSP server started (PID={pid}). Index cached in {data_dir}",
        "reused": False,
    }


def stop_server_persistent(
    repo: str,
    lang: str,
    cache_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Stop a persistent LSP server for a repo.
    
    Args:
        repo: Path to repository root
        lang: Language id ("py" or "java")
        cache_dir: Optional custom cache directory (to find server info)
    
    Returns:
        Dict with ok, message, etc.
    """
    repo_path = Path(repo).resolve()
    
    # Try to unregister from registry first
    server = unregister_server(str(repo_path))
    if server:
        try:
            pid = server.get_pid()
            server.close()
            logging.info("Stopped LSP server: repo=%s lang=%s pid=%s", repo_path, lang, pid)
            return {
                "ok": True,
                "repo": str(repo_path),
                "lang": lang,
                "pid": pid,
                "message": f"LSP server stopped (PID={pid}).",
            }
        except Exception as e:
            logging.warning("Error stopping server: %s", e)
    
    # Check server info file
    data_dir = get_workspace_data_dir(str(repo_path), cache_dir, lang)
    server_info = _load_server_info(data_dir)
    if server_info:
        old_pid = server_info.get("pid")
        _clear_server_info(data_dir)
        if old_pid and _is_process_running(old_pid):
            try:
                if os.name == "nt":
                    os.system(f"taskkill /F /PID {old_pid}")
                else:
                    os.kill(old_pid, 15)  # SIGTERM
                return {
                    "ok": True,
                    "repo": str(repo_path),
                    "lang": lang,
                    "pid": old_pid,
                    "message": f"LSP server process killed (PID={old_pid}).",
                }
            except Exception as e:
                logging.warning("Failed to kill process %d: %s", old_pid, e)
    
    return {
        "ok": True,
        "repo": str(repo_path),
        "lang": lang,
        "message": "No running LSP server found for this repo.",
    }


def get_server_status(
    repo: str,
    lang: str,
    cache_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Get status of LSP server for a repo.
    
    Args:
        repo: Path to repository root
        lang: Language id ("py" or "java")
        cache_dir: Optional custom cache directory
    
    Returns:
        Dict with running status, pid, data_dir, etc.
    """
    repo_path = Path(repo).resolve()
    data_dir = get_workspace_data_dir(str(repo_path), cache_dir, lang)
    
    # Check registry
    server = get_registered_server(str(repo_path))
    if server and server.is_initialized():
        return {
            "ok": True,
            "repo": str(repo_path),
            "running": True,
            "pid": server.get_pid(),
            "data_dir": str(data_dir),
            "source": "registry",
        }
    
    # Check server info file
    server_info = _load_server_info(data_dir)
    if server_info:
        old_pid = server_info.get("pid")
        if old_pid and _is_process_running(old_pid):
            return {
                "ok": True,
                "repo": str(repo_path),
                "running": True,
                "pid": old_pid,
                "data_dir": str(data_dir),
                "source": "info_file",
                "note": "Server running but not in current process registry (started in another session)",
            }
    
    # Check if index exists
    index_exists = data_dir.exists() and any(data_dir.iterdir())
    
    return {
        "ok": True,
        "repo": str(repo_path),
        "running": False,
        "data_dir": str(data_dir),
        "index_exists": index_exists,
    }


def query_references(
    repo: str,
    file_path: str,
    line: int,
    character: int = 0,
    lang: str = "py",
    include_declaration: bool = False,
) -> Dict[str, Any]:
    """
    One-shot: get server for lang, initialize, did_open, references, close.
    line is 1-based in CLI; converted to 0-based for LSP.
    Returns { ok, references: [{ uri, file, line, character }], error?, count }.
    """
    repo_path = Path(repo).resolve()
    if not repo_path.is_dir():
        return {"ok": False, "error": f"Repo not found: {repo}", "references": []}
    server = get_server(lang)
    if not server:
        return {"ok": False, "error": f"No LSP for {lang}", "references": []}
    fp = Path(file_path)
    if not fp.is_absolute():
        fp = repo_path / fp
    if not fp.exists():
        return {"ok": False, "error": f"File not found: {fp}", "references": []}
    fp = fp.resolve()
    root_uri = path_to_uri(str(repo_path))
    file_uri = path_to_uri(str(fp))
    line_0 = max(0, line - 1)
    try:
        if not server.initialize(root_uri):
            err = "LSP initialize failed"
            stderr = getattr(server, "_stderr_lines", [])
            if stderr:
                err += ". Server stderr (last 15): " + " | ".join(stderr[-15:])
            proc = getattr(server, "_proc", None)
            if proc is not None and proc.poll() is not None:
                err += f" (server exit code: {proc.poll()})"
            server.close()
            return {"ok": False, "error": err, "references": []}
        logging.info("LSP: didOpen target %s (lang=%s)", fp, lang)
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
            lang_id = "python" if lang == "py" else "java"
            server.did_open(file_uri, lang_id, text)
        except Exception as e:
            logging.warning("didOpen failed: %s", e)
        refs = server.references(file_uri, line_0, character, include_declaration=include_declaration)
        server.close()
        if refs is None:
            refs = []
        out = []
        for r in refs:
            if "uri" in r and "range" in r:
                ran = r["range"]
                start = ran.get("start", {})
                out.append({
                    "uri": r["uri"],
                    "file": uri_to_path(r["uri"]),
                    "line": start.get("line", 0) + 1,
                    "character": start.get("character", 0),
                })
        return {"ok": True, "references": out, "count": len(out)}
    except Exception as e:
        logging.exception("query_references")
        try:
            server.close()
        except Exception:
            pass
        return {"ok": False, "error": str(e), "references": []}


__all__ = [
    "LSPClient",
    "SUPPORTED_LANGUAGES",
    "get_server",
    "get_registered_server",
    "register_server",
    "unregister_server",
    "list_languages",
    "start_server",
    "start_server_persistent",
    "stop_server_persistent",
    "get_server_status",
    "query_references",
    "path_to_uri",
    "uri_to_path",
    "get_workspace_data_dir",
]
