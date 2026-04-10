"""
LSP server command configuration for Python and Java.
Override via env: VULN_LSP_PYRIGHT_CMD, VULN_LSP_JDTLS_CMD (space-separated args).

Supports custom cache/data directory for index persistence.
"""
import hashlib
import os
import shutil
import sys
from pathlib import Path
from typing import List, Optional


def _get_default_cache_dir() -> Path:
    """Get default cache directory for LSP workspace data."""
    cache_base = os.environ.get("XDG_CACHE_HOME")
    if cache_base:
        return Path(cache_base) / "vuln_reach_lsp"
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "vuln_reach_lsp"
    return Path.home() / ".cache" / "vuln_reach_lsp"


def get_workspace_data_dir(
    repo_path: str,
    cache_dir: Optional[str] = None,
    lang: Optional[str] = None,
) -> Path:
    """
    Get workspace data directory for a specific repo and language.
    Uses hash of repo path to create unique directory per project.
    
    Args:
        repo_path: Path to repository root
        cache_dir: Optional custom cache directory base
        lang: Optional language id (e.g. "py", "java") for language-specific cache
    """
    if cache_dir:
        base = Path(cache_dir)
    else:
        base = _get_default_cache_dir()
    
    repo_abs = str(Path(repo_path).resolve())
    repo_hash = hashlib.sha256(repo_abs.encode()).hexdigest()[:16]
    repo_name = Path(repo_path).name
    
    if lang:
        data_dir = base / f"{repo_name}_{repo_hash}_{lang}"
    else:
        data_dir = base / f"{repo_name}_{repo_hash}"
    
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


# Python: Pyright. Prefer pyright-langserver (stdio LSP entry point).
def _pyright_cmd(data_dir: Optional[Path] = None) -> List[str]:
    env_cmd = os.environ.get("VULN_LSP_PYRIGHT_CMD", "").strip()
    if env_cmd:
        return env_cmd.split()
    # Prefer pyright-langserver; fallback to pyright (some pip packages expose only pyright)
    for name in ["pyright-langserver", "pyright"]:
        exe = shutil.which(name)
        if exe:
            if name == "pyright":
                return [exe, "--stdio"]  # some builds use pyright --stdio
            return [exe, "--stdio"]
    return []


# Java: Eclipse JDT LS. Requires JDTLS_HOME or full path to launcher.
def _jdtls_cmd(data_dir: Optional[Path] = None) -> List[str]:
    env_cmd = os.environ.get("VULN_LSP_JDTLS_CMD", "").strip()
    if env_cmd:
        return env_cmd.split()
    home = os.environ.get("JDTLS_HOME")
    if not home:
        return []
    # Resolve to absolute path (handles relative paths like ./.jdtls)
    base = Path(home).resolve()
    # Prefer official bin/jdtls script (same startup as Eclipse distribution)
    jdtls_bin = base / "bin" / "jdtls"
    if jdtls_bin.exists():
        cmd = [str(jdtls_bin), "--no-validate-java-version"]
        if data_dir:
            cmd.extend(["-data", str(data_dir)])
        return cmd
    plugins = base / "plugins"
    if not plugins.is_dir():
        return []
    launchers = list(plugins.glob("org.eclipse.equinox.launcher_*.jar"))
    if not launchers:
        return []
    config = "config_linux"
    if os.name == "nt":
        config = "config_win"
    elif sys.platform == "darwin":
        config = "config_mac"
    config_dir = base / config
    if not config_dir.is_dir():
        config_dir = base / "config_linux"
    
    # Use provided data_dir or default
    if data_dir is None:
        data_dir = base / "data_workspace"
    data_dir.mkdir(parents=True, exist_ok=True)
    
    java_exe = "java"
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidate = Path(java_home) / "bin" / "java"
        if candidate.exists():
            java_exe = str(candidate)
    cmd = [
        java_exe,
        "-Declipse.application=org.eclipse.jdt.ls.core.id1",
        "-Dosgi.bundles.defaultStartLevel=4",
        "-Declipse.product=org.eclipse.jdt.ls.core.product",
        "-Dlog.protocol=false",
        "-Dlog.level=WARN",
        "-Xmx1G",
        "--add-modules=ALL-SYSTEM",
        "--add-opens", "java.base/java.util=ALL-UNNAMED",
        "--add-opens", "java.base/java.lang=ALL-UNNAMED",
        "-jar", str(launchers[0]),
        "-configuration", str(config_dir),
        "-data", str(data_dir),
    ]
    return cmd


def get_lsp_command(lang: str, data_dir: Optional[Path] = None) -> List[str]:
    """
    Get LSP command for the given language.
    
    Args:
        lang: Language id ("py" or "java")
        data_dir: Optional custom data/cache directory for workspace index
    """
    if lang == "py":
        return _pyright_cmd(data_dir)
    if lang == "java":
        return _jdtls_cmd(data_dir)
    return []
