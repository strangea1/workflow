"""CLI runners for vuln_reach_analysis: shell-exec, file-read, recon-symbol-match."""
import os
import subprocess
import sys
from pathlib import Path

from vfinder.tools.recon_symbol_match import recon_symbol_match


def _merged_cwd(args):
    return getattr(args, "cwd", None) or getattr(args, "global_cwd", None)


def _resolve_under_global(path_str: str, global_cwd) -> str:
    if not path_str or not global_cwd:
        return path_str
    p = Path(path_str)
    if p.is_absolute():
        return path_str
    return str((Path(global_cwd) / p).resolve())



def run_recon_symbol_match(args):
    """Run recon_symbol_match tool from CLI."""
    rf = getattr(args, "recon_file", "recon_output.json")
    rf = _resolve_under_global(rf, getattr(args, "global_cwd", None))
    if not os.path.isabs(rf) and os.environ.get("RECON_FILE"):
        env_rf = os.environ["RECON_FILE"]
        if os.path.isfile(env_rf):
            rf = env_rf
    inp = {"symbol_name": args.symbol, "recon_file": rf}
    result = recon_symbol_match.invoke(inp)
    print(result, file=sys.stdout if result and not result.startswith("[ERROR]") else sys.stderr)
    return 0 if result and not result.startswith("[ERROR]") else 1
