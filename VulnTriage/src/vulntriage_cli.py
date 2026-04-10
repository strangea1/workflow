import argparse
import logging
import os
import sys

from commands import recon as cmd_recon
from commands import vfind as cmd_vfind
from commands import verify as cmd_verify
from commands import all as cmd_all
from commands import tools as cmd_tools
from commands import trace as cmd_trace
from core.logging import init_logging
from storage.writer import write_out

COMMANDS = ["list", "recon", "vfind", "verify", "trace", "all", "shell-exec", "file-read", "recon-symbol-match"]


def build_parser():
    parser = argparse.ArgumentParser(
        prog="vuln_reach_analysis",
        description="Vulnerability reachability analysis: recon, sink finding, call mapping, verification (Python/Java)"
    )
    parser.add_argument("--log-level", default="info", choices=["debug", "info", "warn", "error"], help="logging level")
    parser.add_argument(
        "--cwd",
        dest="global_cwd",
        default=None,
        help=(
            "Default working directory for tool subcommands when placed before the subcommand "
            "(e.g. vuln_reach_analysis --cwd /repo shell-exec -c 'ls'). "
            "Subcommand-specific --cwd overrides this."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    # list commands
    p_list = subparsers.add_parser("list", help="Show available commands")
    p_list.set_defaults(func=handle_list)

    # recon
    p_recon = subparsers.add_parser("recon", help="Run project reconnaissance")
    p_recon.add_argument("--repo", required=True)
    p_recon.add_argument("--lang", default="auto", choices=["auto", "py", "java"])
    p_recon.add_argument("--out")
    p_recon.add_argument("--format", default="jsonl", choices=["json", "jsonl", "sqlite"])
    p_recon.set_defaults(func=cmd_recon.run)

    # vfind
    p_vfind = subparsers.add_parser("vfind", help="Find vulnerable sinks based on bundle")
    p_vfind.add_argument("--repo", required=True)
    p_vfind.add_argument("--bundle", required=True)
    p_vfind.add_argument("--recon", required=True)
    p_vfind.add_argument("--out")
    p_vfind.add_argument("--format", default="jsonl", choices=["json", "jsonl", "sqlite"])
    p_vfind.add_argument("--similarity", default="tfidf", choices=["tfidf", "vector", "off"])
    p_vfind.add_argument("--api-fuzzy", type=float, default=0.8)
    p_vfind.add_argument("--dep-only", action="store_true")
    p_vfind.add_argument(
        "--agent-mode",
        default="langchain",
        choices=["langchain", "codex", "opencode"],
        help="Agent mode: langchain (default), codex (CLI), or opencode (OpenCode CLI)",
    )
    p_vfind.set_defaults(func=cmd_vfind.run)

    # trace (LSP + call trace finder)
    cmd_trace.build_parser(subparsers)

    p_recon_match = subparsers.add_parser("recon-symbol-match", help="[Tool] Search symbol in recon JSON (exports/endpoints/sinks)")
    p_recon_match.add_argument("--symbol", "-s", required=True, help="Symbol/API name to search")
    p_recon_match.add_argument("--recon-file", default="recon_output.json", help="Path to recon JSON (default: recon_output.json)")
    p_recon_match.set_defaults(func=cmd_tools.run_recon_symbol_match)

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify exploitability using traces and optional PoC (LLM agent)")
    p_verify.add_argument("--repo", required=True)
    p_verify.add_argument("--traces", required=True, help="Trace/find output JSON or JSONL")
    p_verify.add_argument("--bundle", default="", help="Vulnerability bundle directory (optional; same role as vfind)")
    p_verify.add_argument("--recon", default="", help="Recon JSON path (optional; recommended for symbol match)")
    p_verify.add_argument("--poc", help="PoC file or directory (optional)")
    p_verify.add_argument("--out")
    p_verify.add_argument("--format", default="json", choices=["json", "jsonl", "sqlite"])
    p_verify.add_argument(
        "--agent-mode",
        default="langchain",
        choices=["langchain", "codex", "opencode"],
        help="Agent backend: langchain (default), codex, or opencode",
    )
    p_verify.add_argument("--dynamic", action="store_true")
    p_verify.add_argument("--timeout", type=int, default=30)
    p_verify.add_argument("--http-only-get", action="store_true")
    p_verify.set_defaults(func=cmd_verify.run)

    # all
    p_all = subparsers.add_parser("all", help="Run end-to-end pipeline")
    p_all.add_argument("--repo", required=True)
    p_all.add_argument("--bundle", required=True)
    p_all.add_argument("--lang", default="auto", choices=["auto", "py", "java"])
    p_all.add_argument("--out")
    p_all.add_argument("--format", default="json", choices=["json", "jsonl", "sqlite"])
    p_all.add_argument("--use-codeql", action="store_true")
    p_all.add_argument("--dynamic", action="store_true")
    p_all.set_defaults(func=cmd_all.run)

    return parser


def handle_list(args):
    print("Available commands:")
    for c in COMMANDS:
        print(f"- {c}")
    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        init_logging(level=getattr(args, "log_level", "info"))
        logging.debug("cli_start", extra={"command": args.command})
        rc = args.func(args)
        # If a command returns structured data, write it via unified writer
        if isinstance(rc, (dict, list)):
            out_path = getattr(args, "out", None) if hasattr(args, "out") else None
            fmt = getattr(args, "format", "jsonl") if hasattr(args, "format") else "jsonl"
            write_out(rc, out_path, fmt=fmt)
            return 0
        return rc if isinstance(rc, int) else 0
    except Exception as e:
        logging.exception("cli_error")
        print(f"Error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
