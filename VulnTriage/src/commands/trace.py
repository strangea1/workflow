"""
Trace finder CLI: LSP server and reference-backward call trace finding.

  trace lsp list        - list supported languages
  trace lsp start       - start LSP server (persistent with index caching)
  trace lsp stop        - stop persistent LSP server
  trace lsp status      - check LSP server status
  trace lsp refs        - query references at file:line (test LSP)
  trace find            - find call traces from sinks
"""

import json
import logging
import sys

from callmap.lsp import (
    get_server_status,
    list_languages,
    query_references,
    start_server,
    start_server_persistent,
    stop_server_persistent,
)
from callmap.trace import find_traces


def run_lsp_list(args):
    if getattr(args, "json", False):
        print(json.dumps({"languages": list_languages()}, indent=2, ensure_ascii=False))
        return 0
    print("Supported languages (LSP-based trace finding):")
    for L in list_languages():
        print(f"  {L['id']}: {L['name']} (LSP: {L['lsp']})")
    return 0


def run_lsp_start(args):
    """Start persistent LSP server with index caching."""
    repo = getattr(args, "repo", None)
    lang = getattr(args, "lang", None)
    cache_dir = getattr(args, "cache_dir", None)
    foreground = getattr(args, "foreground", True)
    if not repo or not lang:
        print(
            "Usage: trace lsp start --repo REPO --lang LANG [--cache-dir DIR] [--no-foreground]",
            file=sys.stderr,
        )
        return 2

    print(f"Starting LSP server for {repo} (lang={lang})...", file=sys.stderr)
    print(
        "This may take a while for initial indexing on large projects.", file=sys.stderr
    )

    result = start_server_persistent(
        repo=repo,
        lang=lang,
        cache_dir=cache_dir,
        wait_for_index=True,
    )

    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if not result.get("ok"):
            return 1
    elif result.get("ok"):
        if result.get("reused"):
            print(f"LSP server already running (PID={result.get('pid')})")
        else:
            print(f"LSP server started successfully:")
            print(f"  PID: {result.get('pid')}")
            print(f"  Data dir: {result.get('data_dir')}")
            print(f"  Init time: {result.get('init_time_seconds', 0):.2f}s")
            if result.get("indexing_time_seconds") is not None:
                print(f"  Indexing time: {result.get('indexing_time_seconds', 0):.2f}s")
    else:
        print(f"Error: {result.get('error', 'Unknown error')}", file=sys.stderr)
        return 1

    if not result.get("ok"):
        return 1

    # Keep server running in foreground mode
    if foreground:
        print("\nServer is running. Press Ctrl+C to stop.", file=sys.stderr)
        print("In another terminal, run 'trace find' to analyze.", file=sys.stderr)
        try:
            import time

            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping LSP server...", file=sys.stderr)
            from callmap.lsp import stop_server_persistent

            stop_server_persistent(repo=repo, lang=lang, cache_dir=cache_dir)
            print("Server stopped.", file=sys.stderr)
    else:
        print("\nServer is ready for trace analysis. Run 'trace find' to analyze.")

    return 0


def run_lsp_stop(args):
    """Stop persistent LSP server."""
    repo = getattr(args, "repo", None)
    lang = getattr(args, "lang", None)
    cache_dir = getattr(args, "cache_dir", None)
    if not repo or not lang:
        print(
            "Usage: trace lsp stop --repo REPO --lang LANG [--cache-dir DIR]",
            file=sys.stderr,
        )
        return 2

    result = stop_server_persistent(repo=repo, lang=lang, cache_dir=cache_dir)

    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result.get("ok") else 1

    print(result.get("message", "Done."))
    return 0


def run_lsp_status(args):
    """Check LSP server status."""
    repo = getattr(args, "repo", None)
    lang = getattr(args, "lang", None)
    cache_dir = getattr(args, "cache_dir", None)
    if not repo or not lang:
        print(
            "Usage: trace lsp status --repo REPO --lang LANG [--cache-dir DIR]",
            file=sys.stderr,
        )
        return 2

    result = get_server_status(repo=repo, lang=lang, cache_dir=cache_dir)

    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    if result.get("running"):
        print(f"LSP server is RUNNING")
        print(f"  PID: {result.get('pid')}")
        print(f"  Data dir: {result.get('data_dir')}")
        if result.get("note"):
            print(f"  Note: {result.get('note')}")
    else:
        print(f"LSP server is NOT RUNNING")
        print(f"  Data dir: {result.get('data_dir')}")
        if result.get("index_exists"):
            print(f"  Index cache exists (will speed up next start)")
        else:
            print(f"  No index cache found")
    return 0


def run_lsp_refs(args):
    """Query LSP references at (file, line); used to verify LSP is working."""
    repo = getattr(args, "repo", None)
    lang = getattr(args, "lang", "py")
    file_path = getattr(args, "file", None)
    line = getattr(args, "line", None)
    if not repo or not file_path or line is None:
        print(
            "Usage: trace lsp refs --repo REPO --file PATH --line N [--lang py|java] [--character N]",
            file=sys.stderr,
        )
        return 2
    line = int(line)
    character = int(getattr(args, "character", 0))
    result = query_references(
        repo=repo,
        file_path=file_path,
        line=line,
        character=character,
        lang=lang,
        include_declaration=getattr(args, "include_declaration", False),
    )
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result.get("ok") else 1
    if not result.get("ok"):
        print(result.get("error", "Unknown error"), file=sys.stderr)
        return 1
    refs = result.get("references", [])
    print(f"References at {file_path}:{line} (lang={lang}): {len(refs)}")
    for r in refs:
        print(f"  {r.get('file', r.get('uri', ''))}:{r.get('line', '?')}")
    return 0


def run_find(args):
    repo = getattr(args, "repo", None)
    sinks = getattr(args, "sinks", None)
    recon = getattr(args, "recon", None)
    lang = getattr(args, "lang", "auto")
    backend = getattr(args, "backend", "lsp")
    max_depth = int(getattr(args, "max_depth", 20))
    cache_dir = getattr(args, "cache_dir", None)
    codeql_db = getattr(args, "codeql_db", None)
    codeql_image = getattr(args, "codeql_image", None)
    codeql_fallback_lsp = bool(getattr(args, "codeql_fallback_lsp", True))
    if not repo or not sinks or not recon:
        logging.error("trace find requires --repo, --sinks, --recon")
        return 2
    result = find_traces(
        repo=repo,
        sinks_path=sinks,
        recon_path=recon,
        lang=lang,
        max_depth=max_depth,
        backend=backend,
        cache_dir=cache_dir,
        codeql_db=codeql_db,
        codeql_image=codeql_image,
        codeql_fallback_lsp=codeql_fallback_lsp,
    )
    if not result.get("ok"):
        logging.error("trace find failed: %s", result.get("error"))
        return 1
    return result


def build_parser(subparsers):
    p_trace = subparsers.add_parser(
        "trace", help="LSP-based call trace: list languages, start server, find traces"
    )
    trace_sub = p_trace.add_subparsers(dest="trace_subcommand", required=True)

    p_lsp = trace_sub.add_parser(
        "lsp", help="LSP server: list languages, start/stop server"
    )
    lsp_sub = p_lsp.add_subparsers(dest="lsp_subcommand", required=True)

    # lsp list
    p_list = lsp_sub.add_parser("list", help="List supported languages")
    p_list.add_argument("--json", action="store_true")
    p_list.set_defaults(func=run_lsp_list)

    # lsp start - persistent server with index caching
    p_start = lsp_sub.add_parser(
        "start", help="Start persistent LSP server with index caching"
    )
    p_start.add_argument("--repo", required=True, help="Repository root path")
    p_start.add_argument("--lang", required=True, help="Language id (e.g. py, java)")
    p_start.add_argument("--cache-dir", help="Custom cache directory for index storage")
    p_start.add_argument(
        "--no-foreground",
        dest="foreground",
        action="store_false",
        help="Don't keep server running in foreground (exits immediately)",
    )
    p_start.add_argument("--json", action="store_true")
    p_start.set_defaults(func=run_lsp_start, foreground=True)

    # lsp stop - stop persistent server
    p_stop = lsp_sub.add_parser("stop", help="Stop persistent LSP server")
    p_stop.add_argument("--repo", required=True, help="Repository root path")
    p_stop.add_argument("--lang", required=True, help="Language id (e.g. py, java)")
    p_stop.add_argument("--cache-dir", help="Custom cache directory")
    p_stop.add_argument("--json", action="store_true")
    p_stop.set_defaults(func=run_lsp_stop)

    # lsp status - check server status
    p_status = lsp_sub.add_parser("status", help="Check LSP server status")
    p_status.add_argument("--repo", required=True, help="Repository root path")
    p_status.add_argument("--lang", required=True, help="Language id (e.g. py, java)")
    p_status.add_argument("--cache-dir", help="Custom cache directory")
    p_status.add_argument("--json", action="store_true")
    p_status.set_defaults(func=run_lsp_status)

    # lsp refs - test references query
    p_refs = lsp_sub.add_parser("refs", help="Query references at file:line (test LSP)")
    p_refs.add_argument("--repo", required=True, help="Repository root path")
    p_refs.add_argument(
        "--file", required=True, help="File path (relative to repo or absolute)"
    )
    p_refs.add_argument("--line", required=True, type=int, help="Line number (1-based)")
    p_refs.add_argument(
        "--character",
        type=int,
        default=0,
        help="Character offset in line (0-based); put cursor on symbol",
    )
    p_refs.add_argument("--lang", default="py", help="Language id (py or java)")
    p_refs.add_argument(
        "--include-declaration",
        action="store_true",
        help="Include declaration in results",
    )
    p_refs.add_argument("--json", action="store_true")
    p_refs.set_defaults(func=run_lsp_refs)

    # find - find call traces
    p_find = trace_sub.add_parser("find", help="Find call traces from sinks")
    p_find.add_argument("--repo", required=True, help="Repository root path")
    p_find.add_argument(
        "--sinks", required=True, help="Path to sinks file (e.g. vfind output)"
    )
    p_find.add_argument("--recon", required=True, help="Path to recon result file")
    p_find.add_argument("--lang", default="auto", help="Language id or auto")
    p_find.add_argument(
        "--backend",
        default="lsp",
        choices=["lsp", "codeql"],
        help="Caller-resolution backend: lsp (default) or codeql",
    )
    p_find.add_argument(
        "--max-depth",
        type=int,
        default=20,
        help="Max reference-backward depth per sink (default 20)",
    )
    p_find.add_argument(
        "--cache-dir",
        help="Custom cache directory for index storage (use same dir as lsp start)",
    )
    p_find.add_argument(
        "--codeql-db", help="CodeQL database path (used when --backend codeql)"
    )
    p_find.add_argument(
        "--codeql-image", help="CodeQL docker image tag (used when --backend codeql)"
    )
    p_find.add_argument(
        "--no-codeql-fallback-lsp",
        dest="codeql_fallback_lsp",
        action="store_false",
        help="Disable fallback to LSP when codeql backend is not fully configured",
    )
    p_find.add_argument("--out", help="Output file path")
    p_find.add_argument("--format", default="json", choices=["json", "jsonl", "sqlite"])
    p_find.set_defaults(func=run_find, codeql_fallback_lsp=True)

    return p_trace
