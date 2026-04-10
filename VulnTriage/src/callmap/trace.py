"""
Trace: reference-backward call trace from sinks using LSP + tree-sitter.

- find_traces: load sinks + recon, call extract_traces, return trace chains.
- extract_traces: from each sink, use tree-sitter to locate containing function/class,
  then LSP references to find callers, recursively trace upward.

Key design:
- LSP server: for querying cross-file references (textDocument/references)
- tree-sitter: for accurate AST parsing to locate symbols (function, class, method, etc.)
  containing a given position
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from callmap.ast import (
    SYMBOL_TYPE_CONSTRUCTOR,
    SYMBOL_TYPE_FUNCTION,
    SYMBOL_TYPE_METHOD,
    AstParser,
    SymbolInfo,
    get_parser,
)
from callmap.backends import CodeQLTraceBackend, LspTraceBackend, TraceBackend
from callmap.lsp import path_to_uri, uri_to_path


def _norm_line(sink: Dict[str, Any]) -> int:
    """Normalize sink line number (ensure >= 1)."""
    line = sink.get("line", 1)
    return max(1, int(line))


def _norm_character(sink: Dict[str, Any]) -> int:
    """Get character/column from sink (default 0)."""
    c = sink.get("character")
    if c is not None:
        return int(c)
    return 0


def _resolve_sink_file(sink: Dict[str, Any], repo_path: Path) -> Optional[Path]:
    """Resolve sink file path to absolute path."""
    f = sink.get("file") or sink.get("path")
    if not f:
        return None
    p = Path(f)
    if not p.is_absolute():
        p = repo_path / p
    return p.resolve() if p.exists() else None


def _lang_from_sinks(sinks: List[Dict[str, Any]], repo_path: Path) -> str:
    """Infer language from first sink file extension."""
    for s in sinks:
        p = _resolve_sink_file(s, repo_path)
        if p and p.suffix in (".py", ".java"):
            return "py" if p.suffix == ".py" else "java"
    return "py"


def _is_callable_type(sym: SymbolInfo) -> bool:
    """Check if symbol is a callable (function/method/constructor)."""
    return sym.symbol_type in (
        SYMBOL_TYPE_FUNCTION,
        SYMBOL_TYPE_METHOD,
        SYMBOL_TYPE_CONSTRUCTOR,
    )


class TraceExtractor:
    """
    Extract backward call traces from sink points.

    Uses:
    - tree-sitter for parsing source and locating containing symbols
    - LSP for finding cross-file references

    Supports:
    - Reusing an already started persistent LSP server (via registry)
    - Custom cache directory for index persistence
    """

    def __init__(
        self,
        repo_path: Path,
        lang: str,
        backend: TraceBackend,
    ):
        """
        Initialize TraceExtractor.

        Args:
            repo_path: Path to repository root
            lang: Language id ("py" or "java")
            backend: caller-resolution backend (LSP, CodeQL, ...)
        """
        self.repo_path = repo_path
        self.lang = lang
        self.lang_id = "python" if lang == "py" else "java"
        self.backend = backend
        self._backend_init_error: Optional[str] = None

        # Initialize tree-sitter parser
        self.ast_parser: AstParser = get_parser(lang)

        # Cache for file contents and parsed trees
        self._file_cache: Dict[str, str] = {}  # path -> content
        self._opened_uris: Set[str] = set()

    def _init_backend(self) -> bool:
        ok = self.backend.initialize()
        if not ok:
            self._backend_init_error = (
                self.backend.get_last_error()
                or f"backend '{self.backend.name}' initialization failed"
            )
        return ok

    def _close_backend(self):
        self.backend.close()

    def _read_file(self, file_path: Path) -> Optional[str]:
        """Read file content with caching."""
        key = str(file_path)
        if key not in self._file_cache:
            try:
                self._file_cache[key] = file_path.read_text(
                    encoding="utf-8", errors="replace"
                )
            except Exception as e:
                logging.debug("TraceExtractor: read_file %s: %s", file_path, e)
                return None
        return self._file_cache[key]

    def _ensure_backend_open(self, file_uri: str, file_path: Path) -> bool:
        """Ensure file content is provided to backend when required (e.g. LSP didOpen)."""
        if file_uri in self._opened_uris:
            return True
        content = self._read_file(file_path)
        if content is None:
            return False
        if not self.backend.did_open(file_uri, self.lang_id, content):
            return False
        self._opened_uris.add(file_uri)
        return True

    def _find_symbol_at_position(
        self,
        file_path: Path,
        line_0: int,
        col_0: int,
        prefer_callable: bool = True,
    ) -> Optional[SymbolInfo]:
        """
        Use tree-sitter to find the symbol containing position (line_0, col_0).

        Args:
            file_path: Path to source file
            line_0: 0-based line number
            col_0: 0-based column number
            prefer_callable: If True, prefer function/method over class/variable

        Returns:
            SymbolInfo or None
        """
        content = self._read_file(file_path)
        if content is None:
            return None

        if prefer_callable:
            return self.ast_parser.find_enclosing_callable_from_text(
                content, line_0, col_0
            )
        else:
            return self.ast_parser.find_symbol_at_position_from_text(
                content, line_0, col_0
            )

    def _make_symbol_key(
        self, file_uri: str, sym: Optional[SymbolInfo]
    ) -> Tuple[str, int, int]:
        """Create a unique key for a symbol to track visited nodes."""
        if sym:
            return (file_uri, sym.start_line, sym.start_column)
        return (file_uri, -1, -1)

    def extract(
        self,
        sinks: List[Dict[str, Any]],
        max_depth: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        Extract backward call traces for all sinks.

        For each sink:
        1. Use tree-sitter to find the containing function/method
        2. Query LSP for references to that function
        3. For each reference, find its containing function using tree-sitter
        4. Recursively trace upward until no more refs or max_depth

        Returns list of trace results, one per sink.
        """
        if not self._init_backend():
            raise RuntimeError(
                self._backend_init_error or "trace backend initialize failed"
            )

        traces_out: List[Dict[str, Any]] = []

        try:
            for sink in sinks:
                trace = self._extract_single_sink(sink, max_depth)
                if trace:
                    traces_out.append(trace)
        finally:
            self._close_backend()

        return traces_out

    def _extract_single_sink(
        self,
        sink: Dict[str, Any],
        max_depth: int,
    ) -> Optional[Dict[str, Any]]:
        """Extract trace for a single sink using DFS to generate all distinct paths."""
        fp = _resolve_sink_file(sink, self.repo_path)
        if not fp:
            return None

        line_1 = _norm_line(sink)
        char_0 = _norm_character(sink)
        line_0 = max(0, line_1 - 1)
        file_uri = path_to_uri(str(fp))

        if not self._ensure_backend_open(file_uri, fp):
            return None

        # Find the containing function/method at sink position using tree-sitter
        sink_sym = self._find_symbol_at_position(
            fp, line_0, char_0, prefer_callable=True
        )

        if not sink_sym:
            logging.debug("extract_single_sink: no symbol found at %s:%d", fp, line_1)
            sink_sym = SymbolInfo(
                name=sink.get("function") or f"L{line_1}",
                symbol_type="unknown",
                start_line=line_0,
                start_column=char_0,
                end_line=line_0,
                end_column=char_0,
            )

        # All collected paths
        all_paths: List[List[Dict[str, Any]]] = []

        # Cache for references to avoid redundant LSP calls
        refs_cache: Dict[Tuple[str, int, int], List[Dict[str, Any]]] = {}

        def _sym_to_node(sym: SymbolInfo, path: Path, is_sink: bool) -> Dict[str, Any]:
            """Convert SymbolInfo to output node dict."""
            return {
                "file": str(path),
                "line": sym.start_line + 1,
                "character": sym.start_column,
                "symbol_name": sym.name,
                "symbol_type": sym.symbol_type,
                "is_sink": is_sink,
            }

        def _get_callers(
            uri: str, sym: SymbolInfo, file_path: Path
        ) -> List[Tuple[Path, str, SymbolInfo]]:
            """Get all callers of a symbol, with caching."""
            query_line = sym.name_line if sym.name_line is not None else sym.start_line
            query_col = (
                sym.name_column if sym.name_column is not None else sym.start_column
            )
            cache_key = (uri, query_line, query_col)

            if cache_key in refs_cache:
                refs = refs_cache[cache_key]
            else:
                logging.info(
                    "Querying refs for: %s (%s:%d:%d)",
                    sym.name,
                    file_path.name,
                    query_line + 1,
                    query_col,
                )
                refs = self.backend.references(uri, query_line, query_col, sym.name)
                refs_cache[cache_key] = refs

            callers: List[Tuple[Path, str, SymbolInfo]] = []
            for ref in refs:
                if "uri" not in ref or "range" not in ref:
                    continue

                ref_uri = ref["uri"]
                r = ref["range"]
                start = r.get("start") or {}
                ref_line_0 = start.get("line", 0)
                ref_col_0 = start.get("character", 0)

                # Skip self-reference (compare with name position, not declaration start)
                sym_name_line = (
                    sym.name_line if sym.name_line is not None else sym.start_line
                )
                if ref_uri == uri and ref_line_0 == sym_name_line:
                    continue

                ref_path_str = uri_to_path(ref_uri)
                ref_path = Path(ref_path_str)

                if not self._ensure_backend_open(ref_uri, ref_path):
                    continue

                caller_sym = self._find_symbol_at_position(
                    ref_path, ref_line_0, ref_col_0, prefer_callable=True
                )

                if not caller_sym:
                    caller_sym = SymbolInfo(
                        name=f"L{ref_line_0 + 1}",
                        symbol_type="unknown",
                        start_line=ref_line_0,
                        start_column=ref_col_0,
                        end_line=ref_line_0,
                        end_column=ref_col_0,
                    )

                callers.append((ref_path, ref_uri, caller_sym))

            logging.debug(
                "_get_callers: %s has %d callers (from %d refs)",
                sym.name,
                len(callers),
                len(refs),
            )
            return callers

        def _dfs(
            file_path: Path,
            uri: str,
            sym: SymbolInfo,
            current_path: List[Dict[str, Any]],
            visited_in_path: Set[Tuple[str, int, int]],
            depth: int,
        ) -> None:
            """DFS to explore all paths from sink to callers."""
            sym_key = self._make_symbol_key(uri, sym)

            # Avoid cycles within the same path
            if sym_key in visited_in_path:
                logging.debug("[DFS depth=%d] Skipping cycle: %s", depth, sym.name)
                return

            # Depth limit
            if depth > max_depth:
                # Save path ending here (before adding current node)
                logging.debug(
                    "[DFS depth=%d] Max depth reached, saving path with %d nodes",
                    depth,
                    len(current_path),
                )
                if current_path:
                    all_paths.append(list(current_path))
                return

            # Add current node to path
            is_sink = depth == 0
            node = _sym_to_node(sym, file_path, is_sink)
            current_path.append(node)
            visited_in_path.add(sym_key)
            logging.debug(
                "[DFS depth=%d] Added: %s, path_len=%d",
                depth,
                sym.name,
                len(current_path),
            )

            # Get callers
            callers = _get_callers(uri, sym, file_path)

            if not callers:
                # No more callers - this is a complete path (reached an entry point)
                logging.info(
                    "[DFS depth=%d] No callers, saving path with %d nodes",
                    depth,
                    len(current_path),
                )
                all_paths.append(list(current_path))
            else:
                # Continue DFS for each caller
                logging.debug(
                    "[DFS depth=%d] %d callers to explore", depth, len(callers)
                )
                # Track if any caller leads to a valid path (not all cycles)
                valid_callers = 0
                for caller_path, caller_uri, caller_sym in callers:
                    caller_key = self._make_symbol_key(caller_uri, caller_sym)
                    if caller_key not in visited_in_path:
                        valid_callers += 1
                        _dfs(
                            caller_path,
                            caller_uri,
                            caller_sym,
                            current_path,
                            visited_in_path,
                            depth + 1,
                        )

                # If all callers were cycles, save current path as endpoint
                if valid_callers == 0:
                    logging.info(
                        "[DFS depth=%d] All callers are cycles, saving path with %d nodes",
                        depth,
                        len(current_path),
                    )
                    all_paths.append(list(current_path))

            # Backtrack
            current_path.pop()
            visited_in_path.discard(sym_key)

        # Start DFS from sink
        _dfs(fp, file_uri, sink_sym, [], set(), 0)

        if not all_paths:
            return None

        return {
            "sink_file": str(fp),
            "sink_line": line_1,
            "paths": all_paths,
        }


def extract_traces(
    repo: str,
    sinks: List[Dict[str, Any]],
    recon: Dict[str, Any],
    *,
    lang: str = "auto",
    max_depth: int = 20,
    backend: str = "lsp",
    cache_dir: Optional[str] = None,
    reuse_server: bool = True,
    codeql_db: Optional[str] = None,
    codeql_image: Optional[str] = None,
    codeql_fallback_lsp: bool = True,
) -> List[Dict[str, Any]]:
    """
    Extract backward call traces from sinks using LSP + tree-sitter.

    Args:
        repo: Path to repository root
        sinks: List of sink definitions with file, line, character
        recon: Recon data (for future use)
        lang: Language ("py", "java", or "auto")
        max_depth: Maximum recursion depth
        backend: caller backend (lsp or codeql)
        cache_dir: Optional custom cache directory for LSP index
        reuse_server: If True, try to reuse an already running server
        codeql_db: optional CodeQL DB path for codeql backend
        codeql_image: optional docker image tag for codeql backend
        codeql_fallback_lsp: allow codeql backend to fallback to lsp

    Returns:
        List of trace results, each containing sink info and call chain.
    """
    repo_path = Path(repo).resolve()
    if not repo_path.is_dir():
        return []

    if lang == "auto":
        lang = _lang_from_sinks(sinks, repo_path)

    if backend == "codeql":
        trace_backend = CodeQLTraceBackend(
            repo_path,
            lang,
            cache_dir=cache_dir,
            reuse_server=reuse_server,
            codeql_db=codeql_db,
            codeql_image=codeql_image,
            fallback_to_lsp=codeql_fallback_lsp,
        )
    else:
        trace_backend = LspTraceBackend(
            repo_path,
            lang,
            cache_dir=cache_dir,
            reuse_server=reuse_server,
        )

    extractor = TraceExtractor(
        repo_path,
        lang,
        backend=trace_backend,
    )
    return extractor.extract(sinks, max_depth=max_depth)


def find_traces(
    repo: str,
    sinks_path: str,
    recon_path: str,
    *,
    lang: str = "auto",
    max_depth: int = 20,
    backend: str = "lsp",
    cache_dir: Optional[str] = None,
    reuse_server: bool = True,
    codeql_db: Optional[str] = None,
    codeql_image: Optional[str] = None,
    codeql_fallback_lsp: bool = True,
) -> Dict[str, Any]:
    """
    Load sinks and recon from files, run extract_traces, return result.

    Args:
        repo: Path to repository root
        sinks_path: Path to sinks JSON file
        recon_path: Path to recon JSON file
        lang: Language ("py", "java", or "auto")
        max_depth: Maximum recursion depth
        backend: caller backend (lsp or codeql)
        cache_dir: Optional custom cache directory for LSP index
        reuse_server: If True, try to reuse an already running server
        codeql_db: optional CodeQL DB path for codeql backend
        codeql_image: optional docker image tag for codeql backend
        codeql_fallback_lsp: allow codeql backend to fallback to lsp

    Returns:
        Dict with ok, traces, and metadata.
    """
    repo_p = Path(repo)
    sinks_f = Path(sinks_path)
    recon_f = Path(recon_path)

    if not repo_p.is_dir():
        return {"ok": False, "error": f"Repo not found: {repo}", "traces": []}
    if not sinks_f.exists():
        return {
            "ok": False,
            "error": f"Sinks file not found: {sinks_path}",
            "traces": [],
        }
    if not recon_f.exists():
        return {
            "ok": False,
            "error": f"Recon file not found: {recon_path}",
            "traces": [],
        }

    try:
        with open(sinks_f, "r", encoding="utf-8") as f:
            sinks_data = json.load(f)
        sinks = sinks_data.get("sinks", []) if isinstance(sinks_data, dict) else []
    except Exception as e:
        logging.warning("find_traces load sinks: %s", e)
        sinks = []

    try:
        with open(recon_f, "r", encoding="utf-8") as f:
            recon_data = json.load(f)
    except Exception as e:
        logging.warning("find_traces load recon: %s", e)
        recon_data = {}

    if not sinks:
        return {
            "ok": True,
            "repo": str(repo_p),
            "sinks_file": str(sinks_f),
            "recon_file": str(recon_path),
            "sinks_loaded": 0,
            "traces": [],
        }

    logging.info(
        "find_traces repo=%s sinks_count=%s lang=%s backend=%s cache_dir=%s",
        repo,
        len(sinks),
        lang,
        backend,
        cache_dir,
    )
    try:
        traces = extract_traces(
            str(repo_p),
            sinks,
            recon_data,
            lang=lang,
            max_depth=max_depth,
            backend=backend,
            cache_dir=cache_dir,
            reuse_server=reuse_server,
            codeql_db=codeql_db,
            codeql_image=codeql_image,
            codeql_fallback_lsp=codeql_fallback_lsp,
        )
    except Exception as e:
        return {
            "ok": False,
            "repo": str(repo_p),
            "sinks_file": str(sinks_f),
            "recon_file": str(recon_path),
            "sinks_loaded": len(sinks),
            "backend": backend,
            "error": str(e),
            "traces": [],
        }

    return {
        "ok": True,
        "repo": str(repo_p),
        "sinks_file": str(sinks_f),
        "recon_file": str(recon_path),
        "sinks_loaded": len(sinks),
        "backend": backend,
        "traces": traces,
    }
