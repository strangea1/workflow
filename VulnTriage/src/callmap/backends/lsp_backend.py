import logging
import time as _time
from pathlib import Path
from typing import Any, Dict, List, Optional

from callmap.backends.base import TraceBackend
from callmap.lsp import (
    get_registered_server,
    get_server,
    get_workspace_data_dir,
    path_to_uri,
)


class LspTraceBackend(TraceBackend):
    """LSP-backed implementation for cross-file reference discovery."""

    def __init__(
        self,
        repo_path: Path,
        lang: str,
        cache_dir: Optional[str] = None,
        reuse_server: bool = True,
    ):
        self.repo_path = repo_path
        self.lang = lang
        self.cache_dir = cache_dir
        self.reuse_server = reuse_server

        self._lsp_server = None
        self._lsp_initialized = False
        self._server_is_reused = False

    @property
    def name(self) -> str:
        return "lsp"

    def _get_server(self):
        if self._lsp_server is None:
            if self.reuse_server:
                server = get_registered_server(str(self.repo_path))
                if server and server.is_initialized():
                    logging.info(
                        "LspTraceBackend: reusing existing LSP server (PID=%s)",
                        server.get_pid(),
                    )
                    self._lsp_server = server
                    self._server_is_reused = True
                    return self._lsp_server

            data_dir = get_workspace_data_dir(
                str(self.repo_path), self.cache_dir, self.lang
            )
            logging.info("LspTraceBackend: using cache dir %s", data_dir)
            self._lsp_server = get_server(self.lang, data_dir)
            self._server_is_reused = False
        return self._lsp_server

    def initialize(self) -> bool:
        if self._lsp_initialized:
            return True

        server = self._get_server()
        if not server:
            logging.warning("LspTraceBackend: no LSP server for lang=%s", self.lang)
            return False

        if self._server_is_reused and server.is_initialized():
            self._lsp_initialized = True
            return True

        root_uri = path_to_uri(str(self.repo_path))
        if not server.initialize(root_uri):
            logging.warning("LspTraceBackend: LSP initialize failed")
            return False

        data_dir = get_workspace_data_dir(
            str(self.repo_path), self.cache_dir, self.lang
        )
        # JDT LS writes Eclipse .metadata/.log; wait_for_indexing polls for "build jobs finished".
        # Pyright has no such log — waiting with timeout=0 would block forever after initialize.
        if self.lang == "java":
            logging.info("LspTraceBackend: waiting for JDT LS indexing (.metadata/.log)...")
            if hasattr(server, "wait_for_indexing"):
                server.wait_for_indexing(timeout=0, data_dir=str(data_dir))
        else:
            logging.debug(
                "LspTraceBackend: skip indexing wait for lang=%s (not JDT LS)",
                self.lang,
            )

        self._lsp_initialized = True
        return True

    def close(self) -> None:
        if self._server_is_reused:
            logging.debug("LspTraceBackend: keeping reused server alive")
            self._lsp_initialized = False
            self._lsp_server = None
            return

        if self._lsp_server and self._lsp_initialized:
            try:
                self._lsp_server.close()
            except Exception:
                pass
        self._lsp_initialized = False
        self._lsp_server = None

    def did_open(self, file_uri: str, lang_id: str, content: str) -> bool:
        server = self._get_server()
        if not server:
            return False
        try:
            server.did_open(file_uri, lang_id, content)
            return True
        except Exception as e:
            logging.debug("LspTraceBackend: did_open %s: %s", file_uri, e)
            return False

    def references(
        self,
        file_uri: str,
        line_0: int,
        col_0: int,
        symbol_name: str = "",
    ) -> List[Dict[str, Any]]:
        server = self._get_server()
        if not server:
            return []

        start_ts = _time.time()
        refs = server.references(file_uri, line_0, col_0, include_declaration=True)
        elapsed_ms = (_time.time() - start_ts) * 1000

        file_short = file_uri.split("/")[-1] if "/" in file_uri else file_uri
        ref_count = len(refs) if refs else 0
        logging.info(
            "  refs[%s]: %s:%d:%d [%s] -> %d refs (%.0fms)",
            self.name,
            file_short,
            line_0 + 1,
            col_0,
            symbol_name or "?",
            ref_count,
            elapsed_ms,
        )
        return refs or []
