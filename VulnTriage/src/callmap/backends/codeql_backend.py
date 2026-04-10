import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from callmap.backends.base import TraceBackend
from callmap.backends.lsp_backend import LspTraceBackend


class CodeQLTraceBackend(TraceBackend):
    """
    CodeQL-backed backend interface.

    Current stage:
    - Java only
    - Multi-backend wiring is ready
    - Caller discovery currently falls back to LSP when enabled
    """

    def __init__(
        self,
        repo_path: Path,
        lang: str,
        *,
        cache_dir: Optional[str] = None,
        reuse_server: bool = True,
        codeql_db: Optional[str] = None,
        codeql_image: Optional[str] = None,
        fallback_to_lsp: bool = True,
    ):
        self.repo_path = repo_path
        self.lang = lang
        self.codeql_db = codeql_db
        self.codeql_image = codeql_image
        self.fallback_to_lsp = fallback_to_lsp
        self._last_error: Optional[str] = None
        self._lsp_fallback_initialized = False

        self._lsp_fallback = None
        if fallback_to_lsp:
            self._lsp_fallback = LspTraceBackend(
                repo_path=repo_path,
                lang=lang,
                cache_dir=cache_dir,
                reuse_server=reuse_server,
            )

    @property
    def name(self) -> str:
        return "codeql"

    def initialize(self) -> bool:
        self._last_error = None
        if self.lang != "java":
            self._last_error = (
                f"CodeQL backend currently supports only java, got lang={self.lang}"
            )
            logging.error(self._last_error)
            return False

        if self.codeql_db and self.codeql_image:
            logging.info(
                "CodeQL backend configured with db=%s image=%s",
                self.codeql_db,
                self.codeql_image,
            )
            return True

        # No image/db provided: try to auto-generate by running fix-compile Java pipeline.
        if not (self.codeql_db and self.codeql_image):
            try:
                from callmap.codeql import CodeQLConfig, CodeQLRunner

                logging.info(
                    "CodeQL backend: --codeql-db/--codeql-image not provided, auto-building with fix-compile for repo=%s",
                    self.repo_path,
                )
                result = CodeQLRunner().build_database(
                    CodeQLConfig(
                        project_dir=str(self.repo_path),
                        no_fix=True,
                    )
                )
                if result.success and result.db_path and result.image_tag:
                    self.codeql_db = result.db_path
                    self.codeql_image = result.image_tag
                    logging.info(
                        "CodeQL backend auto-build succeeded: db=%s image=%s",
                        self.codeql_db,
                        self.codeql_image,
                    )
                else:
                    self._last_error = (
                        result.error
                        or "CodeQL backend auto-build failed (see fix-compile logs)"
                    )
            except Exception as exc:
                self._last_error = f"CodeQL backend auto-build exception: {exc}"
                logging.exception(self._last_error)

        if self.codeql_db and self.codeql_image:
            logging.info(
                "CodeQL backend configured with db=%s image=%s",
                self.codeql_db,
                self.codeql_image,
            )
            return True

        if self._lsp_fallback:
            logging.warning(
                "CodeQL backend unavailable (%s); falling back to LSP caller resolution",
                self._last_error or "missing db/image",
            )
            self._lsp_fallback_initialized = self._lsp_fallback.initialize()
            return self._lsp_fallback_initialized

        if not self._last_error:
            self._last_error = "CodeQL backend requires --codeql-db and --codeql-image when fallback is disabled"
        logging.error(self._last_error)
        return False

    def close(self) -> None:
        if self._lsp_fallback:
            self._lsp_fallback.close()
            self._lsp_fallback_initialized = False

    def did_open(self, file_uri: str, lang_id: str, content: str) -> bool:
        if self.codeql_db and self.codeql_image:
            return True
        if self._lsp_fallback:
            if not self._lsp_fallback_initialized:
                self._lsp_fallback_initialized = self._lsp_fallback.initialize()
                if not self._lsp_fallback_initialized:
                    return False
            return self._lsp_fallback.did_open(file_uri, lang_id, content)
        return True

    def references(
        self,
        file_uri: str,
        line_0: int,
        col_0: int,
        symbol_name: str = "",
    ) -> List[Dict[str, Any]]:
        if self.codeql_db and self.codeql_image:
            logging.warning(
                "CodeQL caller query adapter is not implemented yet for symbol=%s at %s:%d:%d",
                symbol_name or "?",
                file_uri,
                line_0 + 1,
                col_0,
            )
            return []

        if self._lsp_fallback:
            return self._lsp_fallback.references(file_uri, line_0, col_0, symbol_name)
        return []

    def get_last_error(self) -> Optional[str]:
        return self._last_error
