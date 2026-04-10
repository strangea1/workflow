from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class TraceBackend(ABC):
    """Abstract backend for cross-file caller discovery used by trace extraction."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Backend name (e.g. lsp, codeql)."""

    @abstractmethod
    def initialize(self) -> bool:
        """Initialize backend resources."""

    @abstractmethod
    def close(self) -> None:
        """Release backend resources."""

    @abstractmethod
    def references(
        self,
        file_uri: str,
        line_0: int,
        col_0: int,
        symbol_name: str = "",
    ) -> List[Dict[str, Any]]:
        """Return references in LSP-like shape: [{"uri", "range": {"start": {line, character}}}]."""

    def get_last_error(self) -> Optional[str]:
        """Return backend initialization/runtime error if any."""
        return None

    def did_open(self, file_uri: str, lang_id: str, content: str) -> bool:
        """Optional file-open hook used by LSP-like backends."""
        return True
