"""
Call trace: LSP-based reference-backward tracing from sinks to entrypoints,
plus CodeQL-based call-graph support for Java projects.

- LSP: get_server(lang), list_languages, start_server, query_references.
- Persistent LSP: start_server_persistent, stop_server_persistent, get_server_status.
- Trace: find_traces, extract_traces.
- CodeQL: CodeQLRunner, CodeQLConfig, CodeQLResult, CodeQLQueryResult.
"""

from callmap.backends import CodeQLTraceBackend, LspTraceBackend, TraceBackend
from callmap.codeql import CodeQLConfig, CodeQLQueryResult, CodeQLResult, CodeQLRunner
from callmap.lsp import (
    SUPPORTED_LANGUAGES,
    get_registered_server,
    get_server,
    get_server_status,
    list_languages,
    query_references,
    start_server,
    start_server_persistent,
    stop_server_persistent,
)
from callmap.trace import extract_traces, find_traces

__all__ = [
    "SUPPORTED_LANGUAGES",
    "list_languages",
    "start_server",
    "start_server_persistent",
    "stop_server_persistent",
    "get_server_status",
    "get_server",
    "get_registered_server",
    "query_references",
    "find_traces",
    "extract_traces",
    # CodeQL
    "CodeQLRunner",
    "CodeQLConfig",
    "CodeQLResult",
    "CodeQLQueryResult",
    # Trace backends
    "TraceBackend",
    "LspTraceBackend",
    "CodeQLTraceBackend",
]
