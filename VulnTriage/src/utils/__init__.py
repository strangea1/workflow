"""Shared helpers for LLM-backed agents (vfinder, verify, etc.)."""

from .agent_runtime import (
    build_llm_cli_env,
    cli_executable_exists,
    llm_cli_parent_dirs_outside_project,
    merge_opencode_external_directory_allow,
    read_file_tool_root,
    resolve_path_for_cli_env,
    stream_subprocess_to_log,
)

__all__ = [
    "build_llm_cli_env",
    "cli_executable_exists",
    "llm_cli_parent_dirs_outside_project",
    "merge_opencode_external_directory_allow",
    "read_file_tool_root",
    "resolve_path_for_cli_env",
    "stream_subprocess_to_log",
]
