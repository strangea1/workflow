"""
callmap.codeql – CodeQL-based call graph support for Java projects.

Uses fix-compile (JavaCompileAgent) to:
  1. Build an isolated Docker environment with Java + CodeQL installed.
  2. Compile the Java project (with optional LLM auto-fix on failure).
  3. Create a CodeQL database via ``codeql database create``.
  4. Run the default query suite via ``codeql database analyze``.

The resulting Docker image and CodeQL database can later be used to run
arbitrary CodeQL queries for call-graph analysis.

Quick start::

    from callmap.codeql import CodeQLRunner, CodeQLConfig

    runner = CodeQLRunner()
    result = runner.build_database(CodeQLConfig(
        project_dir="/path/to/my-java-app",
        no_fix=True,          # skip LLM loop – no OPENAI_API_KEY needed
    ))

    if result.success:
        print("CodeQL DB :", result.db_path)
        print("SARIF     :", result.sarif_path)
        print("Image     :", result.image_tag)
"""

from callmap.codeql.runner import (
    CodeQLConfig,
    CodeQLQueryResult,
    CodeQLResult,
    CodeQLRunner,
)

__all__ = [
    "CodeQLRunner",
    "CodeQLConfig",
    "CodeQLResult",
    "CodeQLQueryResult",
]
