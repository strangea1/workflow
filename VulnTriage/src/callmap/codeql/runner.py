"""
CodeQL runner: uses fix-compile's JavaCompileAgent to build an isolated Docker
environment, compile a Java project with optional LLM auto-fix, create a CodeQL
database, and run the default query suite.

Public API
----------
- CodeQLConfig   – configuration dataclass
- CodeQLResult   – pipeline result dataclass
- CodeQLQueryResult – single-query result dataclass
- CodeQLRunner   – main runner class
  .build_database(cfg) -> CodeQLResult
  .run_query(image_tag, db_path, query, ...) -> CodeQLQueryResult
"""

import logging
import os
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

log = logging.getLogger(__name__)

# Container-side paths (must match fix-compile's java_fixer.py defaults)
_CONTAINER_RUNSTATE = "/workspace/runstate"
_CONTAINER_CODEQL_DB = f"{_CONTAINER_RUNSTATE}/codeql-db"
_CONTAINER_CODEQL_SARIF = f"{_CONTAINER_RUNSTATE}/codeql-result.sarif"


# ---------------------------------------------------------------------------
# Config / Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class CodeQLConfig:
    """Configuration for CodeQLRunner.build_database()."""

    project_dir: str
    """Absolute path of the Java project root."""

    compile_command: Optional[str] = None
    """Override auto-detected build command (shell string).  None = auto."""

    max_attempts: int = 3
    """Max LLM auto-fix attempts (ignored when no_fix=True)."""

    no_fix: bool = False
    """Disable LLM auto-fix loop.  Set True when OPENAI_API_KEY is unavailable."""

    force_rebuild: bool = False
    """Force rebuild of the Docker image even if one already exists."""

    m2_settings_file: Optional[str] = None
    """Optional path to a custom Maven settings.xml to mount read-only."""

    docker_run_args: List[str] = field(default_factory=list)
    """Extra args passed through to every ``docker run`` invocation."""

    passthrough_args: List[str] = field(default_factory=list)
    """Extra args appended to the compile command."""

    # CodeQL settings --------------------------------------------------------
    query_suite: str = "codeql/java-queries"
    """CodeQL query suite or path to analyse (JAVA_CODEQL_QUERY_SUITE)."""

    language: str = "java"
    """CodeQL language id (JAVA_CODEQL_LANGUAGE)."""

    # LLM / API settings (optional overrides) --------------------------------
    openai_api_key: Optional[str] = None
    """OpenAI-compatible API key.  Reads OPENAI_API_KEY env var when None."""

    openai_api_base: Optional[str] = None
    """API base URL override.  Reads OPENAI_API_BASE env var when None."""

    fixer_model: Optional[str] = None
    """LLM model name for the auto-fix loop.  Uses fix-compile default when None."""


@dataclass
class CodeQLResult:
    """Result of CodeQLRunner.build_database()."""

    success: bool
    image_tag: str
    """Docker image tag that contains CodeQL and the compiled project."""

    logs_dir: str
    """Host-side directory containing all run logs and artifacts."""

    db_path: Optional[str]
    """Host path to the CodeQL database directory (None if not created)."""

    sarif_path: Optional[str]
    """Host path to the SARIF output file (None if not produced)."""

    build_command: str
    """Final compile command used."""

    attempts: int
    """Number of compile attempts used."""

    error: Optional[str] = None
    """Error description when success=False."""


@dataclass
class CodeQLQueryResult:
    """Result of CodeQLRunner.run_query()."""

    success: bool
    output_path: Optional[str]
    """Host path to the query output file (BQRS or SARIF)."""

    stdout: str = ""
    stderr: str = ""


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class CodeQLRunner:
    """
    Builds a CodeQL database for a Java project using fix-compile's
    JavaCompileAgent.

    The runner delegates all Docker management, compile-error analysis, and
    LLM auto-fixing to ``fix_compile.JavaCompileAgent``.  It adds a thin
    adapter layer that translates fix-compile's config/result types into the
    callmap-friendly ``CodeQL*`` dataclasses, and resolves host-side artifact
    paths from inside-container paths.

    Usage::

        runner = CodeQLRunner()
        result = runner.build_database(CodeQLConfig(
            project_dir="/path/to/my-java-app",
            no_fix=True,       # no LLM key needed
        ))
        if result.success:
            print("DB:", result.db_path)
            print("SARIF:", result.sarif_path)
    """

    def build_database(self, cfg: CodeQLConfig) -> CodeQLResult:
        """
        Run compile + CodeQL database creation inside Docker.

        Builds (or reuses) a Docker image with Java + CodeQL, compiles the
        project with optional LLM error-fix loop, then runs::

            codeql database create ...
            codeql database analyze ...

        Returns a CodeQLResult.  On failure the ``error`` field is populated
        and ``success`` is False.
        """
        result = self._build_database_once(cfg)
        if result.success:
            return result

        if self._is_missing_template_error(result.error):
            local_src = self._find_local_fix_compile_src()
            if local_src:
                log.warning(
                    "fix-compile package assets missing; retrying with local source at %s",
                    local_src,
                )
                with self._prefer_fix_compile_source(local_src):
                    retried = self._build_database_once(cfg)
                    if retried.success:
                        return retried
                    return retried

        return result

    def _build_database_once(self, cfg: CodeQLConfig) -> CodeQLResult:
        try:
            from fix_compile import JavaCompileAgent, JavaFixConfig
            from fix_compile.config import Configs
        except ImportError as exc:
            raise ImportError(
                "fix-compile is required for CodeQL support. "
                "Install with: pip install 'fix-compile @ git+https://github.com/Dilrevx/fix-compile.git'"
            ) from exc

        api_key = self._resolve_api_key(cfg)

        config_overrides: dict = {
            "OPENAI_API_KEY": api_key,
            "JAVA_CODEQL_LANGUAGE": cfg.language,
            "JAVA_CODEQL_QUERY_SUITE": cfg.query_suite,
        }
        if cfg.openai_api_base:
            config_overrides["OPENAI_API_BASE"] = cfg.openai_api_base
        if cfg.fixer_model:
            config_overrides["FIXER_MODEL"] = cfg.fixer_model

        fix_config = Configs(**config_overrides)

        java_cfg = JavaFixConfig(
            project_dir=cfg.project_dir,
            docker_env=JavaFixConfig.DockerEnvConfig(
                use_docker=True,
                force_rebuild=cfg.force_rebuild,
                docker_run_args=cfg.docker_run_args,
                m2_settings_file=cfg.m2_settings_file,
            ),
            project_build=JavaFixConfig.ProjectBuildConfig(
                with_codeql=True,
                no_fix=cfg.no_fix,
                max_attempts=cfg.max_attempts,
                compile_command=cfg.compile_command,
                passthrough_args=cfg.passthrough_args,
            ),
        )

        agent = JavaCompileAgent(config=fix_config)
        try:
            fix_result = agent.run_pipeline(java_cfg)
        except Exception as exc:
            log.error("CodeQL pipeline error: %s", exc, exc_info=True)
            return CodeQLResult(
                success=False,
                image_tag="",
                logs_dir="",
                db_path=None,
                sarif_path=None,
                build_command="",
                attempts=0,
                error=str(exc),
            )

        logs_dir = Path(fix_result.logs_dir)
        db_host = logs_dir / "codeql-db"
        sarif_host = logs_dir / "codeql-result.sarif"

        return CodeQLResult(
            success=fix_result.success,
            image_tag=fix_result.image_tag,
            logs_dir=fix_result.logs_dir,
            db_path=db_host.as_posix() if db_host.exists() else None,
            sarif_path=sarif_host.as_posix() if sarif_host.exists() else None,
            build_command=fix_result.build_command,
            attempts=fix_result.attempts,
            error=None if fix_result.success else "Pipeline failed – see logs_dir",
        )

    def run_query(
        self,
        image_tag: str,
        db_path: str,
        query: str,
        output_path: Optional[str] = None,
        *,
        project_dir: Optional[str] = None,
        extra_docker_args: Optional[List[str]] = None,
    ) -> CodeQLQueryResult:
        """
        Run a CodeQL query (or suite) against an existing database inside the
        compiled Docker image.

        The database is mounted at its original ``/workspace/runstate/`` path
        inside the container.  Query output is written to a host-side file.

        Args:
            image_tag:         Docker image tag (from CodeQLResult.image_tag).
            db_path:           Host path to the CodeQL database directory.
            query:             Path to a ``.ql`` file *or* a query pack name
                               (e.g. ``codeql/java-queries``).
            output_path:       Host path for the result file.  Defaults to
                               ``<db_parent>/query-result.bqrs``.
            project_dir:       Java project root to mount.  Defaults to the
                               database's parent directory.
            extra_docker_args: Extra flags forwarded to ``docker run``.
        """
        try:
            from fix_compile.config import Configs
            from fix_compile.executor import Executor
        except ImportError as exc:
            raise ImportError("fix-compile is required for CodeQL support.") from exc

        db = Path(db_path).resolve()
        if not db.exists():
            raise FileNotFoundError(f"CodeQL database not found: {db}")

        run_dir = db.parent
        out_file = (
            Path(output_path).resolve()
            if output_path
            else run_dir / "query-result.bqrs"
        )

        proj_dir = Path(project_dir).resolve() if project_dir else run_dir

        fix_config = Configs(OPENAI_API_KEY="not-set")

        docker_cmd = [
            "docker",
            "run",
            "--rm",
            "--network=host",
            "-v",
            f"{proj_dir.as_posix()}:{fix_config.JAVA_DOCKER_WORKDIR}",
            "-v",
            f"{run_dir.as_posix()}:{_CONTAINER_RUNSTATE}",
        ]
        if extra_docker_args:
            docker_cmd.extend(extra_docker_args)
        docker_cmd.append(image_tag)

        codeql_cmd = (
            f"codeql query run {shlex.quote(query)} "
            f"--database={_CONTAINER_CODEQL_DB} "
            f"--output={_CONTAINER_RUNSTATE}/{out_file.name}"
        )
        docker_cmd.extend(["bash", "-lc", codeql_cmd])

        log.debug("Running CodeQL query: %s", codeql_cmd)
        executor = Executor()
        cmd_result = executor.execute(docker_cmd, stream=True)

        return CodeQLQueryResult(
            success=cmd_result.success,
            output_path=out_file.as_posix() if out_file.exists() else None,
            stdout=cmd_result.stdout,
            stderr=cmd_result.stderr,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_missing_template_error(error: Optional[str]) -> bool:
        if not error:
            return False
        return "Dockerfile-Java" in error or "assets/templates" in error

    @staticmethod
    def _find_local_fix_compile_src() -> Optional[Path]:
        candidates: List[Path] = []
        env_src = os.environ.get("FIX_COMPILE_SRC", "").strip()
        if env_src:
            candidates.append(Path(env_src))
        candidates.append(Path("/home/lhq/workspace/fix-compile/src"))

        for candidate in candidates:
            if (
                candidate / "fix_compile" / "assets" / "templates" / "Dockerfile-Java"
            ).exists():
                return candidate
        return None

    @staticmethod
    def _prefer_fix_compile_source(source_root: Path):
        class _Ctx:
            def __enter__(self_nonlocal):
                self_nonlocal._inserted = False
                root = str(source_root)
                if root not in sys.path:
                    sys.path.insert(0, root)
                    self_nonlocal._inserted = True
                for key in list(sys.modules.keys()):
                    if key == "fix_compile" or key.startswith("fix_compile."):
                        del sys.modules[key]

            def __exit__(self_nonlocal, exc_type, exc, tb):
                root = str(source_root)
                if self_nonlocal._inserted and root in sys.path:
                    sys.path.remove(root)

        return _Ctx()

    @staticmethod
    def _resolve_api_key(cfg: CodeQLConfig) -> str:
        """
        Resolve the OpenAI API key.

        Priority: cfg.openai_api_key > OPENAI_API_KEY env var > "not-set"
        when no_fix=True (LLM is never called, so key is irrelevant).
        """
        key = cfg.openai_api_key or os.environ.get("OPENAI_API_KEY", "")
        if key:
            return key
        if cfg.no_fix:
            return "not-set"
        raise ValueError(
            "OPENAI_API_KEY is required for LLM-assisted auto-fix. "
            "Set the env var or pass openai_api_key=... in CodeQLConfig, "
            "or disable the fix loop with no_fix=True."
        )
