# Known Issues

## CodeQL

### Architecture Overview

CodeQL subsystem has two layers:

```
CLI Entry                      Core Logic
─────────────                ──────────────────────────
vulntriage_cli.py            callmap/codeql/runner.py
  └─ commands/trace.py         └─ CodeQLRunner
       └─ callmap/trace.py          .build_database() → Docker + fix-compile
            └─ backends/            .run_query()      → docker run codeql query
                 codeql_backend.py
                 └─ CodeQLTraceBackend (TraceBackend interface)
```

### P1 — Security: Hardcoded fallback path in `_find_local_fix_compile_src`

**File:** `src/callmap/codeql/runner.py:351`

`_find_local_fix_compile_src()` hardcodes `/home/lhq/workspace/fix-compile/src` as a fallback candidate. This is a developer-local path that should not appear in released code:

- On most machines the path does not exist and is harmless.
- If the path happens to exist in a deployment environment and is attacker-controlled, arbitrary Python code could be loaded via `sys.path`.

**Recommendation:** Remove the hardcoded path. Use the `FIX_COMPILE_SRC` environment variable as the sole entry point.

### P1 — Security: `sys.path` injection in `_prefer_fix_compile_source`

**File:** `src/callmap/codeql/runner.py:362-378`

`_prefer_fix_compile_source()` inserts an external directory at `sys.path[0]` and purges all `fix_compile.*` modules before re-importing. This is a supply-chain risk: if `FIX_COMPILE_SRC` points to a malicious directory, its code will be executed. Additionally, `__exit__` removes the `sys.path` entry but does **not** restore the purged modules, leaving a polluted module cache.

**Recommendation:** Tighten validation of the source directory (e.g. verify expected package structure). Restore original modules in `__exit__`.

### P1 — Functional: `references()` returns empty list

**File:** `src/callmap/backends/codeql_backend.py:144-152`

When the CodeQL backend is successfully initialized (db + image present), `references()` logs a warning and returns `[]`. This means the CodeQL backend **cannot perform trace analysis** — it can build a database but never uses it for caller discovery. Users invoking `--backend codeql --no-codeql-fallback-lsp` will get empty traces for every sink.

**Recommendation:** Implement a CodeQL query adapter that translates `references()` calls into `codeql query run` invocations against the database, or clearly document that this is unimplemented and fail loudly instead of returning silent empty results.

### P2 — Bug: `run_query` output path mapping mismatch

**File:** `src/callmap/codeql/runner.py:320-321, 330`

The container writes output to `{_CONTAINER_RUNSTATE}/{out_file.name}`, but `out_file` is derived from the **host-side** `output_path`. If `output_path` points outside `run_dir` (e.g. `/tmp/result.bqrs`), the container writes to `/workspace/runstate/result.bqrs` which maps to `run_dir/result.bqrs` on the host — but the code checks `out_file` (`/tmp/result.bqrs`) for existence. That file will never appear there, so `output_path` in the result will always be `None`.

**Recommendation:** After docker execution, read from `run_dir / out_file.name` instead of `out_file`, or copy the result to the user-requested `output_path`.

### P2 — Security: `--network=host` in `run_query`

**File:** `src/callmap/codeql/runner.py:306`

The Docker container runs with `--network=host`, granting full access to all host network ports. For a pure compile-and-query workload this is unnecessary and increases the attack surface.

**Recommendation:** Remove `--network=host` or use a restricted network mode. If network access is needed for dependency resolution during build, scope it to `build_database` only, not `run_query`.

### P2 — Functional: auto-build always uses `no_fix=True`

**File:** `src/callmap/backends/codeql_backend.py:81`

When the CodeQL backend auto-provisions a database (no `--codeql-db`/`--codeql-image` provided), it hardcodes `no_fix=True`. If the Java project requires compilation fixes, the auto-build silently fails and falls back to LSP. The user may not understand why CodeQL is not being used.

**Recommendation:** Expose a CLI flag (e.g. `--codeql-auto-fix`) or respect `OPENAI_API_KEY` presence to decide whether to enable the fix loop. At minimum, log a clear message explaining why auto-build failed.

### P2 — Functional: `--use-codeql` on `all` command is a no-op

**File:** `src/commands/all.py:9-14`

The `--use-codeql` flag is captured in the report dict and logged, but no CodeQL logic is actually invoked. Users passing this flag expect CodeQL analysis to run as part of the end-to-end pipeline.

**Recommendation:** Either implement the CodeQL orchestration in the `all` command, or remove the flag and document it as not-yet-supported.

### Low — Redundant condition in `initialize()`

**File:** `src/callmap/backends/codeql_backend.py:60 vs 69`

Line 60 checks `if self.codeql_db and self.codeql_image` and returns `True`. Line 69 then checks `if not (self.codeql_db and self.codeql_image)` which is always `True` at that point (since the positive case already returned). The condition on line 69 is redundant.

### Low — Eager `LspTraceBackend` creation

**File:** `src/callmap/backends/codeql_backend.py:39-45`

The constructor creates an `LspTraceBackend` instance even when `codeql_db` and `codeql_image` are both provided and LSP will never be used. This is only object allocation (no server is started), but is semantically unnecessary.

### Low — API key exposure risk

**File:** `src/callmap/codeql/runner.py:194-196`

`OPENAI_API_KEY` is passed through `Configs` into the Docker environment. Depending on fix-compile's logging, the key may appear in build logs.

### Low — `as_posix()` for host paths

**File:** `src/callmap/codeql/runner.py:247-248, 309, 330`

`as_posix()` produces `/`-separated paths. On macOS/Linux this is identical to `str()`, but on Windows it would produce incorrect paths. Current Docker-based usage is Linux/macOS-only, so impact is limited.

### Implementation Status Summary

| Aspect | Status |
|--------|--------|
| CodeQL database creation (Docker + fix-compile) | Implemented |
| CodeQL query execution (`run_query`) | Implemented (output path bug) |
| TraceBackend abstraction | Implemented |
| Auto-provisioning (no db/image provided) | Implemented (always `no_fix`) |
| Resilient fallback for missing fix-compile assets | Implemented (security concern) |
| CLI integration (`--backend codeql`, `--codeql-db`, etc.) | Implemented |
| LSP fallback when CodeQL unavailable | Implemented |
| CodeQL caller-resolution query adapter | **Not implemented** (returns `[]`) |
| SARIF result consumption/parsing | **Not implemented** |
| `all --use-codeql` orchestration | **Not implemented** (placeholder) |
| Test coverage | **None** |
| Python language support | **Not supported** (Java only) |

---

## Recon

### Architecture Overview

```
CLI Entry                    Core Logic
─────────────              ──────────────────────────
vulntriage_cli.py          recon/detect_lang.py      — language detection
  └─ commands/recon.py     recon/models.py           — dataclasses (EntryPoint, Sink, …)
                           recon/matcher.py           — pattern loading + Python/Java matcher engines
                           recon/matcher_py.py        — PythonMatcher (AST-based)
                           recon/matcher_java.py      — JavaMatcher (regex-based)
                           recon/tech_stack_matcher.py — tech stack file detection
                           patterns/**/*.yaml         — YAML pattern definitions
```

### P1 — Security: Unconstrained `os.walk` on user-supplied repo path

**Files:** `recon/matcher_java.py:63`, `recon/matcher_py.py:60`, `recon/tech_stack_matcher.py:53`, `recon/detect_lang.py:25`

All scanners call `os.walk(repo_root)` where `repo_root` comes directly from CLI `--repo`. There is no validation that the path is a legitimate repository or that it stays within expected boundaries. A path like `/` or `/etc` would cause the scanner to traverse the entire filesystem. The `_find_java_files` method accepts `max_files=float('inf')` as default, providing no upper bound.

**Recommendation:** Validate `repo_root` is a directory and ideally contains a `.git` or build file. Enforce a sane `max_files` default (not infinity). Consider adding a max directory depth to prevent runaway traversal.

### P2 — Bug: Java `_scan_exports` regex misses nested generics

**File:** `src/recon/matcher_java.py:238`

`method_regex = re.compile(r'public\s+(?:static\s+)?(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*\(')` only handles one level of generic nesting (e.g. `List<String>`). A return type like `Map<String, List<Integer>>` would fail to match because the inner `>` terminates the non-greedy group early. Public methods with complex generic return types will be silently missed from exports.

**Recommendation:** Use a more robust regex or a proper Java parser for export scanning.

### P2 — Bug: Java method call matching produces false positives

**File:** `src/recon/matcher.py:280-302`

`JavaPatternMatcher.match_method_calls()` extracts the simple name from patterns (e.g. `exec` from `Runtime.exec`) then regex-matches `exec\s*\(` against every line. This will match any method named `exec` regardless of receiver type — `myHelper.exec()`, `testExec()`, comments containing `exec(`, string literals, etc. There is no receiver-type or context filtering.

**Recommendation:** At minimum, check that the line is not a comment or string literal. Ideally, match the full qualified pattern (e.g. `Runtime.exec`) rather than just the simple name.

### P2 — Bug: `detect_language` early exit can misclassify

**File:** `src/recon/detect_lang.py:36-37`

The file-counting loop breaks when either `py_count > 10` or `java_count > 10`. In a Java project with a `requirements.txt` (e.g. for build scripts), the function returns `'py'` immediately at L12-14 based on marker files, never reaching the counting logic. Conversely, if a project has both `.py` and `.java` files, whichever reaches 10 first terminates counting — a project with 11 `.py` build scripts and 500 `.java` source files would be classified as Python.

**Recommendation:** Marker-file detection should check for Java markers first (or in parallel), not short-circuit on Python markers alone. The counting heuristic should complete scanning or use a ratio rather than first-to-10.

### P2 — Functional: `_find_java_files` excludes test directories

**File:** `src/recon/matcher_java.py:58-61`

`ignore_dirs` includes `'test'` and `'tests'`, meaning test source files are completely excluded from recon scanning. While this is reasonable for exports, it means **sinks and entrypoints in test code are invisible**. Test code often contains security-relevant patterns (e.g. test endpoints, intentionally unsafe calls) that may be worth flagging.

**Recommendation:** Make test directory exclusion configurable, or only apply it to export scanning.

### P2 — Design: Java matching is line-based regex, not AST-based

**Files:** `src/recon/matcher.py:170-358`, `src/recon/matcher_java.py`

Unlike the Python matcher (which uses `ast.parse` for accurate AST analysis), the Java matcher uses line-by-line regex matching. This fundamentally cannot handle:
- Multi-line annotations or method signatures
- Annotations inside comments or strings
- Nested class scoping (all public methods are attributed to the last seen class)
- Annotation parameter expressions spanning multiple lines

**Recommendation:** Consider using tree-sitter (already a project dependency) for Java AST parsing, consistent with how the trace subsystem works.

### Low — Silent exception swallowing

**Files:** `src/recon/matcher.py:374`, `src/recon/matcher_java.py:162,195,227,282`, `src/recon/matcher_py.py:258`

All file-scanning loops catch `Exception` and silently continue (`logging.debug`). A file with an encoding issue, permission error, or syntax error is silently skipped. This makes it hard to diagnose why expected results are missing — the user sees no indication that files were skipped.

**Recommendation:** Log at `warning` level (not `debug`) when files are skipped, at least in verbose mode. Include a summary count of skipped files in the final output.

### Low — `_find_main_package_inits` bare `except`

**File:** `src/recon/matcher_py.py:258`

```python
except:
    pass
```

Bare `except` catches `KeyboardInterrupt` and `SystemExit`, making it impossible to interrupt a long scan with Ctrl-C during this phase.

**Recommendation:** Change to `except Exception:`.

### Low — `_extract_annotation_context` dead code path

**File:** `src/recon/matcher.py:310-316`

The method checks `if not extract_rules:` on L311, then immediately re-reads the same `pattern.get('extract', {})` as a dict and converts it. But `extract_rules` was already assigned from `pattern.get('extract', [])` on L309. If the pattern has `extract` as a dict, L309 assigns the dict (truthy), so L311 is False and the conversion on L313-316 never executes. The old-format fallback is dead code.

### Low — Recon output has no `entrypoints` key (schema mismatch with `recon_symbol_match`)

**File:** `src/commands/recon.py:48-57` vs `src/vfinder/tools/recon_symbol_match.py:71`

`recon_symbol_match` searches for `"endpoints"` in the recon JSON, but `commands/recon.py` outputs the key as `"entrypoints"`. The tool will never find entrypoint matches because it looks for the wrong key.

**Recommendation:** Align the key names — either rename `"entrypoints"` to `"endpoints"` in recon output, or search for `"entrypoints"` in `recon_symbol_match`.

---

## VFinder

### Architecture Overview

```
CLI Entry                    Core Logic
─────────────              ──────────────────────────
vulntriage_cli.py          vfinder/agent.py          — VulnerabilityAnalystAgent (3 modes)
  └─ commands/vfind.py     vfinder/agents.md         — system prompt template
                           vfinder/tools/
                             recon_symbol_match.py    — LangChain tool for recon querying
                           vfinder/codex_client.py   — standalone CodexClient (unused)
```

### P2 — Bug: `recon_symbol_match` searches wrong key for entrypoints

**File:** `src/vfinder/tools/recon_symbol_match.py:71`

As noted in the Recon section above, the tool searches for `"endpoints"` but recon produces `"entrypoints"`. This means the tool **silently misses all HTTP entrypoint matches** when searching recon output.

### P2 — Design: `codex_client.py` is dead code

**File:** `src/vfinder/codex_client.py`

The `CodexClient` class (424 lines) is a standalone Codex CLI wrapper that duplicates functionality now in `agent.py._run_codex_mode()`. It is **not imported or referenced anywhere** in the codebase. It also has its own bugs:
- `cleanup()` on L420 removes `agents.md` (lowercase) but `copy_agents_to_project` writes `AGENTS.md` (uppercase) — cleanup is a no-op.
- `run_analysis()` passes `--json` and `-o` flags to `codex exec` that may not exist in all Codex CLI versions.
- Uses `recon_path = project_path / recon_file` (relative to project) instead of CWD, inconsistent with the current `_resolve_path_for_cli_env` approach.

**Recommendation:** Remove `codex_client.py` to avoid confusion and reduce maintenance surface.

### P2 — Functional: `recon_symbol_match` truncates results at 2000 chars

**File:** `src/vfinder/tools/recon_symbol_match.py:92-93`

Output is hard-truncated at 2000 characters. For large projects with many matches (capped at 20 per category), the JSON output is likely to exceed this limit and get cut mid-JSON, producing invalid JSON that the LLM agent cannot parse.

**Recommendation:** Reduce per-category match limits to stay within budget, or return a summary with file:line pointers instead of full entries.

### P2 — Functional: `recon_symbol_match` loads entire JSON into memory

**File:** `src/vfinder/tools/recon_symbol_match.py:36-37`

The tool's docstring says "without loading full file" but the implementation does `json.load(f)` which loads the entire recon JSON into memory. For very large projects the recon output can be tens of MB.

**Recommendation:** Use streaming JSON parsing (e.g. `ijson`) or document the actual behavior.

### Low — `recon_symbol_match` uses `print()` for debug output

**File:** `src/vfinder/tools/recon_symbol_match.py:29,90`

Debug output uses `print()` instead of `logging`. When called as a LangChain tool, `print()` output goes to stdout and may interfere with structured output parsing in CLI modes.

**Recommendation:** Replace `print()` with `logging.info()` or `logging.debug()`.

### Low — Comment says "Limit to 5 matches" but code limits to 20

**File:** `src/vfinder/tools/recon_symbol_match.py:68`

```python
results["exports"] = matching[:20]  # Limit to 5 matches
```

The comment is stale — the actual limit is 20.

---

## Not Yet Audited

The following subsystems have **not** been reviewed in this document and should be audited separately:

- **`recon/` YAML pattern files** (`patterns/java/*.yaml`, `patterns/python/*.yaml`, `patterns/tech_stack/tech_stack.yaml`) — pattern completeness, correctness, and false-positive rates
- **`callmap/trace.py`** — DFS trace extraction logic, cycle detection correctness, depth-limiting edge cases
- **`callmap/ast/`** — tree-sitter AST parsers (`base.py`, `java.py`, `py.py`)
- **`callmap/lsp/`** — LSP client, server lifecycle, persistent server registry, protocol handling
- **`callmap/backends/lsp_backend.py`** — LSP trace backend implementation
- **`commands/verify.py`** — exploitability verification command
- **`core/`** — logging, config, error handling utilities
- **`storage/`** — output writer (`writer.py`; note: SQLite format is a placeholder no-op)
