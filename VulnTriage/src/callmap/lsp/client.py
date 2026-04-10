"""
LSP client: stdio process + JSON-RPC (initialize, did_open, references, definition, document_symbol, close).

Supports persistent server management with PID file for reuse across invocations.

Env:
  VULN_LSP_REQUEST_TIMEOUT — seconds per JSON-RPC request (default 120). Set to 0/none/off to disable (not recommended).
  On Windows, timeout is not applied to stdout reads (pipes); disable is implicit.
"""
import json
import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# LSP 3.17: line/character are 0-based
# Content-Length is in bytes (UTF-8)


def _make_message(obj: Dict[str, Any]) -> bytes:
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n"
    return header.encode("ascii") + body


def _parse_request_timeout_env() -> Optional[float]:
    raw = os.environ.get("VULN_LSP_REQUEST_TIMEOUT", "").strip()
    if not raw:
        return 120.0
    if raw.lower() in ("0", "none", "off", "inf", "infinite"):
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        return 120.0


def _read_message(stream, deadline: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """Read one LSP message (Content-Length: N + body). deadline is time.monotonic() upper bound, or None."""
    import select

    def _remaining() -> Optional[float]:
        if deadline is None:
            return None
        return deadline - time.monotonic()

    def _wait_for_readable() -> bool:
        rem = _remaining()
        if rem is not None and rem <= 0:
            return False
        if deadline is None:
            return True
        if os.name == "nt":
            return True
        try:
            fd = stream.fileno()
        except (AttributeError, OSError):
            return True
        try:
            w = min(max(rem or 0.0, 0.001), 60.0)
            r, _, _ = select.select([fd], [], [], w)
        except (ValueError, OSError):
            return True
        return bool(r)

    header = b""
    while not header.endswith(b"\r\n\r\n"):
        if deadline is not None and time.monotonic() >= deadline:
            logging.warning("LSP: read timeout while reading message header")
            return None
        if not _wait_for_readable():
            logging.warning("LSP: read timeout waiting for stdout (header)")
            return None
        try:
            chunk = stream.read1(1) if hasattr(stream, "read1") else stream.read(1)
        except Exception:
            return None
        if not chunk:
            return None
        header += chunk
        if len(header) > 2048:
            return None
    parts = header.decode("utf-8").strip().split("\r\n")
    length = 0
    for p in parts:
        if p.lower().startswith("content-length:"):
            length = int(p.split(":", 1)[1].strip())
            break
    if length <= 0:
        return None
    body = b""
    while len(body) < length:
        if deadline is not None and time.monotonic() >= deadline:
            logging.warning("LSP: read timeout while reading message body")
            return None
        if not _wait_for_readable():
            logging.warning("LSP: read timeout waiting for stdout (body)")
            return None
        to_read = min(length - len(body), 65536)
        try:
            chunk = stream.read(to_read)
        except Exception:
            return None
        if not chunk:
            return None
        body += chunk
    try:
        return json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        logging.warning("LSP: invalid JSON in message body")
        return None


def _is_process_running(pid: int) -> bool:
    """Check if a process with the given PID is running."""
    try:
        if os.name == "nt":
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
            if handle:
                kernel32.CloseHandle(handle)
                return True
            return False
        else:
            os.kill(pid, 0)
            return True
    except (OSError, ProcessLookupError):
        return False


class LSPClient:
    """LSP over stdio: initialize, did_open, references, definition, document_symbol, shutdown, exit, close."""

    def __init__(self, cmd: List[str], cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None):
        self._cmd = cmd
        self._cwd = cwd
        self._env = env or os.environ.copy()
        self._proc: Optional[subprocess.Popen] = None
        self._request_id = 0
        self._stderr_lines: List[str] = []
        self._initialized = False
        self._workspace_root_uri: Optional[str] = None
        
        # Progress tracking for indexing
        self._progress_tokens: Dict[str, Dict[str, Any]] = {}  # token -> progress info
        self._indexing_complete = False
        self._request_timeout: Optional[float] = _parse_request_timeout_env()

    def start(self) -> bool:
        try:
            self._proc = subprocess.Popen(
                self._cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self._cwd,
                env=self._env,
            )
            # Consume stderr in background so it doesn't fill pipe
            def read_stderr():
                for line in self._proc.stderr:
                    self._stderr_lines.append(line.decode("utf-8", errors="replace").strip())
                    logging.debug("lsp_stderr: %s", self._stderr_lines[-1][:200])

            t = threading.Thread(target=read_stderr, daemon=True)
            t.start()
            return True
        except Exception as e:
            logging.error("LSP start failed: %s", e)
            return False

    def stop(self) -> None:
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _handle_notification(self, method: str, params: Optional[Dict[str, Any]]) -> None:
        """Handle LSP notifications, especially progress updates."""
        if method == "$/progress" and params:
            token = params.get("token")
            value = params.get("value", {})
            kind = value.get("kind")
            
            if kind == "begin":
                self._progress_tokens[str(token)] = {
                    "title": value.get("title", ""),
                    "message": value.get("message", ""),
                    "percentage": value.get("percentage", 0),
                    "started": time.time(),
                }
                logging.info("LSP progress begin: %s - %s", value.get("title"), value.get("message"))
            elif kind == "report":
                if str(token) in self._progress_tokens:
                    self._progress_tokens[str(token)]["message"] = value.get("message", "")
                    self._progress_tokens[str(token)]["percentage"] = value.get("percentage", 0)
                logging.debug("LSP progress: %s%% - %s", value.get("percentage"), value.get("message"))
            elif kind == "end":
                if str(token) in self._progress_tokens:
                    title = self._progress_tokens[str(token)].get("title", "")
                    elapsed = time.time() - self._progress_tokens[str(token)].get("started", time.time())
                    logging.info("LSP progress end: %s (%.1fs)", title, elapsed)
                    del self._progress_tokens[str(token)]
        
        elif method == "window/logMessage" and params:
            msg_type = params.get("type", 4)  # 1=Error, 2=Warning, 3=Info, 4=Log
            message = params.get("message", "")
            if msg_type <= 2:
                logging.warning("LSP server: %s", message[:200])
            else:
                logging.debug("LSP server: %s", message[:200])

    def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        if not self._proc or not self._proc.stdin:
            return None
        req_id = self._next_id()
        msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params
        raw = _make_message(msg)
        try:
            self._proc.stdin.write(raw)
            self._proc.stdin.flush()
        except Exception as e:
            logging.error("LSP write failed: %s", e)
            return None
        deadline: Optional[float] = None
        if self._request_timeout is not None:
            deadline = time.monotonic() + self._request_timeout
        # Read responses until we get one with matching id
        while True:
            resp = _read_message(self._proc.stdout, deadline=deadline)
            if resp is None:
                logging.error(
                    "LSP: no usable response for id=%s method=%s (timeout, EOF, or parse error)",
                    req_id,
                    method,
                )
                return None
            # Our JSON-RPC response (has result or error)
            if resp.get("id") == req_id and ("result" in resp or "error" in resp):
                if "error" in resp:
                    logging.warning("LSP error: %s", resp["error"])
                    return None
                return resp.get("result")
            smethod = resp.get("method")
            # Server -> client request (has id + method, no result/error); must reply or Pyright hangs
            if smethod and "id" in resp and "result" not in resp and "error" not in resp:
                self._handle_server_request(resp)
                continue
            # Notification (method, no id)
            if smethod and "id" not in resp:
                self._handle_notification(smethod, resp.get("params"))
                continue
            logging.debug("LSP: unexpected message while waiting for id=%s: %s", req_id, list(resp.keys()))

    def _handle_server_request(self, msg: Dict[str, Any]) -> None:
        """Reply to server-initiated JSON-RPC requests (e.g. window/workDoneProgress/create)."""
        rid = msg.get("id")
        smethod = msg.get("method")
        params = msg.get("params") or {}
        if rid is None or not self._proc or not self._proc.stdin:
            return
        result: Any = None
        if smethod == "window/workDoneProgress/create":
            result = None
        elif smethod == "client/registerCapability":
            result = None
        elif smethod == "workspace/configuration":
            items = params.get("items") or []
            result = [None] * len(items)
        else:
            logging.debug("LSP: unhandled server request %s; replying result=null", smethod)
            result = None
        out = {"jsonrpc": "2.0", "id": rid, "result": result}
        try:
            self._proc.stdin.write(_make_message(out))
            self._proc.stdin.flush()
        except Exception as e:
            logging.error("LSP server-request reply failed (%s): %s", smethod, e)

    def send_notification(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        if not self._proc or not self._proc.stdin:
            return
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        try:
            self._proc.stdin.write(_make_message(msg))
            self._proc.stdin.flush()
        except Exception as e:
            logging.error("LSP notify failed: %s", e)

    def initialize(self, workspace_root_uri: str) -> bool:
        """Start process if not started, send initialize with workspace. Returns True if ready."""
        if self._initialized and self._workspace_root_uri == workspace_root_uri:
            return True
        if self._cwd is None:
            self._cwd = uri_to_path(workspace_root_uri)
        if not self._proc and not self.start():
            return False
        logging.info("LSP: sending initialize (rootUri=%s)", workspace_root_uri)
        result = self.send_request(
            "initialize",
            {
                "processId": os.getpid(),
                "rootUri": workspace_root_uri,
                "rootPath": uri_to_path(workspace_root_uri),
                "capabilities": {
                    "window": {
                        "workDoneProgress": True,  # Enable progress reporting
                    },
                },
                "workspaceFolders": [{"uri": workspace_root_uri, "name": "repo"}],
                "clientInfo": {"name": "reach-ability-trace", "version": "0.1.0"},
            },
        )
        if result is None:
            return False
        self.send_notification("initialized", {})
        self._initialized = True
        self._workspace_root_uri = workspace_root_uri
        logging.info("LSP: initialize finished")
        return True

    def wait_for_indexing(self, timeout: int = 0, poll_interval: float = 5.0, data_dir: Optional[str] = None) -> bool:
        """
        Wait for JDTLS to complete indexing by monitoring .metadata/.log for completion message.
        
        Strategy:
        1. Monitor .metadata/.log file for "build jobs finished" message
        2. This is the definitive signal that JDTLS has finished all build/index jobs
        
        Args:
            timeout: Maximum seconds to wait (0 = no timeout, wait forever)
            poll_interval: Seconds between progress checks
            data_dir: Cache directory path containing .metadata/.log
        
        Returns:
            True if indexing appears complete, False on timeout (if timeout > 0)
        """
        from pathlib import Path
        
        if not self._proc or not self.is_running():
            return False
        
        start_time = time.time()
        log_file = Path(data_dir) / ".metadata" / ".log" if data_dir else None
        last_log_size = 0
        
        if timeout > 0:
            logging.info("Waiting for indexing to complete (timeout=%ds)...", timeout)
        else:
            logging.info("Waiting for indexing to complete (monitoring .metadata/.log)...")
        
        while True:
            elapsed = time.time() - start_time
            
            # Check timeout if set
            if timeout > 0 and elapsed >= timeout:
                logging.warning("Indexing wait timeout after %ds", timeout)
                return False
            
            # Check if process still running
            if not self.is_running():
                logging.error("LSP process died during indexing")
                return False
            
            # Check .metadata/.log for completion message
            build_finished = False
            workspace_initialized = False
            log_content = ""
            
            if log_file and log_file.exists():
                try:
                    log_content = log_file.read_text(encoding="utf-8", errors="replace")
                    # Check for the definitive completion markers
                    if ">> build jobs finished" in log_content:
                        build_finished = True
                    if "Workspace initialized" in log_content:
                        workspace_initialized = True
                except Exception as e:
                    logging.debug("Failed to read log file: %s", e)
            
            if build_finished:
                logging.info("Detected 'build jobs finished' in .metadata/.log")
                self._indexing_complete = True
                return True
            
            # Log progress with status indicators
            status_parts = []
            if workspace_initialized:
                status_parts.append("workspace_init=OK")
            else:
                status_parts.append("workspace_init=pending")
            status_parts.append("build_jobs=pending")
            
            # Also check cache size for progress indication
            cache_size_mb = 0
            if data_dir:
                try:
                    import subprocess as sp
                    result = sp.run(
                        ["du", "-sm", data_dir],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        cache_size_mb = int(result.stdout.split()[0])
                except Exception:
                    pass
            
            logging.info("  [%.0fs] Cache: %dMB, %s", 
                       elapsed, cache_size_mb, ", ".join(status_parts))
            
            time.sleep(poll_interval)

    def has_active_progress(self) -> bool:
        """Check if there are any active progress tokens."""
        return len(self._progress_tokens) > 0

    def is_indexing_complete(self) -> bool:
        """Check if indexing has been marked as complete."""
        return self._indexing_complete

    def is_running(self) -> bool:
        """Check if the LSP server process is running."""
        if self._proc is None:
            return False
        return self._proc.poll() is None

    def is_initialized(self) -> bool:
        """Check if the LSP server has been initialized."""
        return self._initialized and self.is_running()

    def get_pid(self) -> Optional[int]:
        """Get the PID of the LSP server process."""
        if self._proc:
            return self._proc.pid
        return None

    def exit(self) -> None:
        """Send LSP exit notification."""
        self.send_notification("exit")

    def close(self) -> None:
        """Shutdown, exit, stop process. Idempotent."""
        if self._proc:
            try:
                self.shutdown()
            except Exception:
                pass
            self.stop()
            self._proc = None

    def did_open(self, file_uri: str, language_id: str, text: str) -> None:
        """Notify server that a document is open. version=1 used internally."""
        self._did_open(file_uri, language_id, 1, text)

    def _did_open(self, file_uri: str, language_id: str, version: int, text: str) -> None:
        """Internal: didOpen with explicit version (for tests/callers that need it)."""
        self.send_notification(
            "textDocument/didOpen",
            {
                "textDocument": {
                    "uri": file_uri,
                    "languageId": language_id,
                    "version": version,
                    "text": text,
                }
            },
        )

    def references(self, file_uri: str, line: int, character: int, include_declaration: bool = False) -> List[Dict]:
        """LSP textDocument/references. line/character 0-based. Returns list of Location-like dicts."""
        short_uri = file_uri.split("/")[-1] if "/" in file_uri else file_uri
        logging.info(
            "LSP: sending textDocument/references (%s L%d:%d include_decl=%s)",
            short_uri,
            line + 1,
            character,
            include_declaration,
        )
        t0 = time.time()
        result = self.send_request(
            "textDocument/references",
            {
                "textDocument": {"uri": file_uri},
                "position": {"line": line, "character": character},
                "context": {"includeDeclaration": include_declaration},
            },
        )
        elapsed_ms = (time.time() - t0) * 1000
        if result is None or not isinstance(result, list):
            logging.info(
                "LSP: textDocument/references returned empty/error after %.0fms",
                elapsed_ms,
            )
            return []
        logging.info(
            "LSP: textDocument/references -> %d locations (%.0fms)",
            len(result),
            elapsed_ms,
        )
        return result

    def definition(self, file_uri: str, line: int, character: int) -> Optional[Dict]:
        """LSP textDocument/definition. Returns first Location or None."""
        result = self.send_request(
            "textDocument/definition",
            {"textDocument": {"uri": file_uri}, "position": {"line": line, "character": character}},
        )
        if result is None:
            return None
        if isinstance(result, list) and result:
            return result[0]
        if isinstance(result, dict):
            return result
        return None

    def document_symbol(self, file_uri: str) -> List[Dict]:
        """LSP textDocument/documentSymbol. Returns list of DocumentSymbol-like dicts."""
        result = self.send_request(
            "textDocument/documentSymbol",
            {"textDocument": {"uri": file_uri}},
        )
        if result is None or not isinstance(result, list):
            return []
        return result

    def shutdown(self) -> None:
        """Send shutdown request and exit notification to LSP server."""
        try:
            # shutdown is a request that requires response
            result = self.send_request("shutdown")
            logging.debug("LSP shutdown response: %s", result)
        except Exception as e:
            logging.warning("LSP shutdown request failed: %s", e)
        
        # Give server time to save state
        time.sleep(0.5)
        
        # exit is a notification (no response expected)
        try:
            self.send_notification("exit")
        except Exception as e:
            logging.debug("LSP exit notification failed (expected if process exited): %s", e)
        
        # Wait a bit for clean exit
        time.sleep(0.5)


def path_to_uri(path: str) -> str:
    """Convert absolute path to file URI."""
    p = Path(path).resolve()
    return p.as_uri()


def uri_to_path(uri: str) -> str:
    """Convert file URI to path."""
    if uri.startswith("file://"):
        import urllib.parse
        return urllib.parse.unquote(uri[7:])
    return uri
