"""Codex CLI client for vulnerability analysis.

This module provides a CodexClient class that wraps codex CLI commands
for agent-based vulnerability analysis. It handles:
- Copying agent description files to target project
- Executing codex commands in target project directory
- Logging analysis output with timestamps
"""
import os
import shutil
import subprocess
import logging
import time
import threading
import queue
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any


class CodexClient:
    """Client for interacting with Codex CLI for agent-based analysis."""
    
    def __init__(self, codex_cmd: str = "codex", agents_file: Optional[str] = None):
        """
        Initialize CodexClient.
        
        Args:
            codex_cmd: Path to codex CLI command (default: "codex")
            agents_file: Path to agents.md file (default: auto-detect from module)
        """
        self.codex_cmd = codex_cmd
        self.agents_file = agents_file or self._get_default_agents_file()
        
    def _get_default_agents_file(self) -> str:
        """Get default path to agents.md file."""
        # Get the directory where this module is located
        module_dir = Path(__file__).parent
        agents_path = module_dir / "agents.md"
        return str(agents_path)
    
    def copy_agents_to_project(
        self, 
        project_dir: str, 
        vuln_dir: Optional[str] = None,
        recon_file: Optional[str] = None
    ) -> str:
        """
        Copy AGENTS.md file to target project directory with variable substitution.
        Codex automatically recognizes AGENTS.md in the project root.
        
        Args:
            project_dir: Target project directory path
            vuln_dir: Directory containing vulnerability materials (for variable substitution)
            recon_file: Path to recon output JSON (for variable substitution)
            
        Returns:
            Path to copied AGENTS.md file in target project
        """
        project_path = Path(project_dir).resolve()
        if not project_path.exists():
            raise ValueError(f"Project directory does not exist: {project_dir}")
        
        if not project_path.is_dir():
            raise ValueError(f"Project path is not a directory: {project_dir}")
        
        # Read source agents.md
        if not os.path.exists(self.agents_file):
            raise FileNotFoundError(f"Agents file not found: {self.agents_file}")
        
        with open(self.agents_file, 'r', encoding='utf-8') as f:
            agents_content = f.read()
        
        # Replace variables in agents.md
        agents_content = agents_content.replace("{vuln_dir}", vuln_dir or "{vuln_dir}")
        agents_content = agents_content.replace("{project_dir}", str(project_path))
        agents_content = agents_content.replace("{recon_file}", recon_file or "{recon_file}")
        
        # Write to target project as AGENTS.md (uppercase, codex convention)
        target_agents_path = project_path / "AGENTS.md"
        with open(target_agents_path, 'w', encoding='utf-8') as f:
            f.write(agents_content)
        
        logging.info(f"Copied and customized AGENTS.md to {target_agents_path}")
        
        return str(target_agents_path)
    
    def create_log_file(self, project_dir: str, prefix: str = "codex_analysis") -> str:
        """
        Create log file with timestamp in target project directory.
        
        Args:
            project_dir: Target project directory path
            prefix: Log file prefix (default: "codex_analysis")
            
        Returns:
            Path to created log file
        """
        project_path = Path(project_dir).resolve()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = project_path / f"{prefix}_{timestamp}.log"
        
        # Create log file (empty initially)
        log_file.touch()
        logging.info(f"Created log file: {log_file}")
        
        return str(log_file)
    
    def run_analysis(
        self,
        project_dir: str,
        user_input: str,
        vuln_dir: Optional[str] = None,
        recon_file: Optional[str] = None,
        log_file: Optional[str] = None,
        additional_args: Optional[list] = None
    ) -> Dict[str, Any]:
        """
        Run codex analysis in target project directory.
        
        Args:
            project_dir: Target project directory path
            user_input: Analysis request/prompt
            vuln_dir: Directory containing vulnerability materials
            recon_file: Path to recon output JSON file
            log_file: Path to log file (if None, will be auto-created)
            additional_args: Additional arguments to pass to codex command
            
        Returns:
            Dictionary containing:
            - exit_code: Process exit code
            - stdout: Standard output
            - stderr: Standard error
            - log_file: Path to log file
        """
        project_path = Path(project_dir).resolve()
        
        # Copy agents.md to project with variable substitution
        agents_path = self.copy_agents_to_project(project_dir, vuln_dir, recon_file)
        
        # Create log file if not provided
        if log_file is None:
            log_file = self.create_log_file(project_dir)
        
        # Build codex command
        # Codex CLI interface: codex exec [OPTIONS] [PROMPT]
        # Codex automatically recognizes AGENTS.md in the project root, no need to pass it explicitly
        cmd = [self.codex_cmd, "exec"]
        
        # Set working directory (AGENTS.md will be automatically loaded from here)
        cmd.extend(["-C", str(project_path)])
        
        # Use full-auto mode for automatic execution
        cmd.extend(["--full-auto"])
        
        # Enable JSON output for structured parsing
        cmd.extend(["--json"])
        
        # Create output file for last message
        output_file = project_path / f"codex_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        cmd.extend(["-o", str(output_file)])
        
        # Build user prompt (AGENTS.md is automatically loaded by codex, no need to include it)
        # Just provide the specific task instructions
        user_prompt = f"""Perform the following vulnerability analysis task:

{user_input}

Follow the workflow defined in AGENTS.md and output the final JSON result."""
        
        # Add prompt as argument (codex exec accepts prompt as argument)
        cmd.append(user_prompt)
        
        # Pass context via environment variables
        env = os.environ.copy()
        env["VULN_DIR"] = vuln_dir or ""
        env["PROJECT_DIR"] = str(project_path)
        if recon_file:
            # Resolve recon_file path relative to project_dir if needed
            recon_path = Path(recon_file)
            if not recon_path.is_absolute():
                recon_path = project_path / recon_file
            env["RECON_FILE"] = str(recon_path)
        else:
            env["RECON_FILE"] = ""
        
        # Add additional arguments
        if additional_args:
            cmd.extend(additional_args)
        
        # Change to project directory for execution
        logging.info(f"Running codex command: {' '.join(cmd)}")
        logging.info(f"Working directory: {project_path}")
        logging.info(f"Log file: {log_file}")
        
        # Open log file for writing
        with open(log_file, 'w', encoding='utf-8') as log_f:
            # Write command header
            log_f.write(f"Codex Analysis Log\n")
            log_f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            log_f.write(f"Command: {' '.join(cmd)}\n")
            log_f.write(f"Working Directory: {project_path}\n")
            log_f.write(f"{'='*80}\n\n")
            
            try:
                # Execute codex command
                # Use line buffered mode for JSONL output
                process = subprocess.Popen(
                    cmd,
                    cwd=str(project_path),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    text=True,
                    bufsize=1  # Line buffered for JSONL
                )
                
                # Stream output to both log file and capture
                stdout_lines = []
                stderr_lines = []
                
                # Use threading to read stdout and stderr concurrently
                
                stdout_queue = queue.Queue()
                stderr_queue = queue.Queue()
                
                def read_stdout():
                    try:
                        if process.stdout:
                            # Read line by line for JSONL format
                            for line in process.stdout:
                                line = line.rstrip()
                                if line:
                                    stdout_queue.put(line)
                    except Exception as e:
                        logging.error(f"Error reading stdout: {e}")
                    finally:
                        stdout_queue.put(None)  # Sentinel
                
                def read_stderr():
                    try:
                        if process.stderr:
                            # Read line by line
                            for line in process.stderr:
                                line = line.rstrip()
                                if line:
                                    stderr_queue.put(line)
                    except Exception as e:
                        logging.error(f"Error reading stderr: {e}")
                    finally:
                        stderr_queue.put(None)  # Sentinel
                
                # Start reader threads
                stdout_thread = threading.Thread(target=read_stdout, daemon=True)
                stderr_thread = threading.Thread(target=read_stderr, daemon=True)
                stdout_thread.start()
                stderr_thread.start()
                
                # Process output from both queues
                # Keep reading until both streams are done AND process has completed
                stdout_done = False
                stderr_done = False
                process_done = False
                exit_code = None
                max_wait_time = 300  # Maximum 5 minutes
                start_time = datetime.now()
                
                # Use a longer timeout and check process status
                while not (stdout_done and stderr_done and process_done):
                    # Check timeout
                    elapsed = (datetime.now() - start_time).total_seconds()
                    if elapsed > max_wait_time:
                        logging.warning(f"Codex process timeout after {max_wait_time}s, terminating")
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                        exit_code = -1
                        process_done = True
                        break
                    
                    # Check if process is still running
                    if not process_done:
                        poll_result = process.poll()
                        if poll_result is not None:
                            # Process has completed
                            exit_code = poll_result
                            process_done = True
                            logging.info(f"Codex process completed with exit code: {exit_code}")
                    
                    # Check stdout
                    if not stdout_done:
                        try:
                            line = stdout_queue.get(timeout=1.0)
                            if line is None:
                                stdout_done = True
                            else:
                                stdout_lines.append(line)
                                log_f.write(f"[STDOUT] {line}\n")
                                log_f.flush()
                                # Log important events
                                if '"type":"message"' in line or '"type":"tool' in line or '"type":"turn' in line:
                                    logging.info(f"Codex event: {line[:200]}")
                        except queue.Empty:
                            # If process is done and queue is empty, mark as done
                            if process_done:
                                stdout_done = True
                    
                    # Check stderr
                    if not stderr_done:
                        try:
                            line = stderr_queue.get(timeout=1.0)
                            if line is None:
                                stderr_done = True
                            else:
                                stderr_lines.append(line)
                                log_f.write(f"[STDERR] {line}\n")
                                log_f.flush()
                                logging.warning(f"Codex stderr: {line}")
                        except queue.Empty:
                            # If process is done and queue is empty, mark as done
                            if process_done:
                                stderr_done = True
                
                # If process hasn't been polled yet, wait for it
                if not process_done:
                    exit_code = process.wait()
                    process_done = True
                    logging.info(f"Codex process completed with exit code: {exit_code}")
                
                # Wait for threads to finish (give them more time to flush remaining data)
                stdout_thread.join(timeout=10)
                stderr_thread.join(timeout=10)
                
                # Read any remaining lines from queues (important for buffered output)
                remaining_attempts = 100
                while remaining_attempts > 0:
                    remaining_attempts -= 1
                    got_any = False
                    
                    # Try stdout
                    try:
                        line = stdout_queue.get_nowait()
                        if line is not None:
                            stdout_lines.append(line)
                            log_f.write(f"[STDOUT] {line}\n")
                            log_f.flush()
                            got_any = True
                            if '"type":"message"' in line or '"type":"tool' in line:
                                logging.info(f"Codex event (remaining): {line[:200]}")
                    except queue.Empty:
                        pass
                    
                    # Try stderr
                    try:
                        line = stderr_queue.get_nowait()
                        if line is not None:
                            stderr_lines.append(line)
                            log_f.write(f"[STDERR] {line}\n")
                            log_f.flush()
                            got_any = True
                    except queue.Empty:
                        pass
                    
                    if not got_any:
                        break
                    
                    # Small delay to allow more data to arrive
                    time.sleep(0.1)
                
                log_f.write(f"\n{'='*80}\n")
                log_f.write(f"Exit Code: {exit_code}\n")
                log_f.write(f"Completed: {datetime.now().isoformat()}\n")
                
                # Try to read output file if it exists
                output_content = None
                if output_file.exists():
                    try:
                        with open(output_file, 'r', encoding='utf-8') as f:
                            output_content = f.read()
                        log_f.write(f"\nOutput File Content:\n{output_content}\n")
                    except Exception as e:
                        log_f.write(f"\nFailed to read output file: {e}\n")
                
                logging.info(f"Codex process completed with exit code: {exit_code}")
                
                return {
                    "exit_code": exit_code,
                    "stdout": "\n".join(stdout_lines),
                    "stderr": "\n".join(stderr_lines),
                    "log_file": log_file,
                    "agents_file": agents_path,
                    "output_file": str(output_file) if output_file.exists() else None,
                    "output_content": output_content
                }
                
            except FileNotFoundError:
                error_msg = f"Codex command not found: {self.codex_cmd}. Please ensure codex is installed and in PATH."
                log_f.write(f"[ERROR] {error_msg}\n")
                logging.error(error_msg)
                raise RuntimeError(error_msg)
            except Exception as e:
                error_msg = f"Error running codex command: {str(e)}"
                log_f.write(f"[ERROR] {error_msg}\n")
                logging.exception(error_msg)
                raise
    
    def cleanup(self, project_dir: str, remove_agents: bool = True):
        """
        Clean up temporary files in project directory.
        
        Args:
            project_dir: Target project directory path
            remove_agents: Whether to remove copied agents.md file
        """
        project_path = Path(project_dir).resolve()
        
        if remove_agents:
            agents_path = project_path / "agents.md"
            if agents_path.exists():
                agents_path.unlink()
                logging.info(f"Removed agents.md from {project_dir}")
