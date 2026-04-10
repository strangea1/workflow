import os
import ast
import logging
from pathlib import Path
from typing import List
from .matcher import load_patterns, PythonPatternMatcher, FileScanner
from .models import EntryPoint, Sanitizer, Sink, Export, Dep


class PythonMatcher:
    """Python-specific matcher integrating all pattern types"""
    
    def __init__(self, patterns_dir: str):
        self.patterns_dir = patterns_dir
        self.entry_patterns = load_patterns(os.path.join(patterns_dir, 'python', 'entry.yaml'))
        self.sanitizer_patterns = load_patterns(os.path.join(patterns_dir, 'python', 'sanitizer.yaml'))
        self.sink_patterns = load_patterns(os.path.join(patterns_dir, 'python', 'sink.yaml'))
        self.config_patterns = load_patterns(os.path.join(patterns_dir, 'python', 'config.yaml'))
    
    def scan_repo(self, repo_root: str) -> dict:
        """Scan Python repository for all patterns"""
        result = {
            'entrypoints': [],
            'sanitizers': [],
            'sinks': [],
            'exports': [],
            'deps': []
        }
        
        # Find all Python files
        py_files = self._find_python_files(repo_root)
        logging.info(f"Found {len(py_files)} Python files to scan")
        
        # Scan for entrypoints
        if self.entry_patterns:
            result['entrypoints'] = self._scan_entrypoints(py_files)
        
        # Scan for sanitizers
        if self.sanitizer_patterns:
            result['sanitizers'] = self._scan_sanitizers(py_files)
        
        # Scan for sinks
        if self.sink_patterns:
            result['sinks'] = self._scan_sinks(py_files)
        
        # Scan for exports
        result['exports'] = self._scan_exports(repo_root, py_files)
        
        # Parse dependencies
        if self.config_patterns:
            result['deps'] = self._parse_dependencies(repo_root)
        
        return result
    
    def _find_python_files(self, repo_root: str, max_files: int = 10000) -> List[str]:
        """Find all Python files in repo"""
        py_files = []
        ignore_dirs = {'.git', '__pycache__', '.venv', 'venv', 'node_modules', '.tox', 'build', 'dist', '.egg-info'}
        
        for root, dirs, files in os.walk(repo_root):
            # Filter ignored directories
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            
            for file in files:
                if file.endswith('.py'):
                    py_files.append(os.path.join(root, file))
                    if len(py_files) >= max_files:
                        logging.warning(f"Reached max files limit {max_files}, stopping scan")
                        return py_files
        
        return py_files
    
    def _scan_entrypoints(self, py_files: List[str]) -> List[EntryPoint]:
        """Scan for HTTP entrypoints"""
        matcher = PythonPatternMatcher(self.entry_patterns)
        scanner = FileScanner(matcher)
        entrypoints = []
        
        for file_path in py_files:
            matches = scanner.scan_file(file_path)
            for match in matches:
                if match['type'] == 'decorator':
                    # FastAPI/Flask route
                    ep = EntryPoint(
                        file=file_path,
                        line=match['line'],
                        framework=match.get('framework', 'unknown'),
                        method=match.get('context', {}).get('method', 'UNKNOWN'),
                        path=match.get('context', {}).get('path', ''),
                        handler=match.get('function', ''),
                        confidence=1.0
                    )
                    entrypoints.append(ep)
                elif match['type'] == 'function_call':
                    # Django path()
                    ep = EntryPoint(
                        file=file_path,
                        line=match['line'],
                        framework=match.get('framework', 'unknown'),
                        method='ANY',
                        path=match.get('context', {}).get('pattern', ''),
                        handler=match.get('context', {}).get('view', ''),
                        confidence=0.8
                    )
                    entrypoints.append(ep)
        
        logging.info(f"Found {len(entrypoints)} entrypoints")
        return entrypoints
    
    def _scan_sanitizers(self, py_files: List[str]) -> List[Sanitizer]:
        """Scan for sanitizers/validators"""
        matcher = PythonPatternMatcher(self.sanitizer_patterns)
        scanner = FileScanner(matcher)
        sanitizers = []
        
        for file_path in py_files:
            matches = scanner.scan_file(file_path)
            for match in matches:
                san = Sanitizer(
                    file=file_path,
                    line=match['line'],
                    type=match['type'],
                    name=match.get('decorator', match.get('function', '')),
                    framework=match.get('framework', 'unknown'),
                    confidence=1.0
                )
                sanitizers.append(san)
        
        logging.info(f"Found {len(sanitizers)} sanitizers")
        return sanitizers
    
    def _scan_sinks(self, py_files: List[str]) -> List[Sink]:
        """Scan for sensitive sinks"""
        matcher = PythonPatternMatcher(self.sink_patterns)
        scanner = FileScanner(matcher)
        sinks = []
        
        for file_path in py_files:
            matches = scanner.scan_file(file_path)
            for match in matches:
                sink = Sink(
                    file=file_path,
                    line=match['line'],
                    category=match.get('category', 'unknown'),
                    function=match.get('function', ''),
                    confidence=1.0
                )
                sinks.append(sink)
        
        logging.info(f"Found {len(sinks)} sinks")
        return sinks
    
    def _scan_exports(self, repo_root: str, py_files: List[str]) -> List[Export]:
        """Scan for library exports from __init__.py files"""
        exports = []
        
        # 1. First, look for main package __init__ files directly (not limited by py_files)
        # This ensures we capture the main library's exports even if py_files is capped at 1000
        main_init_files = self._find_main_package_inits(repo_root)
        
        # 2. Also add __init__ files from py_files (already scanned)
        init_files_from_scan = [f for f in py_files if f.endswith('__init__.py')]
        
        # Combine and deduplicate
        all_init_files = list(set(main_init_files + init_files_from_scan))
        
        # Sort to prioritize top-level and src/ package inits
        def init_priority(path: str) -> int:
            # src/*/init = 0 (highest priority)
            if '/src/' in path and path.count('/') < 10:
                return 0
            # Top-level package init = 1
            if path.count('/') < 5:
                return 1
            # Deep nested test files = 100 (lowest)
            return 100
        
        all_init_files = sorted(all_init_files, key=init_priority)
        
        # Limit to reasonable number of init files to scan (focus on main packages)
        # all_init_files = all_init_files[:50]  # Scan up to 50 main package init files
        
        for file_path in all_init_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                tree = ast.parse(content, filename=file_path)
                
                # Track imports and re-exports
                for node in ast.walk(tree):
                    # 1. Check for __all__ assignments (explicit export list)
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name) and target.id == '__all__':
                                if isinstance(node.value, (ast.List, ast.Tuple)):
                                    for elt in node.value.elts:
                                        if isinstance(elt, ast.Constant):
                                            exports.append(Export(
                                                file=file_path,
                                                line=node.lineno,
                                                symbol=elt.value,
                                                type='export_all'
                                            ))
                    
                    # 2. Collect 'from X import Y as Y' patterns (re-exports)
                    if isinstance(node, ast.ImportFrom):
                        module = node.module or ''
                        for alias in node.names:
                            import_name = alias.name
                            export_name = alias.asname or alias.name
                            if not export_name.startswith('_'):  # Public
                                exports.append(Export(
                                    file=file_path,
                                    line=node.lineno,
                                    symbol=export_name,
                                    type='import_re_export',
                                    extra={'from_module': module, 'original_name': import_name}
                                ))
                    
                    # 3. Top-level functions and classes (direct definitions)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        if not node.name.startswith('_'):  # Public API
                            exports.append(Export(
                                file=file_path,
                                line=node.lineno,
                                symbol=node.name,
                                type='function' if isinstance(node, ast.FunctionDef) else ('async_function' if isinstance(node, ast.AsyncFunctionDef) else 'class')
                            ))
                
                # 4. Parse _import_structure dict (common in large libs like transformers)
                if '_import_structure' in content or 'define_import_structure' in content:
                    self._extract_import_structure_exports(file_path, content, exports)
                    
            except Exception as e:
                logging.debug(f"Error parsing {file_path}: {e}")
        
        logging.info(f"Found {len(exports)} exports")
        return exports
    
    def _find_main_package_inits(self, repo_root: str) -> List[str]:
        """Find main package __init__.py files (not limited by file count)"""
        inits = []
        ignore_dirs = {'.git', '__pycache__', '.venv', 'venv', 'node_modules', '.tox', 'build', 'dist', '.egg-info', 'tests', 'test', 'examples', 'docs'}
        
        def walk_limited(path: str, depth: int = 0, max_depth: int = 3) -> None:
            if depth > max_depth:
                return
            try:
                for item in os.listdir(path):
                    if item.startswith('.'):
                        continue
                    item_path = os.path.join(path, item)
                    if os.path.isdir(item_path):
                        if item not in ignore_dirs:
                            walk_limited(item_path, depth + 1, max_depth)
                    elif item == '__init__.py':
                        inits.append(item_path)
            except:
                pass
        
        walk_limited(repo_root)
        return inits
    
    def _extract_import_structure_exports(self, file_path: str, content: str, exports: List[Export]) -> None:
        """Extract exports from _import_structure dictionaries"""
        import re
        try:
            # Look for _import_structure = { ... }
            pattern = r'_import_structure\s*=\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
            matches = re.finditer(pattern, content, re.DOTALL)
            
            for match in matches:
                struct_content = match.group(1)
                # Extract "key": [...] patterns
                entry_pattern = r'"([^"]+)"\s*:\s*\[(.*?)\]'
                for entry_match in re.finditer(entry_pattern, struct_content, re.DOTALL):
                    module = entry_match.group(1)
                    exports_str = entry_match.group(2)
                    # Extract quoted strings
                    for item_match in re.finditer(r'"([^"]+)"', exports_str):
                        symbol = item_match.group(1)
                        if not symbol.startswith('_'):
                            exports.append(Export(
                                file=file_path,
                                line=1,
                                symbol=symbol,
                                type='import_structure_entry',
                                extra={'module': module}
                            ))
        except Exception as e:
            logging.debug(f"Error extracting _import_structure from {file_path}: {e}")
    
    
    def _parse_dependencies(self, repo_root: str) -> List[Dep]:
        """Parse Python dependencies from various sources"""
        deps = []
        
        # 1. Check requirements.txt (and variants)
        req_files = [
            'requirements.txt',
            'requirements-dev.txt',
            'requirements-test.txt',
            'requirements-tests.txt',
            'requirements-docs.txt',
        ]
        
        for req_file_name in req_files:
            req_file = os.path.join(repo_root, req_file_name)
            if os.path.exists(req_file):
                try:
                    with open(req_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            # Skip comments and empty lines
                            if not line or line.startswith('#'):
                                continue
                            # Skip special directives like '-r' or '-e'
                            if line.startswith('-'):
                                deps.append(Dep(
                                    name=line,
                                    version=None,
                                    source=req_file_name
                                ))
                                continue
                            # Parse version specifiers
                            parsed = False
                            for sep in ['==', '>=', '<=', '~=', '!=', '>', '<']:
                                if sep in line:
                                    parts = line.split(sep, 1)
                                    deps.append(Dep(
                                        name=parts[0].strip(),
                                        version=parts[1].strip() if len(parts) > 1 else None,
                                        source=req_file_name
                                    ))
                                    parsed = True
                                    break
                            if not parsed:
                                # No version specifier
                                deps.append(Dep(name=line, source=req_file_name))
                except Exception as e:
                    logging.debug(f"Error parsing {req_file}: {e}")
        
        # 2. Parse pyproject.toml if present
        pyproject_file = os.path.join(repo_root, 'pyproject.toml')
        if os.path.exists(pyproject_file):
            try:
                import sys
                if sys.version_info >= (3, 11):
                    import tomllib
                else:
                    try:
                        import tomli as tomllib
                    except ImportError:
                        tomllib = None
            except:
                tomllib = None
            
            if tomllib:
                try:
                    with open(pyproject_file, 'rb') as f:
                        if hasattr(tomllib, 'load'):
                            pyproject = tomllib.load(f)
                        else:
                            import toml
                            f.seek(0)
                            pyproject = toml.load(f)
                    
                    # Extract dependencies from [project] section
                    if 'project' in pyproject and 'dependencies' in pyproject['project']:
                        for dep_spec in pyproject['project']['dependencies']:
                            # Parse version from dep_spec (e.g., "starlette>=0.40.0,<0.51.0")
                            for sep in ['>=', '<=', '==', '~=', '!=', '>', '<', ',']:
                                if sep in dep_spec:
                                    parts = dep_spec.split(sep, 1)
                                    deps.append(Dep(
                                        name=parts[0].strip(),
                                        version=parts[1].strip() if len(parts) > 1 else None,
                                        source='pyproject.toml'
                                    ))
                                    break
                            else:
                                deps.append(Dep(name=dep_spec.strip(), source='pyproject.toml'))
                except Exception as e:
                    logging.debug(f"Error parsing pyproject.toml: {e}")
        
        # 3. Parse setup.py if present (simple parsing)
        setup_file = os.path.join(repo_root, 'setup.py')
        if os.path.exists(setup_file):
            try:
                with open(setup_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Look for install_requires list
                import re
                install_requires_match = re.search(
                    r'install_requires\s*=\s*\[(.*?)\]',
                    content,
                    re.DOTALL
                )
                if install_requires_match:
                    deps_str = install_requires_match.group(1)
                    # Extract quoted strings
                    for match in re.finditer(r'["\']([^"\']+)["\']', deps_str):
                        dep_spec = match.group(1)
                        for sep in ['>=', '<=', '==', '~=', '!=', '>', '<']:
                            if sep in dep_spec:
                                parts = dep_spec.split(sep, 1)
                                deps.append(Dep(
                                    name=parts[0].strip(),
                                    version=parts[1].strip() if len(parts) > 1 else None,
                                    source='setup.py'
                                ))
                                break
                        else:
                            deps.append(Dep(name=dep_spec.strip(), source='setup.py'))
            except Exception as e:
                logging.debug(f"Error parsing setup.py: {e}")
        
        logging.info(f"Found {len(deps)} dependencies")
        return deps
