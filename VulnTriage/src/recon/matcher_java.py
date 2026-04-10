import os
import re
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any
from .matcher import load_patterns, JavaPatternMatcher
from .models import EntryPoint, Sanitizer, Sink, Export, Dep


class JavaMatcher:
    """Java-specific matcher integrating all pattern types"""
    
    def __init__(self, patterns_dir: str):
        self.patterns_dir = patterns_dir
        self.entry_patterns = load_patterns(os.path.join(patterns_dir, 'java', 'entry.yaml'))
        self.sanitizer_patterns = load_patterns(os.path.join(patterns_dir, 'java', 'sanitizer.yaml'))
        self.sink_patterns = load_patterns(os.path.join(patterns_dir, 'java', 'sink.yaml'))
        self.config_patterns = load_patterns(os.path.join(patterns_dir, 'java', 'config.yaml'))
    
    def scan_repo(self, repo_root: str) -> dict:
        """Scan Java repository for all patterns"""
        result = {
            'entrypoints': [],
            'sanitizers': [],
            'sinks': [],
            'exports': [],
            'deps': []
        }
        
        # Find all Java files
        java_files = self._find_java_files(repo_root)
        logging.info(f"Found {len(java_files)} Java files to scan")
        
        # Scan for entrypoints
        if self.entry_patterns:
            result['entrypoints'] = self._scan_entrypoints(java_files)
        
        # # Scan for sanitizers
        if self.sanitizer_patterns:
            result['sanitizers'] = self._scan_sanitizers(java_files)
        
        # # Scan for sinks
        if self.sink_patterns:
            result['sinks'] = self._scan_sinks(java_files)
        
        # Scan for exports (public APIs)
        result['exports'] = self._scan_exports(java_files)
        
        # Parse dependencies
        result['deps'] = self._parse_dependencies(repo_root)
        
        return result
    
    def _find_java_files(self, repo_root: str, max_files: int = float('inf')) -> List[str]:
        """Find Java source files, respecting common ignore patterns"""
        java_files = []
        ignore_dirs = {
            'target', 'build', 'out', '.git', '.gradle', 
            'node_modules', 'test', 'tests', '__pycache__'
        }
        
        for root, dirs, files in os.walk(repo_root):
            # Filter ignored directories
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            
            for file in files:
                if file.endswith('.java'):
                    java_files.append(os.path.join(root, file))
                    if len(java_files) >= max_files:
                        logging.warning(f"Reached max files limit {max_files}, stopping scan")
                        return java_files
        
        return java_files
    
    def _scan_entrypoints(self, java_files: List[str]) -> List[EntryPoint]:
        """Scan for HTTP endpoints using patterns"""
        entrypoints = []
        
        if not self.entry_patterns:
            return entrypoints
        
        # Use JavaPatternMatcher to match annotations based on patterns
        matcher = JavaPatternMatcher(self.entry_patterns)
        
        for file_path in java_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                # Match annotations using pattern-based matcher
                matches = matcher.match_annotations(file_path, lines)
                
                # First pass: identify class-level context
                class_path = None
                class_is_controller = False
                class_framework = 'unknown'
                
                for match in matches:
                    annotation = match['annotation']
                    scope = match.get('scope', 'method')
                    
                    # Check if this is a class-level controller annotation
                    if scope in ['class', 'class_or_method']:
                        if 'Controller' in annotation or 'RestController' in annotation:
                            class_is_controller = True
                            class_framework = match.get('framework', 'unknown')
                            context = match.get('context', {})
                            if 'path' in context:
                                class_path = context['path']
                
                # Second pass: process method-level endpoint annotations
                for match in matches:
                    annotation = match['annotation']
                    context = match.get('context', {})
                    framework = match.get('framework', class_framework)
                    scope = match.get('scope', 'method')
                    
                    # Only process method-level endpoint annotations
                    # Also handle JAX-RS and Servlet annotations that don't require controller class
                    is_endpoint_annotation = (
                        scope in ['method', 'class_or_method'] and 
                        (class_is_controller or 
                         annotation in ['Path', 'WebServlet', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
                    )
                    
                    if is_endpoint_annotation:
                        # Extract path from context
                        path = context.get('path', '')
                        
                        # Extract method from context
                        method = context.get('method', 'UNKNOWN')
                        
                        # Combine class and method paths
                        full_path = path
                        if class_path and path:
                            full_path = class_path.rstrip('/') + '/' + path.lstrip('/')
                        elif class_path:
                            full_path = class_path
                        elif not full_path:
                            full_path = '/'
                        
                        # Look for method name (next line typically has method signature)
                        handler = ''
                        line_num = match['line']
                        if line_num < len(lines):
                            next_line = lines[line_num].strip()
                            method_sig_match = re.search(r'(?:public|private|protected)?\s+\w+\s+(\w+)\s*\(', next_line)
                            if method_sig_match:
                                handler = method_sig_match.group(1)
                        
                        entrypoints.append(EntryPoint(
                            file=file_path,
                            line=line_num,
                            framework=framework,
                            method=method,
                            path=full_path,
                            handler=handler,
                            confidence=0.9
                        ))
            except Exception as e:
                logging.debug(f"Error scanning {file_path}: {e}")
        
        logging.info(f"Found {len(entrypoints)} entrypoints")
        return entrypoints
    
    def _scan_sanitizers(self, java_files: List[str]) -> List[Sanitizer]:
        """Scan for validation/security annotations using patterns"""
        sanitizers = []
        
        if not self.sanitizer_patterns:
            return sanitizers
        
        # Use JavaPatternMatcher to match annotations based on patterns
        matcher = JavaPatternMatcher(self.sanitizer_patterns)
        
        for file_path in java_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                # Match annotations using pattern-based matcher
                matches = matcher.match_annotations(file_path, lines)
                
                for match in matches:
                    sanitizers.append(Sanitizer(
                        file=file_path,
                        line=match['line'],
                        type='annotation',
                        name=match['annotation'],
                        framework=match.get('framework', 'unknown'),
                        confidence=1.0
                    ))
            except Exception as e:
                logging.debug(f"Error scanning {file_path}: {e}")
        
        logging.info(f"Found {len(sanitizers)} sanitizers")
        return sanitizers
    
    def _scan_sinks(self, java_files: List[str]) -> List[Sink]:
        """Scan for sensitive method calls using patterns"""
        sinks = []
        
        if not self.sink_patterns:
            return sinks
        
        # Use JavaPatternMatcher to match method calls based on patterns
        matcher = JavaPatternMatcher(self.sink_patterns)
        
        for file_path in java_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                # Match method calls using pattern-based matcher
                matches = matcher.match_method_calls(file_path, lines)
                
                for match in matches:
                    sinks.append(Sink(
                        file=file_path,
                        line=match['line'],
                        category=match.get('category', 'unknown'),
                        function=match.get('function', ''),
                        confidence=match.get('confidence', 0.8)
                    ))
            except Exception as e:
                logging.debug(f"Error scanning {file_path}: {e}")
        
        logging.info(f"Found {len(sinks)} sinks")
        return sinks
    
    def _scan_exports(self, java_files: List[str]) -> List[Export]:
        """Scan for public API exports (public classes and methods)"""
        exports = []
        
        # Regex for public class/interface declarations
        class_regex = re.compile(r'public\s+(?:class|interface|enum)\s+(\w+)')
        method_regex = re.compile(r'public\s+(?:static\s+)?(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*\(')
        
        for file_path in java_files:
            # Skip test files
            if '/test/' in file_path or '/tests/' in file_path:
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                in_public_class = False
                current_class = None
                
                for i, line in enumerate(lines, 1):
                    # Check for public class
                    class_match = class_regex.search(line)
                    if class_match:
                        class_name = class_match.group(1)
                        current_class = class_name
                        in_public_class = True
                        exports.append(Export(
                            file=file_path,
                            line=i,
                            symbol=class_name,
                            type='class',
                            extra={'access': 'public'}
                        ))
                    
                    # Check for public methods (only in public classes)
                    if in_public_class:
                        method_match = method_regex.search(line)
                        if method_match:
                            method_name = method_match.group(1)
                            # Skip constructors (same name as class)
                            if method_name != current_class:
                                exports.append(Export(
                                    file=file_path,
                                    line=i,
                                    symbol=f"{current_class}.{method_name}",
                                    type='method',
                                    extra={'class': current_class, 'access': 'public'}
                                ))
            except Exception as e:
                logging.debug(f"Error scanning {file_path}: {e}")
        
        logging.info(f"Found {len(exports)} exports")
        return exports
    
    def _parse_dependencies(self, repo_root: str) -> List[Dep]:
        """Parse Java dependencies from pom.xml, build.gradle, etc."""
        deps = []
        
        # 1. Parse pom.xml (Maven)
        pom_file = os.path.join(repo_root, 'pom.xml')
        if os.path.exists(pom_file):
            try:
                tree = ET.parse(pom_file)
                root = tree.getroot()
                
                # Maven uses XML namespaces
                ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
                
                # Find all dependencies
                for dep in root.findall('.//m:dependency', ns):
                    group_id = dep.find('m:groupId', ns)
                    artifact_id = dep.find('m:artifactId', ns)
                    version = dep.find('m:version', ns)
                    
                    if group_id is not None and artifact_id is not None:
                        name = f"{group_id.text}:{artifact_id.text}"
                        ver = version.text if version is not None else None
                        deps.append(Dep(
                            name=name,
                            version=ver,
                            source='pom.xml'
                        ))
                
                # Also try without namespace (some pom.xml don't use it)
                if not deps:
                    for dep in root.findall('.//dependency'):
                        group_id = dep.find('groupId')
                        artifact_id = dep.find('artifactId')
                        version = dep.find('version')
                        
                        if group_id is not None and artifact_id is not None:
                            name = f"{group_id.text}:{artifact_id.text}"
                            ver = version.text if version is not None else None
                            deps.append(Dep(
                                name=name,
                                version=ver,
                                source='pom.xml'
                            ))
            except Exception as e:
                logging.debug(f"Error parsing pom.xml: {e}")
        
        # 2. Parse build.gradle (Gradle)
        gradle_files = ['build.gradle', 'build.gradle.kts']
        for gradle_file_name in gradle_files:
            gradle_file = os.path.join(repo_root, gradle_file_name)
            if os.path.exists(gradle_file):
                try:
                    with open(gradle_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Regex for dependencies: implementation 'group:artifact:version'
                    # Patterns: implementation('...') or implementation "..."
                    dep_patterns = [
                        r'(?:implementation|api|compile|testImplementation|runtimeOnly)\s*\(["\']([^"\']+)["\']\)',
                        r'(?:implementation|api|compile|testImplementation|runtimeOnly)\s+["\']([^"\']+)["\']',
                    ]
                    
                    for pattern in dep_patterns:
                        for match in re.finditer(pattern, content):
                            dep_str = match.group(1)
                            # Parse group:artifact:version
                            parts = dep_str.split(':')
                            if len(parts) >= 2:
                                name = f"{parts[0]}:{parts[1]}"
                                version = parts[2] if len(parts) >= 3 else None
                                deps.append(Dep(
                                    name=name,
                                    version=version,
                                    source=gradle_file_name
                                ))
                except Exception as e:
                    logging.debug(f"Error parsing {gradle_file_name}: {e}")
        
        logging.info(f"Found {len(deps)} dependencies")
        return deps
