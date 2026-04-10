import yaml
import ast
import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
import fnmatch


def load_patterns(pattern_file: str) -> List[Dict[str, Any]]:
    """Load patterns from YAML file"""
    if not os.path.exists(pattern_file):
        return []
    with open(pattern_file, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
        return data.get('patterns', [])


def match_name(name: str, pattern: str) -> bool:
    """Match name against pattern (supports wildcards like *.get)"""
    if '*' in pattern:
        return fnmatch.fnmatch(name, pattern)
    return name == pattern


class PythonPatternMatcher:
    """Core pattern matching engine for Python (AST-based)"""
    
    def __init__(self, patterns: List[Dict[str, Any]]):
        self.patterns = patterns
        
    def match_decorators(self, node: ast.FunctionDef, file_path: str) -> List[Dict[str, Any]]:
        """Match decorators on a function"""
        matches = []
        for decorator in node.decorator_list:
            dec_name = self._get_decorator_name(decorator)
            if not dec_name:
                continue
                
            for pattern in self.patterns:
                if pattern.get('type') != 'decorator':
                    continue
                    
                for name_pattern in pattern.get('names', []):
                    if match_name(dec_name, name_pattern):
                        match = {
                            'type': 'decorator',
                            'matched_pattern': name_pattern,
                            'file': file_path,
                            'line': node.lineno,
                            'function': node.name,
                            'decorator': dec_name,
                            'framework': pattern.get('framework', 'unknown'),
                            'context': self._extract_context(decorator, pattern)
                        }
                        matches.append(match)
                        break
        return matches
    
    def match_function_calls(self, node: ast.Call, file_path: str, line: int) -> List[Dict[str, Any]]:
        """Match function calls"""
        matches = []
        call_name = self._get_call_name(node)
        if not call_name:
            return matches
            
        for pattern in self.patterns:
            if pattern.get('type') != 'function_call':
                continue
                
            for name_pattern in pattern.get('names', []):
                if match_name(call_name, name_pattern):
                    match = {
                        'type': 'function_call',
                        'matched_pattern': name_pattern,
                        'file': file_path,
                        'line': line,
                        'function': call_name,
                        'context': self._extract_call_context(node, pattern)
                    }
                    if 'framework' in pattern:
                        match['framework'] = pattern['framework']
                    if 'category' in pattern:
                        match['category'] = pattern['category']
                    matches.append(match)
                    break
        return matches
    
    def _get_decorator_name(self, decorator: ast.expr) -> Optional[str]:
        """Extract decorator name from AST node"""
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Attribute):
            parts = []
            node = decorator
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name):
                parts.append(node.id)
            return '.'.join(reversed(parts))
        elif isinstance(decorator, ast.Call):
            return self._get_decorator_name(decorator.func)
        return None
    
    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Extract function call name"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            n = node.func
            while isinstance(n, ast.Attribute):
                parts.append(n.attr)
                n = n.value
            if isinstance(n, ast.Name):
                parts.append(n.id)
            return '.'.join(reversed(parts))
        return None
    
    def _extract_context(self, decorator: ast.expr, pattern: Dict[str, Any]) -> Dict[str, Any]:
        """Extract context from decorator based on pattern extract rules"""
        context = {}
        extract_rules = pattern.get('extract', {})
        
        if not isinstance(decorator, ast.Call):
            return context
            
        # Extract path from first_arg
        if 'path' in extract_rules and extract_rules['path'] == 'first_arg':
            if decorator.args:
                arg = decorator.args[0]
                if isinstance(arg, ast.Constant):
                    context['path'] = arg.value
        
        # Extract method from decorator name
        if 'method' in extract_rules and extract_rules['method'] == 'decorator_name':
            dec_name = self._get_decorator_name(decorator)
            if dec_name and '.' in dec_name:
                context['method'] = dec_name.split('.')[-1].upper()
        
        return context
    
    def _extract_call_context(self, node: ast.Call, pattern: Dict[str, Any]) -> Dict[str, Any]:
        """Extract context from function call"""
        context = {}
        extract_rules = pattern.get('extract', {})
        
        if 'pattern' in extract_rules and extract_rules['pattern'] == 'first_arg':
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant):
                    context['pattern'] = arg.value
        
        if 'view' in extract_rules and extract_rules['view'] == 'second_arg':
            if len(node.args) > 1:
                arg = node.args[1]
                if isinstance(arg, ast.Name):
                    context['view'] = arg.id
                    
        return context


class JavaPatternMatcher:
    """Core matching engine for Java source files (pattern-based)"""
    
    def __init__(self, patterns: List[Dict[str, Any]]):
        self.patterns = patterns
    
    def match_annotations(self, file_path: str, file_lines: List[str]) -> List[Dict[str, Any]]:
        """Match annotations in Java source file"""
        matches = []
        
        # Build annotation patterns
        annotation_patterns = []
        for pattern in self.patterns:
            if pattern.get('type') == 'annotation':
                annotation_patterns.append(pattern)
        
        if not annotation_patterns:
            return matches
        
        # Build regex for all annotation names
        all_annotation_names = set()
        for pattern in annotation_patterns:
            all_annotation_names.update(pattern.get('names', []))
        
        if not all_annotation_names:
            return matches
        
        # Regex to match annotations: @AnnotationName or @AnnotationName(params)
        annotation_regex = re.compile(
            r'@(' + '|'.join(re.escape(name) for name in all_annotation_names) + 
            r')\s*(?:\(([^)]*)\))?',
            re.IGNORECASE
        )
        
        class_path = None
        class_is_controller = False
        current_class = None
        
        for i, line in enumerate(file_lines, 1):
            # Check for class-level controller annotations
            for pattern in annotation_patterns:
                if pattern.get('scope') in ['class', 'class_or_method']:
                    for name in pattern.get('names', []):
                        if f'@{name}' in line or f'@' + name in line:
                            if 'Controller' in name or 'RestController' in name:
                                class_is_controller = True
                                # Extract class-level path
                                path_match = re.search(r'["\']([^"\']+)["\']', line)
                                if path_match:
                                    class_path = path_match.group(1)
            
            # Match annotations in line
            for match in annotation_regex.finditer(line):
                annotation_name = match.group(1)
                params = match.group(2) or ''
                
                # Find matching pattern
                matched_pattern = None
                name_pattern = None
                for pattern in annotation_patterns:
                    for name_pat in pattern.get('names', []):
                        if match_name(annotation_name, name_pat):
                            matched_pattern = pattern
                            name_pattern = name_pat
                            break
                    if matched_pattern:
                        break
                
                if not matched_pattern:
                    continue
                
                # Extract context based on pattern rules
                context = self._extract_annotation_context(annotation_name, params, matched_pattern)
                
                # Determine scope
                scope = matched_pattern.get('scope', 'method')
                if scope in ['class', 'class_or_method'] and class_is_controller:
                    context['class_path'] = class_path
                
                match_result = {
                    'type': 'annotation',
                    'matched_pattern': name_pattern if name_pattern else annotation_name,
                    'file': file_path,
                    'line': i,
                    'annotation': annotation_name,
                    'framework': matched_pattern.get('framework', 'unknown'),
                    'scope': scope,
                    'context': context
                }
                
                if 'category' in matched_pattern:
                    match_result['category'] = matched_pattern['category']
                
                matches.append(match_result)
        
        return matches
    
    def match_method_calls(self, file_path: str, file_lines: List[str]) -> List[Dict[str, Any]]:
        """Match method calls in Java source file"""
        matches = []
        
        # Build method call patterns
        method_call_patterns = []
        for pattern in self.patterns:
            if pattern.get('type') == 'method_call':
                method_call_patterns.append(pattern)
        
        if not method_call_patterns:
            return matches
        
        for pattern in method_call_patterns:
            method_names = pattern.get('names', [])
            category = pattern.get('category', 'unknown')
            
            for i, line in enumerate(file_lines, 1):
                for method_name in method_names:
                    # Extract simple method name (last part after dot)
                    simple_name = method_name.split('.')[-1]
                    
                    # Match method calls: MethodName( or .methodName( or Class.MethodName(
                    patterns_to_try = [
                        re.compile(re.escape(simple_name) + r'\s*\('),
                        re.compile(r'\.' + re.escape(simple_name) + r'\s*\('),
                        re.compile(re.escape(method_name) + r'\s*\('),
                    ]
                    
                    for pattern_regex in patterns_to_try:
                        if pattern_regex.search(line):
                            match_result = {
                                'type': 'method_call',
                                'matched_pattern': method_name,
                                'file': file_path,
                                'line': i,
                                'function': method_name,
                                'category': category,
                                'confidence': 0.8
                            }
                            matches.append(match_result)
                            break
        
        return matches
    
    def _extract_annotation_context(self, annotation_name: str, params: str, pattern: Dict[str, Any]) -> Dict[str, Any]:
        """Extract context from annotation based on pattern extract rules"""
        context = {}
        extract_rules = pattern.get('extract', [])
        
        if not extract_rules:
            # Support old format: extract as dict
            extract_rules_dict = pattern.get('extract', {})
            if isinstance(extract_rules_dict, dict):
                # Convert to list format
                extract_rules = [{'key': k, 'source': v} for k, v in extract_rules_dict.items()]
        
        if not extract_rules:
            return context
        
        # Handle list format: extract: [{path: value}, {method: annotation_name}]
        for rule in extract_rules:
            if isinstance(rule, dict):
                for key, source in rule.items():
                    if source == 'value':
                        # Extract from annotation params: value="path" or "path"
                        path_match = re.search(r'(?:value\s*=\s*)?["\']([^"\']+)["\']', params)
                        if path_match:
                            context[key] = path_match.group(1)
                    elif source == 'annotation_name':
                        # Extract from annotation name itself
                        if 'GetMapping' in annotation_name or annotation_name == 'GET':
                            context[key] = 'GET'
                        elif 'PostMapping' in annotation_name or annotation_name == 'POST':
                            context[key] = 'POST'
                        elif 'PutMapping' in annotation_name or annotation_name == 'PUT':
                            context[key] = 'PUT'
                        elif 'DeleteMapping' in annotation_name or annotation_name == 'DELETE':
                            context[key] = 'DELETE'
                        elif 'PatchMapping' in annotation_name or annotation_name == 'PATCH':
                            context[key] = 'PATCH'
                        elif 'RequestMapping' in annotation_name:
                            # Try to extract method from params
                            method_match = re.search(r'method\s*=\s*RequestMethod\.(\w+)', params)
                            if method_match:
                                context[key] = method_match.group(1)
                            else:
                                context[key] = 'REQUEST'
                    elif source == 'urlPatterns':
                        # Extract urlPatterns from params
                        url_match = re.search(r'urlPatterns\s*=\s*\{([^}]+)\}', params)
                        if url_match:
                            # Extract quoted strings from array
                            patterns = re.findall(r'["\']([^"\']+)["\']', url_match.group(1))
                            if patterns:
                                context[key] = patterns[0]  # Take first pattern
        
        return context


class FileScanner:
    """Scan Python files with pattern matcher"""
    
    def __init__(self, matcher: PythonPatternMatcher):
        self.matcher = matcher
    
    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a single Python file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            tree = ast.parse(content, filename=file_path)
            return self._scan_tree(tree, file_path)
        except Exception as e:
            return []
    
    def _scan_tree(self, tree: ast.AST, file_path: str) -> List[Dict[str, Any]]:
        """Scan AST tree for matches"""
        matches = []
        
        for node in ast.walk(tree):
            # Match decorators on functions (sync/async)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                matches.extend(self.matcher.match_decorators(node, file_path))
            
            # Match function calls
            if isinstance(node, ast.Call):
                matches.extend(self.matcher.match_function_calls(node, file_path, node.lineno))
        
        return matches
