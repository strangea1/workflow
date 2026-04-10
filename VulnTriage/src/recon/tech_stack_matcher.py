import os
import yaml
import logging
from pathlib import Path
from typing import List, Dict, Any
from .models import TechStack
from .matcher import load_patterns


class TechStackMatcher:
    """Technology stack matcher based on pattern files"""
    
    def __init__(self, patterns_dir: str):
        self.patterns_dir = patterns_dir
        tech_stack_file = os.path.join(patterns_dir, 'tech_stack', 'tech_stack.yaml')
        self.patterns = load_patterns(tech_stack_file)
    
    def match_tech_stack(self, repo_root: str) -> List[TechStack]:
        """Match technology stack based on patterns"""
        tech_stack_items = []
        
        for pattern in self.patterns:
            # Use standard pattern format: type: file, names: [...]
            if pattern.get('type') != 'file':
                continue
            
            names = pattern.get('names', [])
            framework = pattern.get('framework', 'unknown')
            
            if not names:
                continue
            
            # Search for files matching each name pattern
            for name_pattern in names:
                matched_files = self._find_files(repo_root, name_pattern)
                
                for file_path in matched_files:
                    tech_stack_items.append(TechStack(
                        type=framework,  # Use framework as tech stack type
                        file=file_path
                    ))
        
        logging.info(f"Found {len(tech_stack_items)} tech stack items")
        return tech_stack_items
    
    def _find_files(self, repo_root: str, filename: str) -> List[str]:
        """Find files matching the filename pattern"""
        matched_files = []
        
        # Support wildcard patterns
        if '*' in filename:
            import fnmatch
            for root, dirs, files in os.walk(repo_root):
                # Skip common ignore directories
                dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules', '.venv', 'venv', 'target', 'build'}]
                
                for file in files:
                    if fnmatch.fnmatch(file, filename):
                        matched_files.append(os.path.join(root, file))
        else:
            # Exact filename match
            for root, dirs, files in os.walk(repo_root):
                # Skip common ignore directories
                dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules', '.venv', 'venv', 'target', 'build'}]
                
                if filename in files:
                    matched_files.append(os.path.join(root, filename))
        
        return matched_files
    
    def get_matched_frameworks(self, repo_root: str) -> List[str]:
        """Get list of matched framework/technology names from tech stack"""
        tech_stack = self.match_tech_stack(repo_root)
        frameworks = set()
        
        # Map tech stack types to framework names
        for item in tech_stack:
            frameworks.add(item.type)
        
        return list(frameworks)
