import os
from pathlib import Path
from typing import Optional


def detect_language(repo_root: str, override: Optional[str] = None) -> str:
    """Detect primary language of repository"""
    if override and override != 'auto':
        return override
    
    # Check for marker files
    if os.path.exists(os.path.join(repo_root, 'pyproject.toml')) or \
       os.path.exists(os.path.join(repo_root, 'setup.py')) or \
       os.path.exists(os.path.join(repo_root, 'requirements.txt')):
        return 'py'
    
    if os.path.exists(os.path.join(repo_root, 'pom.xml')) or \
       os.path.exists(os.path.join(repo_root, 'build.gradle')):
        return 'java'
    
    # Count files by extension
    py_count = 0
    java_count = 0
    
    for root, dirs, files in os.walk(repo_root):
        # Skip common ignore directories
        dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules', '.venv', 'venv'}]
        
        for file in files:
            if file.endswith('.py'):
                py_count += 1
            elif file.endswith('.java'):
                java_count += 1
        
        # Early exit if clear winner
        if py_count > 10 or java_count > 10:
            break
    
    if py_count > java_count:
        return 'py'
    elif java_count > 0:
        return 'java'
    
    return 'unknown'
