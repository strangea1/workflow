from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class EntryPoint:
    """HTTP entrypoint (router/controller)"""
    file: str
    line: int
    framework: str
    method: str  # GET/POST/etc
    path: str
    handler: str
    confidence: float = 1.0
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Sanitizer:
    """Validation/sanitization point"""
    file: str
    line: int
    type: str  # decorator/function_call
    name: str
    framework: str
    confidence: float = 1.0


@dataclass
class Sink:
    """Sensitive operation sink"""
    file: str
    line: int
    category: str  # command_injection/code_injection/file_access
    function: str
    confidence: float = 1.0


@dataclass
class Export:
    """Library export (public API)"""
    file: str
    line: int
    symbol: str
    type: str  # export_all//function/async_function/class
    extra: Dict[str, Any] = field(default_factory=dict)
    

@dataclass
class Dep:
    """Dependency"""
    name: str
    version: Optional[str] = None
    source: str = ""  # requirements.txt/pyproject.toml/etc


@dataclass
class Config:
    """Configuration file"""
    file: str
    type: str
    content: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TechStack:
    """Technology stack item"""
    type: str
    file: str
    

@dataclass
class ReconResult:
    """Complete recon result"""
    repo: str
    language: str
    entrypoints: List[EntryPoint] = field(default_factory=list)
    sanitizers: List[Sanitizer] = field(default_factory=list)
    sinks: List[Sink] = field(default_factory=list)
    exports: List[Export] = field(default_factory=list)
    deps: List[Dep] = field(default_factory=list)
    configs: List[Config] = field(default_factory=list)
    tech_stack: List[TechStack] = field(default_factory=list)
