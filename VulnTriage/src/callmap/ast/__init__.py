"""
callmap.ast - Tree-sitter based AST parsing for symbol location.

Provides language-specific AST parsers to find the containing function/class/variable
for a given source position.
"""

from callmap.ast.base import (
    AstParser,
    SymbolInfo,
    SYMBOL_TYPE_FUNCTION,
    SYMBOL_TYPE_CLASS,
    SYMBOL_TYPE_VARIABLE,
    SYMBOL_TYPE_METHOD,
    SYMBOL_TYPE_CONSTRUCTOR,
)
from callmap.ast.py import PyAstParser
from callmap.ast.java import JavaAstParser

__all__ = [
    "AstParser",
    "SymbolInfo",
    "SYMBOL_TYPE_FUNCTION",
    "SYMBOL_TYPE_CLASS",
    "SYMBOL_TYPE_VARIABLE",
    "SYMBOL_TYPE_METHOD",
    "SYMBOL_TYPE_CONSTRUCTOR",
    "PyAstParser",
    "JavaAstParser",
    "get_parser",
]


def get_parser(lang: str) -> AstParser:
    """Get AST parser for the specified language."""
    if lang in ("py", "python"):
        return PyAstParser()
    elif lang in ("java",):
        return JavaAstParser()
    else:
        raise ValueError(f"Unsupported language: {lang}")
