"""
Base AST parser interface using tree-sitter.

Defines the abstract interface for language-specific AST parsers that locate
symbols (functions, classes, variables) containing a given source position.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

import tree_sitter

# Symbol types
SYMBOL_TYPE_FUNCTION = "function"
SYMBOL_TYPE_CLASS = "class"
SYMBOL_TYPE_VARIABLE = "variable"
SYMBOL_TYPE_METHOD = "method"
SYMBOL_TYPE_CONSTRUCTOR = "constructor"


@dataclass
class SymbolInfo:
    """Information about a code symbol (function, class, variable, etc.)."""

    name: str
    symbol_type: str  # function, class, variable, method, constructor
    start_line: int  # 0-based, start of entire declaration
    start_column: int  # 0-based, start of entire declaration
    end_line: int  # 0-based
    end_column: int  # 0-based
    # Position of the symbol name itself (for LSP queries)
    name_line: Optional[int] = None  # 0-based, line of the name token
    name_column: Optional[int] = None  # 0-based, column of the name token
    # For nested symbols, parent may be set
    parent: Optional["SymbolInfo"] = None

    def contains_position(self, line: int, column: int) -> bool:
        """Check if this symbol's range contains the given position (0-based)."""
        if line < self.start_line or line > self.end_line:
            return False
        if line == self.start_line and column < self.start_column:
            return False
        if line == self.end_line and column > self.end_column:
            return False
        return True

    def span(self) -> int:
        """Return a rough size measure for comparing symbol specificity."""
        return (self.end_line - self.start_line) * 10000 + (self.end_column - self.start_column)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "symbol_type": self.symbol_type,
            "start_line": self.start_line,
            "start_column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        }


class AstParser(ABC):
    """Abstract base class for language-specific AST parsers."""

    def __init__(self):
        self._parser: Optional[tree_sitter.Parser] = None
        self._language: Optional[tree_sitter.Language] = None

    @abstractmethod
    def _init_language(self) -> tree_sitter.Language:
        """Initialize and return the tree-sitter Language object."""
        pass

    @property
    def parser(self) -> tree_sitter.Parser:
        """Lazy-initialize and return the parser."""
        if self._parser is None:
            self._language = self._init_language()
            self._parser = tree_sitter.Parser(self._language)
        return self._parser

    def parse_file(self, file_path: Path) -> Optional[tree_sitter.Tree]:
        """Parse a file and return the syntax tree."""
        try:
            content = file_path.read_bytes()
            return self.parser.parse(content)
        except Exception:
            return None

    def parse_text(self, text: str) -> Optional[tree_sitter.Tree]:
        """Parse text content and return the syntax tree."""
        try:
            return self.parser.parse(text.encode("utf-8"))
        except Exception:
            return None

    @abstractmethod
    def extract_symbols(self, tree: tree_sitter.Tree, source: bytes) -> List[SymbolInfo]:
        """
        Extract all relevant symbols (functions, classes, variables) from the AST.
        Returns a flat list; nesting is indicated via parent field.
        """
        pass

    @abstractmethod
    def get_symbol_node_types(self) -> Tuple[str, ...]:
        """Return node types that represent key symbols (function_definition, class_definition, etc.)."""
        pass

    def find_symbol_at_position(
        self,
        tree: tree_sitter.Tree,
        source: bytes,
        line: int,
        column: int,
        symbol_types: Optional[List[str]] = None,
    ) -> Optional[SymbolInfo]:
        """
        Find the innermost symbol containing the given position.
        
        Args:
            tree: Parsed syntax tree
            source: Source code bytes
            line: 0-based line number
            column: 0-based column number
            symbol_types: Optional filter for symbol types (function, class, variable, method)
        
        Returns:
            The innermost SymbolInfo containing the position, or None.
        """
        symbols = self.extract_symbols(tree, source)
        if symbol_types:
            symbols = [s for s in symbols if s.symbol_type in symbol_types]

        # Find all symbols containing the position
        containing = [s for s in symbols if s.contains_position(line, column)]
        if not containing:
            return None

        # Return the smallest (innermost) one
        containing.sort(key=lambda s: s.span())
        return containing[0]

    def find_enclosing_callable(
        self,
        tree: tree_sitter.Tree,
        source: bytes,
        line: int,
        column: int,
    ) -> Optional[SymbolInfo]:
        """
        Find the innermost function/method containing the given position.
        Falls back to class if no function found.
        """
        callable_types = [SYMBOL_TYPE_FUNCTION, SYMBOL_TYPE_METHOD, SYMBOL_TYPE_CONSTRUCTOR]
        result = self.find_symbol_at_position(tree, source, line, column, symbol_types=callable_types)
        if result:
            return result
        # Fall back to class
        return self.find_symbol_at_position(tree, source, line, column, symbol_types=[SYMBOL_TYPE_CLASS])

    def find_symbol_at_position_from_text(
        self,
        text: str,
        line: int,
        column: int,
        symbol_types: Optional[List[str]] = None,
    ) -> Optional[SymbolInfo]:
        """Convenience method to parse text and find symbol at position."""
        tree = self.parse_text(text)
        if not tree:
            return None
        return self.find_symbol_at_position(tree, text.encode("utf-8"), line, column, symbol_types)

    def find_enclosing_callable_from_text(
        self,
        text: str,
        line: int,
        column: int,
    ) -> Optional[SymbolInfo]:
        """Convenience method to parse text and find enclosing callable."""
        tree = self.parse_text(text)
        if not tree:
            return None
        return self.find_enclosing_callable(tree, text.encode("utf-8"), line, column)
