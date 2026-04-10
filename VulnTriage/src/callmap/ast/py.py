"""
Python AST parser using tree-sitter-python.

Extracts functions, classes, and module-level variables from Python source code.
"""

from typing import List, Optional, Tuple

import tree_sitter
import tree_sitter_python

from callmap.ast.base import (
    AstParser,
    SymbolInfo,
    SYMBOL_TYPE_FUNCTION,
    SYMBOL_TYPE_CLASS,
    SYMBOL_TYPE_METHOD,
    SYMBOL_TYPE_VARIABLE,
)


class PyAstParser(AstParser):
    """Tree-sitter based Python AST parser."""

    def _init_language(self) -> tree_sitter.Language:
        return tree_sitter.Language(tree_sitter_python.language())

    def get_symbol_node_types(self) -> Tuple[str, ...]:
        return (
            "function_definition",
            "class_definition",
            "assignment",
            "decorated_definition",
        )

    def extract_symbols(self, tree: tree_sitter.Tree, source: bytes) -> List[SymbolInfo]:
        """Extract all functions, classes, and top-level variables from Python AST."""
        symbols: List[SymbolInfo] = []
        self._extract_from_node(tree.root_node, source, symbols, parent=None, in_class=False)
        return symbols

    def _extract_from_node(
        self,
        node: tree_sitter.Node,
        source: bytes,
        symbols: List[SymbolInfo],
        parent: Optional[SymbolInfo],
        in_class: bool,
    ) -> None:
        """Recursively extract symbols from AST nodes."""
        node_type = node.type

        if node_type == "function_definition":
            sym = self._parse_function(node, source, parent, is_method=in_class)
            if sym:
                symbols.append(sym)
                # Recurse into function body for nested functions
                for child in node.children:
                    if child.type == "block":
                        self._extract_from_node(child, source, symbols, parent=sym, in_class=False)

        elif node_type == "class_definition":
            sym = self._parse_class(node, source, parent)
            if sym:
                symbols.append(sym)
                # Recurse into class body
                for child in node.children:
                    if child.type == "block":
                        self._extract_from_node(child, source, symbols, parent=sym, in_class=True)

        elif node_type == "decorated_definition":
            # Handle @decorator followed by function or class
            for child in node.children:
                if child.type in ("function_definition", "class_definition"):
                    # Use the decorated_definition's range for the symbol
                    self._extract_from_node(child, source, symbols, parent, in_class)

        elif node_type == "assignment" and parent is None:
            # Module-level variable assignment
            sym = self._parse_assignment(node, source)
            if sym:
                symbols.append(sym)

        else:
            # Recurse into children
            for child in node.children:
                self._extract_from_node(child, source, symbols, parent, in_class)

    def _parse_function(
        self,
        node: tree_sitter.Node,
        source: bytes,
        parent: Optional[SymbolInfo],
        is_method: bool,
    ) -> Optional[SymbolInfo]:
        """Parse a function_definition node."""
        name_node = node.child_by_field_name("name")
        if not name_node:
            return None
        name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
        return SymbolInfo(
            name=name,
            symbol_type=SYMBOL_TYPE_METHOD if is_method else SYMBOL_TYPE_FUNCTION,
            start_line=node.start_point[0],
            start_column=node.start_point[1],
            end_line=node.end_point[0],
            end_column=node.end_point[1],
            name_line=name_node.start_point[0],
            name_column=name_node.start_point[1],
            parent=parent,
        )

    def _parse_class(
        self,
        node: tree_sitter.Node,
        source: bytes,
        parent: Optional[SymbolInfo],
    ) -> Optional[SymbolInfo]:
        """Parse a class_definition node."""
        name_node = node.child_by_field_name("name")
        if not name_node:
            return None
        name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
        return SymbolInfo(
            name=name,
            symbol_type=SYMBOL_TYPE_CLASS,
            start_line=node.start_point[0],
            start_column=node.start_point[1],
            end_line=node.end_point[0],
            end_column=node.end_point[1],
            name_line=name_node.start_point[0],
            name_column=name_node.start_point[1],
            parent=parent,
        )

    def _parse_assignment(
        self,
        node: tree_sitter.Node,
        source: bytes,
    ) -> Optional[SymbolInfo]:
        """Parse module-level assignment (variable definition)."""
        # Get the left side (target)
        left = node.child_by_field_name("left")
        if not left:
            # Try first child for simple assignments
            for child in node.children:
                if child.type == "identifier":
                    left = child
                    break
        if not left or left.type != "identifier":
            return None
        name = source[left.start_byte:left.end_byte].decode("utf-8", errors="replace")
        return SymbolInfo(
            name=name,
            symbol_type=SYMBOL_TYPE_VARIABLE,
            start_line=node.start_point[0],
            start_column=node.start_point[1],
            end_line=node.end_point[0],
            end_column=node.end_point[1],
            name_line=left.start_point[0],
            name_column=left.start_point[1],
            parent=None,
        )
