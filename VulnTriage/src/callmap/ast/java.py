"""
Java AST parser using tree-sitter-java.

Extracts classes, methods, constructors, and fields from Java source code.
"""

from typing import List, Optional, Tuple

import tree_sitter
import tree_sitter_java

from callmap.ast.base import (
    AstParser,
    SymbolInfo,
    SYMBOL_TYPE_FUNCTION,
    SYMBOL_TYPE_CLASS,
    SYMBOL_TYPE_METHOD,
    SYMBOL_TYPE_CONSTRUCTOR,
    SYMBOL_TYPE_VARIABLE,
)


class JavaAstParser(AstParser):
    """Tree-sitter based Java AST parser."""

    def _init_language(self) -> tree_sitter.Language:
        return tree_sitter.Language(tree_sitter_java.language())

    def get_symbol_node_types(self) -> Tuple[str, ...]:
        return (
            "class_declaration",
            "interface_declaration",
            "enum_declaration",
            "method_declaration",
            "constructor_declaration",
            "field_declaration",
        )

    def extract_symbols(self, tree: tree_sitter.Tree, source: bytes) -> List[SymbolInfo]:
        """Extract all classes, methods, constructors, and fields from Java AST."""
        symbols: List[SymbolInfo] = []
        self._extract_from_node(tree.root_node, source, symbols, parent=None)
        return symbols

    def _extract_from_node(
        self,
        node: tree_sitter.Node,
        source: bytes,
        symbols: List[SymbolInfo],
        parent: Optional[SymbolInfo],
    ) -> None:
        """Recursively extract symbols from AST nodes."""
        node_type = node.type

        if node_type in ("class_declaration", "interface_declaration", "enum_declaration"):
            sym = self._parse_class(node, source, parent)
            if sym:
                symbols.append(sym)
                # Recurse into class body
                body = node.child_by_field_name("body")
                if body:
                    for child in body.children:
                        self._extract_from_node(child, source, symbols, parent=sym)

        elif node_type == "method_declaration":
            sym = self._parse_method(node, source, parent)
            if sym:
                symbols.append(sym)
                # Recurse into method body for nested classes/lambdas
                body = node.child_by_field_name("body")
                if body:
                    for child in body.children:
                        self._extract_from_node(child, source, symbols, parent=sym)

        elif node_type == "constructor_declaration":
            sym = self._parse_constructor(node, source, parent)
            if sym:
                symbols.append(sym)
                body = node.child_by_field_name("body")
                if body:
                    for child in body.children:
                        self._extract_from_node(child, source, symbols, parent=sym)

        elif node_type == "field_declaration":
            syms = self._parse_field(node, source, parent)
            symbols.extend(syms)

        elif node_type == "lambda_expression":
            # Handle lambda as anonymous function
            sym = self._parse_lambda(node, source, parent)
            if sym:
                symbols.append(sym)
                body = node.child_by_field_name("body")
                if body:
                    for child in body.children:
                        self._extract_from_node(child, source, symbols, parent=sym)

        else:
            # Recurse into children
            for child in node.children:
                self._extract_from_node(child, source, symbols, parent)

    def _parse_class(
        self,
        node: tree_sitter.Node,
        source: bytes,
        parent: Optional[SymbolInfo],
    ) -> Optional[SymbolInfo]:
        """Parse class/interface/enum declaration."""
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

    def _parse_method(
        self,
        node: tree_sitter.Node,
        source: bytes,
        parent: Optional[SymbolInfo],
    ) -> Optional[SymbolInfo]:
        """Parse method_declaration."""
        name_node = node.child_by_field_name("name")
        if not name_node:
            return None
        name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
        # Optionally include parameter types in name for disambiguation
        params = node.child_by_field_name("parameters")
        if params:
            param_text = source[params.start_byte:params.end_byte].decode("utf-8", errors="replace")
            name = f"{name}{param_text}"
        return SymbolInfo(
            name=name,
            symbol_type=SYMBOL_TYPE_METHOD,
            start_line=node.start_point[0],
            start_column=node.start_point[1],
            end_line=node.end_point[0],
            end_column=node.end_point[1],
            name_line=name_node.start_point[0],
            name_column=name_node.start_point[1],
            parent=parent,
        )

    def _parse_constructor(
        self,
        node: tree_sitter.Node,
        source: bytes,
        parent: Optional[SymbolInfo],
    ) -> Optional[SymbolInfo]:
        """Parse constructor_declaration."""
        name_node = node.child_by_field_name("name")
        if not name_node:
            return None
        name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
        params = node.child_by_field_name("parameters")
        if params:
            param_text = source[params.start_byte:params.end_byte].decode("utf-8", errors="replace")
            name = f"{name}{param_text}"
        return SymbolInfo(
            name=name,
            symbol_type=SYMBOL_TYPE_CONSTRUCTOR,
            start_line=node.start_point[0],
            start_column=node.start_point[1],
            end_line=node.end_point[0],
            end_column=node.end_point[1],
            name_line=name_node.start_point[0],
            name_column=name_node.start_point[1],
            parent=parent,
        )

    def _parse_field(
        self,
        node: tree_sitter.Node,
        source: bytes,
        parent: Optional[SymbolInfo],
    ) -> List[SymbolInfo]:
        """Parse field_declaration (may have multiple declarators)."""
        symbols: List[SymbolInfo] = []
        for child in node.children:
            if child.type == "variable_declarator":
                name_node = child.child_by_field_name("name")
                if name_node:
                    name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
                    symbols.append(SymbolInfo(
                        name=name,
                        symbol_type=SYMBOL_TYPE_VARIABLE,
                        start_line=node.start_point[0],
                        start_column=node.start_point[1],
                        end_line=node.end_point[0],
                        end_column=node.end_point[1],
                        name_line=name_node.start_point[0],
                        name_column=name_node.start_point[1],
                        parent=parent,
                    ))
        return symbols

    def _parse_lambda(
        self,
        node: tree_sitter.Node,
        source: bytes,
        parent: Optional[SymbolInfo],
    ) -> Optional[SymbolInfo]:
        """Parse lambda_expression as anonymous function."""
        return SymbolInfo(
            name="<lambda>",
            symbol_type=SYMBOL_TYPE_FUNCTION,
            start_line=node.start_point[0],
            start_column=node.start_point[1],
            end_line=node.end_point[0],
            end_column=node.end_point[1],
            parent=parent,
        )
