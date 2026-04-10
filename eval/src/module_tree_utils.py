from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def load_module_tree(module_tree_path: Path) -> dict:
    """Load and return the module tree JSON from the given path."""
    if not module_tree_path.exists():
        raise FileNotFoundError(f"module_tree.json not found at {module_tree_path}")
    with module_tree_path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def flatten_module_tree(module_tree: dict, parent: Tuple[str, ...] = ()) -> List[Tuple[str, dict]]:
    """Flatten the nested module tree into a list of (dot.path, info) tuples."""
    rows: List[Tuple[str, dict]] = []
    for name, info in module_tree.items():
        module_path = parent + (name,)
        rows.append((".".join(module_path), info))
        children = info.get("children")
        if isinstance(children, dict) and children:
            rows.extend(flatten_module_tree(children, module_path))
    return rows


def build_component_map(module_tree: dict) -> Dict[str, List[str]]:
    """Build a component -> list of module paths mapping."""
    mapping: Dict[str, List[str]] = {}

    def traverse(nodes: dict, prefix: str = "") -> None:
        for module_name, info in nodes.items():
            full_path = f"{prefix}.{module_name}" if prefix else module_name
            for component in info.get("components", []):
                mapping.setdefault(component, []).append(full_path)
            children = info.get("children") or {}
            if isinstance(children, dict):
                traverse(children, full_path)

    traverse(module_tree)
    return mapping


def get_module_info(module_tree: dict, module_path: str) -> Optional[dict]:
    """Return the metadata dict for the provided module path (dot-separated)."""
    parts = module_path.split(".")
    current = module_tree
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current
