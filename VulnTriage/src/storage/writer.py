import json
import os
import sys
from typing import Any


def _ensure_dir(path: str):
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def write_out(data: Any, out_path: str | None, fmt: str = "jsonl"):
    if out_path:
        _ensure_dir(out_path)
        if fmt == "json":
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        elif fmt == "jsonl":
            with open(out_path, "w", encoding="utf-8") as f:
                if isinstance(data, list):
                    for row in data:
                        f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
                else:
                    f.write(json.dumps(data, ensure_ascii=False, default=str) + "\n")
        elif fmt == "sqlite":
            # TODO: implement SQLite writer; placeholder no-op file touch
            with open(out_path, "w", encoding="utf-8") as f:
                f.write("")
        else:
            raise ValueError(f"unsupported format: {fmt}")
    else:
        # stdout result stream (logs should go to stderr)
        sys.stdout.write(json.dumps(data, ensure_ascii=False, default=str) + "\n")
