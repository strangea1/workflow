"""Match symbols in recon files without loading entire file contents."""
import json
from pathlib import Path
from langchain_core.tools import tool


@tool("recon_symbol_match")
def recon_symbol_match(symbol_name: str, recon_file: str = "recon_output.json") -> str:
    """
    Search for a specific symbol/API in recon output without loading full file.
    Useful for avoiding context overflow when analyzing large recon datasets.
        Recon file expected entry format example (exports array):
        {
            "file": "examples/libs/python/fastapi/fastapi/security/__init__.py",
            "line": 1,
            "symbol": "APIKeyCookie",
            "type": "import_re_export",
            "extra": {"from_module": "api_key", "original_name": "APIKeyCookie"}
        }
    
    Args:
        symbol_name: Symbol/class/method name to search for (e.g., 'Runtime.exec', 'ProcessBuilder')
        recon_file: Path to recon JSON output file (defaults to recon_output.json)
    
    Returns:
        Matching entries from recon file (JSON format, truncated to 2000 chars)
    """
    try:
        print(f"[TOOL] recon_symbol_match: symbol='{symbol_name}' in {recon_file}")
        path = Path(recon_file)
        
        if not path.exists():
            return f"[ERROR] Recon file not found: {recon_file}"
        
        # Parse recon JSON (expected structure: {exports, endpoints, sinks, sanitizers})
        with open(path, "r", encoding="utf-8") as f:
            recon_data = json.load(f)
        
        def _match_entries(entries):
            """Match entries by symbol field first; fallback to substring search."""
            matches = []
            symbol_lower = symbol_name.lower()
            for item in entries:
                if isinstance(item, dict):
                    sym_val = str(item.get("symbol", "")).lower()
                    if sym_val and symbol_lower in sym_val:
                        matches.append(item)
                        continue
                    # Fallback: search entire entry string
                    if symbol_lower in json.dumps(item, ensure_ascii=False).lower():
                        matches.append(item)
                else:
                    if symbol_lower in str(item).lower():
                        matches.append(item)
            return matches, len(matches)

        results = {}
        export_matches = 0
        endpoint_matches = 0
        sink_matches = 0
        sanitizer_matches = 0


        # Search in exports/API definitions
        if "exports" in recon_data and isinstance(recon_data["exports"], list):
            matching, export_matches = _match_entries(recon_data["exports"])
            if matching:
                results["exports"] = matching[:20]  # Limit to 5 matches

        # Search in endpoints
        if "endpoints" in recon_data and isinstance(recon_data["endpoints"], list):
            matching, endpoint_matches = _match_entries(recon_data["endpoints"])
            if matching:
                results["endpoints"] = matching[:20]

        # Search in sinks (critical for vulnerability analysis)
        if "sinks" in recon_data and isinstance(recon_data["sinks"], list):
            matching, sink_matches = _match_entries(recon_data["sinks"])
            if matching:
                results["sinks"] = matching[:20]

        # Search in sanitizers
        if "sanitizers" in recon_data and isinstance(recon_data["sanitizers"], list):
            matching, sanitizer_matches = _match_entries(recon_data["sanitizers"])
            if matching:
                results["sanitizers"] = matching[:20]
        
        if not results:
            return f"[NO MATCH] Symbol '{symbol_name}' not found in recon output"
        print(f"[TOOL] recon_symbol_match: found exports={export_matches}, endpoints={endpoint_matches}, sinks={sink_matches}, sanitizers={sanitizer_matches} matches for symbol='{symbol_name}'")
        output = json.dumps(results, ensure_ascii=False, indent=2)
        if len(output) > 2000:
            return output[:2000] + "\n[TRUNCATED]"
        return output
    except json.JSONDecodeError:
        return f"[ERROR] Invalid JSON in {recon_file}"
    except Exception as e:
        return f"[ERROR] {str(e)}"
