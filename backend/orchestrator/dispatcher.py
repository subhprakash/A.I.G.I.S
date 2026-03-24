from concurrent.futures import ThreadPoolExecutor, as_completed

from backend.utils.yaml_loader import load_yaml
from backend.orchestrator.input_detector import detect_input_type
from backend.sandbox.tool_executor import execute_tool

TOOLS_CONFIG = "/app/config/tools.yaml"


def dispatch(target: str) -> list:
    """
    Detect the input type, select the matching tools from tools.yaml,
    and execute them in parallel.

    ZIP files must NOT reach this function directly — the zip task
    in tasks.py extracts individual files first, then calls dispatch()
    on each one. If a .zip somehow arrives here we return an explicit
    error rather than mis-scanning it with binary tools.
    """
    config     = load_yaml(TOOLS_CONFIG)
    input_type = detect_input_type(target)

    # ── Zip guard ─────────────────────────────────────────────────────────────
    # ZIP archives must be handled by run_zip_scan_task which extracts
    # them and dispatches each contained file individually.
    if input_type == "zip":
        return [{
            "tool":   "none",
            "output": {
                "error": (
                    "ZIP files must be submitted via /api/scan/upload/zip — "
                    "they cannot be dispatched directly."
                )
            }
        }]

    # ── Build tool list ───────────────────────────────────────────────────────
    tools = []

    if input_type in config.get("engines", {}):
        tools.extend([e["name"] for e in config["engines"][input_type]])

    if input_type == "binary":
        binary_tools = config.get("binary", [])
        # binary section can be a list of strings or list of dicts
        for entry in binary_tools:
            tools.append(entry["name"] if isinstance(entry, dict) else entry)

    if input_type == "project":
        for entry in config.get("project", []):
            tools.append(entry["name"] if isinstance(entry, dict) else entry)

    if not tools:
        return [{
            "tool":   "none",
            "output": {
                "error": f"No tools configured for input type: {input_type}"
            }
        }]

    # ── Execute in parallel ───────────────────────────────────────────────────
    results = []

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {
            executor.submit(execute_tool, tool, target): tool
            for tool in tools
        }
        for future in as_completed(futures):
            tool = futures[future]
            try:
                output = future.result()
                results.append({"tool": tool, "output": output})
            except Exception as e:
                results.append({"tool": tool, "output": {"error": str(e)}})

    return results