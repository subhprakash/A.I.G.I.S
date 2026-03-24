import os
import re


def detect_input_type(target: str) -> str:
    """
    Detect the type of scan target.

    Returns one of:
        web | zip | project | python | javascript | java |
        c_cpp | ruby | go | binary
    """

    # ── URL ───────────────────────────────────────────────────────────────────
    if isinstance(target, str) and re.match(r"^https?://", target):
        return "web"

    # ── Directory (project scan) ───────────────────────────────────────────────
    if os.path.isdir(target):
        return "project"

    # ── File — dispatch by extension ──────────────────────────────────────────
    ext = os.path.splitext(target)[1].lower()

    mapping = {
        # Archive — must be handled by zip_handler, not binary tools
        ".zip":  "zip",

        # Python
        ".py":   "python",

        # JavaScript / TypeScript
        ".js":   "javascript",
        ".ts":   "javascript",
        ".jsx":  "javascript",
        ".tsx":  "javascript",

        # Java
        ".java": "java",

        # C / C++
        ".c":    "c_cpp",
        ".cpp":  "c_cpp",
        ".cc":   "c_cpp",
        ".h":    "c_cpp",
        ".hpp":  "c_cpp",

        # Ruby
        ".rb":   "ruby",

        # Go
        ".go":   "go",

        # Web / PHP
        ".php":  "web",
        ".html": "web",
        ".htm":  "web",
    }

    if ext in mapping:
        return mapping[ext]

    # ── Default: treat as binary ───────────────────────────────────────────────
    return "binary"