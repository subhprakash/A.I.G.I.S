import magic
import re


def detect_input_type(path):

    mime = magic.from_file(path, mime=True)

    if "text" in mime:

        with open(path) as f:
            content = f.read()

        if "import" in content and "def" in content:
            return "source", "python"

        if "package" in content:
            return "source", "java"

        return "source", "unknown"

    if "executable" in mime:
        return "binary", "elf"

    return "unknown", "unknown"


def is_url(target):

    pattern = re.compile(
        r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    )

    return pattern.match(target)