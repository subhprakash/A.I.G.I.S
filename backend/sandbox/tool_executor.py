from backend.sandbox.docker_runner import run_tool
from backend.orchestrator.task_builder import get_tools


def execute_security_tests(path, language):

    tools = get_tools(language)

    results = []

    for tool in tools:

        command = f"{tool['name']} /scan"

        output = run_tool("aigis-scanner", command, path)

        results.append({
            "tool": tool['name'],
            "output": output
        })

    return results