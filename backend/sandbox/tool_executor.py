from sandbox.docker_runner import run_tool
from orchestrator.task_builder import get_tools


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