from backend.ai.ollama_client import query_llm


def generate_remediation(results):

    prompt = f"""
    Analyze the following security scan findings.

    {results}

    Provide:
    - explanation
    - severity
    - mitigation
    - secure coding fixes
    """

    return query_llm(prompt)