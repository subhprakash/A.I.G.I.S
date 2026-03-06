import requests
from backend.config import settings


def query_llm(prompt):

    payload = {
        "model": "llama3",
        "prompt": prompt,
        "stream": False
    }

    response = requests.post(
        settings.OLLAMA_URL,
        json=payload
    )

    return response.json()["response"]