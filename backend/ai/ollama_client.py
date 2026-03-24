import requests
from backend.config import settings
from backend.utils.logger import get_logger

logger = get_logger(__name__)

OLLAMA_GENERATE_URL = f"{settings.OLLAMA_HOST}/api/generate"
OLLAMA_TAGS_URL = f"{settings.OLLAMA_HOST}/api/tags"

OLLAMA_TIMEOUT = 90

_MODEL_NAME = None


def _get_model_name() -> str:
    """
    Detect the correct model name by querying /api/tags.
    Cached after first successful call.
    """
    global _MODEL_NAME
    if _MODEL_NAME:
        return _MODEL_NAME

    try:
        r = requests.get(OLLAMA_TAGS_URL, timeout=10)
        r.raise_for_status()
        models = [m.get("name", "") for m in r.json().get("models", [])]
        logger.info(f"[AIGIS] Ollama models available: {models}")

        for candidate in ["llama3", "llama3:latest", "llama3:8b"]:
            if candidate in models:
                _MODEL_NAME = candidate
                logger.info(f"[AIGIS] Using Ollama model: {_MODEL_NAME}")
                return _MODEL_NAME

        if models:
            _MODEL_NAME = models[0]
            logger.info(f"[AIGIS] Using first available model: {_MODEL_NAME}")
            return _MODEL_NAME

    except Exception as e:
        logger.warning(f"[AIGIS] Could not query Ollama tags: {e}")

    _MODEL_NAME = "llama3"
    return _MODEL_NAME


def _extract_text(data: dict) -> str:
    if isinstance(data, dict) and "response" in data:
        return data["response"]
    if isinstance(data, dict) and "error" in data:
        return f"Ollama error: {data['error']}"
    return str(data)


def query_llm(prompt: str) -> str:
    """
    Call Ollama /api/generate only.
    The /api/chat fallback was causing the 404 errors in reports —
    that endpoint does not exist on this Ollama version.
    """
    model = _get_model_name()

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_predict": 300,
            "temperature": 0.1,
        }
    }

    try:
        logger.debug(f"[AIGIS] Calling Ollama: model={model}")
        r = requests.post(
            OLLAMA_GENERATE_URL,
            json=payload,
            timeout=OLLAMA_TIMEOUT
        )

        # If 404 — model name mismatch, try the other variant
        if r.status_code == 404:
            global _MODEL_NAME
            alt = "llama3:latest" if model == "llama3" else "llama3"
            logger.warning(
                f"[AIGIS] Model '{model}' not found, trying '{alt}'"
            )
            _MODEL_NAME = alt
            payload["model"] = alt
            r = requests.post(
                OLLAMA_GENERATE_URL,
                json=payload,
                timeout=OLLAMA_TIMEOUT
            )

        r.raise_for_status()
        result = _extract_text(r.json())
        logger.debug(f"[AIGIS] Ollama responded: {len(result)} chars")
        return result

    except requests.exceptions.Timeout:
        logger.warning("[AIGIS] Ollama timed out")
        return "AI remediation timed out. The vulnerability details are in the report."

    except requests.exceptions.ConnectionError:
        logger.error("[AIGIS] Cannot connect to Ollama")
        return "AI remediation unavailable — Ollama is not reachable."

    except Exception as e:
        logger.error(f"[AIGIS] Ollama error: {e}")
        return f"AI remediation unavailable: {str(e)}"