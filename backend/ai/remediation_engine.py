from backend.ai.ollama_client import query_llm
from backend.ai.remediation_fallbacks import get_fallback
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Sequential cap — Ollama processes one request at a time internally.
# At ~8s per call, 10 vulns ≈ 80s. Beyond this the session budget is
# exhausted; remaining vulns get static remediations instead.
MAX_LLM_VULNS = 10


def generate_remediation(vulnerabilities: list) -> list:
    """
    Attach a remediation string to every vulnerability dict.

    Strategy (in order):
      1. Try Ollama LLM for up to MAX_LLM_VULNS findings.
      2. If Ollama returns empty/fails → use static fallback (always succeeds).
      3. Findings beyond the cap → skip LLM, use static fallback directly.

    This guarantees every finding in the report has a meaningful remediation,
    regardless of whether Ollama is running.
    """
    if not vulnerabilities:
        return vulnerabilities

    llm_batch  = vulnerabilities[:MAX_LLM_VULNS]
    static_batch = vulnerabilities[MAX_LLM_VULNS:]

    logger.info(
        f"[AIGIS] Remediating {len(llm_batch)} vulns via LLM, "
        f"{len(static_batch)} via static fallback (cap={MAX_LLM_VULNS})."
    )

    # ── LLM batch ─────────────────────────────────────────────────────────────
    for i, vuln in enumerate(llm_batch):
        logger.info(
            f"[AIGIS] Remediating {i+1}/{len(llm_batch)}: "
            f"[{vuln.get('tool')}] {vuln.get('test_id', '')} "
            f"— {vuln.get('severity', '').upper()}"
        )
        try:
            llm_result = _try_llm(vuln)
            if llm_result:
                vuln["remediation"] = llm_result
                logger.debug(f"[AIGIS] LLM remediation OK for {vuln.get('test_id')}")
            else:
                # LLM unavailable or returned nothing — use static
                vuln["remediation"] = _static(vuln)
                logger.info(
                    f"[AIGIS] LLM empty for {vuln.get('test_id')} "
                    f"— using static fallback."
                )
        except Exception as e:
            logger.warning(f"[AIGIS] Remediation error for vuln {i}: {e}")
            vuln["remediation"] = _static(vuln)

    # ── Static batch (beyond cap) ─────────────────────────────────────────────
    for vuln in static_batch:
        vuln["remediation"] = _static(vuln)

    return llm_batch + static_batch


# ── Helpers ───────────────────────────────────────────────────────────────────

def _try_llm(vuln: dict) -> str:
    """
    Call Ollama. Returns the response string, or '' if unavailable.
    ollama_client.query_llm() already returns '' on any failure,
    so we just pass that through.
    """
    location = _clean_location(vuln.get("location", "unknown"))

    prompt = (
        f"Security vulnerability found:\n"
        f"Tool: {vuln.get('tool', 'unknown')} | "
        f"Severity: {vuln.get('severity', '').upper()} | "
        f"CWE: {vuln.get('cwe', 'N/A')} | "
        f"Location: {location}\n"
        f"Issue: {vuln.get('description', 'No description')}\n\n"
        f"Respond in exactly this format:\n"
        f"EXPLANATION:\n<one sentence — what this is and why it matters>\n\n"
        f"FIX:\n<the exact code or config change needed>\n\n"
        f"EXAMPLE:\n<before/after snippet, 3-5 lines max>"
    )

    response = query_llm(prompt)
    return response.strip() if response else ""


def _static(vuln: dict) -> str:
    """Return the best static remediation for this vulnerability."""
    return get_fallback(
        test_id=vuln.get("test_id", ""),
        cwe=vuln.get("cwe", ""),
    )


def _clean_location(location: str) -> str:
    """Strip internal container paths from location strings."""
    if "/app/uploads/" in location:
        parts = location.split("/app/uploads/")[-1]
        if len(parts) > 37 and parts[36] == "_":
            parts = parts[37:]
        return parts
    return location