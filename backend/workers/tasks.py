import os
import re
import shutil
import tempfile
import subprocess

from backend.workers.celery_app import celery
from backend.orchestrator.dispatcher import dispatch
from backend.security.vulnerability_parser import parse_vulnerabilities
from backend.security.cvss_engine import score_vulnerabilities
from backend.ai.remediation_engine import generate_remediation
from backend.reporting.report_generator import generate_report
from backend.utils.logger import get_logger

logger = get_logger(__name__)


# ── DB helper ─────────────────────────────────────────────────────────────────

def _write_scan_job(input_name, input_type, status, user_id=None):
    try:
        from backend.database.database import SessionLocal
        from backend.database.models import ScanJob
        db  = SessionLocal()
        job = ScanJob(
            input_name=input_name,
            input_type=input_type,
            status=status,
            user_id=user_id if hasattr(ScanJob, "user_id") else None,
        )
        db.add(job)
        db.commit()
        db.close()
    except Exception as e:
        logger.warning(f"[AIGIS] Could not write ScanJob: {e}")


def _strip_uuid_prefix(filename: str) -> str:
    """Remove the '<uuid>_' prefix that job uploads prepend."""
    if len(filename) > 37 and filename[36] == "_":
        return filename[37:]
    return filename


# ── UI Formatter Helper ───────────────────────────────────────────────────────
def _format_vulns_for_ui(remediated):
    """Formats the raw vulnerabilities array into the structured list expected by the React/Streamlit UI."""
    formatted = []
    for v in remediated:
        loc = str(v.get("location", ""))
        file_part = loc.split(":")[0] if loc else "Unknown"
        line_part = loc.split(":")[-1] if ":" in loc else "?"
        
        # We include CWE here so the OWASP Radar Chart can plot it!
        formatted.append({
            "title": v.get("test_id", "Vulnerability"),
            "severity": v.get("cvss_rating", "Unknown"),
            "file": file_part,
            "line": line_part,
            "snippet": v.get("description", "No snippet available."),
            "language": "auto",
            "description": v.get("description", "No description available."),
            "remediation": v.get("remediation", "No remediation available."),
            "cwe": v.get("cwe", "CWE-200") # Fallback to CWE-200 (Information Exposure) if missing
        })
    return formatted

# ── File scan ─────────────────────────────────────────────────────────────────

@celery.task(name="backend.workers.tasks.run_scan_task", bind=True)
def run_scan_task(self, file_path: str, user_id: int = None):
    logger.info(f"[AIGIS] Starting file scan: {file_path}")

    filename = _strip_uuid_prefix(os.path.basename(file_path))

    if not os.path.exists(file_path):
        _write_scan_job(filename, "file", "failed", user_id)
        return {"status": "error", "reason": "file not found"}

    _write_scan_job(filename, "file", "running", user_id)

    try:
        raw_results  = dispatch(file_path)
        vulns        = parse_vulnerabilities(raw_results)
        scored       = score_vulnerabilities(vulns)
        remediated   = generate_remediation(scored)

        report_path  = generate_report(
            job_id=self.request.id,
            vulnerabilities=remediated,
            scan_type="file",
            target=file_path,
            user_id=user_id,
        )

        _write_scan_job(filename, "file", "completed", user_id)
        logger.info("[AIGIS] File scan completed")
        return {
            "status":               "completed",
            "file":                 file_path,
            "report":               report_path,
            "vulnerabilities":      len(remediated),
            "vulnerabilities_list": _format_vulns_for_ui(remediated),
            "dependencies":         [] # Can be populated later by a real SBOM tool like Syft
        }

    except Exception as e:
        _write_scan_job(filename, "file", "failed", user_id)
        logger.exception("[AIGIS] File scan failed")
        return {"status": "failed", "error": str(e), "file": file_path}


# ── URL scan ──────────────────────────────────────────────────────────────────

@celery.task(name="backend.workers.tasks.run_url_scan_task", bind=True)
def run_url_scan_task(self, url: str, user_id: int = None):
    logger.info(f"[AIGIS] Starting URL scan: {url}")

    if not re.match(r"^https?://", url):
        return {"status": "error", "reason": "Invalid URL", "url": url}

    _write_scan_job(url, "url", "running", user_id)

    try:
        raw_results  = dispatch(url)
        vulns        = parse_vulnerabilities(raw_results)
        scored       = score_vulnerabilities(vulns)
        remediated   = generate_remediation(scored)

        report_path  = generate_report(
            job_id=self.request.id,
            vulnerabilities=remediated,
            scan_type="url",
            target=url,
            user_id=user_id,
        )

        _write_scan_job(url, "url", "completed", user_id)
        logger.info("[AIGIS] URL scan completed")
        return {
            "status":               "completed",
            "url":                  url,
            "report":               report_path,
            "vulnerabilities":      len(remediated),
            "vulnerabilities_list": _format_vulns_for_ui(remediated),
            "dependencies":         []
        }

    except Exception as e:
        _write_scan_job(url, "url", "failed", user_id)
        logger.exception("[AIGIS] URL scan failed")
        return {"status": "failed", "error": str(e), "url": url}


# ── Repository scan ───────────────────────────────────────────────────────────

@celery.task(name="backend.workers.tasks.run_repo_scan_task", bind=True)
def run_repo_scan_task(
    self,
    repo_url: str,
    branch: str = "main",
    user_id: int = None,
):
    logger.info(f"[AIGIS] Starting repository scan: {repo_url}")

    if not re.match(r"^https?://(github|gitlab|bitbucket)\.com/", repo_url):
        return {
            "status":   "error",
            "reason":   "Invalid repository URL.",
            "repo_url": repo_url,
        }

    clone_dir = None
    _write_scan_job(repo_url, "repository", "running", user_id)

    try:
        clone_dir = tempfile.mkdtemp(prefix="aigis_repo_")

        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch,
             repo_url, clone_dir],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            # Retry without --branch (default branch)
            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, clone_dir],
                capture_output=True, text=True, timeout=120,
            )
        if result.returncode != 0:
            _write_scan_job(repo_url, "repository", "failed", user_id)
            return {
                "status":   "error",
                "reason":   f"Git clone failed: {result.stderr.strip()}",
                "repo_url": repo_url,
            }

        raw_results = dispatch(clone_dir)
        vulns       = parse_vulnerabilities(raw_results)
        scored      = score_vulnerabilities(vulns)
        remediated  = generate_remediation(scored)

        report_path = generate_report(
            job_id=self.request.id,
            vulnerabilities=remediated,
            scan_type="repository",
            target=repo_url,
            user_id=user_id,
        )

        _write_scan_job(repo_url, "repository", "completed", user_id)
        logger.info("[AIGIS] Repository scan completed")
        return {
            "status":               "completed",
            "repo_url":             repo_url,
            "report":               report_path,
            "vulnerabilities":      len(remediated),
            "vulnerabilities_list": _format_vulns_for_ui(remediated),
            "dependencies":         []
        }

    except subprocess.TimeoutExpired:
        _write_scan_job(repo_url, "repository", "failed", user_id)
        return {
            "status":   "error",
            "reason":   "Git clone timed out after 120s.",
            "repo_url": repo_url,
        }

    except Exception as e:
        _write_scan_job(repo_url, "repository", "failed", user_id)
        logger.exception("[AIGIS] Repository scan failed")
        return {"status": "failed", "error": str(e), "repo_url": repo_url}

    finally:
        if clone_dir and os.path.exists(clone_dir):
            shutil.rmtree(clone_dir, ignore_errors=True)


# ── ZIP scan ──────────────────────────────────────────────────────────────────

@celery.task(name="backend.workers.tasks.run_zip_scan_task", bind=True)
def run_zip_scan_task(self, zip_path: str, user_id: int = None):
    logger.info(f"[AIGIS] Starting ZIP scan: {zip_path}")

    zip_filename = _strip_uuid_prefix(os.path.basename(zip_path))

    if not os.path.exists(zip_path):
        _write_scan_job(zip_filename, "zip", "failed", user_id)
        return {"status": "error", "reason": "file not found"}

    _write_scan_job(zip_filename, "zip", "running", user_id)
    extract_dir = None

    try:
        from backend.orchestrator.zip_handler import extract_zip
        extract_dir, scannable_files = extract_zip(zip_path)

        if not scannable_files:
            _write_scan_job(zip_filename, "zip", "completed", user_id)
            return {
                "status":        "completed",
                "zip":           zip_path,
                "report":        None,
                "vulnerabilities": 0,
                "files_scanned": 0,
                "message": (
                    "No scannable files found in archive. "
                    "Supported: .py .js .ts .java .c .cpp .rb .go .php "
                    ".exe .elf .bin"
                ),
            }

        logger.info(f"[AIGIS] {len(scannable_files)} scannable file(s) found in zip")

        all_vulnerabilities = []

        for i, file_path in enumerate(scannable_files):
            filename = os.path.basename(file_path)
            logger.info(
                f"[AIGIS] Scanning file {i+1}/{len(scannable_files)}: {filename}"
            )
            try:
                raw_results = dispatch(file_path)
                file_vulns  = parse_vulnerabilities(raw_results)

                # Tag each finding with its source file inside the zip
                for vuln in file_vulns:
                    vuln["source_file"] = filename
                    existing_loc = vuln.get("location", "")
                    if existing_loc and filename not in existing_loc:
                        line = existing_loc.split(":")[-1] if ":" in existing_loc else ""
                        vuln["location"] = (
                            f"{filename}:{line}" if line else filename
                        )

                all_vulnerabilities.extend(file_vulns)
                logger.info(f"[AIGIS] {filename}: {len(file_vulns)} finding(s)")

            except Exception as e:
                logger.warning(f"[AIGIS] Failed to scan {filename}: {e}")
                continue

        logger.info(
            f"[AIGIS] ZIP scan total: {len(all_vulnerabilities)} finding(s) "
            f"across {len(scannable_files)} file(s)"
        )

        scored     = score_vulnerabilities(all_vulnerabilities)
        remediated = generate_remediation(scored)

        report_path = generate_report(
            job_id=self.request.id,
            vulnerabilities=remediated,
            scan_type="zip",
            target=zip_filename,
            user_id=user_id,
        )

        _write_scan_job(zip_filename, "zip", "completed", user_id)
        logger.info("[AIGIS] ZIP scan completed")
        return {
            "status":               "completed",
            "zip":                  zip_path,
            "files_scanned":        len(scannable_files),
            "report":               report_path,
            "vulnerabilities":      len(remediated),
            "vulnerabilities_list": _format_vulns_for_ui(remediated),
            "dependencies":         []
        }

    except ValueError as e:
        # Safety check failure (zip bomb, ZipSlip, bad archive)
        logger.error(f"[AIGIS] ZIP safety check failed: {e}")
        _write_scan_job(zip_filename, "zip", "failed", user_id)
        return {"status": "error", "reason": str(e), "zip": zip_path}

    except Exception as e:
        _write_scan_job(zip_filename, "zip", "failed", user_id)
        logger.exception("[AIGIS] ZIP scan failed")
        return {"status": "failed", "error": str(e), "zip": zip_path}

    finally:
        if extract_dir and os.path.exists(extract_dir):
            shutil.rmtree(extract_dir, ignore_errors=True)
            logger.info("[AIGIS] Cleaned up zip extract directory")