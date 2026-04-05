import streamlit as st
import requests
import time
import pandas as pd
import json
import plotly.express as px # <-- NEW IMPORT FOR TREEMAP

BACKEND_URL = "http://backend:8000"


def auth_headers():
    return {"Authorization": f"Bearer {st.session_state.token}"}

# ── ENGINE MAPPING & ANIMATED BADGE UI ────────────────────────────────────────

TOOL_MAPPING = {
    "Python": ["Bandit", "Semgrep", "Pylint", "Safety"],
    "JavaScript": ["ESLint", "Retire.js"],
    "Java": ["Checkstyle", "SpotBugs", "PMD"],
    "C/C++": ["Cppcheck", "Flawfinder", "RATS"],
    "Ruby": ["Brakeman", "Bundler-Audit"],
    "Go": ["Gosec", "Staticcheck"],
    "PHP": ["PHPCS", "Semgrep"],
    "Binary": ["Checksec", "Binwalk", "Strings", "YARA", "ClamAV"],
    "Repository": ["Semgrep", "Gitleaks", "Trufflehog"],
    "URL": ["Nikto", "Nmap", "WhatWeb", "Wafw00f"],
    "ZIP Archive": ["Auto-Extraction", "Multi-Language SAST", "ClamAV Malware Engine"]
}

def display_active_engines(scan_type: str, language: str = None):
    """
    Renders a sleek UI block showing the active tools with an animated glowing pulse.
    """
    if scan_type == "File" and language:
        tools = TOOL_MAPPING.get(language, ["Semgrep (Fallback)"])
    else:
        tools = TOOL_MAPPING.get(scan_type, [])

    if tools:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("**⚙️ Engines Armed for this Scan:**")
        
        # Added CSS animation for a subtle glowing pulse
        html_badges = """
        <style>
            @keyframes pulse-glow {
                0% { box-shadow: 0 0 0 0 rgba(56, 189, 248, 0.4); }
                70% { box-shadow: 0 0 0 6px rgba(56, 189, 248, 0); }
                100% { box-shadow: 0 0 0 0 rgba(56, 189, 248, 0); }
            }
            .animated-badge {
                display: inline-block;
                background-color: rgba(30, 41, 59, 0.7);
                color: #38BDF8;
                padding: 6px 14px;
                border-radius: 20px;
                font-size: 13px;
                font-weight: 600;
                margin-right: 10px;
                margin-bottom: 10px;
                border: 1px solid rgba(3, 105, 161, 0.5);
                backdrop-filter: blur(4px);
                animation: pulse-glow 2s infinite;
            }
        </style>
        """
        for tool in tools:
            html_badges += f'<span class="animated-badge">{tool}</span>'
            
        st.markdown(html_badges, unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)

# ── GLASSMORPHISM Visual components ────────────────────────────────────────────

def show_dual_speedometers(score: int, vuln_count: int):
    # Determine colors based on threat level
    t_color = "#ef4444" if score > 70 else "#f59e0b" if score > 40 else "#10b981"
    t_glow = "rgba(239, 68, 68, 0.2)" if score > 70 else "rgba(245, 158, 11, 0.2)" if score > 40 else "rgba(16, 185, 129, 0.2)"
    
    v_color = "#ef4444" if vuln_count > 7 else "#f59e0b" if vuln_count > 3 else "#10b981"
    v_glow = "rgba(239, 68, 68, 0.2)" if vuln_count > 7 else "rgba(245, 158, 11, 0.2)" if vuln_count > 3 else "rgba(16, 185, 129, 0.2)"
    
    # Custom CSS for Glassmorphism (Frosted Glass) effect
    glass_css = """
    <style>
        .glass-card {
            background: rgba(17, 25, 40, 0.45);
            border-radius: 16px;
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            padding: 25px;
            text-align: center;
            color: white;
            transition: transform 0.3s ease;
        }
        .glass-card:hover {
            transform: translateY(-5px);
        }
        .glass-label {
            margin: 0;
            font-weight: 600;
            color: #94a3b8;
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 1px;
        }
        .glass-value {
            margin: 15px 0;
            font-size: 3.2rem;
            font-weight: 700;
            text-shadow: 0 0 20px {glow};
        }
        .glass-bar-bg {
            width: 100%;
            background-color: rgba(0,0,0,0.3);
            border-radius: 10px;
            height: 8px;
            overflow: hidden;
            border: 1px solid rgba(255,255,255,0.05);
        }
    </style>
    """
    st.markdown(glass_css, unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"""
            <div class="glass-card">
                <p class="glass-label">Threat Level</p>
                <h1 class="glass-value" style="color:{t_color}; text-shadow: 0 0 20px {t_glow};">{score}%</h1>
                <div class="glass-bar-bg">
                    <div style="width:{score}%; background-color:{t_color}; height:8px; border-radius:10px; box-shadow: 0 0 10px {t_color};"></div>
                </div>
            </div>
        """, unsafe_allow_html=True)
    with col2:
        v_width = min(vuln_count * 10, 100)
        st.markdown(f"""
            <div class="glass-card">
                <p class="glass-label">Vulnerabilities Found</p>
                <h1 class="glass-value" style="color:{v_color}; text-shadow: 0 0 20px {v_glow};">{vuln_count}</h1>
                <div class="glass-bar-bg">
                    <div style="width:{v_width}%; background-color:{v_color}; height:8px; border-radius:10px; box-shadow: 0 0 10px {v_color};"></div>
                </div>
            </div>
        """, unsafe_allow_html=True)


def show_severity_table(vulnerabilities: list):
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    ranges = {
        "Critical": "9.0 – 10.0",
        "High":     "7.0 – 8.9",
        "Medium":   "4.0 – 6.9",
        "Low":      "0.1 – 3.9",
        "Info":     "0.0",
    }
    for v in vulnerabilities:
        sev = v.get("severity", "info").capitalize()
        if sev in stats:
            stats[sev] += 1
    st.table(pd.DataFrame([
        {"Severity": s, "Count": stats[s], "CVSS Range": ranges[s]}
        for s in ["Critical", "High", "Medium", "Low", "Info"]
    ]))


# ── Background scan tracking ───────────────────────────────────────────────────

def _save_jobs_to_cookie():
    """Forces the active jobs list to save to the browser cookie immediately."""
    if "cookies" in st.session_state:
        st.session_state.cookies["active_jobs"] = json.dumps(st.session_state.active_jobs)
        st.session_state.cookies.save()

def _get_active_jobs():
    if "active_jobs" not in st.session_state:
        st.session_state.active_jobs = {}
    return st.session_state.active_jobs

def _set_active_job(scan_type: str, job_id: str):
    jobs = _get_active_jobs()
    jobs[scan_type] = job_id
    _save_jobs_to_cookie()

def _clear_active_job(scan_type: str):
    jobs = _get_active_jobs()
    jobs.pop(scan_type, None)
    _save_jobs_to_cookie()


def _check_job_status(job_id: str) -> dict:
    try:
        resp = requests.get(
            f"{BACKEND_URL}/api/scan/status/{job_id}",
            headers=auth_headers(),
            timeout=15
        )
        if resp.status_code == 401:
            st.error("Session expired. Please log in again.")
            st.session_state.clear()
            st.rerun()
        return resp.json()
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ── Progress bar polling ───────────────────────────────────────────────────────

SCAN_STAGES = [
    (0.05, "📥 Job received"),
    (0.20, "🔍 Identifying file type"),
    (0.35, "🛠️  Dispatching security tools"),
    (0.55, "⚙️  Running tools in sandbox"),
    (0.75, "🧠 Generating AI remediation"),
    (0.90, "📄 Building PDF report"),
    (1.00, "✅ Complete"),
]


def poll_until_complete(job_id: str, scan_type: str = "file"):
    progress_bar = st.progress(0.0)
    status_text = st.empty()

    cancel_col, _ = st.columns([1, 4])
    if cancel_col.button("🛑 Cancel Scan", key=f"cancel_{job_id}"):
        try:
            resp = requests.delete(
                f"{BACKEND_URL}/api/scan/cancel/{job_id}",
                headers=auth_headers(),
                timeout=10
            )
            if resp.status_code == 200:
                progress_bar.empty()
                status_text.warning("Scan cancelled.")
                _clear_active_job(scan_type)
            else:
                status_text.error(f"Could not cancel: {resp.text}")
        except Exception as e:
            status_text.error(f"Cancel error: {e}")
        return None

    # Retrieve saved stage index to prevent progress bar resetting on navigation
    stage_key = f"stage_{job_id}"
    if stage_key not in st.session_state:
        st.session_state[stage_key] = 0

    while True:
        data = _check_job_status(job_id)
        backend_status = data.get("status", "")

        if backend_status == "completed":
            progress_bar.progress(1.0)
            status_text.success("✅ Scan complete!")
            time.sleep(0.5)
            progress_bar.empty()
            status_text.empty()
            _clear_active_job(scan_type)
            st.session_state.pop(stage_key, None)
            return data.get("result", {})

        elif backend_status == "failed":
            progress_bar.empty()
            status_text.empty()
            _clear_active_job(scan_type)
            st.session_state.pop(stage_key, None)
            result = data.get("result", {})
            st.error(
                f"Scan failed: {result.get('error', data.get('error', 'Unknown error'))}"
            )
            return None

        elif backend_status in ("pending", "running"):
            idx = st.session_state[stage_key]
            if idx < len(SCAN_STAGES) - 2:
                st.session_state[stage_key] += 1
                idx = st.session_state[stage_key]
            
            pct, label = SCAN_STAGES[idx]
            progress_bar.progress(pct)
            status_text.warning(f"{label}  —  Job: `{job_id[:8]}`")
            time.sleep(5)

        else:
            time.sleep(5)


def show_scan_result(result: dict, job_id: str):
    if not result:
        return
    vuln_count = result.get("vulnerabilities", 0)
    threat_score = min(vuln_count * 10, 100)
    st.success("✅ Analysis Complete!")
    st.markdown("---")
    show_dual_speedometers(threat_score, vuln_count)
    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2 = st.columns(2)
    col1.metric("Total Vulnerabilities", vuln_count)
    col2.metric("Threat Score", f"{threat_score}%")
    st.markdown("---")
    st.markdown("### 📄 Full Report")
    st.info(
        "The complete report with all vulnerability details, "
        "CVSS scores, and AI remediation is in the PDF below."
    )
    _show_download_button(job_id)


def _show_download_button(job_id: str):
    try:
        dl_resp = requests.get(
            f"{BACKEND_URL}/api/reports/{job_id}/download",
            headers=auth_headers(),
            timeout=30
        )
        if dl_resp.status_code == 200:
            st.download_button(
                label="📥 Download Full PDF Report",
                data=dl_resp.content,
                file_name=f"AIGIS_Report_{job_id[:8]}.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        elif dl_resp.status_code == 404:
            st.warning(
                "Report is still being finalized. "
                "Check My Reports in a moment."
            )
        else:
            st.warning(f"Could not fetch report: {dl_resp.status_code}")
    except Exception as e:
        st.warning(f"Could not fetch report: {e}")


# ── Animated Active job banner ─────────────────────────────────────────────────

def show_active_jobs_banner():
    """
    Shows an animated banner on any page if a scan is still running in the background.
    """
    active_jobs = _get_active_jobs()
    if not active_jobs:
        return

    for scan_type, job_id in list(active_jobs.items()):
        data = _check_job_status(job_id)
        status = data.get("status", "")

        if status == "completed":
            st.success(
                f"✅ **{scan_type.upper()} scan complete!** "
                f"Job `{job_id[:8]}` — go to My Reports to download."
            )
            _clear_active_job(scan_type)

        elif status == "failed":
            st.error(
                f"❌ **{scan_type.upper()} scan failed.** "
                f"Job `{job_id[:8]}`"
            )
            _clear_active_job(scan_type)

        elif status in ("pending", "running"):
            # Animated spinner for active background jobs
            st.markdown(f"""
                <div style="border-left: 4px solid #f59e0b; background-color: rgba(245, 158, 11, 0.1); padding: 12px; border-radius: 4px; display: flex; align-items: center; margin-bottom: 15px;">
                    <div style="border: 3px solid rgba(245, 158, 11, 0.3); border-top: 3px solid #f59e0b; border-radius: 50%; width: 20px; height: 20px; animation: spin 1s linear infinite; margin-right: 15px;"></div>
                    <style>@keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}</style>
                    <span style="color: #fcd34d;"><b>{scan_type.upper()} scan running in background</b> — Job <code>{job_id[:8]}</code>. Navigate to the scan page to see progress.</span>
                </div>
            """, unsafe_allow_html=True)


# ── Shared page functions ──────────────────────────────────────────────────────

def page_file_scan():
    st.header("📁 Static File Analysis")
    st.caption(
        "File type is detected by binary inspection — "
        "renaming a file does not fool the scanner."
    )

    active_jobs = _get_active_jobs()
    existing_job = active_jobs.get("file")

    if existing_job:
        data = _check_job_status(existing_job)
        status = data.get("status", "")
        if status == "completed":
            st.success("✅ Previous scan complete!")
            result = data.get("result", {})
            show_scan_result(result, existing_job)
            _clear_active_job("file")
            return
        elif status in ("pending", "running"):
            st.info(f"Resuming scan — Job ID: `{existing_job}`")
            result = poll_until_complete(existing_job, "file")
            show_scan_result(result, existing_job)
            return
        else:
            _clear_active_job("file")

    # Add interactive preview dropdown for tools!
    file_type = st.selectbox(
        "Select Expected Target Type (To Preview Engines)", 
        ["Python", "JavaScript", "Java", "C/C++", "Ruby", "Go", "PHP", "Binary"]
    )
    display_active_engines("File", language=file_type)

    uploaded_file = st.file_uploader(
        "Choose a file to scan",
        type=[
            "py", "js", "ts", "java", "c", "cpp",
            "go", "rb", "php", "exe", "elf", "bin", "so"
        ]
    )
    if uploaded_file:
        st.info(f"Ready to scan: **{uploaded_file.name}**")
        if st.button("🚀 Start Scan", use_container_width=True):
            try:
                files = {
                    "file": (uploaded_file.name, uploaded_file.getvalue())
                }
                resp = requests.post(
                    f"{BACKEND_URL}/api/scan/upload",
                    files=files,
                    headers=auth_headers(),
                    timeout=30
                )
                if resp.status_code == 401:
                    st.error("Session expired.")
                    st.session_state.clear()
                    st.rerun()
                elif resp.status_code == 429:
                    st.error("Too many scans. Please wait a moment.")
                elif resp.status_code == 200:
                    job_id = resp.json().get("job_id")
                    _set_active_job("file", job_id)
                    st.info(f"Scan queued — Job ID: `{job_id}`")
                    result = poll_until_complete(job_id, "file")
                    show_scan_result(result, job_id)
                else:
                    st.error(f"Upload failed: {resp.text}")
            except requests.exceptions.ConnectionError:
                st.error("Cannot connect to backend.")
            except Exception as e:
                st.error(f"Error: {e}")

def page_zip_scan():
    st.header("🗜️ ZIP Archive Scan")
    st.caption(
        "Upload a .zip archive. Each file inside is safely extracted "
        "and scanned individually. All findings are aggregated into a single PDF."
    )

    active_jobs = _get_active_jobs()
    existing_job = active_jobs.get("zip")

    if existing_job:
        data = _check_job_status(existing_job)
        status = data.get("status", "")
        if status == "completed":
            st.success("✅ Previous ZIP scan complete!")
            result = data.get("result", {})
            show_scan_result(result, existing_job)
            _clear_active_job("zip")
            return
        elif status in ("pending", "running"):
            st.info(f"Resuming ZIP scan — Job ID: `{existing_job}`")
            result = poll_until_complete(existing_job, "zip")
            show_scan_result(result, existing_job)
            return
        else:
            _clear_active_job("zip")

    display_active_engines("ZIP Archive")

    uploaded_file = st.file_uploader(
        "Choose a .zip file to scan",
        type=["zip"]
    )
    if uploaded_file:
        st.info(f"Ready to scan: **{uploaded_file.name}**")
        if st.button("🚀 Start ZIP Scan", use_container_width=True):
            try:
                files = {
                    "file": (uploaded_file.name, uploaded_file.getvalue())
                }
                resp = requests.post(
                    f"{BACKEND_URL}/api/scan/upload/zip",
                    files=files,
                    headers=auth_headers(),
                    timeout=30
                )
                if resp.status_code == 401:
                    st.error("Session expired.")
                    st.session_state.clear()
                    st.rerun()
                elif resp.status_code == 429:
                    st.error("Too many scans. Please wait a moment.")
                elif resp.status_code == 200:
                    job_id = resp.json().get("job_id")
                    _set_active_job("zip", job_id)
                    st.info(f"ZIP scan queued — Job ID: `{job_id}`")
                    result = poll_until_complete(job_id, "zip")
                    show_scan_result(result, job_id)
                else:
                    st.error(f"Upload failed: {resp.text}")
            except requests.exceptions.ConnectionError:
                st.error("Cannot connect to backend.")
            except Exception as e:
                st.error(f"Error: {e}")


def page_url_scan():
    st.header("🌐 URL / Web Application Scan")
    st.caption(
        "Runs nikto, nmap, whatweb and wafw00f. "
        "Private/internal IPs are blocked."
    )

    active_jobs = _get_active_jobs()
    existing_job = active_jobs.get("url")

    if existing_job:
        data = _check_job_status(existing_job)
        status = data.get("status", "")
        if status == "completed":
            st.success("✅ Previous URL scan complete!")
            result = data.get("result", {})
            show_scan_result(result, existing_job)
            _clear_active_job("url")
            return
        elif status in ("pending", "running"):
            st.info(f"Resuming URL scan — Job ID: `{existing_job}`")
            result = poll_until_complete(existing_job, "url")
            show_scan_result(result, existing_job)
            return
        else:
            _clear_active_job("url")

    url_input = st.text_input(
        "Target URL", placeholder="https://example.com"
    )
    
    display_active_engines("URL")

    if url_input:
        if st.button("🚀 Start URL Scan", use_container_width=True):
            try:
                resp = requests.post(
                    f"{BACKEND_URL}/api/scan/url",
                    json={"url": url_input},
                    headers=auth_headers(),
                    timeout=30
                )
                if resp.status_code == 401:
                    st.error("Session expired.")
                    st.session_state.clear()
                    st.rerun()
                elif resp.status_code == 429:
                    st.error("Too many URL scans. Please wait a moment.")
                elif resp.status_code == 422:
                    detail = resp.json().get("detail", [])
                    msg = (
                        detail[0].get("msg", "Invalid URL")
                        if isinstance(detail, list) and detail
                        else "Invalid URL format."
                    )
                    st.error(msg)
                elif resp.status_code == 200:
                    job_id = resp.json().get("job_id")
                    _set_active_job("url", job_id)
                    st.info(f"URL scan queued — Job ID: `{job_id}`")
                    result = poll_until_complete(job_id, "url")
                    show_scan_result(result, job_id)
                else:
                    st.error(f"Request failed: {resp.text}")
            except requests.exceptions.ConnectionError:
                st.error("Cannot connect to backend.")
            except Exception as e:
                st.error(f"Error: {e}")


def page_repo_scan():
    st.header("📦 GitHub / GitLab Repository Scan")
    st.caption(
        "Scans public repos with semgrep, gitleaks and trufflehog. "
        "Only public repositories are supported."
    )

    active_jobs = _get_active_jobs()
    existing_job = active_jobs.get("repository")

    if existing_job:
        data = _check_job_status(existing_job)
        status = data.get("status", "")
        if status == "completed":
            st.success("✅ Previous repository scan complete!")
            result = data.get("result", {})
            show_scan_result(result, existing_job)
            _clear_active_job("repository")
            return
        elif status in ("pending", "running"):
            st.info(f"Resuming repository scan — Job ID: `{existing_job}`")
            result = poll_until_complete(existing_job, "repository")
            show_scan_result(result, existing_job)
            return
        else:
            _clear_active_job("repository")

    repo_input = st.text_input(
        "Repository URL",
        placeholder="https://github.com/owner/repo/tree/main"
    )
    branch_input = st.text_input(
        "Branch (Optional - Overridden if URL contains /tree/)", 
        value="main", 
        placeholder="main"
    )
    
    display_active_engines("Repository")
    
    if repo_input:
        if st.button("🚀 Start Repository Scan", use_container_width=True):
            st.warning(
                "Repository scans take several minutes "
                "depending on repo size."
            )
            
            # --- AUTO BRANCH DETECTION LOGIC ---
            final_repo_url = repo_input
            final_branch = branch_input or "main"
            
            if "/tree/" in repo_input:
                parts = repo_input.split("/tree/")
                final_repo_url = parts[0]
                final_branch = parts[1].split("/")[0]
                st.info(f"🔍 Auto-detected branch: **{final_branch}**")
            # -----------------------------------
            
            try:
                resp = requests.post(
                    f"{BACKEND_URL}/api/scan/repository",
                    json={
                        "repo_url": final_repo_url,
                        "branch": final_branch
                    },
                    headers=auth_headers(),
                    timeout=30
                )
                if resp.status_code == 401:
                    st.error("Session expired.")
                    st.session_state.clear()
                    st.rerun()
                elif resp.status_code == 429:
                    st.error("Too many repository scans. Please wait a moment.")
                elif resp.status_code == 422:
                    detail = resp.json().get("detail", [])
                    msg = (
                        detail[0].get("msg", "Invalid URL")
                        if isinstance(detail, list) and detail
                        else "Invalid repository URL."
                    )
                    st.error(msg)
                elif resp.status_code == 200:
                    job_id = resp.json().get("job_id")
                    _set_active_job("repository", job_id)
                    st.info(f"Repo scan queued — Job ID: `{job_id}`")
                    result = poll_until_complete(job_id, "repository")
                    show_scan_result(result, job_id)
                else:
                    st.error(f"Request failed: {resp.text}")
            except requests.exceptions.ConnectionError:
                st.error("Cannot connect to backend.")
            except Exception as e:
                st.error(f"Error: {e}")


def page_my_reports():
    st.header("📜 My Scan Reports")

    try:
        resp = requests.get(
            f"{BACKEND_URL}/api/reports/",
            headers=auth_headers(),
            timeout=10
        )
        if resp.status_code == 401:
            st.error("Session expired.")
            st.session_state.clear()
            st.rerun()
        elif resp.status_code == 200:
            reports = resp.json()
            if not reports:
                # --- ZERO DATA EMPTY STATE ---
                st.markdown("<br>", unsafe_allow_html=True)
                col_img, col_txt = st.columns([1, 4])
                with col_img:
                    st.markdown("<h1 style='text-align:center; font-size:4rem;'>📭</h1>", unsafe_allow_html=True)
                with col_txt:
                    st.subheader("Your dashboard is looking a little empty!")
                    st.markdown(
                        "You haven't run any security scans yet. Head over to the **Overview** page "
                        "and launch your first File, URL, ZIP, or Repository scan to populate this area with rich data."
                    )
                return

            st.caption(f"Total reports in database: **{len(reports)}**")

            # --- 🔍 GLOBAL SEARCH & FILTER BAR ---
            st.markdown("### 🔍 Filter Reports")
            col_search, col_type, col_sev = st.columns([2, 1, 1])
            
            with col_search:
                search_query = st.text_input("Search by Target...", placeholder="e.g., app.py or example.com")
            
            with col_type:
                unique_types = list(set(r.get("scan_type", "unknown").upper() for r in reports))
                filter_type = st.selectbox("Scan Type", ["All"] + unique_types)
            
            with col_sev:
                filter_sev = st.selectbox("Highest Severity", ["All", "Critical", "High", "Medium", "Low", "Info", "None"])

            # Apply filters
            filtered_reports = []
            for r in reports:
                # 1. Check Scan Type
                if filter_type != "All" and r.get("scan_type", "").upper() != filter_type:
                    continue
                # 2. Check Severity
                if filter_sev != "All" and r.get("highest_severity", "none").capitalize() != filter_sev:
                    continue
                # 3. Check Search Query
                if search_query:
                    target = r.get("target", "").lower()
                    if search_query.lower() not in target:
                        continue
                filtered_reports.append(r)

            st.markdown("---")

            if not filtered_reports:
                st.warning("No reports match your current filter criteria.")
                return

            # History chart (Now uses Filtered Data)
            if len(filtered_reports) > 1:
                st.markdown("### 📈 Vulnerability History")
                df_chart = pd.DataFrame([
                    {
                        "Scan": (
                            r.get("target", "")[-30:] + " " +
                            r.get("created_at", "")[:10]
                        ),
                        "Vulnerabilities": r.get("vulnerability_count", 0),
                    }
                    for r in reversed(filtered_reports)
                ])
                st.bar_chart(
                    df_chart.set_index("Scan")["Vulnerabilities"]
                )

            # History table (Now uses Filtered Data)
            st.markdown(f"### 📋 Scan History ({len(filtered_reports)} matching)")
            sev_icons = {
                "critical": "🔴", "high": "🟠", "medium": "🟡",
                "low": "🟢", "info": "🔵", "none": "⚪",
            }
            df_table = pd.DataFrame([
                {
                    "Date": r.get("created_at", "")[:19].replace("T", " "),
                    "Type": r.get("scan_type", "file").upper(),
                    "Target": r.get("target", "N/A")[-50:],
                    "Vulns": r.get("vulnerability_count", 0),
                    "Threat %": f"{r.get('threat_score', 0.0):.0f}%",
                    "Highest": (
                        sev_icons.get(
                            r.get("highest_severity", "none"), "⚪"
                        ) + " " +
                        r.get("highest_severity", "none").capitalize()
                    ),
                }
                for r in filtered_reports
            ])
            st.dataframe(
                df_table, use_container_width=True, hide_index=True
            )

            # Download section (Now uses Filtered Data)
            st.markdown("### 📥 Download Reports")
            for r in filtered_reports:
                job_id = r.get("job_id", "")
                scan_type = r.get("scan_type", "file").upper()
                target = r.get("target", "N/A")
                created = r.get("created_at", "")[:19].replace("T", " ")
                vuln_count = r.get("vulnerability_count", 0)
                with st.expander(
                    f"[{scan_type}] {target[:50]} — "
                    f"{vuln_count} vulns — {created}"
                ):
                    st.caption(f"Job ID: `{job_id}`")
                    try:
                        dl_resp = requests.get(
                            f"{BACKEND_URL}/api/reports/{job_id}/download",
                            headers=auth_headers(),
                            timeout=30
                        )
                        if dl_resp.status_code == 200:
                            st.download_button(
                                label="📥 Download PDF",
                                data=dl_resp.content,
                                file_name=f"AIGIS_Report_{job_id[:8]}.pdf",
                                mime="application/pdf",
                                key=f"dl_{job_id}"
                            )
                        else:
                            st.warning("Report file not available.")
                    except Exception:
                        st.warning("Could not fetch report file.")
        else:
            st.error(f"Could not load reports: {resp.text}")
    except requests.exceptions.ConnectionError:
        st.error("Cannot connect to backend.")
    except Exception as e:
        st.error(f"Error: {e}")
# ── Main show ──────────────────────────────────────────────────────────────────

def show():
    # Hide standard Streamlit header/footer for a cleaner SaaS look
    st.markdown("""
        <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            header {visibility: hidden;}
            
            /* Custom CSS for the Overview Dashboard */
            .hero-title {
                font-size: 3.2rem;
                font-weight: 800;
                background: -webkit-linear-gradient(45deg, #00ff41, #03a9f4);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 0px;
                padding-bottom: 10px;
            }
            .hero-subtitle {
                font-size: 1.2rem;
                color: #94a3b8;
                margin-bottom: 40px;
            }
            .nav-card {
                background: rgba(30, 41, 59, 0.5);
                border: 1px solid rgba(255, 255, 255, 0.05);
                padding: 25px;
                border-radius: 12px;
                text-align: left;
                transition: transform 0.3s ease, box-shadow 0.3s ease, border-color 0.3s ease;
                margin-bottom: 15px;
            }
            .nav-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 10px 20px rgba(0, 255, 65, 0.05);
                border-color: rgba(0, 255, 65, 0.4);
            }
            .card-icon {
                font-size: 2.5rem;
                margin-bottom: 15px;
                display: block;
            }
            .card-title {
                font-size: 1.4rem;
                font-weight: 700;
                color: #f8fafc;
                margin-bottom: 8px;
            }
            .card-text {
                color: #94a3b8;
                font-size: 0.95rem;
                line-height: 1.5;
            }
        </style>
    """, unsafe_allow_html=True)

    show_active_jobs_banner()

    # Determine current page from URL params for persistence on refresh
    pages = [
        "🏠 Overview",
        "📁 File Scan",
        "🗜️ ZIP Scan",
        "🌐 URL Scan",
        "📦 Repository Scan",
        "📜 My Reports"
    ]
    
    current_page = st.query_params.get("page", "🏠 Overview")
    default_idx = pages.index(current_page) if current_page in pages else 0

    page = st.sidebar.radio(
        "Navigation",
        pages,
        index=default_idx
    )
    
    # Save selected page to URL params
    st.query_params["page"] = page

    if page == "🏠 Overview":
        # --- HERO SECTION ---
        st.markdown(f'<div class="hero-title">A.I.G.I.S Command Center</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="hero-subtitle">Welcome back, <b>{st.session_state.username}</b>. Select a target vector to deploy autonomous security analysis.</div>', unsafe_allow_html=True)

        # --- NAVIGATION GRID ---
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("""
                <div class="nav-card">
                    <span class="card-icon">📁</span>
                    <div class="card-title">Static File Analysis</div>
                    <div class="card-text">Deep code inspection for Python, JS, Java, and binaries. Detect vulnerabilities before execution.</div>
                </div>
            """, unsafe_allow_html=True)
            if st.button("Launch File Scan ➔", use_container_width=True, type="secondary"):
                st.query_params["page"] = "📁 File Scan"
                st.rerun()

            st.markdown("<br>", unsafe_allow_html=True)

            st.markdown("""
                <div class="nav-card">
                    <span class="card-icon">🌐</span>
                    <div class="card-title">URL & Web Application Scan</div>
                    <div class="card-text">Perform dynamic active testing (DAST) on live web applications, APIs, and open server ports.</div>
                </div>
            """, unsafe_allow_html=True)
            if st.button("Launch URL Scan ➔", use_container_width=True, type="secondary"):
                st.query_params["page"] = "🌐 URL Scan"
                st.rerun()

        with col2:
            st.markdown("""
                <div class="nav-card">
                    <span class="card-icon">🗜️</span>
                    <div class="card-title">ZIP Archive Scan</div>
                    <div class="card-text">Upload a compressed project directory. A.I.G.I.S extracts and recursively scans all internal files.</div>
                </div>
            """, unsafe_allow_html=True)
            if st.button("Launch ZIP Scan ➔", use_container_width=True, type="secondary"):
                st.query_params["page"] = "🗜️ ZIP Scan"
                st.rerun()

            st.markdown("<br>", unsafe_allow_html=True)

            st.markdown("""
                <div class="nav-card">
                    <span class="card-icon">📦</span>
                    <div class="card-title">Repository Scan</div>
                    <div class="card-text">Connect to public GitHub or GitLab repositories to scan commit history for leaked secrets and keys.</div>
                </div>
            """, unsafe_allow_html=True)
            if st.button("Launch Repo Scan ➔", use_container_width=True, type="secondary"):
                st.query_params["page"] = "📦 Repository Scan"
                st.rerun()

        # --- BOTTOM ACTION BAR ---
        st.markdown("---")
        st.markdown("### 📊 Security Dashboard & History")
        st.markdown("Review your past scans, download PDF reports, and check your OWASP compliance matrix.")
        
        _, col_center, _ = st.columns([1, 2, 1])
        with col_center:
            if st.button("View My Reports", type="primary", use_container_width=True):
                st.query_params["page"] = "📜 My Reports"
                st.rerun()

    elif page == "📁 File Scan":
        page_file_scan()
    elif page == "🗜️ ZIP Scan":
        page_zip_scan()
    elif page == "🌐 URL Scan":
        page_url_scan()
    elif page == "📦 Repository Scan":
        page_repo_scan()
    elif page == "📜 My Reports":
        page_my_reports()