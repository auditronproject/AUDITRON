
import json
from pathlib import Path
from datetime import datetime

import streamlit as st
import pandas as pd

from modules.cis_checker import run_cis_audit
from modules.system_collector import collect_system_info
from modules.drift_detector import create_baseline, detect_configuration_drift
from modules.risk_analyzer import analyze_risks, get_risk_summary
from modules.report_generator import generate_csv_report
from modules.safety_manager import (
    check_authorization,
    validate_operation,
    get_safety_notice
)


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="AUDITRON | Security Audit Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

HISTORY_FILE = Path(__file__).parent / "output" / "audit_history.json"


# =========================================================
# CUSTOM THEME
# =========================================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

.stApp {
    background: #080F1D;
    color: #E2E8F0;
    font-family: 'Inter', sans-serif;
}

[data-testid="stSidebar"] {
    background: #101A2B;
    border-right: 1px solid #263B56;
}

.block-container {
    max-width: 1550px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

h1, h2, h3, h4 {
    color: #F8FAFC !important;
    font-weight: 700 !important;
}

p, label {
    color: #CBD5E1;
}

[data-testid="stMetric"] {
    background: #142238;
    border: 1px solid #263B56;
    padding: 15px;
    border-radius: 12px;
}

.stButton > button,
.stDownloadButton > button {
    background: linear-gradient(110deg, #087EA4, #2563EB);
    color: white;
    border: 1px solid #38BDF8;
    border-radius: 9px;
    font-weight: 700;
    min-height: 43px;
}

.stButton > button:hover,
.stDownloadButton > button:hover {
    background: linear-gradient(110deg, #0891B2, #3B82F6);
    border-color: #7DD3FC;
    color: white;
}

.stButton > button:disabled {
    background: #334155;
    color: #94A3B8;
    border-color: #475569;
}

div[data-testid="stExpander"] {
    background: #111D30;
    border: 1px solid #263B56;
    border-radius: 10px;
}

div[data-testid="stAlert"] {
    border-radius: 9px;
}

hr {
    border-color: #26364D;
}

.auditron-brand {
    font-size: 27px;
    font-weight: 800;
    letter-spacing: 2px;
    color: #F8FAFC;
}

.auditron-subtitle {
    color: #38BDF8;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 2px;
}

.section-caption {
    color: #94A3B8;
    font-size: 13px;
}

.status-label {
    color: #38BDF8;
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 2px;
}

.module-card {
    background: linear-gradient(145deg, #172A43, #101D31);
    border: 1px solid #29415F;
    border-radius: 13px;
    padding: 18px;
    min-height: 125px;
    margin-bottom: 8px;
}

.module-title {
    color: #F8FAFC;
    font-size: 16px;
    font-weight: 800;
    margin-bottom: 9px;
}

.module-description {
    color: #94A3B8;
    font-size: 12px;
    line-height: 1.7;
}

.metric-card {
    border-radius: 12px;
    padding: 16px;
    min-height: 105px;
    border: 1px solid;
    margin-bottom: 10px;
}

.metric-label {
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 1.3px;
    margin-bottom: 8px;
}

.metric-value {
    font-size: 30px;
    font-weight: 800;
    line-height: 1.2;
}

.metric-total, .metric-neutral {
    background: #1B2B43;
    border-color: #3B5576;
}
.metric-total .metric-label, .metric-total .metric-value,
.metric-neutral .metric-label, .metric-neutral .metric-value {
    color: #E2E8F0;
}

.metric-pass, .metric-low {
    background: #10372F;
    border-color: #16845F;
}
.metric-pass .metric-label, .metric-pass .metric-value,
.metric-low .metric-label, .metric-low .metric-value {
    color: #6EE7B7;
}

.metric-fail, .metric-high {
    background: #421F2A;
    border-color: #B94159;
}
.metric-fail .metric-label, .metric-fail .metric-value,
.metric-high .metric-label, .metric-high .metric-value {
    color: #FDA4AF;
}

.metric-warning, .metric-medium {
    background: #44331A;
    border-color: #B7791F;
}
.metric-warning .metric-label, .metric-warning .metric-value,
.metric-medium .metric-label, .metric-medium .metric-value {
    color: #FCD34D;
}

.metric-info {
    background: #15344A;
    border-color: #287CA5;
}
.metric-info .metric-label, .metric-info .metric-value {
    color: #7DD3FC;
}

.metric-error {
    background: #332642;
    border-color: #8054A5;
}
.metric-error .metric-label, .metric-error .metric-value {
    color: #D8B4FE;
}

.gauge-wrapper {
    background: linear-gradient(145deg, #142238, #101A2B);
    border: 1px solid #263B56;
    border-radius: 14px;
    padding: 22px 15px 18px;
    text-align: center;
    margin-bottom: 12px;
}

.gauge-heading {
    color: #94A3B8;
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 2px;
    margin-bottom: 12px;
}

.gauge-container {
    position: relative;
    width: 280px;
    max-width: 100%;
    height: 145px;
    margin: 0 auto;
    overflow: hidden;
}

.gauge-ring {
    position: absolute;
    width: 250px;
    height: 250px;
    max-width: 90vw;
    left: 50%;
    top: 0;
    transform: translateX(-50%);
    border-radius: 50%;
}

.gauge-hole {
    position: absolute;
    width: 210px;
    height: 210px;
    left: 50%;
    top: 20px;
    transform: translateX(-50%);
    border-radius: 50%;
    background: #142238;
}

.gauge-percentage {
    position: absolute;
    width: 100%;
    top: 78px;
    left: 0;
    font-size: 35px;
    font-weight: 800;
    line-height: 1;
    z-index: 2;
}

.gauge-left-label {
    position: absolute;
    left: 8px;
    bottom: 3px;
    color: #94A3B8;
    font-size: 10px;
    z-index: 3;
}

.gauge-right-label {
    position: absolute;
    right: 8px;
    bottom: 3px;
    color: #94A3B8;
    font-size: 10px;
    z-index: 3;
}

.gauge-description {
    color: #94A3B8;
    font-size: 12px;
    margin-top: 5px;
}
</style>
""", unsafe_allow_html=True)


# =========================================================
# SESSION STATE
# =========================================================

DEFAULTS = {
    "authorized": False,
    "audit_results": [],
    "audit_timestamp": None,
    "drift_result": {},
    "drift_security_results": [],
    "baseline_result": {},
    "system_info": None,
    "navigation": "Overview"
}

for key, value in DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value


# =========================================================
# AUDIT HISTORY
# =========================================================

def load_audit_history():
    try:
        if not HISTORY_FILE.exists():
            return []

        with open(HISTORY_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        return data if isinstance(data, list) else []

    except (OSError, json.JSONDecodeError):
        return []


def save_audit_history(history):
    try:
        HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)

        with open(HISTORY_FILE, "w", encoding="utf-8") as file:
            json.dump(history, file, indent=4)

        return True

    except OSError:
        return False


def get_status_counts(results):
    statuses = ["PASS", "FAIL", "WARNING", "INFO", "ERROR"]

    return {
        status: sum(
            str(item.get("status", "")).upper() == status
            for item in results
            if isinstance(item, dict)
        )
        for status in statuses
    }


def get_pass_rate(counts):
    evaluated = (
        counts["PASS"]
        + counts["FAIL"]
        + counts["WARNING"]
        + counts["ERROR"]
    )

    if evaluated == 0:
        return 0

    return counts["PASS"] / evaluated * 100


def record_audit_history(results, timestamp):
    counts = get_status_counts(results)
    pass_rate = get_pass_rate(counts)

    record = {
        "timestamp": timestamp,
        "total": len(results),
        "pass": counts["PASS"],
        "fail": counts["FAIL"],
        "warning": counts["WARNING"],
        "info": counts["INFO"],
        "error": counts["ERROR"],
        "pass_rate": round(pass_rate, 1)
    }

    history = load_audit_history()
    history.insert(0, record)

    return save_audit_history(history[:100])


# =========================================================
# GENERAL HELPERS
# =========================================================

def navigate_to(target_page):
    st.session_state["navigation"] = target_page


def operation_allowed(operation):
    authorization = check_authorization(
        st.session_state.get("authorized", False)
    )

    if not authorization["allowed"]:
        st.error(authorization["message"])
        return False

    validation = validate_operation(operation)

    if not validation["allowed"]:
        st.error(validation["message"])
        return False

    return True


def clear_current_results():
    st.session_state["audit_results"] = []
    st.session_state["audit_timestamp"] = None
    st.session_state["drift_result"] = {}
    st.session_state["drift_security_results"] = []
    st.session_state["baseline_result"] = {}


def display_page_header(title, description=None):
    st.title(title)

    if description:
        st.markdown(
            f'<p class="section-caption">{description}</p>',
            unsafe_allow_html=True
        )


# =========================================================
# METRIC CARDS
# =========================================================

def display_metric_cards(results):
    counts = get_status_counts(results)

    metrics = [
        ("TOTAL", len(results), "metric-total"),
        ("PASS", counts["PASS"], "metric-pass"),
        ("FAIL", counts["FAIL"], "metric-fail"),
        ("WARNING", counts["WARNING"], "metric-warning"),
        ("INFO", counts["INFO"], "metric-info"),
        ("ERROR", counts["ERROR"], "metric-error")
    ]

    cols = st.columns(6)

    for col, (label, value, css_class) in zip(cols, metrics):
        with col:
            st.markdown(
                f"""
                <div class="metric-card {css_class}">
                    <div class="metric-label">{label}</div>
                    <div class="metric-value">{value}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

    return counts


# =========================================================
# AUDIT PASS RATE GAUGE
# =========================================================

def display_pass_gauge(counts):
    pass_rate = get_pass_rate(counts)

    evaluated = (
        counts["PASS"]
        + counts["FAIL"]
        + counts["WARNING"]
        + counts["ERROR"]
    )

    if evaluated == 0:
        score_text = "N/A"
        description = "Run an audit to calculate the pass rate."
        gauge_color = "#64748B"
        sweep_angle = 0

    else:
        score_text = f"{pass_rate:.1f}%"
        description = (
            f'{counts["PASS"]} passed out of '
            f'{evaluated} evaluated controls'
        )

        sweep_angle = pass_rate * 1.8

        if pass_rate >= 80:
            gauge_color = "#34D399"
        elif pass_rate >= 50:
            gauge_color = "#FBBF24"
        else:
            gauge_color = "#FB7185"

    gauge_html = f"""
    <div class="gauge-wrapper">
        <div class="gauge-heading">AUDIT PASS RATE</div>

        <div class="gauge-container">
            <div class="gauge-ring" style="
                background: conic-gradient(
                    from 270deg,
                    {gauge_color} 0deg,
                    {gauge_color} {sweep_angle}deg,
                    #334155 {sweep_angle}deg,
                    #334155 180deg,
                    transparent 180deg,
                    transparent 360deg
                );
            "></div>

            <div class="gauge-hole"></div>

            <div class="gauge-percentage" style="color:{gauge_color};">
                {score_text}
            </div>

            <div class="gauge-left-label">0%</div>
            <div class="gauge-right-label">100%</div>
        </div>

        <div class="gauge-description">{description}</div>
    </div>
    """

    st.html(gauge_html)

    st.caption(
        "INFO findings are excluded from the pass-rate calculation."
    )


# =========================================================
# AUDIT FINDINGS
# =========================================================

def display_audit_results(results):
    st.markdown("### Security Control Findings")

    for result in results:
        status = str(result.get("status", "UNKNOWN")).upper()
        control = result.get("control", "Unknown Control")
        details = result.get("details", "No details available.")

        with st.expander(f"{control} | {status}"):
            st.write(details)

            if status == "PASS":
                st.success("Control check passed.")
            elif status == "FAIL":
                st.error("Control check failed.")
            elif status == "WARNING":
                st.warning("Manual verification may be required.")
            elif status == "INFO":
                st.info(
                    "Informational finding. Review the detected "
                    "security provider and its protection status."
                )
            elif status == "ERROR":
                st.error("The security check could not be completed.")
            else:
                st.info("Unclassified audit result.")


# =========================================================
# RISK METRICS
# =========================================================

def display_risk_metrics(summary):
    metrics = [
        ("HIGH", "metric-high"),
        ("MEDIUM", "metric-medium"),
        ("LOW", "metric-low"),
        ("INFORMATIONAL", "metric-info"),
        ("UNDETERMINED", "metric-neutral")
    ]

    cols = st.columns(5)

    for col, (level, css_class) in zip(cols, metrics):
        with col:
            st.markdown(
                f"""
                <div class="metric-card {css_class}">
                    <div class="metric-label">{level}</div>
                    <div class="metric-value">
                        {summary.get(level, 0)}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )


# =========================================================
# DRIFT / SECURITY ASSESSMENT HELPERS
# =========================================================

def normalize_control_name(control):
    """
    Convert different control naming formats into
    a consistent key for matching drift and CIS results.
    """

    name = str(control).strip().lower()
    name = name.replace("-", "_").replace(" ", "_")

    if "firewall" in name:
        return "firewall"

    if "defender" in name:
        return "defender"

    if "smb" in name:
        return "smb1"

    if "antivirus" in name or "provider" in name:
        return "antivirus_providers"

    return name


def build_security_assessment_lookup(security_results):
    """
    Match CIS security assessment results to drift controls.
    """

    lookup = {}

    for result in security_results:
        if not isinstance(result, dict):
            continue

        key = normalize_control_name(
            result.get("control", "")
        )

        lookup[key] = result

    return lookup


def display_security_status(assessment):
    """
    Display the security assessment independently
    from the configuration drift status.
    """

    if not assessment:
        st.warning("No matching security assessment is available.")
        return

    status = str(
        assessment.get("status", "UNKNOWN")
    ).upper()

    details = assessment.get(
        "details",
        "No assessment details available."
    )

    if status == "PASS":
        st.success("PASS")
    elif status == "FAIL":
        st.error("FAIL")
    elif status == "WARNING":
        st.warning("WARNING")
    elif status == "INFO":
        st.info("INFO")
    elif status == "ERROR":
        st.error("ERROR")
    else:
        st.info(status)

    st.caption(details)


def display_drift_status(drift_status):
    status = str(drift_status).upper()

    if status == "NO CHANGE":
        st.success("NO CHANGE")
        st.caption(
            "Current configuration matches the saved baseline."
        )

    elif status == "DRIFT DETECTED":
        st.warning("DRIFT DETECTED")
        st.caption(
            "Current configuration differs from the saved baseline."
        )

    else:
        st.info(status)


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.markdown(
        """
        <div style="padding:12px 0 20px 0;">
            <div class="auditron-brand">🛡️ AUDITRON</div>
            <div class="auditron-subtitle">
                SECURITY AUDIT PLATFORM
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("---")
    st.markdown("##### MAIN NAVIGATION")

    page = st.radio(
        "Navigation",
        [
            "Overview",
            "CIS Benchmark Audit",
            "Configuration Drift",
            "Risk Analysis",
            "Report Center",
            "Safety & System"
        ],
        key="navigation",
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown("##### AUTHORIZED SECURITY AUDIT")

    st.checkbox(
        "I am authorized to audit this computer.",
        key="authorized"
    )

    if st.session_state["authorized"]:
        st.success("Authorization confirmed.")
    else:
        st.warning("Authorization required.")

    st.markdown("---")

    st.markdown(
        """
        <div class="section-caption">
            AUDIT MODE<br>
            <strong style="color:#38BDF8;">READ-ONLY</strong>
            <br><br>
            Automatic remediation: Disabled
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("---")
    st.markdown("##### SESSION MANAGEMENT")

    if st.button(
        "🧹 Clear Current Results",
        width="stretch",
        help="Clears current results but preserves history and saved baseline."
    ):
        clear_current_results()
        st.session_state["clear_notice"] = True
        st.rerun()

    st.caption("AUDITRON | Version 2.2")


# =========================================================
# SYSTEM INFORMATION
# =========================================================

if st.session_state["system_info"] is None:
    try:
        st.session_state["system_info"] = collect_system_info()
    except Exception:
        st.session_state["system_info"] = {}

system = st.session_state["system_info"] or {}

if st.session_state.pop("clear_notice", False):
    st.success(
        "Current results cleared. Audit history and saved baseline were preserved."
    )


# =========================================================
# OVERVIEW
# =========================================================

if page == "Overview":

    display_page_header("Security Overview")

    st.markdown(
        '<div class="status-label">AUDITRON SECURITY INTELLIGENCE</div>',
        unsafe_allow_html=True
    )

    if system:
        st.caption(
            f'System: {system.get("operating_system", "Unknown")} '
            f'| Version: {system.get("version", "Unknown")} '
            f'| Host: {system.get("computer_name", "Unknown")}'
        )
    else:
        st.warning("System information is currently unavailable.")

    audit_results = st.session_state["audit_results"]
    counts = get_status_counts(audit_results)

    drift_result = st.session_state["drift_result"]

    drift_count = (
        drift_result.get("drift_count", 0)
        if drift_result.get("success") else 0
    )

    st.markdown("### Security Posture")

    display_pass_gauge(counts)
    display_metric_cards(audit_results)

    col1, col2 = st.columns(2)

    with col1:
        st.metric("CONFIGURATION DRIFT", drift_count)

    with col2:
        st.metric("AUDIT HISTORY RECORDS", len(load_audit_history()))

    st.markdown("---")
    st.markdown("### Platform Modules")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            """
            <div class="module-card">
                <div class="module-title">🛡️ CIS Benchmark Checker</div>
                <div class="module-description">
                    Inspect selected Windows security configurations
                    and identify controls that pass, fail or require review.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.button(
            "Open CIS Benchmark Checker →",
            key="open_cis",
            width="stretch",
            on_click=navigate_to,
            args=("CIS Benchmark Audit",)
        )

    with col2:
        st.markdown(
            """
            <div class="module-card">
                <div class="module-title">🔄 Configuration Drift Detector</div>
                <div class="module-description">
                    Create a security baseline and compare current
                    configuration against the saved reference.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.button(
            "Open Configuration Drift →",
            key="open_drift",
            width="stretch",
            on_click=navigate_to,
            args=("Configuration Drift",)
        )

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(
            """
            <div class="module-card">
                <div class="module-title">📊 Risk Analyzer</div>
                <div class="module-description">
                    Classify audit findings into rule-based risk levels.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.button(
            "Open Risk Analyzer →",
            key="open_risk",
            width="stretch",
            on_click=navigate_to,
            args=("Risk Analysis",)
        )

    with col2:
        st.markdown(
            """
            <div class="module-card">
                <div class="module-title">📄 Report Generator</div>
                <div class="module-description">
                    Generate downloadable security audit reports.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.button(
            "Open Report Center →",
            key="open_report",
            width="stretch",
            on_click=navigate_to,
            args=("Report Center",)
        )

    with col3:
        st.markdown(
            """
            <div class="module-card">
                <div class="module-title">🔐 Safety Manager</div>
                <div class="module-description">
                    Enforce authorization and read-only operation rules.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.button(
            "Open Safety Manager →",
            key="open_safety",
            width="stretch",
            on_click=navigate_to,
            args=("Safety & System",)
        )

    st.markdown("---")
    st.markdown("### Latest Audit Activity")

    if audit_results:
        activity_data = [
            {
                "Security Control": item.get("control", ""),
                "Status": item.get("status", ""),
                "Finding": item.get("details", "")
            }
            for item in audit_results
        ]

        st.dataframe(
            activity_data,
            width="stretch",
            hide_index=True
        )
    else:
        st.info("No current audit activity.")

    st.markdown("---")
    st.markdown("### Recent Audit History")

    history = load_audit_history()

    if history:
        st.dataframe(
            pd.DataFrame(history),
            width="stretch",
            hide_index=True
        )
    else:
        st.caption("No previous audit sessions have been recorded.")


# =========================================================
# CIS BENCHMARK AUDIT
# =========================================================

elif page == "CIS Benchmark Audit":

    display_page_header(
        "CIS Benchmark Checker",
        "Selected Windows security configuration checks."
    )

    st.info(
        "AUDITRON checks selected security controls. "
        "It does not claim full CIS Benchmark certification."
    )

    if st.button(
        "▶ Run Security Audit",
        type="primary",
        width="stretch",
        disabled=not st.session_state["authorized"]
    ):

        if operation_allowed("cis_audit"):

            with st.spinner("Inspecting Windows security configurations..."):

                try:
                    results = run_cis_audit()

                    timestamp = datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )

                    st.session_state["audit_results"] = results
                    st.session_state["audit_timestamp"] = timestamp

                    history_saved = record_audit_history(
                        results,
                        timestamp
                    )

                    st.success("Security audit completed successfully.")

                    if not history_saved:
                        st.warning(
                            "Audit completed, but the history record could not be saved."
                        )

                except Exception as error:
                    st.error(f"Audit failed: {error}")

    results = st.session_state["audit_results"]

    if results:
        st.markdown("---")

        counts = display_metric_cards(results)
        display_pass_gauge(counts)

        st.markdown("---")
        display_audit_results(results)

        st.caption(
            "Latest audit: "
            + str(st.session_state.get("audit_timestamp", "Unavailable"))
        )
    else:
        st.info("No audit results yet. Run the security audit to begin.")


# =========================================================
# CONFIGURATION DRIFT
# =========================================================

elif page == "Configuration Drift":

    display_page_header(
        "Configuration Drift Detector",
        "Compare configuration changes and assess current security posture."
    )

    st.info(
        "AUDITRON provides two separate results: "
        "configuration change detection and security assessment."
    )

    # -----------------------------------------------------
    # BASELINE AND COMPARISON ACTIONS
    # -----------------------------------------------------

    col1, col2 = st.columns(
        2,
        gap="large",
        vertical_alignment="bottom"
    )

    with col1:

        st.markdown("### 01. Create Baseline")

        st.write(
            "Save the current security configuration as the reference baseline."
        )

        if st.button(
            "Create Security Baseline",
            type="primary",
            width="stretch",
            disabled=not st.session_state["authorized"],
            key="create_security_baseline"
        ):

            if operation_allowed("collect_configuration"):

                with st.spinner("Collecting security baseline..."):

                    try:
                        result = create_baseline()
                        st.session_state["baseline_result"] = result

                        if result.get("success"):
                            st.success(result["message"])
                        else:
                            st.error(result["message"])

                    except Exception as error:
                        st.error(
                            f"Baseline creation failed: {error}"
                        )

    with col2:

        st.markdown("### 02. Compare Configuration")

        st.write(
            "Compare current configuration against the saved baseline "
            "and perform a fresh security assessment."
        )

        if st.button(
            "Compare Current Configuration",
            type="primary",
            width="stretch",
            disabled=not st.session_state["authorized"],
            key="compare_current_configuration"
        ):

            if operation_allowed("compare_configuration"):

                with st.spinner(
                    "Analyzing configuration and security posture..."
                ):

                    try:
                        result = detect_configuration_drift()

                        st.session_state["drift_result"] = result
                        st.session_state["drift_security_results"] = []

                        if result.get("success"):

                            if operation_allowed("cis_audit"):

                                security_results = run_cis_audit()

                                st.session_state[
                                    "drift_security_results"
                                ] = security_results

                                st.success(
                                    "Configuration comparison and "
                                    "security assessment completed."
                                )

                        else:
                            st.error(
                                result.get(
                                    "message",
                                    "Drift comparison failed."
                                )
                            )

                    except Exception as error:
                        st.error(f"Analysis failed: {error}")

    # -----------------------------------------------------
    # BASELINE INFORMATION
    # -----------------------------------------------------

    st.markdown("---")

    baseline_result = st.session_state["baseline_result"]

    if baseline_result.get("success"):

        st.success("Saved baseline is available.")

        baseline_data = baseline_result.get("data", {})

        st.caption(
            "Baseline created at: "
            + str(baseline_data.get("created_at", "Unknown"))
        )

    # -----------------------------------------------------
    # DRIFT ANALYSIS RESULTS
    # -----------------------------------------------------

    drift_result = st.session_state["drift_result"]

    if drift_result:

        if drift_result.get("success"):

            st.markdown("### Drift Analysis Results")

            st.caption(
                "Baseline created at: "
                + str(
                    drift_result.get(
                        "baseline_created_at",
                        "Unknown"
                    )
                )
            )

            st.metric(
                "Configuration Changes Detected",
                drift_result.get("drift_count", 0)
            )

            security_results = st.session_state.get(
                "drift_security_results",
                []
            )

            assessment_lookup = build_security_assessment_lookup(
                security_results
            )

            st.markdown("---")
            st.markdown("### Configuration & Security Assessment")

            st.caption(
                "Configuration Status identifies whether settings changed. "
                "Security Assessment evaluates the current security condition."
            )

            for item in drift_result.get("results", []):

                control = item.get("control", "Unknown")
                drift_status = item.get("status", "Unknown")

                control_key = normalize_control_name(control)
                assessment = assessment_lookup.get(control_key)

                with st.expander(
                    f"{control} — {drift_status}",
                    expanded=True
                ):

                    status_col, assessment_col = st.columns(2)

                    with status_col:
                        st.markdown("**CONFIGURATION STATUS**")
                        display_drift_status(drift_status)

                    with assessment_col:
                        st.markdown("**SECURITY ASSESSMENT**")
                        display_security_status(assessment)

                    st.markdown("---")

                    baseline_col, current_col = st.columns(2)

                    with baseline_col:
                        st.markdown("**Saved Baseline**")
                        st.json(item.get("baseline"))

                    with current_col:
                        st.markdown("**Current Configuration**")
                        st.json(item.get("current"))

            if not security_results:
                st.warning(
                    "Configuration comparison is available, but no "
                    "security assessment results are stored for this comparison. "
                    "Run Compare Current Configuration again while authorized."
                )

        else:
            st.error(
                drift_result.get(
                    "message",
                    "Drift comparison failed."
                )
            )

    else:
        st.info(
            "Create a baseline first, then compare the current configuration."
        )

    st.caption(
        "Clear Current Results does not delete the saved baseline file."
    )


# =========================================================
# RISK ANALYSIS
# =========================================================

elif page == "Risk Analysis":

    display_page_header(
        "Risk Analysis",
        "Rule-based risk classification from the latest CIS audit."
    )

    results = st.session_state["audit_results"]

    if results:

        if not st.session_state["authorized"]:
            st.warning(
                "Confirm authorization in the sidebar before performing analysis."
            )

        elif operation_allowed("risk_analysis"):

            risk_results = analyze_risks(results)
            risk_summary = get_risk_summary(risk_results)

            st.markdown("### Risk Distribution")
            display_risk_metrics(risk_summary)

            st.markdown("---")
            st.markdown("### Risk Distribution Chart")

            chart_data = pd.DataFrame({
                "Risk Level": list(risk_summary.keys()),
                "Findings": list(risk_summary.values())
            })

            st.bar_chart(
                chart_data.set_index("Risk Level"),
                width="stretch"
            )

            st.markdown("---")
            st.markdown("### Risk Findings")

            for item in risk_results:

                with st.expander(
                    f'{item["control"]} — {item["risk_level"]}'
                ):

                    st.write("**Audit Status:**", item["status"])
                    st.write("**Risk Level:**", item["risk_level"])
                    st.write("**Details:**", item["details"])

            st.caption(
                "Risk levels use the project's rule-based classification. "
                "They are not CVSS scores or formal business-impact ratings."
            )

    else:
        st.info(
            "Run the CIS Benchmark Audit first to generate risk findings."
        )


# =========================================================
# REPORT CENTER
# =========================================================

elif page == "Report Center":

    display_page_header(
        "Security Report Center",
        "Generate and download reports from the latest security audit."
    )

    results = st.session_state["audit_results"]

    if results:

        if not st.session_state["authorized"]:
            st.warning(
                "Confirm authorization in the sidebar before generating a report."
            )

        elif operation_allowed("generate_report"):

            risk_results = analyze_risks(results)
            counts = get_status_counts(results)

            st.markdown("### Report Summary")

            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric("Audit Controls", len(results))

            with col2:
                st.metric("Passed", counts["PASS"])

            with col3:
                st.metric("Failed", counts["FAIL"])

            st.markdown("---")

            try:
                csv_report = generate_csv_report(
                    results,
                    risk_results
                )

                st.success("Your security audit report is ready.")

                st.download_button(
                    label="⬇ Download Security Audit Report (CSV)",
                    data=csv_report,
                    file_name="AUDITRON_security_audit_report.csv",
                    mime="text/csv",
                    width="stretch"
                )

                st.caption(
                    "The CSV report contains audit controls, statuses, "
                    "risk classifications and finding details."
                )

            except Exception as error:
                st.error(f"Unable to generate report: {error}")

    else:
        st.info(
            "No audit data available. Run the CIS Benchmark Audit first."
        )


# =========================================================
# SAFETY & SYSTEM
# =========================================================

elif page == "Safety & System":

    display_page_header(
        "Safety & System",
        "Authorization, operational restrictions and target system details."
    )

    st.markdown("### Authorized Security Audit")

    safety_notice = get_safety_notice()

    st.success(f'Security Mode: {safety_notice["mode"]}')
    st.info(safety_notice["notice"])

    st.markdown("**Automatic Remediation:** Disabled")

    st.warning(
        "AUTHORIZED USE ONLY: Audit only systems you own "
        "or have explicit permission to inspect."
    )

    if st.session_state["authorized"]:
        st.success("Authorization confirmed.")
    else:
        st.warning("Authorization has not been confirmed.")

    st.markdown("---")
    st.markdown("### System Information")

    if system:

        col1, col2 = st.columns(2)

        with col1:
            st.write(
                "**Operating System:**",
                system.get("operating_system", "Unknown")
            )

            st.write(
                "**Computer Name:**",
                system.get("computer_name", "Unknown")
            )

        with col2:
            st.write(
                "**System Version:**",
                system.get("version", "Unknown")
            )

    else:
        st.error("Unable to retrieve system information.")

    st.markdown("---")
    st.markdown("### Operational Restrictions")

    st.write("- Read-only security inspection")
    st.write("- No automatic remediation")
    st.write("- Authorization required before security operations")
    st.write("- No unauthorized system access")

    st.markdown("---")
    st.markdown("### About AUDITRON")

    st.write(
        "AUDITRON is a cybersecurity audit and compliance platform "
        "designed to inspect selected Windows security configurations, "
        "identify configuration differences and generate audit reports."
    )

    st.caption(
        "AUDITRON | Security Audit & Compliance Platform | Version 2.2"
    )


# =========================================================
# FOOTER
# =========================================================

st.html("""
<div style="
    text-align: center;
    padding: 18px;
    border-top: 1px solid #263B56;
">
    <div style="
        color: #38BDF8;
        font-size: 16px;
        font-weight: 800;
        letter-spacing: 3px;
    ">
        AUDITRON
    </div>

    <div style="
        color: #94A3B8;
        font-size: 11px;
        letter-spacing: 1.5px;
        margin-top: 5px;
    ">
        SECURITY AUDIT &amp; COMPLIANCE PLATFORM
    </div>

    <div style="
        color: #64748B;
        font-size: 10px;
        margin-top: 9px;
        line-height: 1.8;
    ">
        Educational Cybersecurity Project<br>
        Read-Only Operations | Version 2.2
    </div>
</div>
""")
