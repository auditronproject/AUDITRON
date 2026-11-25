
import argparse
import json
import sys
from pathlib import Path
from datetime import datetime

from modules.cis_checker import run_cis_audit
from modules.system_collector import (
    collect_system_info,
    abort_active_collection,
    reset_abort_state
)
from modules.drift_detector import create_baseline, detect_configuration_drift
from modules.risk_analyzer import (
    analyze_risks,
    get_risk_summary,
    get_risk_methodology
)
from modules.report_generator import generate_csv_report
from modules.safety_manager import (
    DEFAULT_TARGET_SCOPE,
    check_authorization,
    validate_operation,
    validate_target_scope,
    get_safety_notice,
    get_legal_disclaimer
)


# =========================================================
# CLI INTERFACE (ARGPARSE SUPPORT FOR TERMINAL EXECUTION)
# =========================================================

def build_cli_parser():
    parser = argparse.ArgumentParser(
        prog="python main.py",
        description=(
            "AUDITRON v1.0.0 | Windows Security Audit & Configuration Drift "
            "Detection Platform (Read-Only)."
        ),
        epilog=(
            "Usage Examples:\n"
            "  Launch Streamlit Web Dashboard:\n"
            "    python -m streamlit run main.py\n\n"
            "  Run CIS Benchmark Audit & Risk Analysis in CLI:\n"
            "    python main.py --cli --authorize --target 127.0.0.1 --audit\n\n"
            "  Create a Configuration Baseline in CLI:\n"
            "    python main.py --cli --authorize --baseline\n\n"
            "  Detect Configuration Drift against Saved Baseline:\n"
            "    python main.py --cli --authorize --drift\n\n"
            "  Export CSV Audit Report from CLI:\n"
            "    python main.py --cli --authorize --audit --report output/audit_report.csv\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "--cli",
        action="store_true",
        help="Run AUDITRON in command-line interface (CLI) mode instead of Streamlit."
    )
    parser.add_argument(
        "--authorize",
        action="store_true",
        help="Confirm explicit authorization to audit the target computer (Required)."
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET_SCOPE,
        help=f"Target scope to audit (Safe default: {DEFAULT_TARGET_SCOPE})."
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Run the CIS Benchmark security audit and rule-based risk analysis."
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Create and save a reference security configuration baseline."
    )
    parser.add_argument(
        "--drift",
        action="store_true",
        help="Compare current configuration against the saved security baseline."
    )
    parser.add_argument(
        "--report",
        metavar="FILE",
        help="Save the CSV security audit report to the specified file path."
    )

    return parser


def run_cli_mode(argv):
    parser = build_cli_parser()
    args = parser.parse_args(argv)

    print("=" * 72)
    print("AUDITRON v1.0.0 | SECURITY AUDIT & COMPLIANCE PLATFORM (READ-ONLY)")
    print("=" * 72)
    print(get_legal_disclaimer())
    print("-" * 72)

    auth_check = check_authorization(args.authorize)
    if not auth_check["allowed"]:
        print(f"[BLOCKED] {auth_check['message']}")
        print("Tip: Pass --authorize to confirm you have permission to audit this host.")
        return 1

    scope_check = validate_target_scope(args.target)
    if not scope_check["allowed"]:
        print(f"[BLOCKED] {scope_check['message']}")
        return 1

    print(f"[OK] {auth_check['message']}")
    print(f"[OK] {scope_check['message']}")
    print("-" * 72)

    if not (args.audit or args.baseline or args.drift or args.report):
        print("No operation specified. Use --audit, --baseline, --drift, or --report.")
        print("Run 'python main.py --help' for usage examples.")
        return 0

    try:
        if args.baseline:
            result = create_baseline()
            status_tag = "OK" if result.get("success") else "ERROR"
            print(f"[{status_tag}] {result.get('message')}")

        if args.drift:
            drift = detect_configuration_drift()
            if drift.get("success"):
                print(
                    f"[DRIFT] Baseline: {drift.get('baseline_created_at')} | "
                    f"Changes Detected: {drift.get('drift_count', 0)}"
                )
                for item in drift.get("results", []):
                    print(f"  - {item['control']}: {item['status']}")
            else:
                print(f"[ERROR] {drift.get('message')}")

        if args.audit or args.report:
            audit_results = run_cis_audit()
            risk_results = analyze_risks(audit_results)

            print("CIS BENCHMARK AUDIT & RISK FINDINGS:")
            for item in risk_results:
                score = (
                    f"{item['risk_score']}/10"
                    if item["risk_score"] is not None
                    else "N/A"
                )
                print(
                    f"  [{item['finding_id']}] {item['control']} | "
                    f"Status: {item['status']} | Risk: {item['risk_level']} ({score})"
                )
                print(f"      Details: {item['details']}")
                print(f"      Recommendation: {item['recommendation']}")

            if args.report:
                report_path = Path(args.report)
                report_path.parent.mkdir(parents=True, exist_ok=True)
                csv_content = generate_csv_report(audit_results, risk_results)
                report_path.write_text(csv_content, encoding="utf-8")
                print(f"\n[OK] CSV report saved to: {report_path}")

    except KeyboardInterrupt:
        print("\n[KILL SWITCH] Execution aborted cleanly by user (Ctrl+C).")
        return 130

    return 0


CLI_TRIGGER_FLAGS = {
    "-h", "--help", "--cli", "--authorize",
    "--target", "--audit", "--baseline", "--drift", "--report"
}

if any(arg in CLI_TRIGGER_FLAGS for arg in sys.argv[1:]):
    raise SystemExit(run_cli_mode(sys.argv[1:]))

import streamlit as st
import pandas as pd


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
    "kill_switch_active": False,
    "target_scope": DEFAULT_TARGET_SCOPE,
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

    scope_check = validate_target_scope(
        st.session_state.get("target_scope", DEFAULT_TARGET_SCOPE)
    )

    if not scope_check["allowed"]:
        st.error(scope_check["message"])
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


def trigger_kill_switch():
    """
    Emergency Stop (Kill Switch): aborts any running PowerShell collection
    subprocesses and freezes/halts dashboard execution while preserving
    existing in-memory session results.
    """
    abort_active_collection()
    st.session_state["kill_switch_active"] = True
    st.session_state["authorized"] = False


def release_kill_switch():
    """
    Release the Emergency Kill Switch so the user can re-authorize
    and resume normal operation with preserved session results.
    """
    reset_abort_state()
    st.session_state["kill_switch_active"] = False


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

    if "guest" in name:
        return "guest_account"

    if "uac" in name or "user_account_control" in name:
        return "uac"

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
            "Configuration Drift",
            "CIS Benchmark Audit",
            "Risk Analysis",
            "Report Center",
            "Safety & System"
        ],
        key="navigation",
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown("##### AUTHORIZED SECURITY AUDIT")

    st.caption(
        "**Computer Crimes Act 1997 (Act 563):** "
        "Audit only systems with explicit authorization."
    )

    st.text_input(
        "Target Scope (Safe Default: 127.0.0.1)",
        key="target_scope",
        help="Permitted scope: 127.0.0.1, localhost, ::1, or the local hostname."
    )

    scope_validation = validate_target_scope(
        st.session_state.get("target_scope", DEFAULT_TARGET_SCOPE)
    )

    if not scope_validation["allowed"]:
        st.error(scope_validation["message"])

    st.checkbox(
        "I am authorized to audit this computer.",
        key="authorized"
    )

    if st.session_state["authorized"] and scope_validation["allowed"]:
        st.success("Authorization confirmed.")
    elif st.session_state["authorized"] and not scope_validation["allowed"]:
        st.warning("Valid local target scope required.")
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
    st.markdown("##### SESSION & KILL SWITCH")

    if st.session_state.get("kill_switch_active", False):
        if st.button(
            "Release Kill Switch (Resume)",
            width="stretch",
            on_click=release_kill_switch,
            help="Release the emergency halt so you can re-authorize and continue."
        ):
            st.rerun()
    else:
        if st.button(
            "Emergency Stop (Kill Switch)",
            width="stretch",
            on_click=trigger_kill_switch,
            help="Immediately abort active PowerShell queries and freeze/halt execution (preserves collected results)."
        ):
            st.rerun()

    if st.button(
        "Clear Current Results",
        width="stretch",
        help="Clears current results but preserves history and saved baseline."
    ):
        clear_current_results()
        st.session_state["clear_notice"] = True
        st.rerun()

    st.caption("AUDITRON | Version 1.0.0")


# =========================================================
# SYSTEM INFORMATION
# =========================================================

if st.session_state["system_info"] is None:
    try:
        st.session_state["system_info"] = collect_system_info()
    except Exception:
        st.session_state["system_info"] = {}

system = st.session_state["system_info"] or {}

if st.session_state.get("kill_switch_active", False):
    st.error(
        "### EMERGENCY KILL SWITCH ENGAGED: EXECUTION HALTED\n\n"
        "- All active PowerShell inspection queries have been aborted.\n"
        "- Audit execution is currently **frozen** and authorization has been suspended.\n"
        "- **In-memory session results, audit history, and saved baselines have been preserved.**\n\n"
        "To resume using AUDITRON, click **Release Kill Switch (Resume)** in the left sidebar "
        "(or below) and re-confirm your authorization."
    )
    if st.button(
        "Release Kill Switch & Return to Dashboard",
        type="primary",
        on_click=release_kill_switch
    ):
        st.rerun()
    st.stop()

if st.session_state.pop("clear_notice", False):
    st.success(
        "Current results cleared. Audit history and saved baseline were preserved."
    )

# =========================================================
# STARTUP LEGAL DISCLAIMER BANNER
# =========================================================

current_scope_check = validate_target_scope(
    st.session_state.get("target_scope", DEFAULT_TARGET_SCOPE)
)

if not st.session_state["authorized"] or not current_scope_check["allowed"]:
    st.warning(
        f"**{get_legal_disclaimer()}**\n\n"
        "Please verify the **Target Scope** (default `127.0.0.1`) and confirm your "
        "authorization in the **Authorized Security Audit** section in the left sidebar "
        "before running any security audit operations."
    )
    st.markdown(
        """
        <div id="unauthorized-anchor"></div>
        <style>
        /* Dim, grayscale, and slightly blur ALL blocks (including columns/cards/buttons) after the legal disclaimer */
        div:has(> #unauthorized-anchor) ~ *,
        div[data-testid="stElementContainer"]:has(#unauthorized-anchor) ~ * {
            opacity: 0.25 !important;
            filter: grayscale(100%) blur(1px) !important;
            pointer-events: none !important;
            user-select: none !important;
            transition: opacity 0.25s ease, filter 0.25s ease;
        }
        /* Highlight the sidebar authorization checkbox area */
        [data-testid="stSidebar"] [data-testid="stCheckbox"] {
            background: rgba(56, 189, 248, 0.14);
            border: 1px solid #38BDF8;
            border-radius: 8px;
            padding: 8px 10px;
            box-shadow: 0 0 12px rgba(56, 189, 248, 0.25);
        }
        </style>
        """,
        unsafe_allow_html=True
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

        st.markdown("---")
        st.button(
            "View Detailed Risk Analysis & Recommendations →",
            key="cis_to_risk",
            width="stretch",
            on_click=navigate_to,
            args=("Risk Analysis",)
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
            methodology = get_risk_methodology()

            st.markdown("### Risk Distribution")
            display_risk_metrics(risk_summary)

            st.markdown("---")
            st.markdown("### Risk Findings")

            with st.expander("Risk Scoring Methodology", expanded=True):
                st.write("**Method:**", methodology["method"])
                st.write("**Score Range:**", methodology["score_range"])
                st.markdown("**Classification Rules:**")
                for level, desc in methodology["classification"].items():
                    st.write(f"- **{level}:** {desc}")
                st.caption(methodology["limitation"])

            for item in risk_results:
                finding_id = item.get("finding_id", "N/A")
                score = item.get("risk_score")
                score_display = f"{score} / 10" if score is not None else "Not Scored"

                with st.expander(
                    f'{finding_id} | {item["control"]} — {item["risk_level"]}'
                ):
                    meta_col1, meta_col2, meta_col3, meta_col4 = st.columns(4)

                    with meta_col1:
                        st.write("**Finding ID:**", finding_id)
                    with meta_col2:
                        st.write("**Audit Status:**", item["status"])
                    with meta_col3:
                        st.write("**Risk Level:**", item["risk_level"])
                    with meta_col4:
                        st.write("**Risk Score:**", score_display)

                    st.write("**Priority:**", item.get("priority", "N/A"))
                    st.write("**Details:**", item["details"])
                    st.write(
                        "**Risk Explanation:**",
                        item.get("risk_explanation", "No explanation available.")
                    )
                    st.info(
                        f'**Recommendation:** {item.get("recommendation", "No recommendation available.")}'
                    )

            st.caption(
                "Risk levels use the project's rule-based classification. "
                "They are not CVSS scores or formal business-impact ratings."
            )

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
            st.button(
                "Proceed to Report Center (Download CSV Report) →",
                key="risk_to_report",
                width="stretch",
                on_click=navigate_to,
                args=("Report Center",)
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
    st.markdown(
        f"**Default Safe Target Scope:** `{safety_notice.get('default_target_scope', DEFAULT_TARGET_SCOPE)}`"
    )
    st.markdown(
        f"**Active Target Scope:** `{st.session_state.get('target_scope', DEFAULT_TARGET_SCOPE)}`"
    )
    st.markdown("**Emergency Kill Switch:** Enabled (Sidebar Session & Kill Switch)")

    st.warning(
        "AUTHORIZED USE ONLY: Audit only systems you own "
        "or have explicit permission to inspect."
    )

    st.info(
        f"**Legal Reference ({safety_notice.get('legal_reference', 'Computer Crimes Act 1997')}):** "
        f"{safety_notice.get('legal_disclaimer', get_legal_disclaimer())}"
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
        "AUDITRON | Security Audit & Compliance Platform | Version 1.0.0"
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
        Read-Only Operations | Version 1.0.0
    </div>
</div>
""")
