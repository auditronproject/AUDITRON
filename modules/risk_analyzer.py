
"""
AUDITRON - Rule-Based Risk Analyzer

Assigns risk levels, scores, explanations and recommendations
to security audit findings.

Risk scores are AUDITRON internal rule-based values.
They are not official CVSS scores.
"""


# ==========================================
# RISK CLASSIFICATION RULES
# ==========================================

RISK_MAPPING = {
    "FAIL": {
        "risk_level": "HIGH",
        "risk_score": 9,
        "priority": "HIGH",
        "explanation": (
            "The security control failed. This configuration "
            "may expose the system to security risks."
        )
    },
    "WARNING": {
        "risk_level": "MEDIUM",
        "risk_score": 6,
        "priority": "MEDIUM",
        "explanation": (
            "The security control could not be fully verified. "
            "Further investigation is recommended."
        )
    },
    "PASS": {
        "risk_level": "LOW",
        "risk_score": 1,
        "priority": "LOW",
        "explanation": (
            "The checked security control meets the configured "
            "audit requirement. Routine monitoring is still recommended."
        )
    },
    "INFO": {
        "risk_level": "INFORMATIONAL",
        "risk_score": 2,
        "priority": "INFORMATIONAL",
        "explanation": (
            "The finding provides security information but does "
            "not independently confirm a security failure."
        )
    },
    "ERROR": {
        "risk_level": "UNDETERMINED",
        "risk_score": None,
        "priority": "REVIEW",
        "explanation": (
            "The security check could not be completed reliably. "
            "The actual risk cannot be determined from this result."
        )
    }
}


# ==========================================
# SECURITY RECOMMENDATIONS
# ==========================================

CONTROL_RECOMMENDATIONS = {
    "windows firewall": {
        "FAIL": (
            "Review the affected firewall profiles and enable "
            "Windows Firewall where required by the system security policy."
        ),
        "WARNING": (
            "Verify the firewall profile status and investigate "
            "any configuration that could not be checked."
        ),
        "PASS": (
            "Keep all required firewall profiles enabled and "
            "review the configuration periodically."
        )
    },
    "microsoft defender": {
        "FAIL": (
            "Investigate the disabled Defender protection settings. "
            "Enable the required protection or verify an approved "
            "alternative antivirus solution."
        ),
        "WARNING": (
            "Check Windows Security and verify the Defender service "
            "and protection status. Confirm whether an approved "
            "third-party antivirus solution is providing protection."
        ),
        "PASS": (
            "Keep real-time protection and the required Defender "
            "security services enabled."
        ),
        "INFO": (
            "Verify that the registered third-party antivirus "
            "provider is installed, updated and actively protecting "
            "the system."
        )
    },
    "third-party antivirus": {
        "WARNING": (
            "Open Windows Security and verify that an antivirus "
            "solution is installed and providing active protection."
        ),
        "INFO": (
            "Confirm the registered antivirus provider is active, "
            "updated and recognised by Windows Security."
        ),
        "PASS": (
            "Continue monitoring antivirus registration and "
            "protection status."
        )
    },
    "smbv1": {
        "FAIL": (
            "Disable SMBv1 where it is not required. Check application "
            "and device compatibility before making configuration changes."
        ),
        "WARNING": (
            "Verify the SMBv1 configuration and investigate why "
            "its status could not be determined."
        ),
        "PASS": (
            "Keep SMBv1 disabled unless a documented business "
            "requirement justifies its use."
        )
    }
}


DEFAULT_RECOMMENDATIONS = {
    "FAIL": (
        "Investigate the failed security control and apply an "
        "appropriate corrective action according to the organisation's "
        "security policy."
    ),
    "WARNING": (
        "Investigate the finding and collect sufficient information "
        "to verify the security control."
    ),
    "PASS": (
        "Maintain the current configuration and perform routine "
        "security reviews."
    ),
    "INFO": (
        "Review this information and verify whether additional "
        "security action is required."
    ),
    "ERROR": (
        "Repeat the security check after resolving the collection "
        "or execution error."
    )
}


# ==========================================
# INPUT VALIDATION
# ==========================================

def validate_audit_results(audit_results):
    """
    Validate the audit results input.
    """

    if not isinstance(audit_results, list):
        raise TypeError("audit_results must be a list.")

    for index, result in enumerate(audit_results):

        if not isinstance(result, dict):
            raise ValueError(
                f"Audit result at index {index} must be a dictionary."
            )


def normalise_status(status):
    """
    Return a supported uppercase audit status.
    """

    if not isinstance(status, str):
        return "ERROR"

    status = status.strip().upper()

    if status not in RISK_MAPPING:
        return "ERROR"

    return status


# ==========================================
# RECOMMENDATION ENGINE
# ==========================================

def get_recommendation(control, status):
    """
    Return a recommendation based on the control and audit status.
    """

    if not isinstance(control, str):
        control = ""

    control_name = control.strip().lower()

    for known_control, recommendations in CONTROL_RECOMMENDATIONS.items():

        if known_control in control_name:
            recommendation = recommendations.get(status)

            if recommendation:
                return recommendation

    return DEFAULT_RECOMMENDATIONS[status]


# ==========================================
# RISK ANALYSIS
# ==========================================

def analyze_risks(audit_results):
    """
    Analyse security audit results.

    Each result includes:
    - Finding ID
    - Control name
    - Audit status
    - Risk level
    - Rule-based risk score
    - Priority
    - Risk explanation
    - Recommendation
    - Original details
    """

    validate_audit_results(audit_results)

    risk_results = []

    for index, result in enumerate(audit_results, start=1):

        status = normalise_status(
            result.get("status", "ERROR")
        )

        control = result.get("control", "Unknown")

        if not isinstance(control, str) or not control.strip():
            control = "Unknown"

        details = result.get("details", "")

        if not isinstance(details, str):
            details = str(details)

        risk_rule = RISK_MAPPING[status]

        risk_results.append({
            "finding_id": f"AUD-{index:03d}",
            "control": control,
            "status": status,
            "risk_level": risk_rule["risk_level"],
            "risk_score": risk_rule["risk_score"],
            "priority": risk_rule["priority"],
            "risk_explanation": risk_rule["explanation"],
            "recommendation": get_recommendation(
                control,
                status
            ),
            "details": details
        })

    return risk_results


# ==========================================
# RISK SUMMARY
# ==========================================

def get_risk_summary(risk_results):
    """
    Count findings according to risk level.

    The five original summary keys are retained
    for compatibility with the AUDITRON dashboard.
    """

    if not isinstance(risk_results, list):
        raise TypeError("risk_results must be a list.")

    summary = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFORMATIONAL": 0,
        "UNDETERMINED": 0
    }

    for result in risk_results:

        if not isinstance(result, dict):
            continue

        level = result.get(
            "risk_level",
            "UNDETERMINED"
        )

        if level not in summary:
            level = "UNDETERMINED"

        summary[level] += 1

    return summary


# ==========================================
# RISK METHODOLOGY
# ==========================================

def get_risk_methodology():
    """
    Explain the rule-based risk scoring methodology.
    """

    return {
        "method": "AUDITRON Rule-Based Risk Scoring",
        "score_range": "0-10",
        "classification": {
            "HIGH": "9 - Failed security control",
            "MEDIUM": "6 - Verification required",
            "LOW": "1 - Checked control passed",
            "INFORMATIONAL": "2 - Informational finding",
            "UNDETERMINED": "Not scored - check returned an error"
        },
        "limitation": (
            "Scores are internal rule-based assessment values. "
            "They are not official CVSS scores and do not represent "
            "a complete measurement of exploitability or business impact."
        )
    }
