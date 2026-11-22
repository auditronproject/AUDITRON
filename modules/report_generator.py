
"""
AUDITRON - CSV Report Generator

Generates structured security audit reports with
risk classification, scoring and recommendations.
"""

import csv
import io
from datetime import datetime


# ==========================================
# REPORT CONFIGURATION
# ==========================================

REPORT_FIELDS = [
    "Generated At",
    "Finding ID",
    "Control",
    "Audit Status",
    "Risk Level",
    "Risk Score",
    "Priority",
    "Risk Explanation",
    "Recommendation",
    "Details"
]


# ==========================================
# INPUT VALIDATION
# ==========================================

def validate_results(results, field_name):
    """
    Validate audit or risk result collections.
    """

    if not isinstance(results, list):
        raise TypeError(f"{field_name} must be a list.")

    for index, item in enumerate(results):

        if not isinstance(item, dict):
            raise ValueError(
                f"{field_name} item at index {index} "
                "must be a dictionary."
            )


# ==========================================
# RISK RESULT LOOKUP
# ==========================================

def build_risk_lookup(risk_results):
    """
    Group risk findings by control name.

    A list is used for each control to support
    repeated control names without overwriting findings.
    """

    risk_lookup = {}

    for item in risk_results:

        control = item.get("control", "Unknown")

        if not isinstance(control, str):
            control = "Unknown"

        risk_lookup.setdefault(control, []).append(item)

    return risk_lookup


# ==========================================
# CSV REPORT GENERATION
# ==========================================

def generate_csv_report(audit_results, risk_results=None):
    """
    Generate a detailed CSV security audit report.

    Includes:
    - Finding ID
    - Security control
    - Audit status
    - Risk level and score
    - Priority
    - Risk explanation
    - Recommendation
    - Audit details

    Returns:
        str: CSV report content.
    """

    validate_results(audit_results, "audit_results")

    if risk_results is None:
        risk_results = []

    validate_results(risk_results, "risk_results")

    output = io.StringIO(newline="")

    generated_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    risk_lookup = build_risk_lookup(risk_results)

    writer = csv.DictWriter(
        output,
        fieldnames=REPORT_FIELDS,
        extrasaction="ignore"
    )

    writer.writeheader()

    for index, result in enumerate(audit_results, start=1):

        control = result.get("control", "Unknown")

        if not isinstance(control, str) or not control.strip():
            control = "Unknown"

        status = result.get("status", "UNKNOWN")

        if not isinstance(status, str):
            status = "UNKNOWN"

        details = result.get("details", "")

        if not isinstance(details, str):
            details = str(details)

        # Match risk findings by control name.
        matching_findings = risk_lookup.get(control, [])

        risk_data = (
            matching_findings.pop(0)
            if matching_findings
            else {}
        )

        finding_id = risk_data.get(
            "finding_id",
            f"AUD-{index:03d}"
        )

        risk_level = risk_data.get(
            "risk_level",
            "NOT ANALYZED"
        )

        risk_score = risk_data.get(
            "risk_score",
            ""
        )

        priority = risk_data.get(
            "priority",
            "NOT ANALYZED"
        )

        risk_explanation = risk_data.get(
            "risk_explanation",
            ""
        )

        recommendation = risk_data.get(
            "recommendation",
            ""
        )

        writer.writerow({
            "Generated At": generated_at,
            "Finding ID": finding_id,
            "Control": control,
            "Audit Status": status,
            "Risk Level": risk_level,
            "Risk Score": (
                risk_score if risk_score is not None else ""
            ),
            "Priority": priority,
            "Risk Explanation": risk_explanation,
            "Recommendation": recommendation,
            "Details": details
        })

    return output.getvalue()
