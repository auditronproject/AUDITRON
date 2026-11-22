
"""
Safety Manager for Heker Beretika.

Provides authorization checks and ensures that
the tool only performs read-only security audits.
"""


READ_ONLY_OPERATIONS = [
    "cis_audit",
    "collect_configuration",
    "compare_configuration",
    "risk_analysis",
    "generate_report"
]


def check_authorization(authorized):
    """
    Check whether the user confirms authorization
    to inspect the target computer.
    """

    if authorized is True:
        return {
            "allowed": True,
            "message": "Authorization confirmed."
        }

    return {
        "allowed": False,
        "message": (
            "Audit blocked. User authorization is required."
        )
    }


def validate_operation(operation):
    """
    Allow only approved read-only operations.
    """

    if operation in READ_ONLY_OPERATIONS:
        return {
            "allowed": True,
            "message": (
                f"Operation '{operation}' is permitted."
            )
        }

    return {
        "allowed": False,
        "message": (
            f"Operation '{operation}' is not permitted. "
            "Only approved read-only operations are allowed."
        )
    }


def get_safety_notice():
    """
    Return the tool's safety notice.
    """

    return {
        "mode": "READ-ONLY",
        "automatic_remediation": False,
        "notice": (
            "This tool only inspects and reports security "
            "configurations. It does not modify Windows settings."
        )
    }
