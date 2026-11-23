
"""
Safety Manager for Heker Beretika.

Provides authorization checks, target scope enforcement,
safe defaults, and ensures that the tool only performs
read-only security audits.
"""

import platform


DEFAULT_TARGET_SCOPE = "127.0.0.1"

ALLOWED_LOCAL_TARGETS = {
    "127.0.0.1",
    "localhost",
    "::1"
}

READ_ONLY_OPERATIONS = [
    "cis_audit",
    "collect_configuration",
    "compare_configuration",
    "risk_analysis",
    "generate_report"
]


def get_allowed_targets():
    """
    Return the set of approved local target identifiers
    (localhost, loopback IPs, and the local computer hostname).
    """

    allowed = set(ALLOWED_LOCAL_TARGETS)
    local_hostname = platform.node().strip().lower()

    if local_hostname:
        allowed.add(local_hostname)

    return allowed


def validate_target_scope(target_scope):
    """
    Validate that the target scope is restricted to
    safe local targets (127.0.0.1, localhost, ::1, or local hostname).
    """

    if not isinstance(target_scope, str) or not target_scope.strip():
        return {
            "allowed": False,
            "target": "",
            "message": (
                "Target scope is required. Default safe target is "
                f"'{DEFAULT_TARGET_SCOPE}' (localhost)."
            )
        }

    normalized = target_scope.strip().lower()
    allowed_targets = get_allowed_targets()

    if normalized in allowed_targets:
        return {
            "allowed": True,
            "target": target_scope.strip(),
            "message": (
                f"Target scope '{target_scope.strip()}' verified "
                "(authorized local host)."
            )
        }

    return {
        "allowed": False,
        "target": target_scope.strip(),
        "message": (
            f"Target scope '{target_scope.strip()}' is outside the "
            "permitted safe scope. AUDITRON only permits local host "
            "auditing (127.0.0.1, localhost, or the local computer name)."
        )
    }


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
    Return the tool's safety notice and legal disclaimer.
    """

    return {
        "mode": "READ-ONLY",
        "default_target_scope": DEFAULT_TARGET_SCOPE,
        "automatic_remediation": False,
        "kill_switch_enabled": True,
        "notice": (
            "This tool only inspects and reports security "
            "configurations. It does not modify Windows settings."
        ),
        "legal_reference": "Computer Crimes Act 1997 (Act 563) - Malaysia",
        "legal_disclaimer": (
            "LEGAL DISCLAIMER: Unauthorized access, inspection, or misuse of "
            "computer systems is an offence under Malaysia's Computer Crimes "
            "Act 1997 (Act 563). You must only run AUDITRON on systems you own "
            "or have explicit written authorization to audit."
        )
    }


def get_legal_disclaimer():
    """
    Return the startup legal disclaimer referencing the Computer Crimes Act.
    """

    return get_safety_notice()["legal_disclaimer"]
