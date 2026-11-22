
from modules.system_collector import (
    collect_firewall_status,
    collect_defender_status,
    collect_smb1_status,
    collect_antivirus_providers
)


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def is_microsoft_defender(provider_name):
    """
    Identify Microsoft Defender names,
    including Windows Defender naming variants.
    """

    if not isinstance(provider_name, str):
        return False

    name = provider_name.strip().lower()

    microsoft_names = [
        "microsoft defender",
        "windows defender"
    ]

    return any(
        name == known_name
        or name.startswith(known_name + " ")
        for known_name in microsoft_names
    )


def normalise_provider_data(providers):
    """
    Validate and normalise antivirus provider data.

    Returns:
        list: Valid provider records.
        None: Invalid provider data.
    """

    if isinstance(providers, dict):
        providers = [providers]

    if not isinstance(providers, list):
        return None

    if not all(isinstance(provider, dict) for provider in providers):
        return None

    return providers


def get_third_party_provider_names(providers):
    """
    Return unique third-party antivirus provider names.

    Registered providers are not assumed to be active.
    """

    providers = normalise_provider_data(providers)

    if providers is None:
        return []

    names = []

    for provider in providers:
        name = provider.get("displayName")

        if not isinstance(name, str) or not name.strip():
            continue

        name = name.strip()

        if not is_microsoft_defender(name):
            names.append(name)

    return list(dict.fromkeys(names))


def get_provider_data(providers=None):
    """
    Collect antivirus provider information when not supplied.
    """

    if providers is not None:
        return providers

    return collect_antivirus_providers()


# ==========================================
# WINDOWS FIREWALL CHECK
# ==========================================

def check_firewall():

    try:
        profiles = collect_firewall_status()

        if isinstance(profiles, dict):
            profiles = [profiles]

        if not isinstance(profiles, list) or not profiles:
            return {
                "control": "Windows Firewall",
                "status": "ERROR",
                "details": "No valid firewall profile data returned."
            }

        disabled = []
        unknown = []
        valid_count = 0

        for profile in profiles:

            if not isinstance(profile, dict):
                unknown.append("Invalid profile data")
                continue

            name = profile.get("Name", "Unknown")
            enabled = profile.get("Enabled")

            if not isinstance(name, str) or not name.strip():
                name = "Unknown"

            if type(enabled) is bool:

                valid_count += 1

                if enabled is False:
                    disabled.append(name)

            else:
                unknown.append(name)

        if valid_count == 0:
            return {
                "control": "Windows Firewall",
                "status": "ERROR",
                "details": "No valid firewall profile status available."
            }

        if disabled:
            details = "Disabled profiles: " + ", ".join(disabled)

            if unknown:
                details += (
                    ". Unable to verify: "
                    + ", ".join(unknown)
                )

            return {
                "control": "Windows Firewall",
                "status": "FAIL",
                "details": details
            }

        if unknown:
            return {
                "control": "Windows Firewall",
                "status": "WARNING",
                "details": (
                    "Unable to verify profiles: "
                    + ", ".join(unknown)
                )
            }

        return {
            "control": "Windows Firewall",
            "status": "PASS",
            "details": "All firewall profiles are enabled."
        }

    except Exception as error:
        return {
            "control": "Windows Firewall",
            "status": "ERROR",
            "details": str(error)
        }


# ==========================================
# MICROSOFT DEFENDER CHECK
# ==========================================

def check_defender(providers=None, provider_error=False):
    """
    Check Microsoft Defender protection status.

    A registered third-party provider is reported as INFO.
    Provider registration does not prove active protection.
    """

    try:
        defender = collect_defender_status()

        if not isinstance(defender, dict):
            return {
                "control": "Microsoft Defender",
                "status": "ERROR",
                "details": "Unexpected Defender data format."
            }

        required = [
            "AMServiceEnabled",
            "AntivirusEnabled",
            "RealTimeProtectionEnabled"
        ]

        missing = [
            key for key in required
            if type(defender.get(key)) is not bool
        ]

        if missing:
            return {
                "control": "Microsoft Defender",
                "status": "WARNING",
                "details": (
                    "Unable to verify Defender properties: "
                    + ", ".join(missing)
                )
            }

        disabled = [
            key for key in required
            if defender[key] is False
        ]

        if disabled:

            if provider_error:
                return {
                    "control": "Microsoft Defender",
                    "status": "WARNING",
                    "details": (
                        "Microsoft Defender is not fully enabled. "
                        "Antivirus provider information could not "
                        "be collected, so alternative protection "
                        "could not be confirmed."
                    )
                }

            if providers is None:
                providers = get_provider_data()

            validated_providers = normalise_provider_data(providers)

            if validated_providers is None:
                return {
                    "control": "Microsoft Defender",
                    "status": "WARNING",
                    "details": (
                        "Microsoft Defender is not fully enabled. "
                        "Antivirus provider data is invalid or unavailable."
                    )
                }

            third_party = get_third_party_provider_names(
                validated_providers
            )

            if third_party:
                return {
                    "control": "Microsoft Defender",
                    "status": "INFO",
                    "details": (
                        "Microsoft Defender is not fully enabled. "
                        "Registered third-party provider(s): "
                        + ", ".join(third_party)
                        + ". Verify active protection in Windows Security."
                    )
                }

            return {
                "control": "Microsoft Defender",
                "status": "FAIL",
                "details": (
                    "Disabled settings: "
                    + ", ".join(disabled)
                    + ". No third-party antivirus provider was confirmed."
                )
            }

        return {
            "control": "Microsoft Defender",
            "status": "PASS",
            "details": (
                "All checked Defender protection properties are enabled."
            )
        }

    except Exception as error:
        return {
            "control": "Microsoft Defender",
            "status": "ERROR",
            "details": str(error)
        }


# ==========================================
# THIRD-PARTY ANTIVIRUS CHECK
# ==========================================

def check_third_party_antivirus(
    providers=None,
    provider_error=False
):
    """
    Detect registered third-party antivirus providers.

    Registration does not prove active protection.
    """

    try:

        if provider_error:
            return {
                "control": "Third-Party Antivirus",
                "status": "ERROR",
                "details": (
                    "Unable to collect antivirus provider information."
                )
            }

        if providers is None:
            providers = get_provider_data()

        validated_providers = normalise_provider_data(providers)

        if validated_providers is None:
            return {
                "control": "Third-Party Antivirus",
                "status": "ERROR",
                "details": "Invalid antivirus provider data format."
            }

        if not validated_providers:
            return {
                "control": "Third-Party Antivirus",
                "status": "WARNING",
                "details": (
                    "No registered antivirus provider was returned "
                    "by Windows Security Center. Protection status "
                    "could not be confirmed."
                )
            }

        third_party = get_third_party_provider_names(
            validated_providers
        )

        if third_party:
            return {
                "control": "Third-Party Antivirus",
                "status": "INFO",
                "details": (
                    "Registered third-party antivirus provider(s): "
                    + ", ".join(third_party)
                    + ". Active protection has not been independently verified."
                )
            }

        return {
            "control": "Third-Party Antivirus",
            "status": "WARNING",
            "details": (
                "No third-party antivirus provider was detected. "
                "This check does not independently verify "
                "Microsoft Defender protection."
            )
        }

    except Exception as error:
        return {
            "control": "Third-Party Antivirus",
            "status": "ERROR",
            "details": str(error)
        }


# ==========================================
# SMBv1 CHECK
# ==========================================

def check_smb1():

    try:
        smb = collect_smb1_status()

        if not isinstance(smb, dict):
            return {
                "control": "SMBv1",
                "status": "ERROR",
                "details": "Unexpected SMB configuration format."
            }

        enabled = smb.get("EnableSMB1Protocol")

        if type(enabled) is not bool:
            return {
                "control": "SMBv1",
                "status": "WARNING",
                "details": "SMBv1 status could not be determined."
            }

        if enabled is True:
            return {
                "control": "SMBv1",
                "status": "FAIL",
                "details": "SMBv1 protocol is enabled."
            }

        return {
            "control": "SMBv1",
            "status": "PASS",
            "details": "SMBv1 protocol is disabled."
        }

    except Exception as error:
        return {
            "control": "SMBv1",
            "status": "ERROR",
            "details": str(error)
        }


# ==========================================
# RUN COMPLETE CIS AUDIT
# ==========================================

def run_cis_audit():
    """
    Run all selected Windows security checks.

    Antivirus provider information is collected once
    and reused by the relevant checks.
    """

    provider_error = False

    try:
        providers = collect_antivirus_providers()

        if normalise_provider_data(providers) is None:
            provider_error = True

    except Exception:
        providers = None
        provider_error = True

    results = [
        check_firewall(),
        check_defender(
            providers,
            provider_error=provider_error
        ),
        check_third_party_antivirus(
            providers,
            provider_error=provider_error
        ),
        check_smb1()
    ]

    return results
