
import json
from pathlib import Path
from datetime import datetime

from modules.system_collector import (
    collect_firewall_status,
    collect_defender_status,
    collect_smb1_status,
    collect_antivirus_providers
)


# Baseline storage location
BASELINE_FILE = Path("output/security_baseline.json")


def collect_security_configuration():
    """
    Collect current security configuration.
    This function performs read-only inspection.
    """

    configuration = {
        "firewall": collect_firewall_status(),
        "defender": collect_defender_status(),
        "smb1": collect_smb1_status(),
        "antivirus_providers": collect_antivirus_providers()
    }

    return configuration


def create_baseline():
    """
    Save current security configuration as a baseline.
    """

    try:
        configuration = collect_security_configuration()

        baseline_data = {
            "created_at": datetime.now().isoformat(
                timespec="seconds"
            ),
            "configuration": configuration
        }

        BASELINE_FILE.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with open(BASELINE_FILE, "w", encoding="utf-8") as file:
            json.dump(
                baseline_data,
                file,
                indent=4
            )

        return {
            "success": True,
            "message": "Security baseline created successfully.",
            "data": baseline_data
        }

    except Exception as error:
        return {
            "success": False,
            "message": str(error),
            "data": None
        }


def load_baseline():
    """
    Load previously saved security baseline.
    """

    if not BASELINE_FILE.exists():
        return None

    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except (OSError, json.JSONDecodeError):
        return None


def compare_configurations(baseline, current):
    """
    Compare baseline and current configurations.
    Detect changed, missing and additional controls.
    """

    if not isinstance(baseline, dict):
        raise ValueError(
            "Baseline configuration must be a dictionary."
        )

    if not isinstance(current, dict):
        raise ValueError(
            "Current configuration must be a dictionary."
        )

    drift_results = []

    all_controls = sorted(
        set(baseline.keys()) | set(current.keys())
    )

    for control in all_controls:

        baseline_exists = control in baseline
        current_exists = control in current

        baseline_value = baseline.get(control)
        current_value = current.get(control)

        if not current_exists:
            status = "MISSING CONTROL"

        elif not baseline_exists:
            status = "NEW CONTROL"

        elif baseline_value != current_value:
            status = "DRIFT DETECTED"

        else:
            status = "NO CHANGE"

        drift_results.append({
            "control": control,
            "status": status,
            "baseline": baseline_value,
            "current": current_value
        })

    return drift_results


def detect_configuration_drift():
    """
    Compare current security configuration
    against the saved baseline.
    """

    baseline_data = load_baseline()

    if baseline_data is None:
        return {
            "success": False,
            "message": (
                "No valid baseline found. "
                "Please create a baseline first."
            ),
            "results": []
        }

    try:
        if not isinstance(baseline_data, dict):
            raise ValueError("Invalid baseline file format.")

        baseline_configuration = baseline_data.get(
            "configuration"
        )

        if not isinstance(baseline_configuration, dict):
            raise ValueError(
                "Baseline configuration is missing or invalid."
            )

        current_configuration = collect_security_configuration()

        results = compare_configurations(
            baseline_configuration,
            current_configuration
        )

        drift_count = sum(
            result["status"] != "NO CHANGE"
            for result in results
        )

        return {
            "success": True,
            "message": "Configuration comparison completed.",
            "baseline_created_at": baseline_data.get("created_at"),
            "drift_count": drift_count,
            "results": results
        }

    except Exception as error:
        return {
            "success": False,
            "message": str(error),
            "results": []
        }
