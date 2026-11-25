
import json
import subprocess
import platform
import threading

_PROCESS_LOCK = threading.Lock()
_ACTIVE_PROCESSES = set()
_ABORT_REQUESTED = threading.Event()


def abort_active_collection():
    """
    Emergency Kill Switch hook: set abort flag and terminate
    any running read-only PowerShell collection subprocesses.
    """

    _ABORT_REQUESTED.set()

    with _PROCESS_LOCK:
        active = list(_ACTIVE_PROCESSES)

    terminated_count = 0

    for proc in active:
        try:
            if proc.poll() is None:
                proc.terminate()
                terminated_count += 1
        except OSError:
            pass

    return terminated_count


def reset_abort_state():
    """
    Clear the abort flag when the user releases the kill switch.
    """

    _ABORT_REQUESTED.clear()


def run_powershell(command):
    """
    Execute a read-only PowerShell command
    and return the result as Python data.
    """

    if _ABORT_REQUESTED.is_set():
        raise RuntimeError(
            "Operation aborted by Emergency Kill Switch."
        )

    proc = None

    try:
        proc = subprocess.Popen(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        with _PROCESS_LOCK:
            _ACTIVE_PROCESSES.add(proc)

        stdout, stderr = proc.communicate(timeout=20)

        if _ABORT_REQUESTED.is_set():
            raise RuntimeError(
                "Operation aborted by Emergency Kill Switch."
            )

        if proc.returncode != 0:
            raise RuntimeError(
                stderr.strip() or "PowerShell command failed"
            )

        output = stdout.strip()

        if not output:
            return None

        return json.loads(output)

    except subprocess.TimeoutExpired:
        if proc is not None:
            proc.kill()
        raise RuntimeError("PowerShell command timed out")

    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"Unable to read PowerShell JSON output: {error}"
        )

    finally:
        if proc is not None:
            with _PROCESS_LOCK:
                _ACTIVE_PROCESSES.discard(proc)


def collect_firewall_status():
    command = """
    $ErrorActionPreference = 'Stop'

    $profiles = Get-NetFirewallProfile |
        Select-Object @{
            Name = 'Name'
            Expression = { [string]$_.Name }
        }, @{
            Name = 'Enabled'
            Expression = { [bool]$_.Enabled }
        }

    $profiles | ConvertTo-Json -Compress
    """

    return run_powershell(command)


def collect_defender_status():
    command = """
    $ErrorActionPreference = 'Stop'

    Get-MpComputerStatus |
        Select-Object @{
            Name = 'AMServiceEnabled'
            Expression = { [bool]$_.AMServiceEnabled }
        }, @{
            Name = 'AntivirusEnabled'
            Expression = { [bool]$_.AntivirusEnabled }
        }, @{
            Name = 'RealTimeProtectionEnabled'
            Expression = { [bool]$_.RealTimeProtectionEnabled }
        } |
        ConvertTo-Json -Compress
    """

    return run_powershell(command)

def collect_antivirus_providers():
    command = """
    $ErrorActionPreference = 'Stop'

    Get-CimInstance `
        -Namespace root/SecurityCenter2 `
        -ClassName AntivirusProduct |
        Select-Object displayName, productState |
        ConvertTo-Json -Compress
    """

    return run_powershell(command)

def collect_smb1_status():
    command = """
    $ErrorActionPreference = 'Stop'

    Get-SmbServerConfiguration |
        Select-Object @{
            Name = 'EnableSMB1Protocol'
            Expression = { [bool]$_.EnableSMB1Protocol }
        } |
        ConvertTo-Json -Compress
    """

    return run_powershell(command)


def collect_guest_account_status():
    # The built-in Guest account always has a SID ending in -501,
    # so it is still found if someone renames it.
    command = """
    $ErrorActionPreference = 'Stop'

    Get-LocalUser |
        Where-Object { $_.SID.Value -like 'S-1-5-21-*-501' } |
        Select-Object @{
            Name = 'Enabled'
            Expression = { [bool]$_.Enabled }
        } |
        ConvertTo-Json -Compress
    """

    return run_powershell(command)


def collect_uac_status():
    # EnableLUA is not cast, so a missing value stays null
    # instead of being reported as disabled.
    command = """
    $ErrorActionPreference = 'Stop'

    Get-ItemProperty `
        -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' |
        Select-Object EnableLUA |
        ConvertTo-Json -Compress
    """

    return run_powershell(command)


def collect_system_info():
    return {
        "operating_system": platform.system(),
        "version": platform.version(),
        "computer_name": platform.node()
    }


if __name__ == "__main__":
    print("FIREWALL DATA:")
    print(collect_firewall_status())

    print("\nDEFENDER DATA:")
    print(collect_defender_status())

    print("\nSMBv1 DATA:")
    print(collect_smb1_status())

    print("\nANTIVIRUS PROVIDERS:")
    print(collect_antivirus_providers())

    print("\nGUEST ACCOUNT DATA:")
    print(collect_guest_account_status())

    print("\nUAC DATA:")
    print(collect_uac_status())
