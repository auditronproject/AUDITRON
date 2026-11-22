
import json
import subprocess
import platform


def run_powershell(command):
    """
    Execute a read-only PowerShell command
    and return the result as Python data.
    """

    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command
            ],
            capture_output=True,
            text=True,
            timeout=20
        )

        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip() or "PowerShell command failed"
            )

        output = result.stdout.strip()

        if not output:
            return None

        return json.loads(output)

    except subprocess.TimeoutExpired:
        raise RuntimeError("PowerShell command timed out")

    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"Unable to read PowerShell JSON output: {error}"
        )


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

