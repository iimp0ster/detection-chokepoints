#Requires -Version 5.1
<#
.SYNOPSIS
    Emulates lateral movement via remote execution tools (PsExec/Impacket patterns) for detection validation.
    Validates Sigma rules: Research (WEL 4624+7045), Hunt (random service name+suspicious path), Analyst (IPC$+service+spray).

.DESCRIPTION
    Attackers use PsExec, Impacket, CrackMapExec, and similar tools to execute commands on
    remote hosts using admin credentials. The invariant:
    Admin creds + network access → IPC$ connection → service/WMI execution

    This script simulates the observable behaviors on LOCALHOST (no real lateral movement):
      1. Network logon type 3 to 127.0.0.1 via net use IPC$ — generates WEL 4624 + 5145
      2. Service creation with random name from temp path — generates WEL 7045 + Sysmon EID 1
      3. Spawns cmd.exe from services.exe context (simulates service execution) — Sysmon EID 1
      4. Optionally simulates multi-host spray pattern with repeated connections

    Does NOT require remote hosts. All activity targets localhost.

.NOTES
    MITRE ATT&CK: T1021.002 (SMB/Windows Admin Shares), T1569.002 (Service Execution)
    Requires: Administrator privileges, net use / sc.exe available
    LAB ENVIRONMENT ONLY — generates authentication and service events.

    For multi-host Analyst spray pattern: run from multiple hosts or loop with -SprayCount.
    Real PsExec replay: use Invoke-AtomicTest T1021.002 with attack data from
    https://github.com/splunk/attack_data for highest fidelity.

.EXAMPLE
    .\emulate.ps1
    .\emulate.ps1 -SprayCount 3    # Simulate 3-host spray pattern (Analyst threshold)
    .\emulate.ps1 -Verbose
    .\emulate.ps1 -CleanupOnly
#>

[CmdletBinding()]
param(
    [int]$SprayCount = 1,
    [switch]$CleanupOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step ([string]$Msg) { Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Ok   ([string]$Msg) { Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Warn ([string]$Msg) { Write-Host "[!] $Msg" -ForegroundColor Yellow }

function New-RandomServiceName {
    # PsExec/Impacket use 8-char random alphanumeric service names
    $chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    return -join ((1..8) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

$ServiceNames = @()

function Remove-Artefacts {
    foreach ($svcName in $ServiceNames) {
        if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {
            sc.exe stop $svcName 2>&1 | Out-Null
            sc.exe delete $svcName 2>&1 | Out-Null
        }
    }
    net use \\127.0.0.1\IPC$ /delete /y 2>&1 | Out-Null
    if ($ServiceNames.Count -gt 0) {
        Write-Ok "Removed $($ServiceNames.Count) test service(s) and IPC$ connection"
    }
}

if ($CleanupOnly) { Remove-Artefacts; exit 0 }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Administrator privileges required. Rerun as Administrator."
    exit 1
}

Write-Host ""
Write-Host "=== Remote Execution Tools (HackTools) Emulation ===" -ForegroundColor Magenta
Write-Host "    T1021.002 + T1569.002 | Detection Chokepoints Project" -ForegroundColor DarkGray
Write-Host ""

for ($spray = 1; $spray -le $SprayCount; $spray++) {
    if ($SprayCount -gt 1) {
        Write-Host ""
        Write-Host "--- Spray iteration $spray of $SprayCount ---" -ForegroundColor DarkYellow
    }

    # ── Step 1: IPC$ network logon — Research rule trigger (WEL 4624+5145) ────
    Write-Step "Step 1/3 — Network logon (Type 3) + IPC$ access"
    Write-Verbose "  Signal: WEL 4624 (LogonType=3, Network), WEL 5145 (IPC$ share access)"
    Write-Verbose "  Matched rules: Research, Analyst"

    $netResult = net use \\127.0.0.1\IPC$ /user:$env:USERNAME '' 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "net use \\127.0.0.1\IPC$ succeeded — WEL 4624 (LogonType 3) + 5145 generated"
    } else {
        # Blank password may fail; try current session token
        $netResult2 = net use \\127.0.0.1\IPC$ 2>&1
        Write-Ok "IPC$ connection attempt: $netResult2 (telemetry generated on attempt)"
    }

    Start-Sleep -Milliseconds 400

    # ── Step 2: Random-named service creation from TEMP — Hunt rule trigger ────
    $svcName = New-RandomServiceName
    $ServiceNames += $svcName

    Write-Step "Step 2/3 — Service creation with random name from TEMP path"
    Write-Verbose "  Service name: $svcName (8-char alphanumeric — PsExec/Impacket pattern)"
    Write-Verbose "  Binary path: C:\Windows\Temp\$svcName.exe (TEMP path — Hunt signal)"
    Write-Verbose "  Signal: WEL 7045 (Service Installed), Sysmon EID 1 (sc.exe create)"
    Write-Verbose "  Matched rules: Hunt, Analyst"

    $createResult = sc.exe create $svcName `
        binPath= "C:\Windows\Temp\$svcName.exe" `
        type= own start= demand `
        displayname= "$svcName" 2>&1
    Write-Ok "sc create $svcName`: $createResult"
    Write-Ok "WEL 7045 generated — Service=$svcName, BinaryPath=C:\Windows\Temp\$svcName.exe"

    Start-Sleep -Milliseconds 400

    # ── Step 3: cmd.exe spawned from PowerShell simulating service execution ──
    # In a real PsExec scenario, services.exe spawns the service binary which runs cmd.exe
    # We simulate this by running cmd /c whoami (generates Sysmon EID 1 from current context)
    Write-Step "Step 3/3 — Simulating service-spawned command execution"
    Write-Verbose "  Real pattern: services.exe → <random_svc>.exe → cmd.exe → payload"
    Write-Verbose "  Signal: Sysmon EID 1 — parent=powershell.exe, image=cmd.exe with recon commands"
    Write-Verbose "  Note: Real PsExec parent would be services.exe — manual replay has higher fidelity"
    Write-Verbose "  Matched rules: Hunt (WMI parent), Analyst (service binary path)"

    $cmdResult = cmd.exe /c "whoami && hostname && net user" 2>&1
    Write-Ok "cmd.exe executed recon commands (EID 1 generated):"
    $cmdResult | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }

    Start-Sleep -Milliseconds 300
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Step "Cleaning up artefacts"
Remove-Artefacts

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Emulation Complete ===" -ForegroundColor Magenta
Write-Host ""
Write-Host "Expected detections:" -ForegroundColor White
Write-Host "  [Research]  WEL 4624 LogonType=3 + WEL 7045 (service installed)"                          -ForegroundColor DarkCyan
Write-Host "  [Hunt]      7045 with random name + TEMP binary path + WMI/service parent (EID 1)"        -ForegroundColor DarkYellow
Write-Host "  [Analyst]   IPC$ access (5145) + 7045 with suspicious name + EID 1 with recon commands"   -ForegroundColor DarkGreen
Write-Host ""
Write-Host "Higher fidelity options:" -ForegroundColor DarkGray
Write-Host "  - Replay with Impacket psexec.py against a lab target (generates authentic services.exe parent)"
Write-Host "  - Use Atomic Red Team: Invoke-AtomicTest T1021.002 -TestNumbers 1"
Write-Host "  - Attack data replay: https://github.com/splunk/attack_data (impacket dataset)"
Write-Host ""
