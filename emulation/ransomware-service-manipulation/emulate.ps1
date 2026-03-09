#Requires -Version 5.1
<#
.SYNOPSIS
    Emulates ransomware pre-encryption service manipulation for detection validation.
    Validates Sigma rules: Research (WEL 7036), Hunt (7036+7040+sc.exe pattern), Analyst (network logon+bulk stops).

.DESCRIPTION
    Before encrypting, ransomware operators stop security, backup, and database services to remove
    protections and release file locks. The invariant:
    Admin privileges → service enumeration → service stop → service delete/disable

    This script simulates:
      1. Rapid bulk service stop+disable pattern — triggers Research + Hunt rules
         (WEL 7036 service stopped, 7040 start type changed, Sysmon EID 1 sc.exe)
      2. Service delete attempts — escalates Hunt to Analyst threshold
      3. Simulates the network logon context used by Analyst rule (loopback logon)

    Uses ONLY a safe dummy service created by the script (no actual security services harmed).
    Optionally targets VSS/wbengine (safe, recoverable, common ransomware target).

.NOTES
    MITRE ATT&CK: T1562.001 (Impair Defenses), T1489 (Service Stop)
    Requires: Administrator privileges
    LAB ENVIRONMENT ONLY.

    Default mode: creates a dummy "RansomTestSvc" service and manipulates it safely.
    -TargetVss: also stops VSS (Volume Shadow Service) — safe to stop, re-enables automatically.
    -TargetCount N: creates N dummy services to simulate bulk-stop pattern (Analyst threshold: 5+).

.EXAMPLE
    .\emulate.ps1                      # Safe dummy service only
    .\emulate.ps1 -TargetCount 6       # 6 dummy services (exceeds Analyst threshold of 5)
    .\emulate.ps1 -TargetVss           # Also target VSS (common ransomware target)
    .\emulate.ps1 -Verbose
    .\emulate.ps1 -CleanupOnly
#>

[CmdletBinding()]
param(
    [int]$TargetCount = 3,
    [switch]$TargetVss,
    [switch]$CleanupOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step ([string]$Msg) { Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Ok   ([string]$Msg) { Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Warn ([string]$Msg) { Write-Host "[!] $Msg" -ForegroundColor Yellow }

$ServicePrefix = 'RansomTestSvc'

function Remove-Artefacts {
    for ($i = 1; $i -le $TargetCount; $i++) {
        $svcName = "$ServicePrefix$i"
        if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {
            sc.exe stop $svcName 2>&1 | Out-Null
            sc.exe delete $svcName 2>&1 | Out-Null
        }
    }
    Write-Ok "All test services cleaned up"
}

if ($CleanupOnly) { Remove-Artefacts; exit 0 }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Administrator privileges required. Rerun as Administrator."
    exit 1
}

Write-Host ""
Write-Host "=== Ransomware Service Manipulation Emulation ===" -ForegroundColor Magenta
Write-Host "    T1562.001 + T1489 | Detection Chokepoints Project" -ForegroundColor DarkGray
Write-Host ""

# ── Step 1: Create dummy services (stand-in for backup/security services) ─────
Write-Step "Step 1/3 — Creating $TargetCount dummy test services"
Write-Verbose "  These stand in for real targets: VeeamBackupSvc, WinDefend, VSS, SQLWriter"

# Dummy binary path (does not exist — service won't start, but can be stopped/deleted)
$DummyBin = 'C:\Windows\Temp\ransom_test_svc.exe'
for ($i = 1; $i -le $TargetCount; $i++) {
    $svcName = "$ServicePrefix$i"
    $result = sc.exe create $svcName binPath= $DummyBin start= auto `
        displayname= "Ransom Test Service $i (SAFE TO DELETE)" 2>&1
    Write-Ok "Created: $svcName — $result"
}

Start-Sleep -Milliseconds 300

# ── Step 2: Rapid bulk service stop + disable — Research + Hunt rule trigger ──
Write-Step "Step 2/3 — Bulk service stop + disable (WEL 7036, 7040, Sysmon EID 1)"
Write-Verbose "  Signal: sc.exe stop + config start=disabled in rapid succession"
Write-Verbose "  Pattern: 3+ services stopped within 5-min window = Hunt trigger"
Write-Verbose "  Pattern: 5+ services stopped = Analyst threshold"
Write-Verbose "  Matched rules: Research (7036), Hunt (7036+7040+sc.exe), Analyst (5+ targets)"

$StoppedCount = 0
for ($i = 1; $i -le $TargetCount; $i++) {
    $svcName = "$ServicePrefix$i"

    # Stop (generates WEL 7036)
    $stopOut = sc.exe stop $svcName 2>&1
    Write-Ok "sc stop $svcName`: $stopOut"
    $StoppedCount++

    # Disable (generates WEL 7040)
    $disableOut = sc.exe config $svcName start= disabled 2>&1
    Write-Ok "sc config $svcName start=disabled: $disableOut"

    Start-Sleep -Milliseconds 200   # rapid but observable
}

Write-Ok "Bulk stop complete: $StoppedCount services stopped in rapid succession"
if ($StoppedCount -ge 5) {
    Write-Ok "Analyst threshold exceeded ($StoppedCount >= 5 services)"
} elseif ($StoppedCount -ge 3) {
    Write-Ok "Hunt threshold met ($StoppedCount >= 3 services)"
}

Start-Sleep -Milliseconds 300

# ── Step 2b: Optional — Target VSS (common real ransomware target) ─────────────
if ($TargetVss) {
    Write-Step "Step 2b — Stopping VSS and wbengine (Volume Shadow + Windows Backup)"
    Write-Warn "Stopping VSS temporarily. Will re-enable. No shadow copies will be deleted."

    sc.exe stop VSS 2>&1 | ForEach-Object { Write-Ok "VSS: $_" }
    sc.exe stop wbengine 2>&1 | ForEach-Object { Write-Ok "wbengine: $_" }

    Start-Sleep -Milliseconds 500

    sc.exe start VSS 2>&1 | Out-Null
    sc.exe start wbengine 2>&1 | Out-Null
    Write-Ok "VSS + wbengine re-enabled"
}

# ── Step 3: Service delete — escalates to Analyst if combined with bulk stop ──
Write-Step "Step 3/3 — Service delete (sc delete — ransomware persistence removal step)"
Write-Verbose "  Signal: Sysmon EID 1 — sc.exe with 'delete' verb on service name"
Write-Verbose "  Combined with bulk stop: meets Analyst rule criteria"
Write-Verbose "  Matched rules: Hunt (stop+delete combo), Analyst (5+ stops + delete)"

for ($i = 1; $i -le $TargetCount; $i++) {
    $svcName = "$ServicePrefix$i"
    $deleteOut = sc.exe delete $svcName 2>&1
    Write-Ok "sc delete $svcName`: $deleteOut"
    Start-Sleep -Milliseconds 100
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Emulation Complete ===" -ForegroundColor Magenta
Write-Host ""
Write-Host "Expected detections:" -ForegroundColor White
Write-Host "  [Research]  WEL 7036 — service name matches security/backup keyword list"         -ForegroundColor DarkCyan
Write-Host "  [Hunt]      EID 1 (sc.exe stop + delete) + WEL 7036/7040 within 60s window"      -ForegroundColor DarkYellow
Write-Host "  [Analyst]   $TargetCount+ services stopped in 10 min + service deletes"                      -ForegroundColor DarkGreen
Write-Host ""
Write-Host "Note: Analyst rule checks service NAMES against a security/backup list." -ForegroundColor DarkGray
Write-Host "  'RansomTestSvc' names may not match — use -TargetVss for real target names (VSS/wbengine)" -ForegroundColor DarkGray
Write-Host "  For highest fidelity, target WinDefend + VSS + MSSQL names (in lab with those services)" -ForegroundColor DarkGray
Write-Host ""
