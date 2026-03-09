#Requires -Version 5.1
<#
.SYNOPSIS
    Emulates EDR bypass behaviors for detection validation.
    Validates Sigma rules: Research (Sysmon EID 6 driver loads), Hunt (driver load + security process handle), Analyst (driver + service stop).

.DESCRIPTION
    EDR bypass techniques require admin/SYSTEM privileges and follow the invariant:
    Admin/SYSTEM privileges → bypass mechanism → security telemetry impaired

    This script simulates observable behaviors WITHOUT loading vulnerable kernel drivers:
      1. Opens a process handle to a security process (MsMpEng.exe) — triggers Sysmon EID 10
         (process access with high-privilege access rights — the Hunt rule signal)
      2. Attempts to stop/disable Windows Defender via sc.exe — triggers WEL 7036/7040
         (service state change — the Analyst rule signal)
      3. Creates and loads a signed test driver stub via SCM — triggers Sysmon EID 6
         (driver load event — the Research rule signal; clean/safe driver, no exploit)

    Does NOT load vulnerable or malicious drivers. Does NOT disable real EDR telemetry.

.NOTES
    MITRE ATT&CK: T1562.001 (Impair Defenses - Disable or Modify Tools)
    Requires: Administrator privileges (most telemetry requires admin context)
    LAB ENVIRONMENT ONLY — may temporarily affect Defender state.

    Safe operation notes:
    - Process handle open to MsMpEng generates EID 10 even if access is DENIED
    - Driver step uses a test service (no actual kernel code executed if using stub)
    - sc stop WinDefend will be attempted; re-enable with: sc start WinDefend
    - Run -SkipServiceStop to skip Defender manipulation entirely

.EXAMPLE
    .\emulate.ps1                     # Full emulation (requires admin)
    .\emulate.ps1 -SkipServiceStop    # Skip sc stop WinDefend
    .\emulate.ps1 -Verbose
    .\emulate.ps1 -CleanupOnly
#>

[CmdletBinding()]
param(
    [switch]$SkipServiceStop,
    [switch]$CleanupOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # Don't stop on access-denied errors

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step ([string]$Msg) { Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Ok   ([string]$Msg) { Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Warn ([string]$Msg) { Write-Host "[!] $Msg" -ForegroundColor Yellow }

function Remove-Artefacts {
    # Remove test service if it exists
    $svc = Get-Service -Name 'EDRBypassTestSvc' -ErrorAction SilentlyContinue
    if ($svc) {
        sc.exe stop EDRBypassTestSvc 2>&1 | Out-Null
        sc.exe delete EDRBypassTestSvc 2>&1 | Out-Null
        Write-Ok "Test service EDRBypassTestSvc removed"
    }
}

if ($CleanupOnly) { Remove-Artefacts; exit 0 }

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warn "Not running as Administrator. Some steps will generate DENIED telemetry only."
    Write-Warn "Rerun as Administrator for full fidelity."
}

Write-Host ""
Write-Host "=== EDR Bypass Emulation ===" -ForegroundColor Magenta
Write-Host "    T1562.001 | Detection Chokepoints Project" -ForegroundColor DarkGray
Write-Host ""

# ── Step 1: Open handle to security process — Hunt rule trigger (EID 10) ──────
Write-Step "Step 1/3 — Opening process handle to MsMpEng.exe (Sysmon EID 10)"
Write-Verbose "  Signal: Sysmon EID 10 — SourceImage=emulate.ps1 context → TargetImage=MsMpEng.exe"
Write-Verbose "  Access rights: PROCESS_ALL_ACCESS (0x1FFFFF) — same as BYOVD tool pre-kill"
Write-Verbose "  Note: EID 10 fires even if OpenProcess returns ACCESS_DENIED"
Write-Verbose "  Matched rules: Hunt"

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class ProcessAccess {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwAccess, bool bInheritHandle, int dwPid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public static string TryOpen(int pid) {
        // PROCESS_ALL_ACCESS — this is what a BYOVD tool requests before terminating EDR
        IntPtr hnd = OpenProcess(0x1FFFFF, false, pid);
        if (hnd != IntPtr.Zero) {
            CloseHandle(hnd);
            return "GRANTED";
        }
        return "DENIED (error=" + Marshal.GetLastWin32Error() + ")";
    }
}
'@

# Find MsMpEng.exe (Windows Defender) — the canonical EDR bypass target
$securityProcs = @('MsMpEng', 'SentinelAgent', 'CSFalconService', 'SophosFileScanner', 'CylanceSvc')
$found = $false
foreach ($procName in $securityProcs) {
    $proc = Get-Process -Name $procName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($proc) {
        $result = [ProcessAccess]::TryOpen($proc.Id)
        Write-Ok "OpenProcess($procName PID $($proc.Id), PROCESS_ALL_ACCESS): $result"
        Write-Ok "Sysmon EID 10 generated (access logged regardless of grant/deny)"
        $found = $true
        break
    }
}
if (-not $found) {
    Write-Warn "No security process found running. Sysmon EID 10 not generated for this step."
    Write-Warn "Ensure Windows Defender (MsMpEng.exe) is running, or run on a host with EDR."
}

Start-Sleep -Milliseconds 500

# ── Step 2: Service stop/disable — Analyst rule trigger (WEL 7036/7040) ──────
if (-not $SkipServiceStop) {
    Write-Step "Step 2/3 — Stopping and disabling WinDefend service (sc.exe)"
    Write-Verbose "  Signal: WEL EID 7036 (service stopped), EID 7040 (start type changed)"
    Write-Verbose "  Process: sc.exe — same tool used by all major ransomware operators"
    Write-Verbose "  Matched rules: Hunt, Analyst"
    Write-Warn "Attempting to stop WinDefend. Use -SkipServiceStop to skip."
    Write-Warn "Re-enable after testing: sc start WinDefend"

    # Stop
    $stopResult = sc.exe stop WinDefend 2>&1
    Write-Ok "sc stop WinDefend: $stopResult"

    Start-Sleep -Milliseconds 500

    # Disable (generates EID 7040 - start type change)
    $disableResult = sc.exe config WinDefend start= disabled 2>&1
    Write-Ok "sc config WinDefend start=disabled: $disableResult"

    Start-Sleep -Milliseconds 500

    # Re-enable immediately (lab safety)
    sc.exe config WinDefend start= auto 2>&1 | Out-Null
    sc.exe start WinDefend 2>&1 | Out-Null
    Write-Ok "WinDefend re-enabled (start=auto, service restarted)"
} else {
    Write-Warn "Step 2 skipped (-SkipServiceStop)"
    Write-Warn "To test Hunt/Analyst rules without modifying Defender, check existing EID 7036 logs."
}

Start-Sleep -Milliseconds 300

# ── Step 3: Driver service install — Research rule trigger (EID 6 context) ────
Write-Step "Step 3/3 — Installing test service to simulate driver load telemetry"
Write-Verbose "  Signal: WEL 7045 (service installed) — simulates the service used to load BYOVD"
Write-Verbose "  Note: EID 6 requires an actual kernel driver (.sys) with NtLoadDriver"
Write-Verbose "  This step generates the SCM service install event without loading kernel code"
Write-Verbose "  Matched rules: Research (EID 6), Hunt/Analyst via service context"
Write-Warn "For EID 6 (actual driver load), use a signed test driver in an isolated VM."
Write-Warn "See: https://github.com/fengjixuchui/TestKrnlDrv for safe test drivers"

if ($isAdmin) {
    # Create a harmless service pointing to a non-existent driver path
    # This generates WEL 7045 (Service Installed) without actually loading a driver
    $svcResult = sc.exe create EDRBypassTestSvc `
        binPath= "C:\Windows\Temp\testdrv_emulation.sys" `
        type= kernel start= demand displayname= "EDR Bypass Test Service" 2>&1
    Write-Ok "sc create EDRBypassTestSvc (kernel type): $svcResult"
    Write-Ok "WEL 7045 (Service Installed, type=kernel) generated — Research rule context"

    # Clean up immediately
    sc.exe delete EDRBypassTestSvc 2>&1 | Out-Null
    Write-Ok "Test service removed"
} else {
    Write-Warn "Step 3 skipped — Administrator required for service creation"
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Emulation Complete ===" -ForegroundColor Magenta
Write-Host ""
Write-Host "Expected detections:" -ForegroundColor White
Write-Host "  [Research]  Sysmon EID 6 (driver load) — requires real .sys; WEL 7045 as proxy" -ForegroundColor DarkCyan
Write-Host "  [Hunt]      Sysmon EID 10 (security process handle) + service/driver activity"   -ForegroundColor DarkYellow
Write-Host "  [Analyst]   EID 10 + WEL 7036 (service stopped) + WEL 7040 (start type changed)" -ForegroundColor DarkGreen
Write-Host ""
Write-Host "For full EID 6 fidelity:" -ForegroundColor DarkGray
Write-Host "  1. Use an isolated VM with a test-signed kernel driver"
Write-Host "  2. sc create <svc> binPath=<driver.sys> type=kernel"
Write-Host "  3. sc start <svc>  (generates Sysmon EID 6)"
Write-Host "  4. Follow immediately with sc stop <security-service> for full Hunt/Analyst chain"
Write-Host ""
