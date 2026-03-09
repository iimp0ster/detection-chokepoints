#Requires -Version 5.1
<#
.SYNOPSIS
    Emulates renamed RMM tool execution for detection validation.
    Validates Sigma rules: Research (RMM process name), Hunt (browser-downloaded+renamed binary), Analyst (campaign name+outbound).

.DESCRIPTION
    Threat actors rename legitimate RMM tools (AnyDesk, ScreenConnect, etc.) to social engineering
    filenames (tax-2024.exe, invoice.exe) and deliver them via browser. The invariant:
    browser download → renamed binary → user execution → outbound RMM connection

    This script simulates three observable behaviors:
      1. Places a renamed binary (signed, legitimate Windows binary) in %Downloads% or %TEMP%
         as if downloaded by a browser — triggers Research/Hunt rules on file metadata mismatch
      2. Executes the renamed binary briefly — generates Sysmon EID 1 with OriginalFilename mismatch
      3. Makes outbound TCP connection to an RMM relay port — triggers Analyst rule

    Does NOT install RMM software or establish real remote access.

.NOTES
    MITRE ATT&CK: T1219.002 (Remote Access Tools)
    Safe to run: uses a benign signed Windows binary (notepad.exe) as the "RMM tool" stand-in.
    LAB ENVIRONMENT ONLY.

    For higher-fidelity testing: replace $RmmSourceBinary with the actual AnyDesk.exe or
    ScreenConnect binary. The OriginalFilename metadata check will then produce a true-positive
    signal (OriginalFilename=AnyDesk.exe vs. ProcessName=tax-document-2024.exe).

.EXAMPLE
    .\emulate.ps1
    .\emulate.ps1 -CampaignName "W2-document-2025"
    .\emulate.ps1 -Verbose
    .\emulate.ps1 -CleanupOnly
#>

[CmdletBinding()]
param(
    [string]$CampaignName  = 'tax-document-2024',
    [switch]$CleanupOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Configuration ─────────────────────────────────────────────────────────────
# Use a legitimate signed Windows binary as the "RMM" stand-in for safe emulation.
# In a real engagement, replace this with actual AnyDesk.exe for full fidelity.
$RmmSourceBinary = Join-Path $env:WINDIR 'System32\notepad.exe'
$DownloadsPath   = Join-Path $env:USERPROFILE 'Downloads'
$RenamedBinary   = Join-Path $DownloadsPath "$CampaignName.exe"
$RmmPort         = 443    # AnyDesk relay uses 443/80/6568; use 443 for lab (less likely blocked)
$RmmHost         = 'relay.anydesk.com'

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step ([string]$Msg) { Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Ok   ([string]$Msg) { Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Warn ([string]$Msg) { Write-Host "[!] $Msg" -ForegroundColor Yellow }

function Remove-Artefacts {
    if (Test-Path $RenamedBinary) {
        Remove-Item $RenamedBinary -Force -ErrorAction SilentlyContinue
        Write-Ok "Removed: $RenamedBinary"
    }
}

if ($CleanupOnly) { Remove-Artefacts; exit 0 }

Write-Host ""
Write-Host "=== Renamed RMM Tool Emulation ===" -ForegroundColor Magenta
Write-Host "    T1219.002 | Detection Chokepoints Project" -ForegroundColor DarkGray
Write-Host ""

# ── Step 1: File drop — simulate browser download of renamed binary ────────────
Write-Step "Step 1/3 — Dropping renamed binary to Downloads (browser-download simulation)"
Write-Verbose "  Source binary: $RmmSourceBinary"
Write-Verbose "  Renamed to:    $RenamedBinary"
Write-Verbose "  Signal: Sysmon EID 11 (FileCreate) in Downloads path"
Write-Verbose "  Matched rules: Hunt, Analyst"

# Ensure Downloads directory exists
if (-not (Test-Path $DownloadsPath)) {
    New-Item -ItemType Directory -Path $DownloadsPath -Force | Out-Null
}

Copy-Item -Path $RmmSourceBinary -Destination $RenamedBinary -Force
Write-Ok "Binary copied to: $RenamedBinary"
Write-Ok "File name: $CampaignName.exe (social engineering name)"

# Report OriginalFilename vs current name mismatch (the key detection signal)
try {
    $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($RenamedBinary)
    Write-Host ""
    Write-Host "  File metadata (key detection signal):" -ForegroundColor White
    Write-Host "    CurrentName:       $CampaignName.exe" -ForegroundColor DarkGray
    Write-Host "    OriginalFilename:  $($versionInfo.OriginalFilename)" -ForegroundColor DarkGray
    Write-Host "    ProductName:       $($versionInfo.ProductName)" -ForegroundColor DarkGray
    Write-Host "    FileDescription:   $($versionInfo.FileDescription)" -ForegroundColor DarkGray
    if ($versionInfo.OriginalFilename -and $versionInfo.OriginalFilename -ne "$CampaignName.exe") {
        Write-Ok "MISMATCH CONFIRMED: OriginalFilename != current name — Analyst rule will fire"
    }
} catch {
    Write-Warn "Could not read version info: $_"
}

Start-Sleep -Milliseconds 500

# ── Step 2: Execute renamed binary — triggers Sysmon EID 1 ────────────────────
Write-Step "Step 2/3 — Executing renamed binary (brief run to generate process telemetry)"
Write-Verbose "  Signal: Sysmon EID 1 — Image=$CampaignName.exe, OriginalFilename=notepad.exe"
Write-Verbose "  Note: In real scenario, OriginalFilename=AnyDesk.exe vs. CurrentName=$CampaignName.exe"
Write-Verbose "  Matched rules: Research, Hunt, Analyst"

try {
    # Start notepad briefly then kill it — generates EID 1 with the renamed image path
    $proc = Start-Process -FilePath $RenamedBinary -PassThru -ErrorAction Stop
    Start-Sleep -Milliseconds 800
    if (-not $proc.HasExited) {
        $proc.Kill()
        $proc.WaitForExit(2000) | Out-Null
    }
    Write-Ok "Renamed binary executed (PID $($proc.Id)) and terminated — Sysmon EID 1 generated"
} catch {
    Write-Warn "Binary execution failed: $_"
}

Start-Sleep -Milliseconds 300

# ── Step 3: Outbound connection to RMM relay — Analyst rule trigger ────────────
Write-Step "Step 3/3 — Outbound connection to RMM relay port (network telemetry)"
Write-Verbose "  Target: $RmmHost`:$RmmPort"
Write-Verbose "  Signal: Sysmon EID 3 — non-browser process connecting to RMM infrastructure"
Write-Verbose "  Matched rules: Analyst"
Write-Warn "Note: real AnyDesk connects to relay.anydesk.com:443/80/6568; using TCP connect test only"

try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $async = $tcp.BeginConnect($RmmHost, $RmmPort, $null, $null)
    $connected = $async.AsyncWaitHandle.WaitOne(5000, $false)
    if ($connected) {
        $tcp.EndConnect($async)
        Write-Ok "TCP connection to $RmmHost`:$RmmPort succeeded — Sysmon EID 3 generated"
    } else {
        Write-Warn "TCP connect timed out (connection attempt still generated EID 3)"
    }
    $tcp.Close()
} catch {
    Write-Warn "Network connection failed (telemetry may still have fired): $_"
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
Write-Host "  [Research]  Sysmon EID 1 — process name matches known RMM tool OR OriginalFilename" -ForegroundColor DarkCyan
Write-Host "  [Hunt]      EID 11 (file in Downloads) + EID 1 (execution within 5 min)"            -ForegroundColor DarkYellow
Write-Host "  [Analyst]   Campaign filename + OriginalFilename mismatch + EID 3 to RMM infra"     -ForegroundColor DarkGreen
Write-Host ""
Write-Host "Higher fidelity: replace source binary with actual AnyDesk.exe for real metadata" -ForegroundColor DarkGray
Write-Host "  OriginalFilename=AnyDesk.exe vs. CurrentName=$CampaignName.exe is the key signal" -ForegroundColor DarkGray
Write-Host ""
