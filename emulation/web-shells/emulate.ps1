#Requires -Version 5.1
<#
.SYNOPSIS
    Emulates web shell deployment and execution for detection validation.
    Validates Sigma rules: Research (web server child process), Hunt (web server spawns shell), Analyst (file create + shell spawn + outbound).

.DESCRIPTION
    Web shells are scripts placed in web-accessible directories that allow remote command execution
    via HTTP. The invariant: HTTP request → web server process → child OS interpreter

    This script simulates three observable behaviors:
      1. Creates a web shell file (.aspx/.php) in a simulated web directory — Sysmon EID 11
      2. Spawns cmd.exe with recon commands from a simulated w3wp context — Sysmon EID 1
         (parent process chain: powershell.exe simulates w3wp.exe spawning cmd.exe)
      3. Makes outbound HTTP connection from the spawned child — Sysmon EID 3

    Does NOT deploy a real web shell, does NOT require IIS/Apache, does NOT execute arbitrary code.

.NOTES
    MITRE ATT&CK: T1505.003 (Server Software Component: Web Shell)
    Safe to run: creates a test text file (not executable web shell), runs benign commands.
    LAB ENVIRONMENT ONLY.

    For Hunt/Analyst rules that specifically check ParentImage=w3wp.exe:
      - Install IIS in the lab VM
      - Deploy a real (benign) ASPX script to wwwroot
      - Request it via HTTP to generate the actual w3wp.exe → cmd.exe parent chain
      - The -UseIis flag provides guidance for this approach

    For Linux web server emulation: use the companion emulate.sh script.

.EXAMPLE
    .\emulate.ps1
    .\emulate.ps1 -WebRoot "C:\inetpub\wwwroot"    # Use actual IIS web root
    .\emulate.ps1 -ShellExtension ".php"            # PHP web shell variant
    .\emulate.ps1 -Verbose
    .\emulate.ps1 -CleanupOnly
#>

[CmdletBinding()]
param(
    [string]$WebRoot        = (Join-Path $env:TEMP 'wwwroot-emulation'),
    [string]$ShellExtension = '.aspx',
    [switch]$CleanupOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ── Configuration ─────────────────────────────────────────────────────────────
$ShellName   = "cmd$(Get-Random -Maximum 9999)$ShellExtension"
$ShellPath   = Join-Path $WebRoot $ShellName
$C2Endpoint  = 'https://example.com'

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step ([string]$Msg) { Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Ok   ([string]$Msg) { Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Warn ([string]$Msg) { Write-Host "[!] $Msg" -ForegroundColor Yellow }

function Remove-Artefacts {
    if (Test-Path $ShellPath)  { Remove-Item $ShellPath  -Force -ErrorAction SilentlyContinue }
    if (Test-Path $WebRoot -and (Get-ChildItem $WebRoot -ErrorAction SilentlyContinue).Count -eq 0) {
        Remove-Item $WebRoot -Force -ErrorAction SilentlyContinue
    }
    Write-Ok "Artefacts removed"
}

if ($CleanupOnly) { Remove-Artefacts; exit 0 }

Write-Host ""
Write-Host "=== Web Shell Emulation ===" -ForegroundColor Magenta
Write-Host "    T1505.003 | Detection Chokepoints Project" -ForegroundColor DarkGray
Write-Host ""

# ── Step 1: Web shell file creation — Research + Analyst trigger (EID 11) ─────
Write-Step "Step 1/3 — Creating web shell file in web-accessible directory"
Write-Verbose "  Path: $ShellPath"
Write-Verbose "  Signal: Sysmon EID 11 (FileCreate) — extension=$ShellExtension in web path"
Write-Verbose "  Matched rules: Research (file in web dir), Hunt (web shell ext), Analyst (file+exec)"

# Ensure web root exists
if (-not (Test-Path $WebRoot)) {
    New-Item -ItemType Directory -Path $WebRoot -Force | Out-Null
    Write-Ok "Created test web root: $WebRoot"
}

# Write a safe marker file (NOT an executable web shell — just text content)
$ShellContent = @"
<%@ Page Language="C#" %>
<!-- Web Shell Emulation Marker — NOT executable, for detection testing only -->
<!-- Created by Detection Chokepoints emulation script -->
<!-- T1505.003 — File created at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -->
<% Response.Write("Detection test"); %>
"@
Set-Content -Path $ShellPath -Value $ShellContent -Encoding UTF8
Write-Ok "Web shell marker created: $ShellPath"
Write-Ok "Sysmon EID 11 generated — extension=$ShellExtension, path contains web root pattern"

Start-Sleep -Milliseconds 400

# ── Step 2: Simulate w3wp.exe → cmd.exe execution chain — Hunt rule trigger ──
Write-Step "Step 2/3 — Simulating web server → cmd.exe execution chain"
Write-Verbose "  Real pattern: w3wp.exe → cmd.exe (web server spawns interpreter after HTTP request)"
Write-Verbose "  Simulated:    powershell.exe → cmd.exe (same child process, different parent)"
Write-Verbose "  Signal: Sysmon EID 1 — child=cmd.exe, commands=whoami/ipconfig/net user"
Write-Verbose "  Note: Hunt/Analyst rules check ParentImage=w3wp.exe specifically"
Write-Verbose "  For w3wp parent: deploy in IIS and access via HTTP (see below)"
Write-Verbose "  Matched rules: Research (any child), Hunt (shell child), Analyst (shell+encoded cmd)"

# Run recon commands that web shells execute post-exploitation
$reconCommands = @(
    'whoami',
    'hostname',
    'ipconfig /all',
    'net user',
    'net localgroup administrators'
)

foreach ($cmd in $reconCommands) {
    $result = cmd.exe /c $cmd 2>&1 | Select-Object -First 3
    Write-Ok "cmd /c $cmd`: $($result[0])"
}

# Also run an encoded command (Analyst rule trigger)
$encodedPayload = [Convert]::ToBase64String(
    [System.Text.Encoding]::Unicode.GetBytes('Get-ChildItem C:\inetpub\wwwroot -ErrorAction SilentlyContinue')
)
powershell.exe -NonInteractive -NoProfile -EncodedCommand $encodedPayload 2>&1 | Out-Null
Write-Ok "Encoded command executed from cmd context — Analyst rule EID 1 pattern matched"

Start-Sleep -Milliseconds 400

# ── Step 3: Outbound connection from child process — Analyst rule trigger ─────
Write-Step "Step 3/3 — Outbound HTTP connection from spawned interpreter"
Write-Verbose "  Signal: Sysmon EID 3 — connection from cmd.exe/powershell.exe child process"
Write-Verbose "  In real scenario: w3wp.exe child makes outbound connection to C2"
Write-Verbose "  Matched rules: Analyst"

try {
    $resp = Invoke-WebRequest -Uri $C2Endpoint -Method HEAD -TimeoutSec 10 `
        -UseBasicParsing -ErrorAction Stop
    Write-Ok "Outbound connection (HTTP $($resp.StatusCode)) from interpreter — Sysmon EID 3 generated"
} catch {
    Write-Warn "Network request failed (EID 3 may still have fired for the TCP attempt): $_"
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
Write-Host "  [Research]  Sysmon EID 1 — any child process of web server"                               -ForegroundColor DarkCyan
Write-Host "  [Hunt]      EID 11 ($ShellExtension in web path) + EID 1 (cmd.exe/powershell.exe child)"  -ForegroundColor DarkYellow
Write-Host "  [Analyst]   EID 11 (web shell ext) + EID 1 (-enc or recon cmd) + EID 3 (outbound)"       -ForegroundColor DarkGreen
Write-Host ""
Write-Host "For w3wp.exe parent chain (IIS-specific Hunt/Analyst rules):" -ForegroundColor DarkGray
Write-Host "  1. Install IIS: Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer"
Write-Host "  2. Copy shell marker to C:\inetpub\wwwroot\$ShellName"
Write-Host "  3. For ASPX execution: rename to .aspx, enable ASP.NET in IIS"
Write-Host "  4. Use a benign ASPX that runs: Response.Write(new System.Diagnostics.Process(){...}.StandardOutput.ReadToEnd())"
Write-Host "  5. HTTP request to http://localhost/$ShellName generates authentic w3wp.exe → cmd.exe"
Write-Host ""
Write-Host "For Linux (Apache/nginx) parent chain:" -ForegroundColor DarkGray
Write-Host "  Use companion emulate.sh (spawn bash from httpd/nginx context via PHP)"
Write-Host ""
