#Requires -Version 5.1
<#
.SYNOPSIS
    Emulates infostealer browser credential theft patterns for detection validation.
    Validates Sigma rules: Research (EID 10/11/4663), Hunt (EID 10 + DPAPI), Analyst (EID 10/11/3).

.DESCRIPTION
    Simulates the three behavioral steps common to all infostealer browser credential theft:
      1. Non-browser process opens Chrome Login Data (triggers EID 10 / 4663)
      2. DPAPI decryption attempt via CryptUnprotectData (triggers Hunt rule correlation)
      3. Outbound network connection from non-browser process (triggers Analyst rule)

    Does NOT steal actual credentials. Uses a scratch copy of Login Data opened read-only
    and makes a benign HTTPS request to example.com for the network telemetry trigger.

.NOTES
    MITRE ATT&CK: T1555.003 (Credentials from Web Browsers)
    Safe to run: no credentials are exfiltrated, no persistence is created.
    Tested on: Windows 10/11 with Sysmon v15+, WEL Security auditing enabled.

    LAB ENVIRONMENT ONLY — run in an isolated VM.
    Enable Object Access Auditing before testing the WEL EID 4663 signal:
      auditpol /set /subcategory:"File System" /success:enable /failure:enable

.EXAMPLE
    .\emulate.ps1
    .\emulate.ps1 -Verbose
    .\emulate.ps1 -SkipNetwork     # Skip the outbound connection step
    .\emulate.ps1 -CleanupOnly     # Remove artefacts from a previous run
#>

[CmdletBinding()]
param(
    [switch]$SkipNetwork,
    [switch]$CleanupOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Configuration ─────────────────────────────────────────────────────────────
$ChromeLoginDataPath = Join-Path $env:LOCALAPPDATA `
    'Google\Chrome\User Data\Default\Login Data'
$TempCopy   = Join-Path $env:TEMP "~cred_emu_$(Get-Random).db"
$C2Endpoint = 'https://example.com'   # benign destination — change to your lab listener

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step ([string]$Message) {
    Write-Host "[*] $Message" -ForegroundColor Cyan
}
function Write-Ok ([string]$Message) {
    Write-Host "[+] $Message" -ForegroundColor Green
}
function Write-Warn ([string]$Message) {
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Remove-Artefacts {
    if (Test-Path $TempCopy) {
        Remove-Item -Path $TempCopy -Force -ErrorAction SilentlyContinue
        Write-Ok "Removed temp file: $TempCopy"
    }
}

# ── Cleanup-only mode ─────────────────────────────────────────────────────────
if ($CleanupOnly) {
    Remove-Artefacts
    exit 0
}

# ── Pre-flight checks ─────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Browser Credential Theft Emulation ===" -ForegroundColor Magenta
Write-Host "    T1555.003 | Detection Chokepoints Project" -ForegroundColor DarkGray
Write-Host ""

if (-not (Test-Path $ChromeLoginDataPath)) {
    Write-Warn "Chrome Login Data not found at: $ChromeLoginDataPath"
    Write-Warn "Chrome must be installed and have been launched at least once."
    Write-Warn "Falling back to synthetic file for file-access telemetry only."
    $ChromeLoginDataPath = $null
}

# ── Step 1: File access — triggers Sysmon EID 10 and/or WEL 4663 ─────────────
Write-Step "Step 1/3 — Opening browser credential store (file access telemetry)"
Write-Verbose "  Target: $ChromeLoginDataPath"
Write-Verbose "  Signal: Sysmon EID 10 (ProcessAccess), WEL EID 4663 (Object Access)"
Write-Verbose "  Matched rules: Research, Analyst"

if ($ChromeLoginDataPath) {
    try {
        # Open the file read-only to trigger file-access audit events.
        # Chrome locks Login Data while running; we copy first (also an Analyst indicator).
        $fs = [System.IO.File]::Open(
            $ChromeLoginDataPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite
        )
        $buf = New-Object byte[] 4
        [void]$fs.Read($buf, 0, 4)   # read SQLite magic bytes only — no credential parsing
        $fs.Close()
        Write-Ok "File access completed (read 4 bytes — SQLite header only, no credentials parsed)"
    }
    catch [System.IO.IOException] {
        # Chrome is running and has an exclusive lock — copy approach instead
        Write-Warn "Chrome is running (file locked). Using file copy to trigger EID 11."
        Copy-Item -Path $ChromeLoginDataPath -Destination $TempCopy -ErrorAction SilentlyContinue
        Write-Ok "Copied Login Data to: $TempCopy"
        Write-Verbose "  Signal: Sysmon EID 11 (FileCreate) for temp copy path"
    }
} else {
    # Synthetic fallback: create a dummy file in TEMP to generate EID 11
    [System.IO.File]::WriteAllText($TempCopy, "SQLite format 3`0")
    Write-Ok "Created synthetic credential file at: $TempCopy"
}

Start-Sleep -Milliseconds 500

# ── Step 2: DPAPI decryption — triggers Hunt rule temporal correlation ─────────
Write-Step "Step 2/3 — Calling CryptUnprotectData (DPAPI decryption telemetry)"
Write-Verbose "  Signal: CryptUnprotectData call within 60s of EID 10"
Write-Verbose "  Matched rules: Hunt"

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public class Dpapi {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DATA_BLOB {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn,
        StringBuilder szDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        ref DATA_BLOB pDataOut);

    public static bool TestDpapi() {
        // Encrypt a benign string, then decrypt — exercises the CryptUnprotectData API path
        byte[] plain = Encoding.UTF8.GetBytes("detection-chokepoints-emulation-test");
        byte[] encrypted = System.Security.Cryptography.ProtectedData.Protect(
            plain, null, System.Security.Cryptography.DataProtectionScope.CurrentUser);

        DATA_BLOB inBlob  = new DATA_BLOB();
        DATA_BLOB outBlob = new DATA_BLOB();
        inBlob.cbData = encrypted.Length;
        inBlob.pbData = Marshal.AllocHGlobal(encrypted.Length);
        Marshal.Copy(encrypted, 0, inBlob.pbData, encrypted.Length);

        bool result = CryptUnprotectData(ref inBlob, null, IntPtr.Zero,
                                          IntPtr.Zero, IntPtr.Zero, 0, ref outBlob);
        Marshal.FreeHGlobal(inBlob.pbData);
        if (result) Marshal.FreeHGlobal(outBlob.pbData);
        return result;
    }
}
'@ -ReferencedAssemblies 'System.Security'

try {
    $result = [Dpapi]::TestDpapi()
    if ($result) {
        Write-Ok "CryptUnprotectData called successfully (benign test data decrypted)"
    } else {
        Write-Warn "CryptUnprotectData returned false — API monitoring telemetry may still fire"
    }
} catch {
    Write-Warn "DPAPI call skipped: $_"
}

Start-Sleep -Milliseconds 500

# ── Step 3: Network connection — triggers Analyst rule ────────────────────────
if (-not $SkipNetwork) {
    Write-Step "Step 3/3 — Making outbound connection (network exfiltration telemetry)"
    Write-Verbose "  Destination: $C2Endpoint"
    Write-Verbose "  Signal: Sysmon EID 3 (NetworkConnect) from non-browser process"
    Write-Verbose "  Matched rules: Analyst"

    try {
        $response = Invoke-WebRequest -Uri $C2Endpoint -Method HEAD `
            -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
        Write-Ok "Network connection completed (HTTP $($response.StatusCode) from $C2Endpoint)"
    } catch {
        Write-Warn "Network request failed (connection telemetry may still have been generated): $_"
    }
} else {
    Write-Warn "Step 3 skipped (-SkipNetwork flag set)"
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
Write-Host "  [Research]  Sysmon EID 10/11 or WEL EID 4663 — non-browser file access" -ForegroundColor DarkCyan
Write-Host "  [Hunt]      EID 10 + CryptUnprotectData within 60 seconds"               -ForegroundColor DarkYellow
Write-Host "  [Analyst]   EID 10/11 + Sysmon EID 3 (outbound connection)"              -ForegroundColor DarkGreen
Write-Host ""
Write-Host "If no alerts fired, verify:" -ForegroundColor DarkGray
Write-Host "  - Sysmon is running with a config that captures EID 3/8/10/11"
Write-Host "  - Object Access auditing is enabled (auditpol) for EID 4663"
Write-Host "  - Sigma rules are deployed and log sources are ingested"
Write-Host ""
