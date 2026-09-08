#Requires -Version 5.1
# MITRE ATT&CK: T1053.005 — Scheduled Task/Job: Scheduled Task
# Registers inert scheduled-task shapes used to validate Event 4698 collection and
# the Research, Hunt, and Analyst rules. Task actions are never started.

[CmdletBinding()]
param(
    [switch]$CleanupOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Suffix = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$TaskNames = @(
    "TIC-System-Control-$Suffix",
    "TIC-AppData-Logon-$Suffix",
    "TempLogA-$Suffix",
    "BackupCheck-$Suffix",
    "Windows\ApplicationData\DsSvcCleanup-$Suffix",
    "WindowsConnSvc-$Suffix",
    "INetHealth-$Suffix"
)

function Remove-LabTasks {
    foreach ($TaskName in $TaskNames) {
        & "$env:SystemRoot\System32\schtasks.exe" /Delete /TN $TaskName /F 2>$null | Out-Null
    }
}

if ($CleanupOnly) {
    Remove-LabTasks
    return
}

Write-Host '=== Scheduled Task Chokepoint Emulation ===' -ForegroundColor Magenta
Write-Host 'Registers seven inert task definitions. No task action is executed.' -ForegroundColor DarkGray

try {
    $Definitions = @(
        @{
            Name = $TaskNames[0]; Schedule = 'ONSTART'
            Action = "$env:SystemRoot\System32\wevtutil.exe gli System /c:1"
        },
        @{
            Name = $TaskNames[1]; Schedule = 'ONLOGON'
            Action = "$env:APPDATA\TIC\updater.exe --check"
        },
        @{
            Name = $TaskNames[2]; Schedule = 'DAILY'; Start = '13:00'
            Action = "$env:APPDATA\WPy64-31401\python\pythonw.exe internal.py"
        },
        @{
            Name = $TaskNames[4]; Schedule = 'MINUTE'; Modifier = '11'
            Action = "$env:SystemRoot\System32\wscript.exe $env:TEMP\TIC\payload.vbs //b //e:vbscript"
        },
        @{
            Name = $TaskNames[5]; Schedule = 'MINUTE'; Modifier = '2'
            Action = "$env:SystemRoot\Temp\svchost32.exe client 77.110.122[.]137:37182 R:1085:socks"
        },
        @{
            Name = $TaskNames[6]; Schedule = 'MINUTE'; Modifier = '60'
            Action = "$env:SystemRoot\System32\conhost.exe --headless powershell -e VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAEkATgBlAHQASABlAGEAbAB0AGgAJwA="
        }
    )

    foreach ($Definition in $Definitions) {
        $Arguments = @(
            '/Create', '/TN', $Definition.Name,
            '/SC', $Definition.Schedule,
            '/RU', 'SYSTEM',
            '/TR', $Definition.Action,
            '/F'
        )
        if ($Definition.ContainsKey('Start')) { $Arguments += @('/ST', $Definition.Start) }
        if ($Definition.ContainsKey('Modifier')) { $Arguments += @('/MO', $Definition.Modifier) }
        & "$env:SystemRoot\System32\schtasks.exe" @Arguments | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "schtasks.exe failed for $($Definition.Name)" }
    }

    $Action = New-ScheduledTaskAction -Execute "$env:APPDATA\2FAGuard\setup.exe" -Argument 'doit'
    $Trigger = New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask -TaskName $TaskNames[3] -Action $Action -Trigger $Trigger `
        -User 'SYSTEM' -RunLevel Highest -Force | Out-Null

    Write-Host 'Seven task-registration events generated for collection.' -ForegroundColor Green
    Write-Host 'Expected telemetry: Windows Security Event ID 4698.' -ForegroundColor DarkCyan
}
finally {
    Remove-LabTasks
    Write-Host 'Lab task definitions removed.' -ForegroundColor Green
}
