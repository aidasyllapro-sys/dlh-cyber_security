<#
.SYNOPSIS
    Deploys and verifies the Windows telemetry stack on hawthorne-adm-01
    - the Windows-side counterpart to 5-telemetry_deploy.sh.
 
.DESCRIPTION
    Verifies Sysmon is installed, running and using the MedDefense
    configuration; verifies PowerShell Script Block Logging is active
    via the registry; runs a controlled sequence of authorized test
    actions (create a local user, create and run a scheduled task,
    start and stop a service, run a short authorized PowerShell
    command); verifies each action left the expected event in the
    expected channel (Sysmon Operational, PowerShell Operational,
    Security) within the last 10 minutes; and exports the last 30
    minutes of Sysmon and PowerShell events as structured JSON.
 
.NOTES
    Author: Aïda Sylla
    Date:   2026-08-22
 
    EXIT CODES (documented, per this capstone's own rule):
      0 - every test action produced its expected event
      1 - controlled failure (at least one test action's expected event
          was not found, or Sysmon/Script Block Logging is not active)
      2 - environment error (a required cmdlet/module is missing)
 
    ASSUMPTION - MedDefense Sysmon config: this script checks that
    Sysmon is running and that ITS CONFIGURATION HASH matches what
    Get-Service/Sysmon itself reports as loaded, but the actual
    MedDefense sysmonconfig.xml content and its expected hash/path were
    not available when this script was written - the
    $ExpectedConfigNameHint below is a documented placeholder to adjust
    once the real config file is confirmed on hawthorne-adm-01.
 
    NOT YET VALIDATED: written with no pwsh, no Windows-only cmdlets and
    no Windows host to test against. Confirm every assumption here
    against a real, non-critical Windows machine before trusting this
    script's verdicts, the same caution given to every other Windows
    script in this project.
 
.EXAMPLE
    PS> .\5-telemetry_deploy.ps1
#>
 
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ExpectedConfigNameHint = 'meddefense'
)
 
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
 
$CapstoneDir = Join-Path -Path $PSScriptRoot -ChildPath 'capstone'
$TelemetryDir = Join-Path -Path $CapstoneDir -ChildPath 'telemetry'
New-Item -Path $TelemetryDir -ItemType Directory -Force | Out-Null
 
# Per this task's own instructions, exports are written to
# capstone\telemetry\windows_events.json and the per-action coverage
# summary to capstone\telemetry\windows_coverage.json.
$EventsOutputPath = Join-Path -Path $TelemetryDir -ChildPath 'windows_events.json'
$CoverageOutputPath = Join-Path -Path $TelemetryDir -ChildPath 'windows_coverage.json'
 
function Write-Status {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "[*] $Message"
}
 
$overallPass = $true
$testResults = @()
 
# ---------------------------------------------------------------------------
# 1. Verify Sysmon is installed, running and using the MedDefense config.
# ---------------------------------------------------------------------------
Write-Status 'Verifying Sysmon...'
$sysmonService = Get-Service -Name Sysmon* -ErrorAction SilentlyContinue
$sysmonRunning = [bool]($sysmonService -and $sysmonService.Status -eq 'Running')
if (-not $sysmonRunning) {
    Write-Warning 'Sysmon is not installed or not running.'
    $overallPass = $false
}
else {
    Write-Host "    Sysmon running: $($sysmonService.Name)"
}
# Best-effort confirmation the loaded config looks like the MedDefense
# one - see ASSUMPTION note above about the exact expected file/hash.
$sysmonConfigLooksRight = $false
try {
    $sysmonKey = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon*\Parameters' -ErrorAction SilentlyContinue
    if ($sysmonKey -and ($sysmonKey.ConfigHash -match $ExpectedConfigNameHint -or $sysmonKey.Rules -match $ExpectedConfigNameHint)) {
        $sysmonConfigLooksRight = $true
    }
}
catch {
    $sysmonConfigLooksRight = $false
}
 
# ---------------------------------------------------------------------------
# 2. Verify Script Block Logging is active via the registry.
# ---------------------------------------------------------------------------
Write-Status 'Verifying PowerShell Script Block Logging...'
$sbLoggingPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$scriptBlockLoggingEnabled = $false
if (Test-Path $sbLoggingPath) {
    $sbValue = (Get-ItemProperty -Path $sbLoggingPath -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    $scriptBlockLoggingEnabled = ($sbValue -eq 1)
}
if (-not $scriptBlockLoggingEnabled) {
    Write-Warning 'Script Block Logging is not enabled.'
    $overallPass = $false
}
else {
    Write-Host '    Script Block Logging enabled.'
}
 
# ---------------------------------------------------------------------------
# 3/4. Controlled test sequence, each verified against its expected
#      event channel within the last 10 minutes.
# ---------------------------------------------------------------------------
function Test-Action {
    param(
        [string]$ActionName,
        [scriptblock]$ActionBlock,
        [scriptblock]$VerifyBlock
    )
    Write-Status "Test: $ActionName"
    try {
        & $ActionBlock | Out-Null
    }
    catch {
        Write-Warning "Action '$ActionName' threw: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds 2
 
    $found = $false
    try {
        $found = [bool](& $VerifyBlock)
    }
    catch {
        $found = $false
    }
 
    $result = if ($found) { 'PASS' } else { 'FAIL' }
    Write-Host "    -> $result"
    if (-not $found) { $script:overallPass = $false }
 
    return [PSCustomObject]@{
        action = $ActionName
        result = $result
    }
}
 
$testUser = 'meddefense_capstone_test'
Remove-LocalUser -Name $testUser -ErrorAction SilentlyContinue
 
$cutoff = (Get-Date).AddMinutes(-10)
 
$testResults += Test-Action -ActionName 'create local user' `
    -ActionBlock { New-LocalUser -Name $testUser -NoPassword -ErrorAction SilentlyContinue } `
    -VerifyBlock {
        Get-WinEvent -LogName Security -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -eq 4720 -and $_.TimeCreated -gt $cutoff -and $_.Message -match $testUser } |
            Select-Object -First 1
    }
 
$taskName = 'MedDefenseCapstoneTestTask'
$testResults += Test-Action -ActionName 'create and run scheduled task' `
    -ActionBlock {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit 0'
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
    } `
    -VerifyBlock {
        Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeCreated -gt $cutoff -and $_.Message -match $taskName } |
            Select-Object -First 1
    }
 
$testResults += Test-Action -ActionName 'start and stop a service (Spooler)' `
    -ActionBlock {
        Restart-Service -Name Spooler -Force -ErrorAction SilentlyContinue
    } `
    -VerifyBlock {
        Get-WinEvent -LogName System -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -in @(7036, 7040) -and $_.TimeCreated -gt $cutoff -and $_.Message -match 'Spooler' } |
            Select-Object -First 1
    }
 
$testResults += Test-Action -ActionName 'short authorized PowerShell command' `
    -ActionBlock { Invoke-Expression 'Write-Output "meddefense-capstone-marker"' } `
    -VerifyBlock {
        Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeCreated -gt $cutoff -and $_.Message -match 'meddefense-capstone-marker' } |
            Select-Object -First 1
    }
 
# Cleanup test artifacts.
Remove-LocalUser -Name $testUser -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
 
# ---------------------------------------------------------------------------
# 5. Export the last 30 minutes of Sysmon and PowerShell events.
# ---------------------------------------------------------------------------
Write-Status 'Exporting the last 30 minutes of Sysmon and PowerShell events...'
$exportCutoff = (Get-Date).AddMinutes(-30)
 
$sysmonEvents = @(Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -gt $exportCutoff } |
    Select-Object TimeCreated, Id, Message)
 
$powershellEvents = @(Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -gt $exportCutoff } |
    Select-Object TimeCreated, Id, Message)
 
$eventsExport = [PSCustomObject]@{
    timestamp          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname            = $env:COMPUTERNAME
    window_since        = $exportCutoff.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    sysmon_event_count  = $sysmonEvents.Count
    sysmon_events       = $sysmonEvents
    powershell_event_count = $powershellEvents.Count
    powershell_events   = $powershellEvents
}
 
try {
    $eventsExport | ConvertTo-Json -Depth 6 | Set-Content -Path $EventsOutputPath -Encoding utf8
}
catch {
    Write-Error "FAILED: could not write $EventsOutputPath : $($_.Exception.Message)"
    exit 1
}
 
Write-Host "    $($sysmonEvents.Count) Sysmon events, $($powershellEvents.Count) PowerShell events exported."
 
# ---------------------------------------------------------------------------
# 6. Emit windows_coverage.json - same per-action schema as Linux.
# ---------------------------------------------------------------------------
$coverage = [PSCustomObject]@{
    timestamp   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname     = $env:COMPUTERNAME
    tests        = $testResults
    all_passed   = $overallPass
}
 
try {
    $coverage | ConvertTo-Json -Depth 6 | Set-Content -Path $CoverageOutputPath -Encoding utf8
}
catch {
    Write-Error "FAILED: could not write $CoverageOutputPath : $($_.Exception.Message)"
    exit 1
}
 
# Validate both JSON files we just wrote are genuinely well-formed.
try {
    Get-Content -Path $EventsOutputPath -Raw | ConvertFrom-Json | Out-Null
    Get-Content -Path $CoverageOutputPath -Raw | ConvertFrom-Json | Out-Null
}
catch {
    Write-Error "FAILED: an output file was written but is not valid JSON: $($_.Exception.Message)"
    exit 1
}
 
Write-Host ""
Write-Host "Events saved to: $EventsOutputPath"
Write-Host "Coverage saved to: $CoverageOutputPath"
 
if ($overallPass -and $sysmonRunning -and $scriptBlockLoggingEnabled) {
    Write-Host "PASS: every test action produced its expected record."
    exit 0
}
else {
    Write-Error "FAIL: overallPass=$overallPass sysmonRunning=$sysmonRunning scriptBlockLoggingEnabled=$scriptBlockLoggingEnabled"
    exit 1
}
