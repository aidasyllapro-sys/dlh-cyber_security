<#
.SYNOPSIS
    Orchestrates the full Windows hardening pass on hawthorne-adm-01 as a
    single idempotent workflow, the Windows-side counterpart to
    3-linux_harden.sh.
 
.DESCRIPTION
    Composes the seven already-validated hardening scripts from
    2x01 (account policy, audit policy, Windows Firewall baseline,
    Sysmon installation, PowerShell Script Block Logging, AppLocker/
    Defender Application Control baseline, service minimization) in a
    deterministic order, capturing every sub-step's stdout and exit
    code as structured evidence into capstone\exec\windows_harden.log.
    After the run, re-invokes the project-supplied win_audit.ps1 helper
    (the same one used in Task 1) to measure the new CIS Level 1 pass
    rate and compares it against target_state.json's WIN-CIS-01 control.
    This script does not reimplement any hardening logic itself - it
    composes and measures.
 
.NOTES
    Author: Aïda Sylla
    Date:   2026-08-22
 
    EXIT CODES (documented, per this capstone's own rule):
      0 - every sub-step exited 0 AND post_pass_rate >= target_state's
          WIN-CIS-01 expected_value
      1 - controlled failure (a sub-step failed, or the post-run pass
          rate did not reach the target)
      2 - environment error (a required sub-step script,
          target_state.json, baseline_windows.json or the win_audit.ps1
          helper is missing)
 
    SCHEMA NOTE - per this task's own explicit instruction, this script
    emits the EXACT SAME field names as 3-linux_harden.sh's JSON
    (timestamp, hostname, steps, lynis_before, lynis_after, index_delta,
    controls_touched), so T8's validation suite can read both without
    branching. On THIS side, lynis_before/lynis_after literally hold the
    CIS Level 1 pass-rate PERCENTAGE (not a Lynis Hardening Index -
    Windows has no Lynis), and index_delta is that percentage's delta.
    This is a deliberate schema-matching choice, not a naming mistake -
    field VALUES differ in meaning by platform, field NAMES do not.
 
    ASSUMPTION - sub-step script location: this capstone's own directory
    (blue_team\2x05_defensible_endpoint\) is assumed to be a sibling of
    blue_team\2x01_<windows-hardening-module>\ on the deployment host,
    mirroring the confirmed real layout of 3-linux_harden.sh's own
    sibling relationship to blue_team\2x00_locking_the_gates\. The exact
    2x01 folder name and script filenames were not available when this
    script was written - override every path in $StepScripts below (or
    the -HardenScriptsDir parameter) to match the real repository layout
    before running this for real.
 
    NOT YET VALIDATED: written with no pwsh, no access to the real 2x01
    scripts or the real win_audit.ps1 helper, and no Windows host to
    test against. Confirm every assumption above against
    hawthorne-adm-01 before trusting this script's output.
 
.PARAMETER HardenScriptsDir
    Directory containing the seven 2x01 hardening scripts. Defaults to
    a sibling "2x01 hardening" directory - see ASSUMPTION above.
 
.PARAMETER AuditHelperPath
    Path to the project-supplied win_audit.ps1 helper (same one used in
    Task 1).
 
.EXAMPLE
    PS> .\4-windows_harden.ps1
    PS> .\4-windows_harden.ps1 -HardenScriptsDir "C:\repo\blue_team\2x01_securing_the_desktop"
#>
 
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$HardenScriptsDir = (Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath '2x01_securing_the_desktop'),
 
    [Parameter(Mandatory = $false)]
    [string]$AuditHelperPath = '/home/analyst/MedDefense_Lab/capstone/win_audit.ps1'
)
 
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
 
$CapstoneDir = Join-Path -Path $PSScriptRoot -ChildPath 'capstone'
$ExecDir = Join-Path -Path $CapstoneDir -ChildPath 'exec'
$BaselineDir = Join-Path -Path $CapstoneDir -ChildPath 'baseline'
New-Item -Path $ExecDir -ItemType Directory -Force | Out-Null
 
# Per this task's own instructions, the full execution log is written to
# capstone\exec\windows_harden.log, and the JSON evidence summary to
# capstone\exec\windows_harden.json.
$LogPath = Join-Path -Path $ExecDir -ChildPath 'windows_harden.log'
$OutputPath = Join-Path -Path $ExecDir -ChildPath 'windows_harden.json'
$TargetStatePath = Join-Path -Path $CapstoneDir -ChildPath 'target_state.json'
$BaselineWindowsPath = Join-Path -Path $BaselineDir -ChildPath 'baseline_windows.json'
 
function Write-Status {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "[*] $Message"
}
 
# A corrupted or missing target_state.json is fatal, per this
# capstone's own explicit rule from Task 2.
if (-not (Test-Path $TargetStatePath)) {
    Write-Error "FATAL: $TargetStatePath is missing. Run 2-target_state.sh first."
    exit 2
}
try {
    $targetState = Get-Content -Path $TargetStatePath -Raw | ConvertFrom-Json
}
catch {
    Write-Error "FATAL: $TargetStatePath is not valid JSON. $($_.Exception.Message)"
    exit 2
}
 
if (-not (Test-Path $BaselineWindowsPath)) {
    Write-Error "FATAL: $BaselineWindowsPath is missing. Run 1-baseline_snapshot.ps1 first."
    exit 2
}
try {
    $baselineWindows = Get-Content -Path $BaselineWindowsPath -Raw | ConvertFrom-Json
}
catch {
    Write-Error "FATAL: $BaselineWindowsPath is not valid JSON. $($_.Exception.Message)"
    exit 2
}
 
if (-not (Test-Path $AuditHelperPath)) {
    Write-Error "FATAL: audit helper not found at $AuditHelperPath. Cannot measure the post-run pass rate without it."
    exit 2
}
 
$passRateBefore = $baselineWindows.pass_rate_percent
$cisControl = $targetState.controls | Where-Object { $_.id -eq 'WIN-CIS-01' } | Select-Object -First 1
$passRateTarget = if ($cisControl) { $cisControl.expected_value } else { 85 }
 
Write-Status "Orchestrating Windows hardening on $env:COMPUTERNAME..."
Write-Host "    Pass rate before: $passRateBefore%   Target: >= $passRateTarget%"
'' | Set-Content -Path $LogPath -Encoding utf8
 
# ---------------------------------------------------------------------------
# 1. Deterministic step order, each mapped to its expected 2x01 script and
#    the target_state.json control IDs it is responsible for.
#    KNOWN GAP - controls_touched mapping: target_state.json (Task 2)
#    only defines dedicated IDs for Windows Firewall (WIN-FW-01), Script
#    Block Logging (WIN-PSLOG-01), Sysmon (WIN-SYSMON-01) and audit
#    policy (WIN-AUDIT-01). It has no dedicated ID for account policy,
#    AppLocker/Defender Application Control, or service minimization -
#    those three steps' controls_touched arrays are correctly empty
#    below, not a bug.
# ---------------------------------------------------------------------------
$StepOrder = @(
    'account_policy',
    'audit_policy',
    'firewall_baseline',
    'sysmon_installation',
    'scriptblock_logging',
    'applocker_defender_baseline',
    'service_minimization'
)
$StepScripts = @{
    account_policy               = Join-Path $HardenScriptsDir 'account_policy_hardening.ps1'
    audit_policy                 = Join-Path $HardenScriptsDir 'audit_policy_hardening.ps1'
    firewall_baseline            = Join-Path $HardenScriptsDir 'firewall_baseline.ps1'
    sysmon_installation          = Join-Path $HardenScriptsDir 'sysmon_install.ps1'
    scriptblock_logging          = Join-Path $HardenScriptsDir 'scriptblock_logging_enable.ps1'
    applocker_defender_baseline  = Join-Path $HardenScriptsDir 'applocker_defender_baseline.ps1'
    service_minimization         = Join-Path $HardenScriptsDir 'service_minimization.ps1'
}
$StepControls = @{
    account_policy               = @()
    audit_policy                 = @('WIN-AUDIT-01')
    firewall_baseline            = @('WIN-FW-01')
    sysmon_installation          = @('WIN-SYSMON-01')
    scriptblock_logging          = @('WIN-PSLOG-01')
    applocker_defender_baseline  = @()
    service_minimization         = @()
}
 
# ---------------------------------------------------------------------------
# Lightweight before/after state signature per step, used to determine
# the "changed" boolean without depending on any output convention of
# the underlying 2x01 scripts (which this orchestrator does not author
# and must not assume the internals of) - mirrors 3-linux_harden.sh's
# own approach on the Linux side.
# ---------------------------------------------------------------------------
function Get-StepStateSignature {
    param([string]$StepKey)
    switch ($StepKey) {
        'account_policy' {
            (net accounts 2>$null) -join '|'
        }
        'audit_policy' {
            (auditpol /get /category:* 2>$null) -join '|'
        }
        'firewall_baseline' {
            (Get-NetFirewallProfile | ForEach-Object { "$($_.Name):$($_.DefaultInboundAction)" }) -join '|'
        }
        'sysmon_installation' {
            (Get-Service -Name Sysmon* -ErrorAction SilentlyContinue).Status -join '|'
        }
        'scriptblock_logging' {
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            if (Test-Path $p) { (Get-ItemProperty -Path $p -ErrorAction SilentlyContinue).EnableScriptBlockLogging } else { 'absent' }
        }
        'applocker_defender_baseline' {
            (Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue).Status
        }
        'service_minimization' {
            (Get-Service | Where-Object { $_.Status -eq 'Running' }).Count
        }
        default { '' }
    }
}
 
# ---------------------------------------------------------------------------
# Wrapper that runs a sub-step, captures its stdout+exit code into the
# shared log, times it, and determines whether it changed anything - per
# this project's own established pattern from 3-linux_harden.sh.
# ---------------------------------------------------------------------------
$StepEntries = @()
$allStepsOk = $true
 
function Invoke-HardeningStep {
    param([string]$StepKey)
 
    $scriptPath = $StepScripts[$StepKey]
    "`n===== STEP: $StepKey ($scriptPath) =====" | Add-Content -Path $LogPath -Encoding utf8
 
    if (-not (Test-Path $scriptPath)) {
        "SCRIPT NOT FOUND: $scriptPath" | Add-Content -Path $LogPath -Encoding utf8
        Write-Warning "Step '$StepKey' script not found: $scriptPath"
        $script:allStepsOk = $false
        return [PSCustomObject]@{
            name             = $StepKey
            script_path      = $scriptPath
            exit_code        = 127
            duration_seconds = 0
            changed          = $false
        }
    }
 
    $before = Get-StepStateSignature -StepKey $StepKey
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $exitCode = 0
    try {
        $output = & $scriptPath 2>&1
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) { $exitCode = 0 }
        $output | Add-Content -Path $LogPath -Encoding utf8
    }
    catch {
        $exitCode = 1
        "EXCEPTION: $($_.Exception.Message)" | Add-Content -Path $LogPath -Encoding utf8
    }
    $stopwatch.Stop()
    $duration = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)
 
    $after = Get-StepStateSignature -StepKey $StepKey
    $changed = ($before -ne $after)
 
    "exit_code=$exitCode duration=${duration}s changed=$changed" | Add-Content -Path $LogPath -Encoding utf8
 
    if ($exitCode -ne 0) { $script:allStepsOk = $false }
 
    Write-Host "    ${StepKey}: exit=$exitCode duration=${duration}s changed=$changed"
 
    return [PSCustomObject]@{
        name             = $StepKey
        script_path      = $scriptPath
        exit_code        = $exitCode
        duration_seconds = $duration
        changed          = $changed
    }
}
 
Write-Status 'Running hardening steps in order...'
foreach ($step in $StepOrder) {
    $StepEntries += Invoke-HardeningStep -StepKey $step
}
 
# ---------------------------------------------------------------------------
# 3. Re-invoke the audit helper and compute the new CIS Level 1 pass rate.
# ---------------------------------------------------------------------------
Write-Status 'Re-running the CIS audit helper to measure the delta...'
$passRateAfter = 0
try {
    $auditOutput = & $AuditHelperPath 2>&1
    $passCount = 0; $failCount = 0; $naCount = 0
    foreach ($line in $auditOutput) {
        $trimmed = ($line -as [string]).Trim()
        if ($trimmed -match '\bPASS$') { $passCount++ }
        elseif ($trimmed -match '\bFAIL$') { $failCount++ }
        elseif ($trimmed -match '\bNOT_APPLICABLE$') { $naCount++ }
    }
    $total = $passCount + $failCount + $naCount
    $passRateAfter = if ($total -gt 0) { [math]::Round(($passCount / $total) * 100, 1) } else { 0 }
}
catch {
    Write-Error "Could not re-run the audit helper: $($_.Exception.Message)"
    $passRateAfter = 0
}
 
$indexDelta = [math]::Round($passRateAfter - $passRateBefore, 1)
Write-Host "    Pass rate after: $passRateAfter%   Delta: $indexDelta"
 
# ---------------------------------------------------------------------------
# controls_touched: union of every step's mapped control IDs.
# ---------------------------------------------------------------------------
$controlsTouched = @()
foreach ($step in $StepOrder) {
    $controlsTouched += $StepControls[$step]
}
$controlsTouched = $controlsTouched | Select-Object -Unique
 
# ---------------------------------------------------------------------------
# Emit windows_harden.json - same schema as 3-linux_harden.sh's JSON.
# See SCHEMA NOTE above.
# ---------------------------------------------------------------------------
$evidence = [PSCustomObject]@{
    timestamp        = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname          = $env:COMPUTERNAME
    steps             = $StepEntries
    lynis_before      = $passRateBefore
    lynis_after       = $passRateAfter
    index_delta       = $indexDelta
    controls_touched  = $controlsTouched
}
 
try {
    $evidence | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding utf8
}
catch {
    Write-Error "FAILED: could not write $OutputPath : $($_.Exception.Message)"
    exit 1
}
 
try {
    Get-Content -Path $OutputPath -Raw | ConvertFrom-Json | Out-Null
}
catch {
    Write-Error "FAILED: $OutputPath was written but is not valid JSON: $($_.Exception.Message)"
    exit 1
}
 
Write-Host ""
Write-Host "Log saved to: $LogPath"
Write-Host "Report saved to: $OutputPath"
 
# ---------------------------------------------------------------------------
# 4. Final exit logic: 0 only if every sub-step exited 0 AND
#    post_pass_rate >= target_state.windows.pass_rate.
# ---------------------------------------------------------------------------
if ($allStepsOk -and ($passRateAfter -ge $passRateTarget)) {
    Write-Host "PASS: all steps succeeded and pass rate ($passRateAfter%) meets target ($passRateTarget%)."
    exit 0
}
else {
    Write-Error "FAIL: allStepsOk=$allStepsOk   passRateAfter=$passRateAfter vs target=$passRateTarget"
    exit 1
}
