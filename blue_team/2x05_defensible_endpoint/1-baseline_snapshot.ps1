<#
.SYNOPSIS
    Runs the project-supplied CIS Level 1 audit helper against
    hawthorne-adm-01 and persists both the raw output and the extracted
    pass rate as the quantitative Windows-side baseline for the
    capstone.
 
.DESCRIPTION
    Invokes /home/analyst/MedDefense_Lab/capstone/win_audit.ps1 (a
    project-supplied helper this script does not author), which walks a
    fixed list of CIS Level 1 controls and prints one line per control
    ending in PASS, FAIL or NOT_APPLICABLE. This script captures that
    full output verbatim to a log file, counts each outcome, and emits
    a structured JSON summary - the Windows-side counterpart to
    1-baseline_snapshot.sh's Lynis-based Hardening Index on
    hawthorne-app-01.
 
.NOTES
    Author: Aïda Sylla
    Date:   2026-08-22
 
    EXIT CODES (documented, per this capstone's own rule):
      0 - baseline captured successfully
      1 - controlled failure (the helper ran but produced no
          recognizable PASS/FAIL/NOT_APPLICABLE lines, or the emitted
          JSON is malformed)
      2 - environment error (the audit helper script is missing)
 
    ASSUMPTION - line format: this task's own wording says the helper
    outputs "one line per control with PASS, FAIL or NOT_APPLICABLE,"
    without specifying the exact line shape (e.g. "CIS-1.1.1: PASS" vs
    "PASS - Control description"). This script matches any line whose
    LAST whitespace-separated token is exactly PASS, FAIL or
    NOT_APPLICABLE, which tolerates either ordering - documented here so
    the assumption is explicit rather than silently baked into a
    narrower regex.
 
    NOT YET VALIDATED AGAINST A REAL WINDOWS HOST OR THE REAL HELPER
    SCRIPT: written with no pwsh, no access to win_audit.ps1 itself, and
    no network to test against. Test the line-format assumption above
    against the real helper's actual output on hawthorne-adm-01 before
    trusting this script's counts.
 
.EXAMPLE
    PS> .\1-baseline_snapshot.ps1
#>
 
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$AuditHelperPath = '/home/analyst/MedDefense_Lab/capstone/win_audit.ps1',
 
    [Parameter(Mandatory = $false)]
    [string]$BaselineDir = (Join-Path -Path $PSScriptRoot -ChildPath 'capstone\baseline')
)
 
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
 
function Write-Status {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "[*] $Message"
}
 
if (-not (Test-Path -Path $AuditHelperPath)) {
    Write-Error "Audit helper not found at $AuditHelperPath. This script does not author it - it must be supplied by the project. Cannot proceed."
    exit 2
}
 
if (-not (Test-Path -Path $BaselineDir)) {
    New-Item -Path $BaselineDir -ItemType Directory -Force | Out-Null
}
 
$logPath = Join-Path -Path $BaselineDir -ChildPath 'windows_baseline.log'
$outputPath = Join-Path -Path $BaselineDir -ChildPath 'baseline_windows.json'
 
# ---------------------------------------------------------------------------
# 1. Run the provided audit helper and capture its full output verbatim.
# ---------------------------------------------------------------------------
Write-Status "Running $AuditHelperPath (CIS Level 1 walk)..."
 
$auditOutput = $null
try {
    $auditOutput = & $AuditHelperPath 2>&1
}
catch {
    Write-Error "The audit helper threw an error: $($_.Exception.Message)"
    exit 1
}
 
$auditOutput | Out-File -FilePath $logPath -Encoding utf8
 
if (-not $auditOutput -or @($auditOutput).Count -eq 0) {
    Write-Error "The audit helper produced no output at all. See $logPath (empty)."
    exit 1
}
 
# ---------------------------------------------------------------------------
# 2. Count the pass rate. See the ASSUMPTION note above about line format.
# ---------------------------------------------------------------------------
Write-Status 'Counting control outcomes...'
 
$passCount = 0
$failCount = 0
$naCount = 0
 
foreach ($line in $auditOutput) {
    $trimmed = ($line -as [string]).Trim()
    if ($trimmed -match '\bPASS$') { $passCount++ }
    elseif ($trimmed -match '\bFAIL$') { $failCount++ }
    elseif ($trimmed -match '\bNOT_APPLICABLE$') { $naCount++ }
}
 
$controlsTotal = $passCount + $failCount + $naCount
 
if ($controlsTotal -eq 0) {
    Write-Error "No line in the helper's output matched PASS, FAIL or NOT_APPLICABLE. The line-format assumption documented in this script's header may not match the real helper - see $logPath to compare."
    exit 1
}
 
$passRatePercent = if ($controlsTotal -gt 0) {
    [math]::Round(($passCount / $controlsTotal) * 100, 1)
}
else {
    0
}
 
Write-Host "  Total: $controlsTotal   Pass: $passCount   Fail: $failCount   N/A: $naCount   Pass rate: $passRatePercent%"
 
# ---------------------------------------------------------------------------
# 3. Emit baseline_windows.json
# ---------------------------------------------------------------------------
$baseline = [PSCustomObject]@{
    timestamp          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname            = $env:COMPUTERNAME
    controls_total      = $controlsTotal
    pass_count          = $passCount
    fail_count          = $failCount
    na_count            = $naCount
    pass_rate_percent   = $passRatePercent
    log_path            = $logPath
}
 
try {
    $baseline | ConvertTo-Json -Depth 4 | Set-Content -Path $outputPath -Encoding utf8
}
catch {
    Write-Error "Failed to write $outputPath : $($_.Exception.Message)"
    exit 1
}
 
# Validate the JSON we just wrote is genuinely well-formed before
# declaring success, mirroring 1-baseline_snapshot.sh's own jq-empty
# check on the Linux side.
try {
    Get-Content -Path $outputPath -Raw | ConvertFrom-Json | Out-Null
}
catch {
    Write-Error "baseline_windows.json was written but is not valid JSON: $($_.Exception.Message)"
    exit 1
}
 
Write-Host ""
Write-Host "Report saved to: $outputPath"
Write-Host "Log saved to: $logPath"
exit 0
