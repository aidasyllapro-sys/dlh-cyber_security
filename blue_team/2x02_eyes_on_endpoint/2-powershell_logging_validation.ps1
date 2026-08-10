<#
script name : 2-powershell_logging_validation.ps1
purpose     : Verify that PowerShell Script Block Logging (Event ID 4104),
              Module Logging (Event ID 4103) and Transcription are correctly
              capturing commands of varying complexity - a simple command, an
              encoded command (decoded content must appear in the log), a
              module import, a multi-line script block, and an active
              transcription session - by triggering each and checking the
              matching log entry, then reporting CAPTURED / MISSED with a
              detail-level note for each test.
author      : Aïda Sylla
date        : 2026-08-09
#>
 
Set-StrictMode -Version Latest
 
$PSLog = "Microsoft-Windows-PowerShell/Operational"
$TranscriptDir = "C:\PSTranscripts"
$TotalTests = 5
$Results = New-Object System.Collections.Generic.List[PSObject]
 
# Captured before any test runs: transcription (if active via GPO) begins at
# session start, which may be before this script's first line executes.
$ScriptStartTime = Get-Date
 
# ---------------------------------------------------------------------------
# Pre-flight check: PowerShell Operational log must exist and be readable
# ---------------------------------------------------------------------------
try {
    Get-WinEvent -ListLog $PSLog -ErrorAction Stop | Out-Null
} catch {
    Write-Error "PowerShell Operational log not found or not accessible ('$PSLog'). Confirm PowerShell Script Block/Module Logging is enabled via GPO and this session has sufficient rights."
    exit 1
}
 
# ---------------------------------------------------------------------------
# Generic PowerShell log lookup with short retry window (logging latency).
# Matches against the rendered event Message rather than parsing EventData,
# since 4103 (module logging) events do not expose a simple, stable set of
# key/value Data fields the way 4104 (script block) events do.
# ---------------------------------------------------------------------------
function Test-PSLogEvent {
    param(
        [Parameter(Mandatory)][int]$EventId,
        [Parameter(Mandatory)][datetime]$StartTime,
        [Parameter(Mandatory)][scriptblock]$Match,
        [int]$TimeoutSec = 15
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $events = Get-WinEvent -FilterHashtable @{ LogName = $PSLog; Id = $EventId; StartTime = $StartTime } -ErrorAction SilentlyContinue
        } catch {
            $events = $null
        }
        if ($events) {
            foreach ($e in $events) {
                if (& $Match $e.Message) {
                    return [PSCustomObject]@{ Captured = $true; Message = $e.Message }
                }
            }
        }
        Start-Sleep -Milliseconds 500
    }
    return [PSCustomObject]@{ Captured = $false; Message = $null }
}
 
function Write-TestLine {
    param([string]$Detail, [bool]$Pass)
    $status = if ($Pass) { "[PASS]" } else { "[FAIL]" }
    Write-Host "          $($Detail.PadRight(58))$status"
}
 
Write-Host "[*] Testing PowerShell logging coverage..."
 
# ---------------------------------------------------------------------------
# 1. Simple command (Event ID 4104)
# ---------------------------------------------------------------------------
Write-Host "    [1/$TotalTests] Simple command (Get-Process)..."
$ts1 = Get-Date
Get-Process | Out-Null
$r1 = Test-PSLogEvent -EventId 4104 -StartTime $ts1 -Match { param($m) $m -match 'Get-Process' }
Write-TestLine -Detail "EID 4104: `"Get-Process`" captured" -Pass $r1.Captured
$Results.Add([PSCustomObject]@{ Test = "Simple command (EID 4104)"; Pass = $r1.Captured })
 
# ---------------------------------------------------------------------------
# 2. Encoded command - decoded content must appear in Event ID 4104
# ---------------------------------------------------------------------------
Write-Host "    [2/$TotalTests] Encoded command..."
$plainCommand = 'Write-Host "Test"'
$encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($plainCommand))
Write-Host "          Input: -enc $encodedCommand"
$ts2 = Get-Date
try {
    powershell.exe -NoProfile -EncodedCommand $encodedCommand | Out-Null
} catch {
    Write-Warning "Encoded command execution failed: $($_.Exception.Message)"
}
$r2 = Test-PSLogEvent -EventId 4104 -StartTime $ts2 -Match { param($m) $m -match 'Write-Host' -and $m -match 'Test' }
Write-TestLine -Detail "EID 4104: `"Write-Host 'Test'`" (decoded) captured" -Pass $r2.Captured
$Results.Add([PSCustomObject]@{ Test = "Encoded command (EID 4104)"; Pass = $r2.Captured })
 
# ---------------------------------------------------------------------------
# 3. Module import (Event ID 4103)
#    NOTE: 4103 coverage of Import-Module itself depends on whether the
#    Module Logging GPO's "Module Names" list includes the module in
#    question (or "*"). If ActiveDirectory is not installed on this host,
#    the import will fail, but the invocation may still be logged - a MISS
#    here can mean either "not logged" or "module not installed"; check
#    both before concluding it is a logging gap.
# ---------------------------------------------------------------------------
Write-Host "    [3/$TotalTests] Module import..."
$ts3 = Get-Date
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Warning "Import-Module ActiveDirectory failed (module may not be installed on this host): $($_.Exception.Message)"
}
$r3 = Test-PSLogEvent -EventId 4103 -StartTime $ts3 -Match { param($m) $m -match 'Import-Module' -and $m -match 'ActiveDirectory' }
Write-TestLine -Detail "EID 4103: `"Import-Module ActiveDirectory`" captured" -Pass $r3.Captured
$Results.Add([PSCustomObject]@{ Test = "Module import (EID 4103)"; Pass = $r3.Captured })
 
# ---------------------------------------------------------------------------
# 4. Multi-line script block (Event ID 4104) - verify full block captured
# ---------------------------------------------------------------------------
Write-Host "    [4/$TotalTests] Multi-line script block..."
$marker = "MULTILINE_TEST_$([guid]::NewGuid().ToString('N').Substring(0,8))"
$multilineScript = @"
# multiline test marker $marker
`$a = 1
`$b = 2
`$c = `$a + `$b
if (`$c -eq 3) {
    Write-Host "Sum check passed"
} else {
    Write-Host "Sum check failed"
}
foreach (`$i in 1..3) {
    Write-Host "Iteration `$i"
}
"@
$expectedLineCount = @($multilineScript -split "`n").Count
$ts4 = Get-Date
try {
    Invoke-Expression $multilineScript
} catch {
    Write-Warning "Multi-line script block execution failed: $($_.Exception.Message)"
}
$r4 = Test-PSLogEvent -EventId 4104 -StartTime $ts4 -Match { param($m) $m -match [regex]::Escape($marker) -and $m -match 'Iteration 3' }
Write-TestLine -Detail "EID 4104: Full block captured ($expectedLineCount lines)" -Pass $r4.Captured
$Results.Add([PSCustomObject]@{ Test = "Multi-line script block (EID 4104)"; Pass = $r4.Captured })
 
# ---------------------------------------------------------------------------
# 5. Transcription file for the session
#    NOTE: a transcript for the CURRENTLY RUNNING session may not be fully
#    flushed to disk until the session ends (Stop-Transcript or process
#    exit). This check confirms the file exists and is fresh for this
#    session's start time, not that every line already visible on disk -
#    a fresh, growing file is expected behavior, not a failure.
# ---------------------------------------------------------------------------
Write-Host "    [5/$TotalTests] Transcription file..."
$pass5 = $false
$transcriptDetail = "C:\PSTranscripts\*.txt exists, session recorded"
if (Test-Path $TranscriptDir) {
    $recentTranscripts = Get-ChildItem -Path $TranscriptDir -Filter "*.txt" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $ScriptStartTime.AddMinutes(-30) }
    if ($recentTranscripts) {
        $pass5 = $true
    } else {
        $transcriptDetail = "C:\PSTranscripts\*.txt not found for this session"
    }
} else {
    $transcriptDetail = "C:\PSTranscripts\ directory not found"
}
Write-TestLine -Detail $transcriptDetail -Pass $pass5
$Results.Add([PSCustomObject]@{ Test = "Transcription file"; Pass = $pass5 })
 
# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
$captured = @($Results | Where-Object Pass -eq $true).Count
$missed = $Results.Count - $captured
Write-Host "Tests: $($Results.Count) | Captured: $captured | Missed: $missed"
