<#
script name : 10-windows_detection_proof.ps1
purpose     : read windows_attack_log.json (the ground truth produced by
              9-windows_attack_sim.ps1) and, for each of the 6 simulated
              actions, search the Security, Sysmon Operational and
              PowerShell Operational event logs within a +/-30 second
              window around the recorded timestamp. Records which
              source(s) captured each action, the Event ID, the detail
              level (Full / Partial / Missed) and the key fields present,
              producing a detection matrix as proof that instrumentation
              captured the simulated attack sequence. Writes the result to
              windows_detection_matrix.json.
author      : Aïda Sylla
date        : 2026-08-09
#>
 
Set-StrictMode -Version Latest
 
$GroundTruthPath = Join-Path -Path $PSScriptRoot -ChildPath "windows_attack_log.json"
$OutputPath = Join-Path -Path $PSScriptRoot -ChildPath "windows_detection_matrix.json"
$WindowSeconds = 30
 
if (-not (Test-Path $GroundTruthPath)) {
    Write-Error "windows_attack_log.json not found at $GroundTruthPath. Run 9-windows_attack_sim.ps1 first."
    exit 1
}
 
try {
    $groundTruth = Get-Content -Path $GroundTruthPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-Error "Failed to parse windows_attack_log.json: $($_.Exception.Message)"
    exit 1
}
 
$actions = @($groundTruth.ground_truth)
Write-Host "[*] Loading ground truth ($($actions.Count) actions)..."
Write-Host "[*] Searching telemetry for each action..."
 
# ---------------------------------------------------------------------------
# Helpers (same conventions as earlier telemetry-validation scripts in this
# module: XML EventData flattening for Security/Sysmon, raw Message text
# matching for PowerShell Operational events).
# ---------------------------------------------------------------------------
function Get-EventDataHash {
    param($XmlEvent)
    $hash = @{}
    if ($XmlEvent.Event.EventData -and $XmlEvent.Event.EventData.Data) {
        foreach ($d in @($XmlEvent.Event.EventData.Data)) {
            if ($d.Name) { $hash[$d.Name] = $d.'#text' } else { $hash['Data'] = $d.'#text' }
        }
    }
    return $hash
}
 
function Search-WindowsEvent {
    param(
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][int]$EventId,
        [Parameter(Mandatory)][datetime]$CenterTime,
        [Parameter(Mandatory)][int]$WindowSeconds,
        [Parameter(Mandatory)][scriptblock]$Match
    )
    $start = $CenterTime.AddSeconds(-$WindowSeconds)
    $end = $CenterTime.AddSeconds($WindowSeconds)
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $EventId; StartTime = $start; EndTime = $end } -ErrorAction SilentlyContinue
    } catch {
        $events = $null
    }
    if (-not $events) { return $null }
    foreach ($e in @($events)) {
        $xml = [xml]$e.ToXml()
        $data = Get-EventDataHash -XmlEvent $xml
        if (& $Match $e $data) {
            return [PSCustomObject]@{ Event = $e; Data = $data }
        }
    }
    return $null
}
 
# ---------------------------------------------------------------------------
# Per action-number: canonical short label (matches the Task 9 sequence)
# and the candidate source/EventId/match-criteria to search for. Several
# candidates per action are tried; only sources that actually produce a
# match are reported - some candidates (e.g. Security 5156, 4663) require
# advanced audit policies not enabled by default and are expected to come
# back empty on a baseline configuration, per the caveats already recorded
# in 9-windows_attack_sim.ps1's ground truth.
# ---------------------------------------------------------------------------
$ActionLabels = @{
    1 = "Create user"
    2 = "Add to Administrators"
    3 = "Encoded PowerShell"
    4 = "Scheduled task"
    5 = "Outbound connection"
    6 = "Startup file drop"
}
 
function Get-Candidates {
    param([int]$ActionNumber)
    switch ($ActionNumber) {
        1 {
            @(
                @{ Log = "Security"; EventId = 4720; Detail = { param($d) if ($d.ContainsKey('TargetUserName') -and $d['TargetUserName'] -match 'support_update') { "Full" } else { "Partial" } }; Match = { param($e, $d) $d.ContainsKey('TargetUserName') -and $d['TargetUserName'] -match 'support_update' } }
            )
        }
        2 {
            @(
                @{ Log = "Security"; EventId = 4732; Detail = { param($d) if ($d.ContainsKey('MemberName') -and $d['MemberName'] -match 'support_update') { "Full" } else { "Partial" } }; Match = { param($e, $d) ($e.Message -match 'support_update') -and ($e.Message -match 'Administrators') } }
            )
        }
        3 {
            @(
                @{ Log = "Microsoft-Windows-PowerShell/Operational"; EventId = 4104; Detail = { param($d) "Full" }; Match = { param($e, $d) $e.Message -match 'C2 beacon' } }
                @{ Log = "Microsoft-Windows-Sysmon/Operational"; EventId = 1; Detail = { param($d) if ($d.ContainsKey('CommandLine') -and $d['CommandLine'] -match '-enc') { "Full" } else { "Partial" } }; Match = { param($e, $d) $d.ContainsKey('Image') -and $d['Image'] -match 'powershell\.exe' -and $d.ContainsKey('CommandLine') -and $d['CommandLine'] -match '-enc' } }
            )
        }
        4 {
            @(
                @{ Log = "Microsoft-Windows-Sysmon/Operational"; EventId = 1; Detail = { param($d) if ($d.ContainsKey('CommandLine') -and $d['CommandLine'] -match 'support_update_task') { "Full" } else { "Partial" } }; Match = { param($e, $d) $d.ContainsKey('Image') -and $d['Image'] -match 'schtasks\.exe' } }
                @{ Log = "Security"; EventId = 4698; Detail = { param($d) "Full" }; Match = { param($e, $d) $e.Message -match 'support_update_task' } }
            )
        }
        5 {
            @(
                @{ Log = "Microsoft-Windows-Sysmon/Operational"; EventId = 3; Detail = { param($d) if ($d.ContainsKey('DestinationIp') -and $d['DestinationIp'] -eq '8.8.8.8') { "Full" } else { "Partial" } }; Match = { param($e, $d) $d.ContainsKey('DestinationIp') -and $d['DestinationIp'] -eq '8.8.8.8' } }
            )
        }
        6 {
            @(
                @{ Log = "Microsoft-Windows-Sysmon/Operational"; EventId = 11; Detail = { param($d) if ($d.ContainsKey('TargetFilename') -and $d['TargetFilename'] -match 'support_update_sim\.txt') { "Full" } else { "Partial" } }; Match = { param($e, $d) $d.ContainsKey('TargetFilename') -and $d['TargetFilename'] -match 'support_update_sim\.txt' } }
            )
        }
        default { @() }
    }
}
 
function Get-SourceLabel {
    param([string]$LogName)
    switch ($LogName) {
        "Security" { "Security" }
        "Microsoft-Windows-Sysmon/Operational" { "Sysmon" }
        "Microsoft-Windows-PowerShell/Operational" { "PS ScriptBlock" }
        default { $LogName }
    }
}
 
# ---------------------------------------------------------------------------
# Build the matrix
# ---------------------------------------------------------------------------
$MatrixRows = New-Object System.Collections.Generic.List[PSObject]
$capturedActionCount = 0
$multiSourceCount = 0
 
foreach ($action in $actions) {
    $actionNumber = [int]$action.action_number
    $label = $ActionLabels[$actionNumber]
    if (-not $label) { $label = $action.description }
 
    $centerTime = [datetime]::Parse($action.timestamp, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
 
    $candidates = Get-Candidates -ActionNumber $actionNumber
    $sourcesCaptured = 0
 
    foreach ($candidate in $candidates) {
        $result = Search-WindowsEvent -LogName $candidate.Log -EventId $candidate.EventId -CenterTime $centerTime -WindowSeconds $WindowSeconds -Match $candidate.Match
        if ($result) {
            $detail = & $candidate.Detail $result.Data
            $sourcesCaptured++
            $MatrixRows.Add([PSCustomObject]@{
                action_number = $actionNumber
                action        = $label
                source        = Get-SourceLabel -LogName $candidate.Log
                event_id      = $candidate.EventId
                detail        = $detail
                status        = "CAPTURED"
                key_fields    = $result.Data
            })
        }
    }
 
    if ($sourcesCaptured -eq 0) {
        $MatrixRows.Add([PSCustomObject]@{
            action_number = $actionNumber
            action        = $label
            source        = "-"
            event_id      = "-"
            detail        = "Missed"
            status         = "MISSED"
            key_fields     = $null
        })
    } else {
        $capturedActionCount++
        if ($sourcesCaptured -gt 1) { $multiSourceCount++ }
    }
}
 
# ---------------------------------------------------------------------------
# Print table
# ---------------------------------------------------------------------------
Write-Host ("{0,-25} {1,-14} {2,-10} {3,-9} {4,-10}" -f "Action", "Source", "Event ID", "Detail", "Status")
Write-Host ("{0,-25} {1,-14} {2,-10} {3,-9} {4,-10}" -f "------", "------", "--------", "------", "------")
 
$lastActionNumber = -1
foreach ($row in $MatrixRows) {
    $displayAction = if ($row.action_number -ne $lastActionNumber) { $row.action } else { "" }
    $statusTag = "[$($row.status)]"
    Write-Host ("{0,-25} {1,-14} {2,-10} {3,-9} {4,-10}" -f $displayAction, $row.source, $row.event_id, $row.detail, $statusTag)
    $lastActionNumber = $row.action_number
}
 
$totalActions = $actions.Count
$capturePct = if ($totalActions -gt 0) { [math]::Round(($capturedActionCount / $totalActions) * 100) } else { 0 }
Write-Host "Actions: $totalActions | Captured: $capturedActionCount/$totalActions ($capturePct%) | Multi-source: $multiSourceCount"
 
# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
$report = [PSCustomObject]@{
    generated         = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    ground_truth_source = $GroundTruthPath
    window_seconds     = $WindowSeconds
    total_actions      = $totalActions
    captured_actions   = $capturedActionCount
    capture_rate_pct   = $capturePct
    multi_source_count = $multiSourceCount
    matrix             = $MatrixRows
}
$report | ConvertTo-Json -Depth 8 | Out-File -FilePath $OutputPath -Encoding utf8
 
Write-Host "Report saved to: $(Split-Path -Path $OutputPath -Leaf)"
