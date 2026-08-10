<#
script name : 4-windows_telemetry_quality.ps1
purpose     : Read windows_events_export.json (the normalized export produced
              by 3-windows_telemetry_export.ps1) and assess whether it is
              complete, continuous, and useful enough for analyst handoff.
              Computes event distribution, channel distribution, time
              coverage, gap detection (periods over 30 minutes with no
              events), field completeness (required fields, command line,
              source IP, script block), and a weighted 0-100 quality score
              with a good / acceptable / poor assessment. Writes the full
              report to windows_telemetry_quality.json.
author      : Aïda Sylla
date        : 2026-08-09
#>
 
param(
    [string]$InputPath = (Join-Path -Path $PSScriptRoot -ChildPath "windows_events_export.json"),
    [string]$OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath "windows_telemetry_quality.json"),
    [int]$GapThresholdMinutes = 30
)
 
Set-StrictMode -Version Latest
 
Write-Host "[*] Analyzing windows_events_export.json..."
 
if (-not (Test-Path $InputPath)) {
    Write-Error "windows_events_export.json not found at $InputPath. Run 3-windows_telemetry_export.ps1 first (or update -InputPath)."
    exit 1
}
 
try {
    $export = Get-Content -Path $InputPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-Error "Failed to parse windows_events_export.json: $($_.Exception.Message)"
    exit 1
}
 
$events = @($export.events)
$totalEvents = $events.Count
Write-Host "Total events: $totalEvents"
 
if ($totalEvents -eq 0) {
    Write-Error "windows_events_export.json contains zero events. Nothing to assess."
    exit 1
}
 
function Test-HasValue {
    param($Value)
    return ($null -ne $Value) -and ("$Value".Trim().Length -gt 0)
}
 
function Get-EventLabel {
    param($Event)
    if ($Event.source_type -eq 'sysmon') { return "Sysmon-$($Event.event_id)" }
    return "$($Event.event_id)"
}
 
# ---------------------------------------------------------------------------
# 1. Event distribution - count and % of total per (channel-aware) Event ID
# ---------------------------------------------------------------------------
$eventDistribution = $events | Group-Object { Get-EventLabel $_ } | Sort-Object Count -Descending | ForEach-Object {
    [PSCustomObject]@{
        event_id   = $_.Name
        count      = $_.Count
        percentage = [math]::Round(($_.Count / $totalEvents) * 100, 2)
    }
}
 
# ---------------------------------------------------------------------------
# 2. Channel distribution - Security / Sysmon / PowerShell
# ---------------------------------------------------------------------------
$channelLabels = @{ security = "Security"; sysmon = "Sysmon"; powershell = "PowerShell" }
$channelDistribution = $events | Group-Object source_type | ForEach-Object {
    $label = if ($channelLabels.ContainsKey($_.Name)) { $channelLabels[$_.Name] } else { $_.Name }
    [PSCustomObject]@{
        channel    = $label
        count      = $_.Count
        percentage = [math]::Round(($_.Count / $totalEvents) * 100, 2)
    }
}
 
# ---------------------------------------------------------------------------
# 3. Time coverage - events per hour, hours with/without events
# ---------------------------------------------------------------------------
$timestamps = $events | ForEach-Object { [datetime]$_.timestamp } | Sort-Object
 
$windowStart = if ($export.PSObject.Properties.Name -contains 'window_start' -and $export.window_start) { [datetime]$export.window_start } else { $timestamps[0] }
$windowEnd   = if ($export.PSObject.Properties.Name -contains 'window_end' -and $export.window_end) { [datetime]$export.window_end } else { $timestamps[-1] }
 
$totalHours = [math]::Max(1, [math]::Ceiling(($windowEnd - $windowStart).TotalHours))
 
$hourBuckets = @{}
for ($h = 0; $h -lt $totalHours; $h++) {
    $bucketStart = $windowStart.AddHours($h)
    $hourBuckets[$bucketStart.ToString("yyyy-MM-ddTHH:00:00Z")] = 0
}
foreach ($ts in $timestamps) {
    $bucketKey = $ts.ToString("yyyy-MM-ddTHH:00:00Z")
    if ($hourBuckets.ContainsKey($bucketKey)) {
        $hourBuckets[$bucketKey]++
    } else {
        # Event falls outside the declared window (e.g. clock skew) - still
        # counted, just not attributable to a specific in-window hour bucket.
        $hourBuckets[$bucketKey] = 1
    }
}
 
$hoursWithEvents = @($hourBuckets.Values | Where-Object { $_ -gt 0 }).Count
$hoursWithoutEvents = $hourBuckets.Count - $hoursWithEvents
Write-Host "Hours with events: $hoursWithEvents/$($hourBuckets.Count)"
 
$eventsPerHour = $hourBuckets.GetEnumerator() | Sort-Object Name | ForEach-Object {
    [PSCustomObject]@{ hour = $_.Key; count = $_.Value }
}
 
# ---------------------------------------------------------------------------
# 4. Gap detection - consecutive-event gaps longer than the threshold
# ---------------------------------------------------------------------------
$gaps = New-Object System.Collections.Generic.List[PSObject]
for ($i = 1; $i -lt $timestamps.Count; $i++) {
    $delta = $timestamps[$i] - $timestamps[$i - 1]
    if ($delta.TotalMinutes -gt $GapThresholdMinutes) {
        $gaps.Add([PSCustomObject]@{
            gap_start_utc  = $timestamps[$i - 1].ToUniversalTime().ToString("o")
            gap_end_utc    = $timestamps[$i].ToUniversalTime().ToString("o")
            duration_minutes = [math]::Round($delta.TotalMinutes, 1)
        })
    }
}
$largestGapMinutes = if ($gaps.Count -gt 0) { ($gaps | Measure-Object -Property duration_minutes -Maximum).Maximum } else { 0 }
Write-Host "Largest gap: $largestGapMinutes minutes"
 
# ---------------------------------------------------------------------------
# 5. Field completeness
# ---------------------------------------------------------------------------
$coreFields = @('timestamp', 'hostname', 'platform', 'source_type', 'channel', 'event_id', 'event_category', 'provider', 'raw_message')
$eventsWithAllCoreFields = @($events | Where-Object {
    $e = $_
    -not ($coreFields | Where-Object { -not (Test-HasValue $e.$_) })
}).Count
$requiredFieldCompleteness = [math]::Round(($eventsWithAllCoreFields / $totalEvents) * 100, 2)
 
# Process events: Sysmon EID 1 and Security 4688
$processEvents = @($events | Where-Object {
    ($_.source_type -eq 'sysmon' -and $_.event_id -eq 1) -or ($_.source_type -eq 'security' -and $_.event_id -eq 4688)
})
$commandLineComplete = @($processEvents | Where-Object { Test-HasValue $_.enrichment.command_line }).Count
$commandLineCompleteness = if ($processEvents.Count -gt 0) { [math]::Round(($commandLineComplete / $processEvents.Count) * 100, 2) } else { $null }
 
# Logon events: Security 4624 and 4625
$logonEvents = @($events | Where-Object {
    $_.source_type -eq 'security' -and ($_.event_id -eq 4624 -or $_.event_id -eq 4625)
})
$sourceIpComplete = @($logonEvents | Where-Object { Test-HasValue $_.enrichment.source_ip }).Count
$sourceIpCompleteness = if ($logonEvents.Count -gt 0) { [math]::Round(($sourceIpComplete / $logonEvents.Count) * 100, 2) } else { $null }
 
# PowerShell script block events: 4104
$scriptBlockEvents = @($events | Where-Object { $_.source_type -eq 'powershell' -and $_.event_id -eq 4104 })
$scriptBlockComplete = @($scriptBlockEvents | Where-Object { Test-HasValue $_.enrichment.decoded_script_block }).Count
$scriptBlockCompleteness = if ($scriptBlockEvents.Count -gt 0) { [math]::Round(($scriptBlockComplete / $scriptBlockEvents.Count) * 100, 2) } else { $null }
 
if ($null -ne $commandLineCompleteness) { Write-Host "Command-line completeness: $commandLineCompleteness%" }
if ($null -ne $sourceIpCompleteness) { Write-Host "Source IP completeness: $sourceIpCompleteness%" }
if ($null -ne $scriptBlockCompleteness) { Write-Host "Script block completeness: $scriptBlockCompleteness%" }
 
# ---------------------------------------------------------------------------
# 6. Quality score
#    NOTE: these weights are a practical scoring convention devised for this
#    task, not an external industry-standard formula. Document/adjust them
#    if your program expects a different weighting.
#      - Time coverage (hours with events / total hours): 25%
#      - Gap penalty (based on largest gap relative to the window): 15%
#      - Required field completeness: 20%
#      - Command-line completeness: 15%
#      - Source IP completeness: 15%
#      - Script block completeness: 10%
#    A dimension with no applicable events (Count = 0) is excluded and the
#    remaining weights are rescaled proportionally, so a quiet channel does
#    not unfairly drag the score down.
# ---------------------------------------------------------------------------
$timeCoveragePct = [math]::Round(($hoursWithEvents / $hourBuckets.Count) * 100, 2)
$gapPenaltyPct = [math]::Max(0, 100 - ([math]::Min(100, $largestGapMinutes)))
 
$components = New-Object System.Collections.Generic.List[PSObject]
$components.Add([PSCustomObject]@{ name = "time_coverage"; weight = 25; value = $timeCoveragePct })
$components.Add([PSCustomObject]@{ name = "gap_penalty"; weight = 15; value = $gapPenaltyPct })
$components.Add([PSCustomObject]@{ name = "required_fields"; weight = 20; value = $requiredFieldCompleteness })
if ($null -ne $commandLineCompleteness) { $components.Add([PSCustomObject]@{ name = "command_line"; weight = 15; value = $commandLineCompleteness }) }
if ($null -ne $sourceIpCompleteness) { $components.Add([PSCustomObject]@{ name = "source_ip"; weight = 15; value = $sourceIpCompleteness }) }
if ($null -ne $scriptBlockCompleteness) { $components.Add([PSCustomObject]@{ name = "script_block"; weight = 10; value = $scriptBlockCompleteness }) }
 
$totalWeight = ($components | Measure-Object -Property weight -Sum).Sum
$weightedSum = 0
foreach ($c in $components) { $weightedSum += ($c.value * $c.weight) }
$qualityScore = if ($totalWeight -gt 0) { [math]::Round($weightedSum / $totalWeight, 1) } else { 0 }
 
$assessment = if ($qualityScore -ge 90) { "good" } elseif ($qualityScore -ge 75) { "acceptable" } else { "poor" }
Write-Host "Quality score: $qualityScore% ($assessment)"
 
# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
$report = [PSCustomObject]@{
    generated               = (Get-Date).ToString("o")
    source_file              = $InputPath
    total_events             = $totalEvents
    event_distribution        = $eventDistribution
    channel_distribution      = $channelDistribution
    time_coverage             = [PSCustomObject]@{
        hours_with_events    = $hoursWithEvents
        hours_without_events = $hoursWithoutEvents
        total_hours          = $hourBuckets.Count
        events_per_hour      = $eventsPerHour
    }
    gaps                      = [PSCustomObject]@{
        threshold_minutes = $GapThresholdMinutes
        count             = $gaps.Count
        largest_gap_minutes = $largestGapMinutes
        details           = $gaps
    }
    field_completeness         = [PSCustomObject]@{
        required_fields_pct    = $requiredFieldCompleteness
        command_line_pct       = $commandLineCompleteness
        source_ip_pct          = $sourceIpCompleteness
        script_block_pct       = $scriptBlockCompleteness
    }
    quality_score              = $qualityScore
    assessment                 = $assessment
    score_components           = $components
}
 
$report | ConvertTo-Json -Depth 8 | Out-File -FilePath $OutputPath -Encoding utf8
 
Write-Host "Report saved to: $(Split-Path -Path $OutputPath -Leaf)"
