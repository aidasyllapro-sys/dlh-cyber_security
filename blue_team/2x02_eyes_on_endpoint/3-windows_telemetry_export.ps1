<#
script name : 3-windows_telemetry_export.ps1
purpose     : Export Windows telemetry (Security, Sysmon Operational, and
              PowerShell Operational logs) from a configurable time window
              (default: last 24 hours) into a single normalized JSON file.
              Every event gets a common set of fields (timestamp, hostname,
              platform, source_type, channel, event_id, event_category,
              provider, raw_message); key event types (Security 4624/4625/
              4672/4688, PowerShell 4104, Sysmon 1/3/11/13/22) also get an
              event-specific enrichment block with decoded/parsed detail.
              Prints counts per channel and the top Event IDs observed.
author      : Aïda Sylla
date        : 2026-08-09
#>
 
param(
    [int]$HoursBack = 24,
    [datetime]$EndTime = (Get-Date),
    [string]$OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath "windows_events_export.json")
)
 
Set-StrictMode -Version Latest
 
$Hostname = $env:COMPUTERNAME
$StartTime = $EndTime.AddHours(-$HoursBack)
$WindowEnd = $EndTime
 
Write-Host "[*] Exporting Windows telemetry from last $HoursBack hours..."
 
# ---------------------------------------------------------------------------
# Pull events for one channel/log, tolerating "no events found" as an empty
# result rather than a fatal error (a quiet log is a valid outcome, not a
# broken query). Both StartTime and EndTime bound the query so the window is
# fully configurable, not just open-ended from StartTime onward.
# ---------------------------------------------------------------------------
function Get-ChannelEvents {
    param(
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][datetime]$StartTime,
        [Parameter(Mandatory)][datetime]$EndTime
    )
    try {
        return @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; StartTime = $StartTime; EndTime = $EndTime } -ErrorAction Stop)
    } catch {
        if ($_.Exception.Message -match "No events were found") {
            return @()
        }
        Write-Warning "Failed to query log '$LogName': $($_.Exception.Message)"
        return @()
    }
}
 
# ---------------------------------------------------------------------------
# Flatten an event's <EventData><Data Name="..."> elements into a hashtable.
# ---------------------------------------------------------------------------
function Get-EventDataHash {
    param($XmlEvent)
    $hash = @{}
    if ($XmlEvent.Event.EventData -and $XmlEvent.Event.EventData.Data) {
        foreach ($d in @($XmlEvent.Event.EventData.Data)) {
            if ($d.Name) {
                $hash[$d.Name] = $d.'#text'
            } else {
                $hash['Data'] = $d.'#text'
            }
        }
    }
    return $hash
}
 
function Get-HashValue {
    param($Hash, [string]$Key)
    if ($Hash.ContainsKey($Key)) { return $Hash[$Key] }
    return $null
}
 
# ---------------------------------------------------------------------------
# Build one normalized, enriched record from a raw event.
# ---------------------------------------------------------------------------
function ConvertTo-NormalizedRecord {
    param(
        [Parameter(Mandatory)]$Event,
        [Parameter(Mandatory)][string]$SourceType,
        [Parameter(Mandatory)][string]$Channel
    )
 
    $xml = [xml]$Event.ToXml()
    $data = Get-EventDataHash -XmlEvent $xml
 
    $record = [ordered]@{
        timestamp      = $Event.TimeCreated.ToUniversalTime().ToString("o")
        hostname       = $Hostname
        platform       = "windows"
        source_type    = $SourceType
        channel        = $Channel
        event_id       = $Event.Id
        event_category = if ($Event.TaskDisplayName) { $Event.TaskDisplayName } else { "Unknown" }
        provider       = $Event.ProviderName
        raw_message    = $Event.Message
    }
 
    $enrichment = $null
 
    if ($SourceType -eq "security") {
        switch ($Event.Id) {
            4624 {
                $enrichment = [ordered]@{
                    target_user = Get-HashValue $data 'TargetUserName'
                    logon_type  = Get-HashValue $data 'LogonType'
                    source_ip   = Get-HashValue $data 'IpAddress'
                    workstation = Get-HashValue $data 'WorkstationName'
                }
            }
            4625 {
                $enrichment = [ordered]@{
                    target_user    = Get-HashValue $data 'TargetUserName'
                    failure_reason = Get-HashValue $data 'FailureReason'
                    source_ip      = Get-HashValue $data 'IpAddress'
                }
            }
            4672 {
                $enrichment = [ordered]@{
                    privileged_account = Get-HashValue $data 'SubjectUserName'
                }
            }
            4688 {
                $enrichment = [ordered]@{
                    process_name   = Get-HashValue $data 'NewProcessName'
                    command_line   = Get-HashValue $data 'CommandLine'
                    parent_process = Get-HashValue $data 'ParentProcessName'
                }
            }
        }
    } elseif ($SourceType -eq "sysmon") {
        switch ($Event.Id) {
            1 {
                $enrichment = [ordered]@{
                    image        = Get-HashValue $data 'Image'
                    command_line = Get-HashValue $data 'CommandLine'
                    parent_image = Get-HashValue $data 'ParentImage'
                    hashes       = Get-HashValue $data 'Hashes'
                }
            }
            3 {
                $enrichment = [ordered]@{
                    destination_ip   = Get-HashValue $data 'DestinationIp'
                    destination_port = Get-HashValue $data 'DestinationPort'
                    process          = Get-HashValue $data 'Image'
                }
            }
            11 {
                $enrichment = [ordered]@{
                    target_filename  = Get-HashValue $data 'TargetFilename'
                    creating_process = Get-HashValue $data 'Image'
                }
            }
            13 {
                # NOTE: Sysmon's TargetObject for a RegistryEvent (Value Set)
                # is the full path INCLUDING the value name - there is no
                # separate native field for the value name alone. This script
                # splits TargetObject on its final backslash as a practical
                # convention (registry key = everything before it, value
                # name = the final segment), not a field Sysmon exposes
                # natively.
                $targetObject = Get-HashValue $data 'TargetObject'
                $registryKey = $null
                $valueName = $null
                if ($targetObject) {
                    $lastSlash = $targetObject.LastIndexOf('\')
                    if ($lastSlash -gt 0) {
                        $registryKey = $targetObject.Substring(0, $lastSlash)
                        $valueName = $targetObject.Substring($lastSlash + 1)
                    } else {
                        $registryKey = $targetObject
                    }
                }
                $enrichment = [ordered]@{
                    registry_key = $registryKey
                    value_name   = $valueName
                }
            }
            22 {
                $enrichment = [ordered]@{
                    query_name    = Get-HashValue $data 'QueryName'
                    query_results = Get-HashValue $data 'QueryResults'
                }
            }
        }
    } elseif ($SourceType -eq "powershell" -and $Event.Id -eq 4104) {
        # ScriptBlockText is already the decoded plaintext, even when the
        # original invocation used an encoded/obfuscated command.
        $enrichment = [ordered]@{
            decoded_script_block = Get-HashValue $data 'ScriptBlockText'
        }
    }
 
    if ($enrichment) {
        $record['enrichment'] = $enrichment
    }
 
    return [PSCustomObject]$record
}
 
# ---------------------------------------------------------------------------
# Pull and normalize each channel
# ---------------------------------------------------------------------------
$securityEvents = Get-ChannelEvents -LogName "Security" -StartTime $StartTime -EndTime $EndTime
$sysmonEvents = Get-ChannelEvents -LogName "Microsoft-Windows-Sysmon/Operational" -StartTime $StartTime -EndTime $EndTime
$psEvents = Get-ChannelEvents -LogName "Microsoft-Windows-PowerShell/Operational" -StartTime $StartTime -EndTime $EndTime
 
$allRecords = New-Object System.Collections.Generic.List[PSObject]
foreach ($e in $securityEvents) { $allRecords.Add((ConvertTo-NormalizedRecord -Event $e -SourceType "security" -Channel "Security")) }
foreach ($e in $sysmonEvents) { $allRecords.Add((ConvertTo-NormalizedRecord -Event $e -SourceType "sysmon" -Channel "Microsoft-Windows-Sysmon/Operational")) }
foreach ($e in $psEvents) { $allRecords.Add((ConvertTo-NormalizedRecord -Event $e -SourceType "powershell" -Channel "Microsoft-Windows-PowerShell/Operational")) }
 
$totalEvents = $allRecords.Count
 
Write-Host "Security events: $($securityEvents.Count)"
Write-Host "Sysmon events: $($sysmonEvents.Count)"
Write-Host "PowerShell events: $($psEvents.Count)"
Write-Host "Total events: $totalEvents"
 
# ---------------------------------------------------------------------------
# Top Event IDs - Sysmon IDs are prefixed ("Sysmon-1") since raw numeric IDs
# overlap across channels (e.g. Sysmon Event ID 1 vs Security Event ID 1).
# ---------------------------------------------------------------------------
$topN = 5
$idLabelGroups = $allRecords | Group-Object {
    if ($_.source_type -eq 'sysmon') { "Sysmon-$($_.event_id)" } else { "$($_.event_id)" }
} | Sort-Object Count -Descending
 
$topLabels = @($idLabelGroups | Select-Object -First $topN -ExpandProperty Name)
Write-Host "Top Event IDs: $($topLabels -join ', ')"
 
# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
$report = [PSCustomObject]@{
    generated    = (Get-Date).ToString("o")
    window_start = $StartTime.ToUniversalTime().ToString("o")
    window_end   = $WindowEnd.ToUniversalTime().ToString("o")
    hostname     = $Hostname
    counts       = [PSCustomObject]@{
        security   = $securityEvents.Count
        sysmon     = $sysmonEvents.Count
        powershell = $psEvents.Count
        total      = $totalEvents
    }
    top_event_ids = $topLabels
    events         = $allRecords
}
 
$report | ConvertTo-Json -Depth 8 | Out-File -FilePath $OutputPath -Encoding utf8
 
Write-Host "Output: $(Split-Path -Path $OutputPath -Leaf)"
