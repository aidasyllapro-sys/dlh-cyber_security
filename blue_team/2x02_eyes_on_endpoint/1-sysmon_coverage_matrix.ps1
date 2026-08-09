<#
script name : 1-sysmon_coverage_matrix.ps1
purpose     : Parse sysmonconfig.xml to determine which Sysmon Event IDs are
              enabled, detect include/exclude filter conditions that could
              suppress relevant events, map that configuration state against
              a minimum set of MITRE ATT&CK techniques, and produce a
              structured coverage matrix (covered / partial / blind) with a
              reason and a recommended tuning action for every gap, saved to
              sysmon_coverage_matrix.json.
author      : Aïda Sylla
date        : 2026-08-09
#>
 
Set-StrictMode -Version Latest
 
$ConfigPath = Join-Path -Path $PSScriptRoot -ChildPath "sysmonconfig.xml"
$OutputPath = Join-Path -Path $PSScriptRoot -ChildPath "sysmon_coverage_matrix.json"
 
Write-Host "[*] Parsing Sysmon config: sysmonconfig.xml"
 
if (-not (Test-Path $ConfigPath)) {
    Write-Error "sysmonconfig.xml not found at $ConfigPath. Place the deployed Sysmon config next to this script (or update `$ConfigPath`) before running."
    exit 1
}
 
try {
    [xml]$xmlConfig = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop
} catch {
    Write-Error "Failed to parse sysmonconfig.xml as XML: $($_.Exception.Message)"
    exit 1
}
 
$eventFilteringNode = $xmlConfig.SelectSingleNode("//EventFiltering")
if (-not $eventFilteringNode) {
    Write-Error "No <EventFiltering> section found in sysmonconfig.xml. Cannot assess coverage."
    exit 1
}
 
# ---------------------------------------------------------------------------
# Sysmon config element name -> Event ID(s) it controls.
# NOTE: RegistryEvent covers Event IDs 12 (CreateKey/DeleteKey), 13 (SetValue)
# and 14 (RenameKey) collectively - the config schema does not let a single
# <RegistryEvent> block distinguish which of the three actually fires without
# inspecting each Rule's EventType attribute individually. This script treats
# RegistryEvent as enabling 12/13/14 together, which is the common case for a
# baseline config; verify against your actual rule set if precision on EID 13
# specifically matters.
# ---------------------------------------------------------------------------
$ElementToEventIds = [ordered]@{
    "ProcessCreate"        = @(1)
    "FileCreateTime"       = @(2)
    "NetworkConnect"       = @(3)
    "ProcessTerminate"     = @(5)
    "DriverLoad"           = @(6)
    "ImageLoad"            = @(7)
    "CreateRemoteThread"   = @(8)
    "RawAccessRead"        = @(9)
    "ProcessAccess"        = @(10)
    "FileCreate"           = @(11)
    "RegistryEvent"        = @(12, 13, 14)
    "FileCreateStreamHash" = @(15)
    "PipeEvent"            = @(17, 18)
    "WmiEvent"             = @(19, 20, 21)
    "DnsQuery"             = @(22)
    "FileDelete"           = @(23, 26)
    "ClipboardChange"      = @(24)
    "ProcessTampering"     = @(25)
}
 
# ---------------------------------------------------------------------------
# Inspect each known element anywhere under <EventFiltering> (elements are
# typically nested inside one or more <RuleGroup> wrappers).
# ---------------------------------------------------------------------------
$ConfigElements = @{}
foreach ($elementName in $ElementToEventIds.Keys) {
    $nodes = $eventFilteringNode.SelectNodes(".//$elementName")
    if ($nodes.Count -gt 0) {
        $onmatchValues = New-Object System.Collections.Generic.List[string]
        $conditionCount = 0
        foreach ($node in $nodes) {
            if ($node.Attributes -and $node.Attributes['onmatch']) {
                $onmatchValues.Add($node.Attributes['onmatch'].Value)
            }
            $conditionCount += @($node.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element }).Count
        }
        $ConfigElements[$elementName] = [PSCustomObject]@{
            Present        = $true
            OnMatchValues  = $onmatchValues
            ConditionCount = $conditionCount
        }
    } else {
        $ConfigElements[$elementName] = [PSCustomObject]@{
            Present        = $false
            OnMatchValues  = New-Object System.Collections.Generic.List[string]
            ConditionCount = 0
        }
    }
}
 
# ---------------------------------------------------------------------------
# Build the set of enabled Event IDs from every present element.
# ---------------------------------------------------------------------------
$EnabledIds = New-Object System.Collections.Generic.HashSet[int]
foreach ($elementName in $ConfigElements.Keys) {
    if ($ConfigElements[$elementName].Present) {
        foreach ($id in $ElementToEventIds[$elementName]) {
            [void]$EnabledIds.Add($id)
        }
    }
}
$EnabledIdsSorted = $EnabledIds | Sort-Object
Write-Host "Enabled Event IDs: $($EnabledIdsSorted -join ', ')"
 
# ---------------------------------------------------------------------------
# Filter conflict note per config element - describes include/exclude risk.
# ---------------------------------------------------------------------------
function Get-FilterConflictNote {
    param([Parameter(Mandatory)][string]$ElementName)
    $info = $ConfigElements[$ElementName]
    if (-not $info.Present) {
        return "$ElementName not present in config - event type not enabled."
    }
    if ($info.OnMatchValues -contains "include" -and $info.ConditionCount -gt 0) {
        return "$ElementName uses onmatch=`"include`" with $($info.ConditionCount) condition(s): only matching events are captured, everything else in this category is dropped."
    }
    if ($info.ConditionCount -gt 0) {
        return "$ElementName has $($info.ConditionCount) exclude condition(s): verify they do not suppress technique-relevant activity."
    }
    return "$ElementName enabled with no filtering conditions."
}
 
function Test-IncludeOnlyConflict {
    param([Parameter(Mandatory)][string[]]$ElementNames)
    foreach ($elementName in $ElementNames) {
        $info = $ConfigElements[$elementName]
        if ($info.Present -and $info.OnMatchValues -contains "include" -and $info.ConditionCount -gt 0) {
            return $true
        }
    }
    return $false
}
 
# ---------------------------------------------------------------------------
# Minimum ATT&CK technique -> required Sysmon Event ID(s) / config element(s)
# mapping, with the fields an analyst needs for triage on each event type.
# ---------------------------------------------------------------------------
$Techniques = @(
    [PSCustomObject]@{ Id = "T1059";     Name = "Command and Scripting Interpreter";      RequiredEids = @(1);     Elements = @("ProcessCreate");                        EvidenceFields = @("Image", "CommandLine", "ParentImage", "ParentCommandLine", "User", "Hashes") }
    [PSCustomObject]@{ Id = "T1053";     Name = "Scheduled Task/Job";                     RequiredEids = @(1);     Elements = @("ProcessCreate");                        EvidenceFields = @("Image", "CommandLine", "ParentImage", "User") }
    [PSCustomObject]@{ Id = "T1547";     Name = "Boot or Logon Autostart Execution";      RequiredEids = @(13);    Elements = @("RegistryEvent");                        EvidenceFields = @("TargetObject", "Details", "Image", "EventType") }
    [PSCustomObject]@{ Id = "T1055";     Name = "Process Injection";                      RequiredEids = @(8, 10); Elements = @("CreateRemoteThread", "ProcessAccess");  EvidenceFields = @("SourceImage", "TargetImage", "GrantedAccess", "CallTrace") }
    [PSCustomObject]@{ Id = "T1071";     Name = "Application Layer Protocol";             RequiredEids = @(3, 22); Elements = @("NetworkConnect", "DnsQuery");           EvidenceFields = @("DestinationIp", "DestinationPort", "Image", "QueryName", "QueryResults") }
    [PSCustomObject]@{ Id = "T1574.002"; Name = "DLL Side-Loading";                       RequiredEids = @(7);     Elements = @("ImageLoad");                            EvidenceFields = @("ImageLoaded", "Signed", "SignatureStatus", "Image") }
    [PSCustomObject]@{ Id = "T1027";     Name = "Obfuscated or Compressed Files or Info"; RequiredEids = @(11, 15);Elements = @("FileCreate", "FileCreateStreamHash");   EvidenceFields = @("TargetFilename", "Hashes", "Hash") }
)
 
# ---------------------------------------------------------------------------
# Evaluate coverage per technique
# ---------------------------------------------------------------------------
$Matrix = foreach ($technique in $Techniques) {
    $required = $technique.RequiredEids
    $enabledForTechnique = @($required | Where-Object { $EnabledIds.Contains($_) })
    $missing = @($required | Where-Object { -not $EnabledIds.Contains($_) })
    $filterConflicts = @($technique.Elements | ForEach-Object { Get-FilterConflictNote -ElementName $_ })
    $includeOnlyConflict = Test-IncludeOnlyConflict -ElementNames $technique.Elements
 
    if ($missing.Count -eq $required.Count) {
        $status = "blind"
        $reason = "None of the required Event ID(s) ($($required -join ', ')) are enabled in the current Sysmon configuration."
        $recommendation = "Enable $($technique.Elements -join ' and ') in sysmonconfig.xml (e.g. onmatch=`"exclude`" with a minimal, deliberate exclusion list) to start capturing this technique."
    } elseif ($missing.Count -gt 0) {
        $status = "partial"
        $reason = "Required Event ID(s) $($missing -join ', ') are not enabled; only $($enabledForTechnique -join ', ') currently fire for this technique."
        $recommendation = "Enable the missing element(s) covering Event ID(s) $($missing -join ', '): $($technique.Elements -join ', ')."
    } elseif ($includeOnlyConflict) {
        $status = "partial"
        $reason = "All required Event ID(s) ($($required -join ', ')) are enabled, but an onmatch=`"include`" filter restricts capture to specific conditions, which may miss real-world variants of this technique."
        $recommendation = "Review the include conditions on $($technique.Elements -join ', ') and broaden them, or switch to onmatch=`"exclude`" with a targeted, documented exclusion list instead."
    } else {
        $status = "covered"
        $reason = "All required Event ID(s) ($($required -join ', ')) are enabled without a restrictive include-only filter."
        $recommendation = "None - coverage confirmed by configuration review. Re-validate periodically with a controlled simulation (see 0-sysmon_validation.ps1)."
    }
 
    [PSCustomObject]@{
        technique_id              = $technique.Id
        technique_name            = $technique.Name
        required_event_ids        = $required
        enabled_event_ids         = $enabledForTechnique
        filter_conflicts          = $filterConflicts
        coverage_status           = $status
        evidence_fields_expected  = $technique.EvidenceFields
        reason                    = $reason
        recommendation            = $recommendation
    }
}
 
# ---------------------------------------------------------------------------
# Summary + export
# ---------------------------------------------------------------------------
$coveredCount = @($Matrix | Where-Object coverage_status -eq "covered").Count
$partialCount = @($Matrix | Where-Object coverage_status -eq "partial").Count
$blindCount   = @($Matrix | Where-Object coverage_status -eq "blind").Count
 
Write-Host "Techniques assessed: $($Matrix.Count)"
Write-Host "Covered: $coveredCount"
Write-Host "Partial: $partialCount"
Write-Host "Blind: $blindCount"
 
$report = [PSCustomObject]@{
    generated              = (Get-Date).ToString("o")
    config_source          = $ConfigPath
    enabled_event_ids      = $EnabledIdsSorted
    techniques_assessed    = $Matrix.Count
    covered                = $coveredCount
    partial                = $partialCount
    blind                  = $blindCount
    matrix                 = $Matrix
}
 
$report | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutputPath -Encoding utf8
 
Write-Host "Report saved to: sysmon_coverage_matrix.json"
