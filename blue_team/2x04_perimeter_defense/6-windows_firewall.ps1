<#
.SYNOPSIS
    Aligns Windows Firewall on this domain-joined host to the MedDefense
    segmentation design, and exports the resulting rules as structured
    JSON for downstream comparison against the nftables ruleset.

.DESCRIPTION
    Reads segmentation_rules.json (Task 2's contract, the same file
    4-nftables_config.sh reads) so nftables and Windows Firewall enforce
    the same zone model from a single source of truth. For every
    Domain/Private/Public profile, sets DefaultInboundAction=Block and
    DefaultOutboundAction=Allow, and enables blocked-connection logging.
    Removes every pre-existing rule whose DisplayName starts with
    "MedDefense-" before recreating the set, so the script is idempotent -
    running it twice produces the same ruleset, not a duplicate one.
    Creates one inbound allow rule per flow that terminates on this host
    (the same dst_zone == HostZone filter 4-nftables_config.sh's input
    chain uses, so both platforms answer "should this host accept this
    flow" identically), then exports every MedDefense-* rule (with its
    port and address filters) to windows_firewall_rules.json.

.NOTES
    Author: Aïda Sylla
    Date:   2026-08-17

    ASSUMPTION - HostZone: like 4-nftables_config.sh on the Linux side,
    segmentation_rules.json describes the whole MedDefense zone model but
    does not itself say which zone THIS specific Windows host belongs to.
    Defaults to "INTERNAL" below for consistency with the Linux script's
    own default - override with -HostZone <ZONE> if this host belongs to
    a different zone. Getting this wrong means this host's Windows
    Firewall will not admit the traffic it should, or will admit traffic
    it shouldn't - exactly the same risk 4-nftables_config.sh's own
    HostZone assumption carries on the Linux side.

    NOT YET VALIDATED AGAINST A REAL WINDOWS HOST: this script could not
    be executed or checked with PSScriptAnalyzer in the environment it
    was written in (no pwsh available, no network to install it). Test
    it first against an isolated, non-production Windows machine before
    running it against any domain-joined host that matters - the same
    caution 4-nftables_config.sh's own real SSH-lockout incident on
    billing-srv-01 already demonstrated is worth taking seriously here
    too, since a wrong DefaultInboundAction=Block can just as easily cut
    off RDP/WinRM access as a wrong nftables rule cuts off SSH.

.PARAMETER SegmentationRulesPath
    Path to segmentation_rules.json. Defaults to a file of that name in
    the same directory as this script.

.PARAMETER HostZone
    Which MedDefense zone this Windows host belongs to. Defaults to
    "INTERNAL" (see ASSUMPTION above).

.PARAMETER OutputPath
    Where to write the exported rules JSON. Defaults to
    windows_firewall_rules.json in the same directory as this script.

.EXAMPLE
    PS> .\6-windows_firewall.ps1
    PS> .\6-windows_firewall.ps1 -HostZone MGMT
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SegmentationRulesPath = (Join-Path -Path $PSScriptRoot -ChildPath 'segmentation_rules.json'),

    [Parameter(Mandatory = $false)]
    [string]$HostZone = 'INTERNAL',

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath 'windows_firewall_rules.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Status {
    # A single, consistent [*]/indented-line status writer, matching this
    # project's established console-output style across every prior
    # bash script, so a MedDefense analyst reads the same shape of output
    # regardless of which platform's script produced it.
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [switch]$Indent
    )
    if ($Indent) {
        Write-Host "  $Message"
    }
    else {
        Write-Host "[*] $Message"
    }
}

# ---------------------------------------------------------------------------
# 1. Read segmentation_rules.json.
# ---------------------------------------------------------------------------
Write-Status 'Reading segmentation_rules.json...'

if (-not (Test-Path -Path $SegmentationRulesPath)) {
    Write-Error "segmentation_rules.json not found at $SegmentationRulesPath. Run 2-segmentation_rules.sh (or copy its output here) first."
    exit 1
}

try {
    $rules = Get-Content -Path $SegmentationRulesPath -Raw | ConvertFrom-Json
}
catch {
    Write-Error "segmentation_rules.json is not valid JSON: $SegmentationRulesPath. $($_.Exception.Message)"
    exit 1
}

if (-not $rules.zones -or -not $rules.flows) {
    Write-Error "segmentation_rules.json is missing the expected 'zones' or 'flows' arrays."
    exit 1
}

# Build a zone-name -> CIDR lookup once, used both to render RemoteAddress
# per flow and to resolve a flow's own dst_zone check below.
$zoneCidrByName = @{}
foreach ($zone in $rules.zones) {
    $zoneCidrByName[$zone.name] = $zone.cidr
}

# ---------------------------------------------------------------------------
# 2. Profile defaults: DefaultInboundAction=Block, DefaultOutboundAction=Allow,
#    for every profile, with blocked-connection logging enabled.
# ---------------------------------------------------------------------------
Write-Status 'Setting profile defaults...'

$profileNames = @('Domain', 'Private', 'Public')
$logFileName = '%systemroot%\system32\LogFiles\Firewall\meddefense.log'

foreach ($profileName in $profileNames) {
    try {
        Set-NetFirewallProfile -Profile $profileName `
            -DefaultInboundAction Block `
            -DefaultOutboundAction Allow `
            -LogBlocked True `
            -LogFileName $logFileName `
            -ErrorAction Stop
        Write-Status ("{0,-8} DefaultInboundAction=Block  LogBlocked=True   [SET]" -f "${profileName}:") -Indent
    }
    catch {
        Write-Status ("{0,-8} FAILED: $($_.Exception.Message)" -f "${profileName}:") -Indent
        throw
    }
}

# ---------------------------------------------------------------------------
# 4. Remove any pre-existing MedDefense-* rule before recreating, so the
#    script is idempotent - a second run converges to the same ruleset
#    rather than layering duplicate rules on top of the previous run.
# ---------------------------------------------------------------------------
$existingRules = @(Get-NetFirewallRule -DisplayName 'MedDefense-*' -ErrorAction SilentlyContinue)
$removedCount = $existingRules.Count

Write-Status "Clearing previous MedDefense-* rules...              [$removedCount removed]"

if ($removedCount -gt 0) {
    $existingRules | Remove-NetFirewallRule -ErrorAction Stop
}

# ---------------------------------------------------------------------------
# 3. Create one inbound allow rule per flow that terminates on this host
#    (dst_zone == HostZone) - the same filter 4-nftables_config.sh's own
#    input-chain rendering uses, so both platforms agree on what "a flow
#    that terminates on this host" means.
# ---------------------------------------------------------------------------
Write-Status 'Creating rules from flow matrix...'

$inboundFlows = @($rules.flows | Where-Object { $_.dst_zone -eq $HostZone })
$createdRules = @()

foreach ($flow in $inboundFlows) {
    $srcZone = $flow.src_zone
    $proto = $flow.proto
    $dport = $flow.dport

    # "ALL" is a DNS-only wildcard source in this schema (Task 2), not a
    # real zone with a CIDR - render it as any remote address rather than
    # looking up a zone that does not exist.
    if ($srcZone -eq 'ALL') {
        $remoteAddress = 'Any'
    }
    elseif ($zoneCidrByName.ContainsKey($srcZone)) {
        $remoteAddress = $zoneCidrByName[$srcZone]
    }
    else {
        Write-Warning "Flow references unknown src_zone '$srcZone' - skipping (no CIDR to bind RemoteAddress to)."
        continue
    }

    $protoUpper = $proto.ToUpperInvariant()
    $displayName = "MedDefense-$srcZone-$protoUpper-$dport"

    try {
        New-NetFirewallRule -DisplayName $displayName `
            -Direction Inbound `
            -Action Allow `
            -Protocol $protoUpper `
            -LocalPort $dport `
            -RemoteAddress $remoteAddress `
            -Profile Any `
            -ErrorAction Stop | Out-Null

        $line = "{0,-28} Inbound Allow {1} {2}" -f $displayName, $proto, $dport
        Write-Status ("{0,-46} [CREATED]" -f $line) -Indent

        $createdRules += [PSCustomObject]@{
            display_name   = $displayName
            src_zone       = $srcZone
            dst_zone       = $flow.dst_zone
            proto          = $proto
            dport          = $dport
            remote_address = $remoteAddress
            justification  = $flow.justification
        }
    }
    catch {
        Write-Status ("{0,-28} FAILED: $($_.Exception.Message)" -f $displayName) -Indent
    }
}

# ---------------------------------------------------------------------------
# Export the resulting MedDefense-* ruleset as structured JSON, for
# downstream automation to diff against the nftables side (this task's
# own stated Goal, and this project's own rule that JSON is the
# deliverable format for every tracking task).
# ---------------------------------------------------------------------------
$exportedRules = @()
$liveMedDefenseRules = @(Get-NetFirewallRule -DisplayName 'MedDefense-*' -ErrorAction SilentlyContinue)

foreach ($liveRule in $liveMedDefenseRules) {
    $portFilter = $liveRule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    $addressFilter = $liveRule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue

    $exportedRules += [PSCustomObject]@{
        display_name    = $liveRule.DisplayName
        direction       = $liveRule.Direction.ToString()
        action          = $liveRule.Action.ToString()
        enabled         = $liveRule.Enabled.ToString()
        profile         = $liveRule.Profile.ToString()
        protocol        = if ($portFilter) { $portFilter.Protocol } else { $null }
        local_port      = if ($portFilter) { $portFilter.LocalPort } else { $null }
        remote_address  = if ($addressFilter) { $addressFilter.RemoteAddress } else { $null }
    }
}

$exportPayload = [PSCustomObject]@{
    generated_at         = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname             = $env:COMPUTERNAME
    host_zone            = $HostZone
    profile_defaults_set = $profileNames
    rules_removed_before = $removedCount
    rules_created        = $createdRules.Count
    rules                = $exportedRules
}

$exportPayload | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding utf8

Write-Host ""
Write-Host "Rules created: $($createdRules.Count)   Rules removed (pre-existing): $removedCount"
Write-Host "Report saved to: $(Split-Path -Leaf $OutputPath)"

exit 0
