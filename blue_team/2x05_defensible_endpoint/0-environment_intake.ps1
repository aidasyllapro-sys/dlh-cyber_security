<#
.SYNOPSIS
    Captures the complete unhardened baseline of hawthorne-adm-01
    (Windows) before any hardening action.
 
.DESCRIPTION
    Records hostname/OS build/patch level, installed feature count,
    running services, local user accounts, Windows Firewall state per
    profile, audit policy summary, Sysmon presence, PowerShell Script
    Block Logging state, and account lockout/password policy. This
    script never changes anything - it only observes and records, the
    exact Windows-side counterpart to 0-environment_intake.sh on
    hawthorne-app-01. Every later capstone task measures its success
    against the delta between this snapshot and the post-hardening
    state.
 
.NOTES
    Author: Aïda Sylla
    Date:   2026-08-22
 
    EXIT CODES (documented, per this capstone's own rule):
      0 - intake captured successfully
      1 - controlled failure (reserved for a future consistency check
          on the output itself; not expected for a pure-capture script)
      2 - environment error (a required cmdlet/module is missing)
 
    NOT YET VALIDATED AGAINST A REAL WINDOWS HOST: this script was
    written in an environment with no pwsh, no Windows-only cmdlets
    (NetSecurity, LocalAccounts) and no network to test against. Every
    cmdlet call is wrapped so a missing one degrades the corresponding
    field to null/empty rather than crashing the whole capture, but that
    is not the same as having confirmed the real output shape on
    hawthorne-adm-01 - test this first against an isolated, non-critical
    Windows machine, the same caution this project's own prior Windows
    Firewall script (2x04) was given.
 
.EXAMPLE
    PS> .\0-environment_intake.ps1
#>
 
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath 'environment_intake_windows.json')
)
 
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
 
function Write-Status {
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
 
function Invoke-SafeCommand {
    # Wraps a scriptblock so a missing cmdlet/module (e.g. no
    # Get-WindowsFeature on a client SKU) degrades the corresponding
    # field to $null rather than aborting the entire intake - mirroring
    # the bash script's own approach of recording a legitimate absence
    # rather than crashing.
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [string]$Context = 'command'
    )
    try {
        & $ScriptBlock
    }
    catch {
        Write-Warning "Could not capture ${Context}: $($_.Exception.Message)"
        return $null
    }
}
 
Write-Status 'Capturing hawthorne-adm-01 environment intake...'
 
# ---------------------------------------------------------------------------
# 1. Hostname, OS build and patch level.
# ---------------------------------------------------------------------------
Write-Status 'system identity...' -Indent
$osInfo = Invoke-SafeCommand -Context 'OS info' -ScriptBlock {
    Get-CimInstance -ClassName Win32_OperatingSystem
}
$hostnameVal = $env:COMPUTERNAME
$osBuild = if ($osInfo) { $osInfo.BuildNumber } else { 'unknown' }
$osCaption = if ($osInfo) { $osInfo.Caption } else { 'unknown' }
$lastPatch = Invoke-SafeCommand -Context 'patch level' -ScriptBlock {
    (Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
}
$patchLevelIso = if ($lastPatch) { $lastPatch.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { 'unknown' }
 
# ---------------------------------------------------------------------------
# 2. Installed feature count. Get-WindowsFeature only exists on Server
#    SKUs (RSAT-based); Get-WindowsOptionalFeature is the client-side
#    equivalent - try Server first, fall back to client.
# ---------------------------------------------------------------------------
Write-Status 'feature count...' -Indent
$featureCount = 0
$featureSource = 'none'
if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
    $features = Invoke-SafeCommand -Context 'Windows features (Server)' -ScriptBlock {
        Get-WindowsFeature | Where-Object { $_.InstallState -eq 'Installed' }
    }
    if ($features) { $featureCount = @($features).Count; $featureSource = 'Get-WindowsFeature' }
}
elseif (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
    $features = Invoke-SafeCommand -Context 'Windows optional features (Client)' -ScriptBlock {
        Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq 'Enabled' }
    }
    if ($features) { $featureCount = @($features).Count; $featureSource = 'Get-WindowsOptionalFeature' }
}
 
# ---------------------------------------------------------------------------
# 3. Running services.
# ---------------------------------------------------------------------------
Write-Status 'running services...' -Indent
$runningServices = @(Invoke-SafeCommand -Context 'services' -ScriptBlock {
    Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object -ExpandProperty Name
})
$runningServicesCount = $runningServices.Count
 
# ---------------------------------------------------------------------------
# 4. Local user accounts.
# ---------------------------------------------------------------------------
Write-Status 'local user accounts...' -Indent
$localUsers = @(Invoke-SafeCommand -Context 'local users' -ScriptBlock {
    Get-LocalUser | ForEach-Object {
        [PSCustomObject]@{
            name    = $_.Name
            enabled = $_.Enabled.ToString()
        }
    }
})
 
# ---------------------------------------------------------------------------
# 5. Windows Firewall state per profile.
# ---------------------------------------------------------------------------
Write-Status 'firewall profiles...' -Indent
$firewallProfiles = @(Invoke-SafeCommand -Context 'firewall profiles' -ScriptBlock {
    Get-NetFirewallProfile | ForEach-Object {
        [PSCustomObject]@{
            profile               = $_.Name
            enabled                = $_.Enabled.ToString()
            default_inbound_action = $_.DefaultInboundAction.ToString()
        }
    }
})
 
# ---------------------------------------------------------------------------
# 6. Audit policy summary.
# ---------------------------------------------------------------------------
Write-Status 'audit policy...' -Indent
$auditPolicyRaw = Invoke-SafeCommand -Context 'audit policy' -ScriptBlock {
    auditpol /get /category:* 2>$null
}
$auditPolicyLineCount = if ($auditPolicyRaw) { @($auditPolicyRaw).Count } else { 0 }
 
# ---------------------------------------------------------------------------
# 7. Sysmon presence and version.
# ---------------------------------------------------------------------------
Write-Status 'Sysmon presence...' -Indent
$sysmonService = Invoke-SafeCommand -Context 'Sysmon service' -ScriptBlock {
    Get-Service -Name Sysmon* -ErrorAction Stop
}
$sysmonPresent = [bool]$sysmonService
$sysmonEventChannelSize = $null
if ($sysmonPresent) {
    $sysmonEventChannelSize = Invoke-SafeCommand -Context 'Sysmon event channel size' -ScriptBlock {
        (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop).MaximumSizeInBytes
    }
}
 
# ---------------------------------------------------------------------------
# 8. PowerShell Script Block Logging state (registry).
# ---------------------------------------------------------------------------
Write-Status 'PowerShell logging state...' -Indent
$sbLoggingPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$scriptBlockLoggingEnabled = $false
if (Test-Path $sbLoggingPath) {
    $sbValue = Invoke-SafeCommand -Context 'Script Block Logging registry value' -ScriptBlock {
        (Get-ItemProperty -Path $sbLoggingPath -Name 'EnableScriptBlockLogging' -ErrorAction Stop).EnableScriptBlockLogging
    }
    $scriptBlockLoggingEnabled = ($sbValue -eq 1)
}
 
# ---------------------------------------------------------------------------
# 9. Account lockout and password policy.
# ---------------------------------------------------------------------------
Write-Status 'account policy (net accounts)...' -Indent
$netAccountsRaw = Invoke-SafeCommand -Context 'net accounts' -ScriptBlock {
    net accounts 2>$null
}
$netAccountsLines = @()
if ($netAccountsRaw) {
    foreach ($line in $netAccountsRaw) {
        if ($line -match '^(.+?):\s*(.+)$') {
            $netAccountsLines += [PSCustomObject]@{
                setting = $Matches[1].Trim()
                value   = $Matches[2].Trim()
            }
        }
    }
}
 
# ---------------------------------------------------------------------------
# Emit environment_intake_windows.json
# ---------------------------------------------------------------------------
$intake = [PSCustomObject]@{
    timestamp              = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname                = $hostnameVal
    os_caption              = $osCaption
    os_build                = $osBuild
    patch_level             = $patchLevelIso
    feature_count           = $featureCount
    feature_source          = $featureSource
    running_services        = $runningServices
    running_services_count  = $runningServicesCount
    local_users             = $localUsers
    firewall_profiles       = $firewallProfiles
    audit_policy_line_count = $auditPolicyLineCount
    telemetry               = [PSCustomObject]@{
        sysmon_present            = $sysmonPresent
        sysmon_event_channel_size = $sysmonEventChannelSize
        script_block_logging_enabled = $scriptBlockLoggingEnabled
    }
    account_policy           = $netAccountsLines
}
 
$intake | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding utf8
 
Write-Host ""
Write-Host "Services running: $runningServicesCount   Local users: $($localUsers.Count)   Sysmon present: $sysmonPresent"
Write-Host "Report saved to: $(Split-Path -Leaf $OutputPath)"
 
exit 0
