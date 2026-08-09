<#
    Script name : 0-domain_baseline.ps1
    Purpose     : Read-only security reconnaissance of the MedDefense Active Directory
                  domain (meddefense.local). Produces the Windows equivalent of the
                  2x00 Task 0 Lynis baseline: domain info, users, groups, service
                  accounts, GPOs, password/lockout policy, Kerberos encryption support,
                  privileged accounts, and a severity-ranked findings summary.
    Author      : Aïda Sylla
    Date        : 2026-08-09
#>
 
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
 
# ---------------------------------------------------------------------------
# 0. Module checks
# ---------------------------------------------------------------------------
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "ActiveDirectory module not found. Run this script on DC01 (or a host with RSAT-AD-PowerShell installed)."
    exit 1
}
 
$gpModuleAvailable = $true
try {
    Import-Module GroupPolicy -ErrorAction Stop
} catch {
    $gpModuleAvailable = $false
    Write-Warning "GroupPolicy module not found. GPO inventory will be skipped. Install RSAT-GPMC to enable it."
}
 
# ---------------------------------------------------------------------------
# Findings collector
# ---------------------------------------------------------------------------
$Findings = New-Object System.Collections.Generic.List[PSObject]
 
function Add-Finding {
    param(
        [ValidateSet("Critical","High","Medium","Low")]
        [string]$Severity,
        [string]$Description
    )
    $Findings.Add([PSCustomObject]@{ Severity = $Severity; Description = $Description }) | Out-Null
}
 
Write-Host "=== MedDefense Domain Baseline - $(Get-Date -Format 'yyyy-MM-dd HH:mm') ===" -ForegroundColor Cyan
 
# ---------------------------------------------------------------------------
# 1. Domain information
# ---------------------------------------------------------------------------
$domain = Get-ADDomain
$forest = Get-ADForest
$dcs    = Get-ADDomainController -Filter *
 
Write-Host "`nDomain: $($domain.DNSRoot)"
Write-Host "Forest Functional Level: $($forest.ForestMode)"
Write-Host "Domain Functional Level: $($domain.DomainMode)"
Write-Host "Domain Controllers: $($dcs.Count)"
$dcs | ForEach-Object { Write-Host "  - $($_.HostName)" }
 
# ---------------------------------------------------------------------------
# 2. User accounts
# ---------------------------------------------------------------------------
$users = Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, TrustedForDelegation, SamAccountName
 
$passwordNeverExpiresCount = @($users | Where-Object { $_.PasswordNeverExpires -eq $true }).Count
$disabledCount             = @($users | Where-Object { $_.Enabled -eq $false }).Count
 
Write-Host "`nUser Accounts: $($users.Count)"
Write-Host "  Enabled: $($users.Count - $disabledCount) | Disabled: $disabledCount"
Write-Host "  Password Never Expires: $passwordNeverExpiresCount"
 
$userReport = $users | Select-Object SamAccountName, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, TrustedForDelegation
 
# ---------------------------------------------------------------------------
# 3. Groups and membership
# ---------------------------------------------------------------------------
$groups = Get-ADGroup -Filter *
Write-Host "`nGroups: $($groups.Count)"
 
$groupReport = foreach ($g in $groups) {
    $members = @()
    try {
        $members = Get-ADGroupMember -Identity $g -ErrorAction Stop | Select-Object -ExpandProperty Name
    } catch {
        # Some groups (e.g. circular or foreign security principals) can fail enumeration; note and continue.
        $members = @("<enumeration failed: $($_.Exception.Message)>")
    }
    [PSCustomObject]@{
        Group   = $g.Name
        Members = ($members -join ", ")
    }
}
 
# ---------------------------------------------------------------------------
# 4. Service accounts (name contains "svc", or located in a Service Accounts OU)
# ---------------------------------------------------------------------------
$svcByName = $users | Where-Object { $_.SamAccountName -match "svc" -or $_.Name -match "svc" }
 
$svcOU = Get-ADOrganizationalUnit -Filter { Name -like "*Service*" } -ErrorAction SilentlyContinue
$svcByOU = @()
if ($svcOU) {
    foreach ($ou in $svcOU) {
        $svcByOU += Get-ADUser -SearchBase $ou.DistinguishedName -Filter * -Properties SamAccountName, TrustedForDelegation -ErrorAction SilentlyContinue
    }
}
 
$serviceAccounts = @($svcByName + $svcByOU) | Sort-Object SamAccountName -Unique
Write-Host "`nService Accounts: $($serviceAccounts.Count)"
$serviceAccounts | ForEach-Object { Write-Host "  - $($_.SamAccountName)" }
 
# ---------------------------------------------------------------------------
# 5. GPOs
# ---------------------------------------------------------------------------
$allGPOs = @()
$gpoReport = @()
if ($gpModuleAvailable) {
    $allGPOs = Get-GPO -All
    Write-Host "`nGPOs (defined in domain): $($allGPOs.Count)"
 
    $domainInheritance = Get-GPInheritance -Target $domain.DistinguishedName
    $ous = Get-ADOrganizationalUnit -Filter *
    $ouInheritance = foreach ($ou in $ous) {
        try { Get-GPInheritance -Target $ou.DistinguishedName -ErrorAction Stop } catch { $null }
    }
 
    $gpoReport = [PSCustomObject]@{
        AllGPOs           = $allGPOs | Select-Object DisplayName, Id, GpoStatus
        DomainLinkedGPOs  = $domainInheritance.GpoLinks | Select-Object DisplayName, Enabled, Enforced
        OULinkedGPOCount  = ($ouInheritance | Where-Object { $_ } | ForEach-Object { $_.GpoLinks } | Measure-Object).Count
    }
} else {
    Write-Host "`nGPOs: skipped (GroupPolicy module unavailable)"
}
 
# ---------------------------------------------------------------------------
# 6 & 7. Password policy and account lockout policy
# ---------------------------------------------------------------------------
$pwPolicy = Get-ADDefaultDomainPasswordPolicy
 
$lockoutStatus = if ($pwPolicy.LockoutThreshold -eq 0) { "NOT CONFIGURED" } else { "$($pwPolicy.LockoutThreshold) attempts" }
 
Write-Host "`nPassword Minimum Length: $($pwPolicy.MinPasswordLength)"
Write-Host "Complexity: $(if ($pwPolicy.ComplexityEnabled) { 'Enabled' } else { 'Disabled' })"
Write-Host "Password History: $($pwPolicy.PasswordHistoryCount)"
Write-Host "Max Password Age: $($pwPolicy.MaxPasswordAge)"
Write-Host "Lockout Threshold: $lockoutStatus"
Write-Host "Lockout Duration: $($pwPolicy.LockoutDuration)"
Write-Host "Lockout Observation Window: $($pwPolicy.LockoutObservationWindow)"
 
# ---------------------------------------------------------------------------
# 8. Kerberos encryption types
#    NOTE: msDS-SupportedEncryptionTypes reflects what is CONFIGURED on the
#    krbtgt/account object, not necessarily what is actually negotiated on
#    the wire. Treat this as a configuration check, not a live-traffic read.
#    Bitmask reference: 0x1 DES-CBC-CRC, 0x2 DES-CBC-MD5, 0x4 RC4-HMAC,
#    0x8 AES128-HMAC, 0x10 AES256-HMAC (Microsoft-documented values —
#    worth re-confirming against current Microsoft docs before relying on it).
# ---------------------------------------------------------------------------
function Get-KerberosEncryptionTypes {
    param([Nullable[int]]$Value)
 
    if ($null -eq $Value -or $Value -eq 0) {
        return "Not explicitly set (OS defaults apply - verify negotiated types separately)"
    }
    $types = New-Object System.Collections.Generic.List[string]
    if ($Value -band 0x1)  { $types.Add("DES-CBC-CRC") }
    if ($Value -band 0x2)  { $types.Add("DES-CBC-MD5") }
    if ($Value -band 0x4)  { $types.Add("RC4-HMAC") }
    if ($Value -band 0x8)  { $types.Add("AES128-HMAC") }
    if ($Value -band 0x10) { $types.Add("AES256-HMAC") }
    return ($types -join ", ")
}
 
$krbtgtAccount = Get-ADUser -Identity krbtgt -Properties msDS-SupportedEncryptionTypes
$kerberosTypes = Get-KerberosEncryptionTypes -Value $krbtgtAccount.'msDS-SupportedEncryptionTypes'
 
Write-Host "`nKerberos Encryption Types (krbtgt): $kerberosTypes"
 
# ---------------------------------------------------------------------------
# 9. Privileged accounts and delegation
# ---------------------------------------------------------------------------
$domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object -ExpandProperty Name
 
$enterpriseAdmins = @()
try {
    $enterpriseAdmins = Get-ADGroupMember -Identity "Enterprise Admins" -Recursive -ErrorAction Stop | Select-Object -ExpandProperty Name
} catch {
    # Enterprise Admins only exists in the forest root domain; absence elsewhere is expected, not an error.
    Write-Warning "Enterprise Admins group not resolvable from this domain (expected if this is not the forest root)."
}
 
$delegUsers     = Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation
$delegComputers = Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation
$unconstrainedDelegation = @($delegUsers + $delegComputers)
 
Write-Host "`nDomain Admins: $($domainAdmins -join ', ')"
Write-Host "Enterprise Admins: $($enterpriseAdmins -join ', ')"
Write-Host "Unconstrained Delegation: $($unconstrainedDelegation.Count)"
$unconstrainedDelegation | ForEach-Object { Write-Host "  - $($_.SamAccountName)" }
 
# ---------------------------------------------------------------------------
# 10. Findings summary (rule-based; actual counts depend on live domain data)
# ---------------------------------------------------------------------------
if (-not $pwPolicy.ComplexityEnabled) {
    Add-Finding -Severity "Critical" -Description "Password complexity is disabled."
}
if ($pwPolicy.LockoutThreshold -eq 0) {
    Add-Finding -Severity "Critical" -Description "Account lockout policy is not configured."
}
if ($unconstrainedDelegation.Count -gt 0) {
    Add-Finding -Severity "Critical" -Description "$($unconstrainedDelegation.Count) account(s) configured for unconstrained Kerberos delegation."
}
if ($pwPolicy.MinPasswordLength -lt 8) {
    Add-Finding -Severity "High" -Description "Minimum password length ($($pwPolicy.MinPasswordLength)) is below the commonly recommended 8 characters."
}
if ($passwordNeverExpiresCount -gt 0) {
    Add-Finding -Severity "High" -Description "$passwordNeverExpiresCount account(s) have PasswordNeverExpires set."
}
if ($kerberosTypes -match "DES|RC4") {
    Add-Finding -Severity "High" -Description "Weak Kerberos encryption types (DES and/or RC4) are permitted on krbtgt."
}
if ($serviceAccounts.Count -gt 0 -and -not $svcOU) {
    Add-Finding -Severity "High" -Description "Service accounts exist but are not isolated in a dedicated OU."
}
if ($gpModuleAvailable -and $allGPOs.Count -le 2) {
    Add-Finding -Severity "Medium" -Description "Only default GPOs are present; no custom hardening baseline is enforced via Group Policy."
}
$staleEnabled = @($users | Where-Object { $_.Enabled -eq $true -and $_.LastLogonDate -and $_.LastLogonDate -lt (Get-Date).AddDays(-90) })
if ($staleEnabled.Count -gt 0) {
    Add-Finding -Severity "Medium" -Description "$($staleEnabled.Count) enabled account(s) have not logged on in over 90 days."
}
 
$critCount   = @($Findings | Where-Object Severity -eq "Critical").Count
$highCount   = @($Findings | Where-Object Severity -eq "High").Count
$medCount    = @($Findings | Where-Object Severity -eq "Medium").Count
$lowCount    = @($Findings | Where-Object Severity -eq "Low").Count
 
Write-Host "`nFindings: $($Findings.Count) (Critical: $critCount, High: $highCount, Medium: $medCount, Low: $lowCount)" -ForegroundColor Yellow
$Findings | ForEach-Object { Write-Host "  [$($_.Severity)] $($_.Description)" }
 
# ---------------------------------------------------------------------------
# Export structured report for audit evidence
# ---------------------------------------------------------------------------
$reportDir = Join-Path -Path $PSScriptRoot -ChildPath "reports"
if (-not (Test-Path $reportDir)) {
    New-Item -Path $reportDir -ItemType Directory | Out-Null
}
$timestamp  = Get-Date -Format "yyyyMMdd-HHmmss"
$reportPath = Join-Path -Path $reportDir -ChildPath "domain_baseline_$timestamp.json"
 
$report = [PSCustomObject]@{
    Timestamp            = (Get-Date).ToString("o")
    Domain               = $domain.DNSRoot
    ForestFunctionalLevel = $forest.ForestMode.ToString()
    DomainFunctionalLevel = $domain.DomainMode.ToString()
    DomainControllers    = $dcs | Select-Object HostName, OperatingSystem
    UserCount            = $users.Count
    DisabledUserCount    = $disabledCount
    PasswordNeverExpiresCount = $passwordNeverExpiresCount
    Users                = $userReport
    Groups               = $groupReport
    ServiceAccounts      = $serviceAccounts | Select-Object SamAccountName
    GPOs                 = $gpoReport
    PasswordPolicy       = $pwPolicy | Select-Object MinPasswordLength, ComplexityEnabled, PasswordHistoryCount, MaxPasswordAge, LockoutThreshold, LockoutDuration, LockoutObservationWindow
    KerberosEncryptionTypesKrbtgt = $kerberosTypes
    DomainAdmins         = $domainAdmins
    EnterpriseAdmins     = $enterpriseAdmins
    UnconstrainedDelegation = $unconstrainedDelegation | Select-Object SamAccountName
    Findings             = $Findings
}
 
$report | ConvertTo-Json -Depth 6 | Out-File -FilePath $reportPath -Encoding utf8
 
Write-Host "`nFull report exported to: $reportPath" -ForegroundColor Green
