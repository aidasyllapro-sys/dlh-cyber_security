<#
    Script name : 1-domain_findings.ps1
    Purpose     : Audit the meddefense.local Active Directory domain and produce an
                  actionable findings inventory (domain_security_findings.json) covering
                  password policy gaps, privileged/disabled accounts, stale computer
                  objects, audit visibility gaps, service account risks, and weak GPO
                  posture. Each finding is linked to a severity, evidence, risk, a
                  recommended remediation, and the workflow area that will remediate it.
    Author      : <your name>
    Date        : 2026-08-09
#>
 
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
 
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
    Write-Warning "GroupPolicy module not found. GPO posture checks will be limited."
}
 
# ---------------------------------------------------------------------------
# Windows Fortress target state
# ---------------------------------------------------------------------------
$TargetMinLength       = 14
$TargetComplexity      = $true
$TargetHistory         = 24
$TargetLockoutThreshold = 5
$StalePasswordDays     = 365
$StaleComputerDays     = 90
 
# ---------------------------------------------------------------------------
# Findings collector
# ---------------------------------------------------------------------------
$Findings = New-Object System.Collections.Generic.List[PSObject]
$script:findingCounter = 0
 
function Add-Finding {
    param(
        [Parameter(Mandatory)][ValidateSet("CRITICAL","HIGH","MEDIUM","LOW")]
        [string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Asset,
        [Parameter(Mandatory)][string]$Evidence,
        [Parameter(Mandatory)][string]$Risk,
        [Parameter(Mandatory)][string]$RecommendedRemediation,
        [Parameter(Mandatory)][string]$MappedTask,
        [Parameter(Mandatory)][string]$ConsoleMessage
    )
    $script:findingCounter++
    $id = "F{0:D3}" -f $script:findingCounter
 
    $Findings.Add([PSCustomObject]@{
        id                       = $id
        severity                 = $Severity
        category                 = $Category
        asset                    = $Asset
        evidence                 = $Evidence
        risk                     = $Risk
        recommended_remediation  = $RecommendedRemediation
        mapped_task              = $MappedTask
    }) | Out-Null
 
    Write-Host "[$Severity] $ConsoleMessage"
}
 
# ---------------------------------------------------------------------------
# Shared data pulls
# ---------------------------------------------------------------------------
$allUsers = Get-ADUser -Filter * -Properties Enabled, PasswordLastSet, PasswordNeverExpires, MemberOf, TrustedForDelegation, LastLogonDate, SamAccountName, 'msDS-SupportedEncryptionTypes'
 
$svcOU = Get-ADOrganizationalUnit -Filter { Name -like "*Service*" } -ErrorAction SilentlyContinue
$svcAccountsByOU = @()
if ($svcOU) {
    foreach ($ou in $svcOU) {
        $svcAccountsByOU += Get-ADUser -SearchBase $ou.DistinguishedName -Filter * -Properties Enabled, PasswordLastSet, PasswordNeverExpires, MemberOf, TrustedForDelegation, LastLogonDate, SamAccountName, 'msDS-SupportedEncryptionTypes' -ErrorAction SilentlyContinue
    }
}
$serviceAccounts = @($allUsers | Where-Object { $_.SamAccountName -match "svc" }) + $svcAccountsByOU
$serviceAccounts = $serviceAccounts | Sort-Object SamAccountName -Unique
$serviceAccountNames = $serviceAccounts | Select-Object -ExpandProperty SamAccountName
 
function Test-IsServiceAccount {
    param([string]$SamAccountName)
    return $serviceAccountNames -contains $SamAccountName
}
 
$privilegedGroupNames = @("Domain Admins", "Enterprise Admins", "G_IT_Admins")
$privilegedMembers = @{}
foreach ($grp in $privilegedGroupNames) {
    try {
        $privilegedMembers[$grp] = Get-ADGroupMember -Identity $grp -Recursive -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName
    } catch {
        $privilegedMembers[$grp] = @()
        Write-Warning "Group '$grp' could not be enumerated (not found, or not resolvable from this domain): $($_.Exception.Message)"
    }
}
$allPrivilegedNames = $privilegedMembers.Values | ForEach-Object { $_ } | Sort-Object -Unique
 
function Get-PrivilegedGroupsFor {
    param([string]$SamAccountName)
    $result = @()
    foreach ($grp in $privilegedGroupNames) {
        if ($privilegedMembers[$grp] -contains $SamAccountName) { $result += $grp }
    }
    return $result
}
 
# ---------------------------------------------------------------------------
# 1. Accounts with PasswordNeverExpires
# ---------------------------------------------------------------------------
$pwNeverExpires = $allUsers | Where-Object { $_.PasswordNeverExpires -eq $true }
 
foreach ($u in $pwNeverExpires) {
    $groups = try { (Get-ADUser -Identity $u.SamAccountName -Properties MemberOf).MemberOf | ForEach-Object { (Get-ADGroup -Identity $_).Name } } catch { @() }
    Add-Finding -Severity "HIGH" -Category "Password Policy" -Asset $u.SamAccountName `
        -Evidence "Enabled=$($u.Enabled); PasswordLastSet=$($u.PasswordLastSet); Groups=$($groups -join ', '); IsServiceAccount=$(Test-IsServiceAccount $u.SamAccountName)" `
        -Risk "Non-expiring passwords increase the window an attacker has to exploit a compromised or weak credential." `
        -RecommendedRemediation "Remove PasswordNeverExpires, migrate service accounts to Group Managed Service Accounts (gMSA) where feasible, enforce standard expiration for human accounts." `
        -MappedTask "Password & Account Lifecycle Hardening (upcoming task)" `
        -ConsoleMessage "PasswordNeverExpires account: $($u.SamAccountName)" | Out-Null
}
if ($pwNeverExpires.Count -gt 0) {
    Write-Host "[HIGH] $($pwNeverExpires.Count) accounts with PasswordNeverExpires"
}
 
# ---------------------------------------------------------------------------
# 2. Disabled accounts in privileged groups
# ---------------------------------------------------------------------------
foreach ($grp in $privilegedGroupNames) {
    foreach ($member in $privilegedMembers[$grp]) {
        try {
            $u = Get-ADUser -Identity $member -Properties Enabled
        } catch { continue }
        if ($u.Enabled -eq $false) {
            Add-Finding -Severity "MEDIUM" -Category "Privileged Access" -Asset $u.SamAccountName `
                -Evidence "Disabled account remains a member of '$grp'." `
                -Risk "A disabled-but-not-removed privileged account is a re-enablement target and inflates the real privileged attack surface." `
                -RecommendedRemediation "Remove disabled accounts from privileged groups; if retained for historical reasons, document justification and review cadence." `
                -MappedTask "Privileged Access Cleanup (upcoming task)" `
                -ConsoleMessage "Disabled account in privileged group '$grp': $($u.SamAccountName)"
        }
    }
}
 
# ---------------------------------------------------------------------------
# 3. Stale computer objects (90+ days no logon)
#    NOTE: lastLogonTimestamp is a replicated-but-lagging attribute (can be up
#    to ~14 days stale by design). Treat the 90-day threshold as directional,
#    not to-the-day precise.
# ---------------------------------------------------------------------------
$computers = Get-ADComputer -Filter * -Properties LastLogonTimestamp, OperatingSystem
$staleComputers = foreach ($c in $computers) {
    if ($c.LastLogonTimestamp) {
        $lastLogon = [DateTime]::FromFileTime($c.LastLogonTimestamp)
        if ($lastLogon -lt (Get-Date).AddDays(-$StaleComputerDays)) {
            [PSCustomObject]@{ Name = $c.Name; LastLogon = $lastLogon; OperatingSystem = $c.OperatingSystem }
        }
    } else {
        [PSCustomObject]@{ Name = $c.Name; LastLogon = $null; OperatingSystem = $c.OperatingSystem }
    }
}
foreach ($sc in $staleComputers) {
    Add-Finding -Severity "MEDIUM" -Category "Stale Objects" -Asset $sc.Name `
        -Evidence "LastLogonTimestamp=$($sc.LastLogon); OS=$($sc.OperatingSystem)" `
        -Risk "Stale computer objects are unmanaged/unpatched attack surface and can be a sign of decommissioned hosts left in AD." `
        -RecommendedRemediation "Verify the host is genuinely decommissioned, then disable and remove the object; if active, investigate why it is not authenticating." `
        -MappedTask "Stale Object Cleanup (upcoming task)" `
        -ConsoleMessage "Stale computer object: $($sc.Name)"
}
if ($staleComputers.Count -gt 0) {
    Write-Host "[MEDIUM] Stale computer objects: $($staleComputers.Count)"
}
 
# ---------------------------------------------------------------------------
# 4. Password and lockout policy gaps vs Windows Fortress target state
# ---------------------------------------------------------------------------
$pwPolicy = Get-ADDefaultDomainPasswordPolicy
 
if ($pwPolicy.MinPasswordLength -lt $TargetMinLength) {
    Add-Finding -Severity "CRITICAL" -Category "Password Policy" -Asset "Default Domain Password Policy" `
        -Evidence "Current MinPasswordLength=$($pwPolicy.MinPasswordLength); Target=$TargetMinLength" `
        -Risk "Short minimum password length materially reduces brute-force/credential-stuffing resistance." `
        -RecommendedRemediation "Raise minimum password length to $TargetMinLength via Default Domain Policy or a dedicated PSO." `
        -MappedTask "Password & Lockout Policy Hardening (upcoming task)" `
        -ConsoleMessage "Password policy minimum length: $($pwPolicy.MinPasswordLength)"
}
if (-not $pwPolicy.ComplexityEnabled) {
    Add-Finding -Severity "CRITICAL" -Category "Password Policy" -Asset "Default Domain Password Policy" `
        -Evidence "ComplexityEnabled=$($pwPolicy.ComplexityEnabled); Target=$TargetComplexity" `
        -Risk "Without complexity requirements, weak/common passwords are far more likely across the user base." `
        -RecommendedRemediation "Enable password complexity in the Default Domain Policy." `
        -MappedTask "Password & Lockout Policy Hardening (upcoming task)" `
        -ConsoleMessage "Password complexity: disabled"
}
if ($pwPolicy.PasswordHistoryCount -lt $TargetHistory) {
    Add-Finding -Severity "MEDIUM" -Category "Password Policy" -Asset "Default Domain Password Policy" `
        -Evidence "Current PasswordHistoryCount=$($pwPolicy.PasswordHistoryCount); Target=$TargetHistory" `
        -Risk "Low password history allows rapid password re-use, undermining forced rotation." `
        -RecommendedRemediation "Increase password history to $TargetHistory remembered passwords." `
        -MappedTask "Password & Lockout Policy Hardening (upcoming task)" `
        -ConsoleMessage "Password history: $($pwPolicy.PasswordHistoryCount) (target $TargetHistory)"
}
if ($pwPolicy.LockoutThreshold -eq 0) {
    Add-Finding -Severity "CRITICAL" -Category "Password Policy" -Asset "Default Domain Password Policy" `
        -Evidence "LockoutThreshold=0 (not configured); Target=$TargetLockoutThreshold" `
        -Risk "No account lockout policy leaves every account exposed to unlimited online password-guessing attempts." `
        -RecommendedRemediation "Configure lockout threshold to $TargetLockoutThreshold invalid attempts with an appropriate observation window and duration." `
        -MappedTask "Password & Lockout Policy Hardening (upcoming task)" `
        -ConsoleMessage "Account lockout: not configured"
} elseif ($pwPolicy.LockoutThreshold -gt $TargetLockoutThreshold) {
    Add-Finding -Severity "MEDIUM" -Category "Password Policy" -Asset "Default Domain Password Policy" `
        -Evidence "Current LockoutThreshold=$($pwPolicy.LockoutThreshold); Target=$TargetLockoutThreshold" `
        -Risk "A lockout threshold looser than target state gives attackers more guesses per lockout window." `
        -RecommendedRemediation "Tighten lockout threshold to $TargetLockoutThreshold." `
        -MappedTask "Password & Lockout Policy Hardening (upcoming task)" `
        -ConsoleMessage "Account lockout threshold: $($pwPolicy.LockoutThreshold) (target $TargetLockoutThreshold)"
}
 
# Fine-grained password policies, if any, checked against the same target state
try {
    $fgpps = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction Stop
    foreach ($fgpp in $fgpps) {
        if ($fgpp.MinPasswordLength -lt $TargetMinLength -or -not $fgpp.ComplexityEnabled -or $fgpp.PasswordHistoryCount -lt $TargetHistory) {
            Add-Finding -Severity "MEDIUM" -Category "Password Policy" -Asset "PSO: $($fgpp.Name)" `
                -Evidence "MinPasswordLength=$($fgpp.MinPasswordLength); ComplexityEnabled=$($fgpp.ComplexityEnabled); PasswordHistoryCount=$($fgpp.PasswordHistoryCount)" `
                -Risk "Fine-grained password policy weaker than target state for the accounts it applies to." `
                -RecommendedRemediation "Align this PSO with the Windows Fortress target state (length 14, complexity on, history 24)." `
                -MappedTask "Password & Lockout Policy Hardening (upcoming task)" `
                -ConsoleMessage "Fine-grained password policy below target: $($fgpp.Name)"
        }
    }
} catch {
    Write-Warning "Could not enumerate fine-grained password policies: $($_.Exception.Message)"
}
 
# ---------------------------------------------------------------------------
# 5. Audit visibility gaps (auditpol) + PowerShell logging + Sysmon readiness
# ---------------------------------------------------------------------------
$auditGapFound = $false
try {
    $auditCsv = auditpol /get /category:* /r | ConvertFrom-Csv
    $criticalSubcategories = @(
        "Process Creation",
        "Special Logon",
        "User Account Management",
        "Security Group Management",
        "File System",
        "Registry"
    )
    foreach ($sub in $criticalSubcategories) {
        $entry = $auditCsv | Where-Object { $_.Subcategory -eq $sub }
        if (-not $entry -or $entry.'Inclusion Setting' -eq "No Auditing") {
            $auditGapFound = $true
            Add-Finding -Severity "HIGH" -Category "Audit Visibility" -Asset "Advanced Audit Policy" `
                -Evidence "Subcategory '$sub' inclusion setting: $($entry.'Inclusion Setting')" `
                -Risk "Without this audit subcategory enabled, the corresponding attack technique leaves no event log evidence for detection or incident response." `
                -RecommendedRemediation "Enable success/failure auditing for '$sub' via the Default Domain Controllers Policy (Advanced Audit Policy Configuration)." `
                -MappedTask "Audit Policy & Logging Hardening (upcoming task)" `
                -ConsoleMessage "Advanced Audit Policy gap: $sub not fully audited"
        }
    }
} catch {
    $auditGapFound = $true
    Write-Warning "auditpol.exe could not be run or parsed: $($_.Exception.Message)"
    Add-Finding -Severity "HIGH" -Category "Audit Visibility" -Asset "Advanced Audit Policy" `
        -Evidence "auditpol /get /category:* could not be executed or parsed on this host." `
        -Risk "Audit policy state is unknown; cannot confirm detection coverage for privileged or object-access activity." `
        -RecommendedRemediation "Run this script directly on DC01 with sufficient privileges and re-check auditpol output." `
        -MappedTask "Audit Policy & Logging Hardening (upcoming task)" `
        -ConsoleMessage "Advanced Audit Policy: not configured"
}
 
$psLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$psModuleLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
$scriptBlockLogging = (Test-Path $psLoggingPath) -and ((Get-ItemProperty -Path $psLoggingPath -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 1)
$moduleLogging = (Test-Path $psModuleLoggingPath) -and ((Get-ItemProperty -Path $psModuleLoggingPath -Name EnableModuleLogging -ErrorAction SilentlyContinue).EnableModuleLogging -eq 1)
 
if (-not $scriptBlockLogging -or -not $moduleLogging) {
    Add-Finding -Severity "HIGH" -Category "Audit Visibility" -Asset "PowerShell Logging" `
        -Evidence "ScriptBlockLogging enabled=$scriptBlockLogging; ModuleLogging enabled=$moduleLogging" `
        -Risk "Without PowerShell Script Block/Module logging, obfuscated or fileless attack activity in PowerShell is largely invisible to defenders." `
        -RecommendedRemediation "Enable PowerShell Script Block Logging and Module Logging via GPO." `
        -MappedTask "Audit Policy & Logging Hardening (upcoming task)" `
        -ConsoleMessage "PowerShell logging incomplete (ScriptBlock=$scriptBlockLogging, Module=$moduleLogging)"
}
 
$sysmonService = Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue
if (-not $sysmonService) {
    Add-Finding -Severity "MEDIUM" -Category "Audit Visibility" -Asset "Sysmon" `
        -Evidence "No Sysmon or Sysmon64 service found on this host." `
        -Risk "Without Sysmon, detailed process, network, and image-load telemetry needed for high-fidelity detection is unavailable." `
        -RecommendedRemediation "Deploy Sysmon with a MedDefense-approved configuration across servers, starting with domain controllers." `
        -MappedTask "Audit Policy & Logging Hardening (upcoming task)" `
        -ConsoleMessage "Sysmon: not installed"
}
 
# ---------------------------------------------------------------------------
# 6. Service account risks
# ---------------------------------------------------------------------------
$interactiveLogonAccounts = @()
try {
    $secpolPath = Join-Path $env:TEMP "secpol_$([guid]::NewGuid().ToString('N')).cfg"
    secedit /export /cfg $secpolPath /areas USER_RIGHTS | Out-Null
    $interactiveLine = Get-Content $secpolPath | Where-Object { $_ -match '^SeInteractiveLogonRight' }
    if ($interactiveLine) {
        $sids = ($interactiveLine -split '=')[1].Trim() -split ','
        foreach ($sidToken in $sids) {
            $sidToken = $sidToken.Trim().TrimStart('*')
            try {
                $account = (New-Object System.Security.Principal.SecurityIdentifier($sidToken)).Translate([System.Security.Principal.NTAccount]).Value
                $interactiveLogonAccounts += ($account -split '\\')[-1]
            } catch {
                # Well-known SIDs or unresolvable SIDs are skipped rather than guessed.
            }
        }
    }
    Remove-Item $secpolPath -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Could not read SeInteractiveLogonRight via secedit: $($_.Exception.Message). Interactive-logon check for service accounts will be skipped."
}
 
foreach ($svc in $serviceAccounts) {
    $risks = New-Object System.Collections.Generic.List[string]
 
    if ($interactiveLogonAccounts -contains $svc.SamAccountName) {
        $risks.Add("interactive logon allowed")
    }
    if ($svc.TrustedForDelegation -eq $true) {
        $risks.Add("unconstrained delegation")
    }
    $encTypes = $svc.'msDS-SupportedEncryptionTypes'
    if ($encTypes -and (($encTypes -band 0x1 -or $encTypes -band 0x2)) -and -not ($encTypes -band 0x4 -or $encTypes -band 0x8 -or $encTypes -band 0x10)) {
        $risks.Add("DES-only Kerberos encryption")
    }
    $svcPrivGroups = Get-PrivilegedGroupsFor -SamAccountName $svc.SamAccountName
    if ($svcPrivGroups.Count -gt 0) {
        $risks.Add("privileged group membership ($($svcPrivGroups -join ', '))")
    }
    if ($svc.PasswordLastSet -and $svc.PasswordLastSet -lt (Get-Date).AddDays(-$StalePasswordDays)) {
        $risks.Add("password not rotated in $StalePasswordDays+ days")
    }
    if (-not $svc.LastLogonDate) {
        # Flagged for review, not asserted as malicious - true anomaly detection needs log/SIEM correlation this script does not have.
        $risks.Add("no recorded last logon (requires manual review, not a confirmed anomaly)")
    }
 
    if ($risks.Count -gt 0) {
        Add-Finding -Severity "HIGH" -Category "Service Accounts" -Asset $svc.SamAccountName `
            -Evidence ($risks -join "; ") `
            -Risk "Service accounts combining elevated privilege with weak controls are a preferred lateral-movement and persistence target." `
            -RecommendedRemediation "Migrate to gMSA where possible, remove unnecessary delegation/interactive rights, enforce AES-only Kerberos, and rotate credentials." `
            -MappedTask "Service Account Hardening (upcoming task)" `
            -ConsoleMessage "Service account risk on $($svc.SamAccountName): $($risks -join '; ')"
    }
}
$unconstrainedServiceCount = @($serviceAccounts | Where-Object { $_.TrustedForDelegation -eq $true }).Count
if ($unconstrainedServiceCount -gt 0) {
    Write-Host "[HIGH] $unconstrainedServiceCount service accounts with unconstrained delegation"
}
 
# ---------------------------------------------------------------------------
# 7. GPO security posture
# ---------------------------------------------------------------------------
if ($gpModuleAvailable) {
    $allGPOs = Get-GPO -All
    $meddefenseGPOs = $allGPOs | Where-Object { $_.DisplayName -match "MedDefense|Hardening" }
 
    if ($allGPOs.Count -le 2) {
        Add-Finding -Severity "MEDIUM" -Category "GPO Posture" -Asset "Domain GPOs" `
            -Evidence "Total GPOs defined: $($allGPOs.Count) ($(($allGPOs | Select-Object -ExpandProperty DisplayName) -join ', '))" `
            -Risk "Relying solely on default GPOs means no domain-specific hardening baseline is enforced or auditable." `
            -RecommendedRemediation "Create dedicated MedDefense hardening GPOs (password/audit/service restrictions) and link them at the appropriate OU/domain level." `
            -MappedTask "GPO Hardening Baseline (upcoming task)" `
            -ConsoleMessage "No MedDefense hardening GPOs present"
    } elseif ($meddefenseGPOs.Count -eq 0) {
        Add-Finding -Severity "MEDIUM" -Category "GPO Posture" -Asset "Domain GPOs" `
            -Evidence "Total GPOs defined: $($allGPOs.Count), none matching a MedDefense/Hardening naming convention." `
            -Risk "GPOs without a clear, named security purpose are hard to audit and easy to drift or misconfigure unnoticed." `
            -RecommendedRemediation "Adopt a consistent naming convention for security-purpose GPOs and document each GPO's intent." `
            -MappedTask "GPO Hardening Baseline (upcoming task)" `
            -ConsoleMessage "No MedDefense hardening GPOs present"
    }
} else {
    Add-Finding -Severity "MEDIUM" -Category "GPO Posture" -Asset "Domain GPOs" `
        -Evidence "GroupPolicy module unavailable; GPO inventory could not be retrieved." `
        -Risk "GPO security posture is unknown; cannot confirm hardening baseline coverage." `
        -RecommendedRemediation "Run this script on a host with RSAT-GPMC installed and re-check." `
        -MappedTask "GPO Hardening Baseline (upcoming task)" `
        -ConsoleMessage "GPO posture: could not be assessed (GroupPolicy module missing)"
}
 
# ---------------------------------------------------------------------------
# 4b. Kerberos DES/RC4 check (kept near policy findings, reuses task 0 logic)
# ---------------------------------------------------------------------------
$krbtgtAccount = Get-ADUser -Identity krbtgt -Properties 'msDS-SupportedEncryptionTypes'
$krbEncValue = $krbtgtAccount.'msDS-SupportedEncryptionTypes'
$desOrRc4Enabled = $false
if ($null -eq $krbEncValue -or $krbEncValue -eq 0) {
    # Not explicitly restricted - on unpatched/legacy domains this commonly still permits DES/RC4 by default.
    $desOrRc4Enabled = $true
    $krbEvidence = "msDS-SupportedEncryptionTypes not explicitly set on krbtgt; OS/domain defaults apply (verify - do not assume AES-only)."
} else {
    $desOrRc4Enabled = ([bool]($krbEncValue -band 0x1) -or [bool]($krbEncValue -band 0x2) -or [bool]($krbEncValue -band 0x4))
    $krbEvidence = "msDS-SupportedEncryptionTypes=$krbEncValue on krbtgt"
}
if ($desOrRc4Enabled) {
    Add-Finding -Severity "CRITICAL" -Category "Kerberos Hardening" -Asset "krbtgt / domain Kerberos policy" `
        -Evidence $krbEvidence `
        -Risk "DES and RC4 are cryptographically weak and enable well-documented attacks (e.g. RC4 downgrade abuse in Kerberoasting)." `
        -RecommendedRemediation "Restrict msDS-SupportedEncryptionTypes to AES128/AES256 domain-wide once all clients/services support AES, then disable DES/RC4." `
        -MappedTask "Kerberos Hardening (upcoming task)" `
        -ConsoleMessage "Kerberos DES/RC4 enabled"
}
 
# ---------------------------------------------------------------------------
# Summary + export
# ---------------------------------------------------------------------------
$critCount = @($Findings | Where-Object severity -eq "CRITICAL").Count
$highCount = @($Findings | Where-Object severity -eq "HIGH").Count
$medCount  = @($Findings | Where-Object severity -eq "MEDIUM").Count
$lowCount  = @($Findings | Where-Object severity -eq "LOW").Count
 
Write-Host ""
Write-Host "Findings: $($Findings.Count)"
Write-Host "Critical: $critCount"
Write-Host "High: $highCount"
Write-Host "Medium: $medCount"
if ($lowCount -gt 0) { Write-Host "Low: $lowCount" }
 
$outputPath = Join-Path -Path $PSScriptRoot -ChildPath "domain_security_findings.json"
$report = [PSCustomObject]@{
    domain      = "meddefense.local"
    generated   = (Get-Date).ToString("o")
    target_state = [PSCustomObject]@{
        min_password_length = $TargetMinLength
        complexity_enabled  = $TargetComplexity
        password_history    = $TargetHistory
        lockout_threshold   = $TargetLockoutThreshold
    }
    findings    = $Findings
    summary     = [PSCustomObject]@{
        total    = $Findings.Count
        critical = $critCount
        high     = $highCount
        medium   = $medCount
        low      = $lowCount
    }
}
$report | ConvertTo-Json -Depth 6 | Out-File -FilePath $outputPath -Encoding utf8
 
Write-Host "Report saved to: $outputPath"
