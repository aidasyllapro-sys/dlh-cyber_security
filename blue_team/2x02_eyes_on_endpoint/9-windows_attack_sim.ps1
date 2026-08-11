<#
script name : 9-windows_attack_sim.ps1
purpose     : execute a controlled sequence of attacker-like actions against
              this hardened Windows endpoint (create a local user, escalate
              it to Administrators, run an encoded PowerShell command,
              create a persistence scheduled task, initiate an outbound
              network connection, drop a file in the Startup folder),
              recording the exact timestamp and MITRE ATT&CK technique of
              each action as ground truth for Task 10's detection matrix,
              then clean up every artifact created.
author      : Aïda Sylla
date        : 2026-08-09
#>
 
Set-StrictMode -Version Latest
 
$TestUserName = "support_update"
$TaskName = "support_update_task"
$StartupDir = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
$StartupFile = Join-Path -Path $StartupDir -ChildPath "support_update_sim.txt"
$GroundTruthPath = Join-Path -Path $PSScriptRoot -ChildPath "windows_attack_log.json"
$TotalActions = 6
 
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run from an elevated (Administrator) PowerShell session - it creates a local user and a scheduled task."
    exit 1
}
 
function Get-Iso8601Utc {
    (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}
 
function Write-ActionLine {
    param([int]$Index, [int]$Total, [string]$Label, [string]$Timestamp)
    $padded = "$Label...".PadRight(50)
    Write-Host "    [$Index/$Total] $padded $Timestamp"
}
 
$GroundTruth = New-Object System.Collections.Generic.List[PSObject]
 
function Add-GroundTruthEntry {
    param(
        [int]$ActionNumber,
        [string]$Description,
        [string]$Timestamp,
        [string]$MitreTechnique,
        [string]$SysmonEventId,
        [string]$SecurityEventId,
        [string]$OtherDetectionSource = $null
    )
    $GroundTruth.Add([PSCustomObject]@{
        action_number       = $ActionNumber
        description         = $Description
        timestamp           = $Timestamp
        mitre_technique     = $MitreTechnique
        expected_detection  = [PSCustomObject]@{
            sysmon_event_id        = $SysmonEventId
            security_event_id      = $SecurityEventId
            other_detection_source = $OtherDetectionSource
        }
    }) | Out-Null
}
 
Write-Host "[*] Running Windows attacker simulation..."
 
# ---------------------------------------------------------------------------
# 1. Create a new local user account
# ---------------------------------------------------------------------------
$randomPwChars = -join ((48..57) + (65..90) + (97..122) + (33,35,36,37) | Get-Random -Count 20 | ForEach-Object { [char]$_ })
$securePw = ConvertTo-SecureString $randomPwChars -AsPlainText -Force
try {
    New-LocalUser -Name $TestUserName -Password $securePw -FullName "Support Update Simulation" -Description "MedDefense attack simulation test account - 9-windows_attack_sim.ps1" -AccountNeverExpires -ErrorAction Stop | Out-Null
} catch {
    Write-Warning "Failed to create local user '$TestUserName': $($_.Exception.Message)"
}
$ts1 = Get-Iso8601Utc
Write-ActionLine -Index 1 -Total $TotalActions -Label "Creating local user '$TestUserName'" -Timestamp $ts1
Add-GroundTruthEntry -ActionNumber 1 -Description "Create local user account '$TestUserName'" -Timestamp $ts1 `
    -MitreTechnique "T1136.001 - Create Account: Local Account" `
    -SysmonEventId "Event ID 1 (Process Creation - host process for the account-creation cmdlet)" `
    -SecurityEventId "Event ID 4720 (A user account was created)"
 
# ---------------------------------------------------------------------------
# 2. Add the user to the Administrators group
# ---------------------------------------------------------------------------
try {
    Add-LocalGroupMember -Group "Administrators" -Member $TestUserName -ErrorAction Stop
} catch {
    Write-Warning "Failed to add '$TestUserName' to Administrators: $($_.Exception.Message)"
}
$ts2 = Get-Iso8601Utc
Write-ActionLine -Index 2 -Total $TotalActions -Label "Adding to Administrators group" -Timestamp $ts2
Add-GroundTruthEntry -ActionNumber 2 -Description "Add '$TestUserName' to the local Administrators group" -Timestamp $ts2 `
    -MitreTechnique "T1098 - Account Manipulation" `
    -SysmonEventId "Event ID 1 (Process Creation - host process for the group-membership cmdlet)" `
    -SecurityEventId "Event ID 4732 (A member was added to a security-enabled local group)"
 
# ---------------------------------------------------------------------------
# 3. Run an encoded PowerShell command (harmless payload)
# ---------------------------------------------------------------------------
$plainPayload = 'Write-Host "C2 beacon"'
$encodedPayload = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($plainPayload))
try {
    powershell.exe -NoProfile -enc $encodedPayload | Out-Null
} catch {
    Write-Warning "Encoded PowerShell execution failed: $($_.Exception.Message)"
}
$ts3 = Get-Iso8601Utc
Write-ActionLine -Index 3 -Total $TotalActions -Label "Running encoded PowerShell" -Timestamp $ts3
Add-GroundTruthEntry -ActionNumber 3 -Description "Run encoded PowerShell command (decoded payload: $plainPayload)" -Timestamp $ts3 `
    -MitreTechnique "T1059.001 - Command and Scripting Interpreter: PowerShell" `
    -SysmonEventId "Event ID 1 (Process Creation - powershell.exe with -enc argument)" `
    -SecurityEventId "Event ID 4688 (A new process has been created, if process creation auditing with command-line logging is enabled)" `
    -OtherDetectionSource "PowerShell Operational EID 4104 (Script Block Logging - captures decoded content)"
 
# ---------------------------------------------------------------------------
# 4. Create a scheduled task for persistence
# ---------------------------------------------------------------------------
try {
    schtasks /create /tn $TaskName /tr "cmd.exe /c exit" /sc once /st 23:59 /f | Out-Null
} catch {
    Write-Warning "schtasks /create failed: $($_.Exception.Message)"
}
$ts4 = Get-Iso8601Utc
Write-ActionLine -Index 4 -Total $TotalActions -Label "Creating scheduled task" -Timestamp $ts4
Add-GroundTruthEntry -ActionNumber 4 -Description "Create scheduled task '$TaskName' for persistence" -Timestamp $ts4 `
    -MitreTechnique "T1053.005 - Scheduled Task/Job: Scheduled Task" `
    -SysmonEventId "Event ID 1 (Process Creation - schtasks.exe)" `
    -SecurityEventId "Event ID 4698 (A scheduled task was created)"
 
# ---------------------------------------------------------------------------
# 5. Initiate an outbound network connection
# ---------------------------------------------------------------------------
try {
    Test-NetConnection -ComputerName "8.8.8.8" -Port 443 -ErrorAction SilentlyContinue | Out-Null
} catch {
    Write-Warning "Test-NetConnection failed: $($_.Exception.Message)"
}
$ts5 = Get-Iso8601Utc
Write-ActionLine -Index 5 -Total $TotalActions -Label "Outbound network connection" -Timestamp $ts5
Add-GroundTruthEntry -ActionNumber 5 -Description "Initiate outbound TCP connection to 8.8.8.8:443" -Timestamp $ts5 `
    -MitreTechnique "T1071 - Application Layer Protocol" `
    -SysmonEventId "Event ID 3 (Network Connection)" `
    -SecurityEventId "Event ID 5156 (Windows Filtering Platform permitted a connection - only if advanced Filtering Platform Connection auditing is enabled)"
 
# ---------------------------------------------------------------------------
# 6. Drop a file in the Startup directory
# ---------------------------------------------------------------------------
try {
    if (-not (Test-Path $StartupDir)) { New-Item -Path $StartupDir -ItemType Directory -Force | Out-Null }
    Set-Content -Path $StartupFile -Value "MedDefense attack simulation test artifact - safe to delete" -Force -ErrorAction Stop
} catch {
    Write-Warning "Failed to drop file in Startup directory: $($_.Exception.Message)"
}
$ts6 = Get-Iso8601Utc
Write-ActionLine -Index 6 -Total $TotalActions -Label "Dropping file in Startup" -Timestamp $ts6
Add-GroundTruthEntry -ActionNumber 6 -Description "Drop file '$StartupFile' in the all-users Startup folder" -Timestamp $ts6 `
    -MitreTechnique "T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder" `
    -SysmonEventId "Event ID 11 (File Create)" `
    -SecurityEventId "Event ID 4663 (An attempt was made to access an object - only if object access auditing is enabled on this folder)"
 
# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
Write-Host "[*] Cleaning up artifacts..."
$cleanupIssues = New-Object System.Collections.Generic.List[string]
 
try {
    if (Get-LocalUser -Name $TestUserName -ErrorAction SilentlyContinue) {
        Remove-LocalUser -Name $TestUserName -ErrorAction Stop
    }
} catch {
    $cleanupIssues.Add("user removal failed: $($_.Exception.Message)")
}
 
try {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    }
} catch {
    $cleanupIssues.Add("scheduled task removal failed: $($_.Exception.Message)")
}
 
try {
    if (Test-Path $StartupFile) { Remove-Item -Path $StartupFile -Force -ErrorAction Stop }
} catch {
    $cleanupIssues.Add("startup file removal failed: $($_.Exception.Message)")
}
 
if ($cleanupIssues.Count -eq 0) {
    Write-Host "    User removed, task deleted, file removed           [CLEAN]"
} else {
    Write-Host "    Cleanup incomplete:                                [PARTIAL]"
    foreach ($issue in $cleanupIssues) { Write-Host "        - $issue" }
}
 
# ---------------------------------------------------------------------------
# Export ground truth
# ---------------------------------------------------------------------------
$report = [PSCustomObject]@{
    generated       = Get-Iso8601Utc
    scenario        = "Crimson Tide playbook simulation (Task 9)"
    actions_executed = $GroundTruth.Count
    ground_truth    = $GroundTruth
}
$report | ConvertTo-Json -Depth 6 | Out-File -FilePath $GroundTruthPath -Encoding utf8
 
Write-Host "Actions executed: $($GroundTruth.Count)"
Write-Host "Ground truth saved to: $(Split-Path -Path $GroundTruthPath -Leaf)"
