<#
    Script name : 0-sysmon_validation.ps1
    Purpose     : Validate that Sysmon is correctly capturing 5 categories of
                  security-relevant events (process creation, network connection,
                  file creation, registry modification, DNS query) by triggering
                  each action deliberately and confirming the matching Sysmon
                  Event ID appears in the Operational log with the expected detail.
    Author      : Aïda Sylla
    Date        : 2026-08-09
#>
 
Set-StrictMode -Version Latest
 
$SysmonLog = "Microsoft-Windows-Sysmon/Operational"
$Results = New-Object System.Collections.Generic.List[PSObject]
$TotalActions = 5
 
# ---------------------------------------------------------------------------
# Pre-flight check: Sysmon log must exist and be readable
# ---------------------------------------------------------------------------
try {
    Get-WinEvent -ListLog $SysmonLog -ErrorAction Stop | Out-Null
} catch {
    Write-Error "Sysmon Operational log not found or not accessible ('$SysmonLog'). Confirm Sysmon is installed and this session has sufficient rights."
    exit 1
}
 
# ---------------------------------------------------------------------------
# Generic Sysmon event lookup with short retry window (logging latency)
# ---------------------------------------------------------------------------
function Test-SysmonEvent {
    param(
        [Parameter(Mandatory)][int]$EventId,
        [Parameter(Mandatory)][datetime]$StartTime,
        [Parameter(Mandatory)][scriptblock]$Match,
        [int]$TimeoutSec = 15
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $events = Get-WinEvent -FilterHashtable @{ LogName = $SysmonLog; Id = $EventId; StartTime = $StartTime } -ErrorAction SilentlyContinue
        } catch {
            $events = $null
        }
        if ($events) {
            foreach ($e in $events) {
                $xml = [xml]$e.ToXml()
                $data = @{}
                foreach ($d in $xml.Event.EventData.Data) {
                    $data[$d.Name] = $d.'#text'
                }
                if (& $Match $data) {
                    return [PSCustomObject]@{ Captured = $true; Data = $data }
                }
            }
        }
        Start-Sleep -Milliseconds 500
    }
    return [PSCustomObject]@{ Captured = $false; Data = $null }
}
 
function Write-TestLine {
    param([string]$Detail, [bool]$Pass)
    $status = if ($Pass) { "[PASS]" } else { "[FAIL]" }
    $paddedDetail = $Detail.PadRight(68)
    Write-Host "          $paddedDetail$status"
}
 
Write-Host "[*] Running Sysmon telemetry validation..."
 
# ---------------------------------------------------------------------------
# 1. Process creation (Event ID 1)
# ---------------------------------------------------------------------------
Write-Host "    [1/$TotalActions] Process creation (Event ID 1)..."
$ts1 = Get-Date
try {
    cmd.exe /c whoami | Out-Null
} catch {
    Write-Warning "Could not launch cmd.exe /c whoami: $($_.Exception.Message)"
}
$r1 = Test-SysmonEvent -EventId 1 -StartTime $ts1 -Match {
    param($d) $d.ContainsKey('CommandLine') -and $d['CommandLine'] -match 'whoami'
}
$pass1 = $r1.Captured -and $r1.Data.ContainsKey('CommandLine') -and $r1.Data['CommandLine']
Write-TestLine -Detail "cmd.exe /c whoami -> Sysmon EID 1 captured, cmdline present" -Pass $pass1
$Results.Add([PSCustomObject]@{ Test = "Process creation (EID 1)"; Pass = $pass1 })
 
# ---------------------------------------------------------------------------
# 2. Network connection (Event ID 3)
# ---------------------------------------------------------------------------
Write-Host "    [2/$TotalActions] Network connection (Event ID 3)..."
$testTargetIp = "8.8.8.8"
$ts2 = Get-Date
try {
    Test-NetConnection -ComputerName $testTargetIp -Port 443 -ErrorAction SilentlyContinue | Out-Null
} catch {
    Write-Warning "Test-NetConnection failed: $($_.Exception.Message)"
}
$r2 = Test-SysmonEvent -EventId 3 -StartTime $ts2 -Match {
    param($d) $d.ContainsKey('DestinationIp') -and $d['DestinationIp'] -eq $testTargetIp
}
$pass2 = $r2.Captured -and $r2.Data.ContainsKey('DestinationIp') -and $r2.Data.ContainsKey('DestinationPort') -and $r2.Data.ContainsKey('Image')
Write-TestLine -Detail "Outbound TCP -> Sysmon EID 3 captured, dest IP/port present" -Pass $pass2
$Results.Add([PSCustomObject]@{ Test = "Network connection (EID 3)"; Pass = $pass2 })
 
# ---------------------------------------------------------------------------
# 3. File creation (Event ID 11)
# ---------------------------------------------------------------------------
Write-Host "    [3/$TotalActions] File creation (Event ID 11)..."
$testFile = "C:\Windows\Temp\sysmon_validation_test.txt"
$ts3 = Get-Date
try {
    Set-Content -Path $testFile -Value "sysmon validation test" -Force -ErrorAction Stop
} catch {
    Write-Warning "Could not create test file: $($_.Exception.Message)"
}
$r3 = Test-SysmonEvent -EventId 11 -StartTime $ts3 -Match {
    param($d) $d.ContainsKey('TargetFilename') -and $d['TargetFilename'] -eq $testFile
}
$pass3 = $r3.Captured
Write-TestLine -Detail "$testFile -> Sysmon EID 11 captured" -Pass $pass3
$Results.Add([PSCustomObject]@{ Test = "File creation (EID 11)"; Pass = $pass3 })
 
# ---------------------------------------------------------------------------
# 4. Registry modification (Event ID 13 - RegistryEvent Value Set)
# ---------------------------------------------------------------------------
Write-Host "    [4/$TotalActions] Registry modification (Event ID 13)..."
$regPath = "HKCU:\Software\SysmonValidationTest"
$regValueName = "SysmonTest"
$ts4 = Get-Date
try {
    New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $regPath -Name $regValueName -Value "1" -PropertyType String -Force -ErrorAction Stop | Out-Null
} catch {
    Write-Warning "Could not write test registry value: $($_.Exception.Message)"
}
$r4 = Test-SysmonEvent -EventId 13 -StartTime $ts4 -Match {
    param($d) $d.ContainsKey('TargetObject') -and $d['TargetObject'] -match [regex]::Escape($regValueName)
}
$pass4 = $r4.Captured
Write-TestLine -Detail "HKCU\...\$regValueName -> Sysmon EID 13 captured" -Pass $pass4
$Results.Add([PSCustomObject]@{ Test = "Registry modification (EID 13)"; Pass = $pass4 })
 
# ---------------------------------------------------------------------------
# 5. DNS query (Event ID 22)
#    NOTE: requires Sysmon config with DNS query logging enabled (Sysmon v11+).
# ---------------------------------------------------------------------------
Write-Host "    [5/$TotalActions] DNS query (Event ID 22)..."
$testDomain = "example.com"
$ts5 = Get-Date
try {
    Resolve-DnsName -Name $testDomain -ErrorAction SilentlyContinue | Out-Null
} catch {
    Write-Warning "Resolve-DnsName failed: $($_.Exception.Message)"
}
$r5 = Test-SysmonEvent -EventId 22 -StartTime $ts5 -Match {
    param($d) $d.ContainsKey('QueryName') -and $d['QueryName'] -match [regex]::Escape($testDomain)
}
$pass5 = $r5.Captured
Write-TestLine -Detail "nslookup $testDomain -> Sysmon EID 22 captured" -Pass $pass5
$Results.Add([PSCustomObject]@{ Test = "DNS query (EID 22)"; Pass = $pass5 })
 
# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
Write-Host "[*] Cleanup: removing test artifacts..."
try { if (Test-Path $testFile) { Remove-Item -Path $testFile -Force -ErrorAction Stop } } catch { Write-Warning "Cleanup of test file failed: $($_.Exception.Message)" }
try { if (Test-Path $regPath) { Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop } } catch { Write-Warning "Cleanup of test registry key failed: $($_.Exception.Message)" }
 
# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
$captured = @($Results | Where-Object Pass -eq $true).Count
$missed = $Results.Count - $captured
Write-Host "Actions tested: $($Results.Count) | Captured: $captured | Missed: $missed"
