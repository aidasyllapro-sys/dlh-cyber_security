Evidence Preservation Runbook: IR-2026-0414-01

Evidence store: /evidence/IR-2026-0414-01/ (subfolders: memory, disk, process_tree, network, endpoint_telemetry, siem, proxy_dns, authentication, malware, correlation, per evidence_store_init.sh) Hash algorithm: SHA-256 Hash manifest: IR-2026-0414-01-hashes.txt Host: WST-WS-031 | Account: MEDDEFENSE\dmarsh

Every item is captured, hashed immediately, and logged to the manifest before the next item. No process kill, isolation, or reset on WST-WS-031 until Section 8 is complete.

1. Volatile memory, WST-WS-031
what: full physical memory dump
how: winpmem_3.3.rc3.exe -o \\evidence\IR-2026-0414-01\memory\wst-ws-031.mem
where: /evidence/IR-2026-0414-01/memory/wst-ws-031.mem
hash cmd: certutil -hashfile wst-ws-031.mem SHA256, re-verified with sha256sum after transfer
ordering: captured first — PID 8104/7812 are still believed running, and telemetry flags a PAGE_EXECUTE_READWRITE region with an MZ header in MSBuild.exe that exists only in memory. A kill, isolation, or reboot destroys this permanently.
2. Running process list and process tree, WST-WS-031
what: full process list — PID, PPID, command line, owning user, for every process
how: wmic process get ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath /format:csv > process_list.csv
where: /evidence/IR-2026-0414-01/process_tree/process_list.csv
hash cmd: certutil -hashfile process_list.csv SHA256, re-verified with sha256sum
ordering: captured second, still live/volatile — the only place to see the full chain (update.exe PID 7204 → powershell.exe PID 7812 → MSBuild.exe PID 8104) while processes are still alive to inspect.
3. Active network connections at time of capture
what: all active TCP/UDP connections and listening sockets, with owning PID
how: netstat -ano > netstat_snapshot.txt
where: /evidence/IR-2026-0414-01/network/netstat_snapshot.txt
hash cmd: certutil -hashfile netstat_snapshot.txt SHA256, re-verified with sha256sum
ordering: captured third, while the connection to 185.220.101.47:443 is still believed established — confirms whether the channel is still open before containment decides how urgent network isolation is.
4. Full endpoint telemetry export for WST-WS-031 (24h before the alert)
what: 24h EDR export (edr_wst_ws_031_24h.jsonl), 2026-04-13T03:10:23Z–2026-04-14T02:47:30Z
how: cp edr_wst_ws_031_24h.jsonl /evidence/IR-2026-0414-01/endpoint_telemetry/
where: /evidence/IR-2026-0414-01/endpoint_telemetry/edr_wst_ws_031_24h.jsonl
hash cmd: sha256sum edr_wst_ws_031_24h.jsonl → f7e404df7556b47bb97f08d10746cad73db374622c4d84035ce23317a8a6c325
ordering: not volatile, but preserved before containment — it is the only record of the full attack chain (drop, persistence, next-day execution); a fresh export after containment could roll this window out.
5. SIEM alert record, exported in JSON
what: the detection alert (alert_A-20260414-9841.json)
how: cp alert_A-20260414-9841.json /evidence/IR-2026-0414-01/siem/
where: /evidence/IR-2026-0414-01/siem/alert_A-20260414-9841.json
hash cmd: sha256sum alert_A-20260414-9841.json → 535f02ef55927decc138e5542ad825dea3754a7370c6ee05f58f7d8480eaf6db
ordering: low volatility but preserved early — the record every other document in this incident references.
6. Proxy and DNS logs for dmarsh (24h before the alert)
6a. Proxy log
what: 24h proxy log for the account (proxy_24h_dmarsh.log)
how: cp proxy_24h_dmarsh.log /evidence/IR-2026-0414-01/proxy_dns/
where: /evidence/IR-2026-0414-01/proxy_dns/proxy_24h_dmarsh.log
hash cmd: sha256sum proxy_24h_dmarsh.log → 7738cd69ce3c726273fa6ca1a3eac54bef3d22b63859af071a203cb90b80f303
ordering: preserved with the SIEM alert, before rotation could remove the 18:14:02Z phishing-visit entry.
6b. DNS resolution, host resolver cache
what: DNS queries resident in WST-WS-031's resolver cache (IP 10.42.118.31) — point-in-time, not 24h history
how: ipconfig /displaydns > dns_cache_wst-ws-031.txt
where: /evidence/IR-2026-0414-01/proxy_dns/dns_cache_wst-ws-031.txt
hash cmd: certutil -hashfile dns_cache_wst-ws-031.txt SHA256, re-verified with sha256sum
ordering: captured with Sections 2-3 — live, volatile host state, lost on cache flush or reboot.
6c. DNS resolution, internal DNS server query log
what: DNS server query log for 10.42.118.31, window 2026-04-13T02:47:00Z–2026-04-14T02:47:00Z
how: Get-WinEvent -LogName "Microsoft-Windows-DNS-Server/Analytical" | Where-Object { $_.Message -match "10.42.118.31" -and $_.TimeCreated -ge (Get-Date "2026-04-13T02:47:00Z") -and $_.TimeCreated -le (Get-Date "2026-04-14T02:47:00Z") } | Export-Csv dns_queries_dmarsh.csv
where: /evidence/IR-2026-0414-01/proxy_dns/dns_queries_dmarsh.csv
hash cmd: sha256sum dns_queries_dmarsh.csv, re-verified after transfer
ordering: captured with Section 6a — authoritative export, same urgency as the proxy log before rotation. Requires the DNS analytic log to have been enabled on the domain controller beforehand.
7. Authentication events for dmarsh (24h before the alert, AD + Azure AD)
what: combined AD + Azure AD authentication export (auth_24h_dmarsh.json)
how: cp auth_24h_dmarsh.json /evidence/IR-2026-0414-01/authentication/
where: /evidence/IR-2026-0414-01/authentication/auth_24h_dmarsh.json
hash cmd: sha256sum auth_24h_dmarsh.json → 398aae6da40893af8c41da489b875c96e1cb74d9d3c5a6485645811031a92ced
ordering: preserved with the other log exports, before any retention window rolls it off.
8. ADDITIONAL (beyond the required minimum): persistence and malware artifacts

Five artifacts that edr_wst_ws_031_24h.jsonl shows already exist on disk/registry and would be destroyed by eradication. Each is a separate item so none is mistaken for already covered by another.

8a. update.zip
what: dropper archive, C:\Users\dmarsh\Downloads\update.zip
how: robocopy C:\Users\dmarsh\Downloads \\evidence\IR-2026-0414-01\malware\ update.zip
where: /evidence/IR-2026-0414-01/malware/update.zip
hash cmd: certutil -hashfile update.zip SHA256 → telemetry value 3c2a1b9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a, re-confirmed at collection (Section 9)
ordering: before eradication — destroyed once the dropper is deleted during cleanup.
8b. update.xml
what: MSBuild project file, C:\Users\dmarsh\AppData\Local\Temp\update.xml, modified by powershell.exe at 02:46:51Z right before execution
how: robocopy C:\Users\dmarsh\AppData\Local\Temp \\evidence\IR-2026-0414-01\malware\ update.xml
where: /evidence/IR-2026-0414-01/malware/update.xml
hash cmd: certutil -hashfile update.xml SHA256 → telemetry value a4f1e9b4fe7aa6d5d3f3e2b8c9a7d4e8f5b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3, re-confirmed at collection
ordering: before eradication — the only on-disk record of what MSBuild was instructed to run.
8c. update.exe
what: dropper executable, C:\Users\dmarsh\AppData\Local\Temp\update.exe, launched by the scheduled task at 02:44:05Z
how: robocopy C:\Users\dmarsh\AppData\Local\Temp \\evidence\IR-2026-0414-01\malware\ update.exe
where: /evidence/IR-2026-0414-01/malware/update.exe
hash cmd: certutil -hashfile update.exe SHA256 → telemetry value 5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b, re-confirmed at collection
ordering: before eradication — the binary that launched the full chain.
8d. Run key
what: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateSvc, pointing at update.exe
how: reg export HKCU\Software\Microsoft\Windows\CurrentVersion\Run \\evidence\IR-2026-0414-01\disk\run_key_export.reg
where: /evidence/IR-2026-0414-01/disk/run_key_export.reg
hash cmd: certutil -hashfile run_key_export.reg SHA256, re-verified with sha256sum
ordering: before eradication — clearing this key is a normal first cleanup step.
8e. Scheduled task
what: task {7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A}, trigger user_logon, action update.exe
how: schtasks /query /tn "{7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A}" /xml ONE > \\evidence\IR-2026-0414-01\disk\scheduled_task_export.xml
where: /evidence/IR-2026-0414-01/disk/scheduled_task_export.xml
hash cmd: certutil -hashfile scheduled_task_export.xml SHA256, re-verified with sha256sum
ordering: before eradication — the only artifact proving the user_logon trigger bridged the 8-hour gap between the evening drop and the next morning's execution.
9. Verification
Re-hash every item from Sections 1-8 at its evidence-store location: sha256sum /evidence/IR-2026-0414-01/*/* > verification_run.txt diff IR-2026-0414-01-hashes.txt verification_run.txt
Compare against IR-2026-0414-01-hashes.txt recorded at capture time.
Any mismatch is logged as a new OBSERVATION entry in incident_timeline.md referencing the original capture entry — never silently re-captured or corrected in place.
Preservation is complete, and containment authorized, only once every hash is confirmed unchanged.
