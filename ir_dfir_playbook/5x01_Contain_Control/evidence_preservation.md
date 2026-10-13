Evidence Preservation Runbook: IR-2026-0414-01

Evidence store: /evidence/IR-2026-0414-01/ (created by evidence_store_init.sh; subfolders used below match that script's taxonomy exactly: memory, disk, process_tree, network, endpoint_telemetry, siem, proxy_dns, authentication, malware, correlation)

Hash algorithm: SHA-256 Hash manifest: IR-2026-0414-01-hashes.txt

Host under preservation: WST-WS-031 (Windows 10 Pro 22H2, domain-joined, West Campus Laboratory) Account in scope: MEDDEFENSE\dmarsh

General rule for every step below: the item is captured first, hashed immediately after capture (on the analyst/evidence-store side, not trusted to the source), and the hash is appended to the manifest before moving to the next item. Nothing is deleted, killed, or reset on WST-WS-031 until Section 8 of this runbook is complete.

1. Volatile memory, WST-WS-031
what: full physical memory dump of the host
how:
  winpmem_3.3.rc3.exe -o \\evidence\IR-2026-0414-01\memory\wst-ws-031.mem
where: /evidence/IR-2026-0414-01/memory/wst-ws-031.mem
hash cmd (on the host, immediately after acquisition):
  certutil -hashfile wst-ws-031.mem SHA256

then re-hash after transfer to the evidence store with sha256sum wst-ws-031.mem and confirm the two values match before trusting the copy.

ordering: must be captured first. RAM is the single most volatile source here: PID 8104 (MSBuild.exe) and PID 7812 (powershell.exe) are both still believed to be running, and EDR telemetry (edr_wst_ws_031_24h.jsonl, event at 2026-04-14T02:47:14Z) already flags a PAGE_EXECUTE_READWRITE memory region with an embedded MZ header inside MSBuild.exe — a strong indicator of an injected or reflectively loaded executable that exists only in memory, not on disk. Any later step that kills a process, isolates the host, or resets power destroys this before it can ever be recovered.
2. Running process list and process tree, WST-WS-031
what: full process list with PID, PPID, command line, and owning user for every running process, not only the two already named in the alert
how:
  wmic process get ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath /format:csv > process_list.csv

or, if PowerShell is preferred and still trusted on this host:

  Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | Export-Csv process_list.csv
where: /evidence/IR-2026-0414-01/process_tree/process_list.csv
hash cmd: certutil -hashfile process_list.csv SHA256, re-verified with sha256sum after transfer
ordering: captured second, immediately after memory. This is still live, volatile state — it is the only place to see the full parent chain confirmed by edr_wst_ws_031_24h.jsonl (update.exe PID 7204 → powershell.exe PID 7812 → MSBuild.exe PID 8104, with update.exe itself launched by a scheduled task, not by the user directly) while the processes are still alive to inspect. The alert JSON alone only shows the last two hops of this chain; the live process list and the full telemetry export are what confirm the rest.
3. Active network connections at time of capture
what: all active TCP/UDP connections and listening sockets, with owning PID
how:
  netstat -ano > netstat_snapshot.txt
where: /evidence/IR-2026-0414-01/network/netstat_snapshot.txt
hash cmd: certutil -hashfile netstat_snapshot.txt SHA256, re-verified with sha256sum
ordering: captured third, while the connection to 185.220.101.47:443 is still believed established. edr_wst_ws_031_24h.jsonl already shows two separate outbound connections from MSBuild.exe PID 8104 to that IP (02:47:02Z and a second one at 02:47:30Z with 248 bytes sent / 5192 bytes received) — a live snapshot is needed to confirm whether the channel is still open, idle, or has already closed, which affects how urgent network-level containment is once this runbook finishes.
4. Full endpoint telemetry export for WST-WS-031 (24h before the alert)
what: the already-exported 24-hour EDR telemetry file for the host (edr_wst_ws_031_24h.jsonl), covering 2026-04-13T03:10:23Z through 2026-04-14T02:47:30Z
how: copy the file as provided, do not re-export or filter it:
  cp edr_wst_ws_031_24h.jsonl /evidence/IR-2026-0414-01/endpoint_telemetry/
where: /evidence/IR-2026-0414-01/endpoint_telemetry/edr_wst_ws_031_24h.jsonl
hash cmd: sha256sum edr_wst_ws_031_24h.jsonl actual value, computed directly from the provided lab file: f7e404df7556b47bb97f08d10746cad73db374622c4d84035ce23317a8a6c325
ordering: this file is not volatile — it already exists as an export — but it is preserved before containment regardless, because it is the only record showing the full attack chain: the update.zip download at 18:14:43Z, the registry Run-key and scheduled-task persistence set at 18:15:12Z/18:15:14Z, and the logon/execution sequence the next morning. If containment actions trigger new EDR events on the host, a fresh export taken afterward could overwrite or roll this window out of a limited retention buffer before it is copied out.
5. SIEM alert record, exported in JSON
what: the full detection alert as fired by the SIEM/EDR (alert_A-20260414-9841.json)
how:
  cp alert_A-20260414-9841.json /evidence/IR-2026-0414-01/siem/
where: /evidence/IR-2026-0414-01/siem/alert_A-20260414-9841.json
hash cmd: sha256sum alert_A-20260414-9841.json actual value: 535f02ef55927decc138e5542ad825dea3754a7370c6ee05f58f7d8480eaf6db
ordering: low volatility, but preserved early regardless, since it is the triggering record referenced by every other document in this incident (triage notes, timeline, this runbook) and must be hashed before any SIEM retention policy or index rotation could alter access to it.
6. Proxy and DNS logs for dmarsh (24h before the alert)
6a. Proxy log (already-exported artifact)
what: 24-hour proxy log for the account (proxy_24h_dmarsh.log)
how:
  cp proxy_24h_dmarsh.log /evidence/IR-2026-0414-01/proxy_dns/
where: /evidence/IR-2026-0414-01/proxy_dns/proxy_24h_dmarsh.log
hash cmd: sha256sum proxy_24h_dmarsh.log actual value: 7738cd69ce3c726273fa6ca1a3eac54bef3d22b63859af071a203cb90b80f303
ordering: preserved alongside the SIEM alert, before any proxy log rotation could remove the 2026-04-13T18:14:02Z entry showing the visit to the phishing domain.
6b. DNS resolution evidence (live capture — no export was provided to copy)
what: DNS queries resolved for WST-WS-031 (IP 10.42.118.31, per the alert's network_connection.local_ip) over the same 24-hour window, from two sources: the host's own resolver cache (volatile, point-in-time only) and the internal DNS server's query log (authoritative, covers the full window if logging was enabled)
how, host-side resolver cache (captured with Section 2-3, since it is live and volatile):
  ipconfig /displaydns > dns_cache_wst-ws-031.txt

(this only shows entries whose TTL has not yet expired; it will not reliably cover the full 24h window on its own, which is why the DNS server export below is the primary source)

how, internal DNS server query log (authoritative source for the full window):
  Get-WinEvent -LogName "Microsoft-Windows-DNS-Server/Analytical" |
    Where-Object { $_.Message -match "10.42.118.31" -and $_.TimeCreated -ge (Get-Date "2026-04-13T02:47:00Z") -and $_.TimeCreated -le (Get-Date "2026-04-14T02:47:00Z") } |
    Export-Csv dns_queries_dmarsh.csv

(requires the DNS Server analytic/debug log to have been enabled on the domain controller beforehand; if it was not, this is itself an eradication/visibility gap to note in the incident timeline, not something this runbook can retroactively fix)

where: /evidence/IR-2026-0414-01/proxy_dns/dns_cache_wst-ws-031.txt and /evidence/IR-2026-0414-01/proxy_dns/dns_queries_dmarsh.csv
hash cmd: certutil -hashfile dns_cache_wst-ws-031.txt SHA256 on the host, sha256sum dns_queries_dmarsh.csv on the DNS server export; both re-verified with sha256sum after transfer to the evidence store
ordering: the resolver cache is captured with Sections 2-3 (live, volatile host state); the DNS server export is captured alongside Section 6a (an authoritative log export, same urgency as the proxy log before rotation).
open gap, not filled by assumption: the lab materials provided to this module include a proxy log but no pre-existing DNS log export to copy and hash directly, unlike the other log-based sections. The commands above specify exactly how this evidence would be captured from the host and the DNS server in a real engagement; nothing below this line should be read as DNS data already being in hand, reviewed, or analyzed — only the capture procedure is established here.
7. Authentication events for dmarsh (24h before the alert, Active Directory + Azure AD)
what: the combined AD + Azure AD authentication export for the account (auth_24h_dmarsh.json), sourced from ad_domain_controller_ms-dc01, ad_domain_controller_ms-dc02, and azure_ad_signin_log
how:
  cp auth_24h_dmarsh.json /evidence/IR-2026-0414-01/authentication/
where: /evidence/IR-2026-0414-01/authentication/auth_24h_dmarsh.json
hash cmd: sha256sum auth_24h_dmarsh.json actual value: 398aae6da40893af8c41da489b875c96e1cb74d9d3c5a6485645811031a92ced
ordering: preserved with the other log exports, before any retention window could roll this off. This file turns out to carry the single most significant fact found while preparing this runbook (see note below) and must not be lost.

Significant finding surfaced while reviewing this file for this runbook — not yet reflected in the Task 0 triage note or the Task 1 timeline, and flagged here rather than silently left out: at 2026-04-13T18:14:41Z, an Azure AD sign-in for dmarsh@meddefense.local succeeded from IP 45.63.9.88, located in Russia, with MFA reported as satisfied, 39 seconds after the proxy log shows the same account visiting the phishing page (18:14:02Z). The record itself tags this risk_level_aggregated: medium, risk_detail: impossibleTravel, and notes the risk was "not promoted because device was marked compliant." This is a materially stronger signal than what Task 0 had available: it suggests the credentials entered on the phishing page were used within under a minute, from outside the account's normal geography, with an MFA prompt that was approved — which points toward either phished credentials paired with MFA fatigue/push-bombing, or a device-trust/conditional-access gap, rather than an unconfirmed "possible" credential exposure. This does not on its own prove which of those two mechanisms occurred — that distinction is not established by this file alone — but it does move credential compromise from "suspected" toward "high" certainty. Recommendation: this should be appended as a new entry in incident_timeline.md (not a rewrite of the existing entries), since it changes a past interpretation and the timeline's own rules require exactly that. I have not made that edit without confirming with you first, since it touches an already-delivered file.

8. Persistence and malware artifacts on WST-WS-031

Not explicitly itemized in the task's minimum list, but included because edr_wst_ws_031_24h.jsonl shows these artifacts exist on disk right now and would be destroyed by any eradication step (deleting the dropper, clearing the Run key, removing the scheduled task) — exactly the kind of evidence this runbook exists to protect.

what: the dropper file chain and the two persistence mechanisms it installed:
C:\Users\dmarsh\Downloads\update.zip (sha256 3c2a1b9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a, per telemetry)
C:\Users\dmarsh\AppData\Local\Temp\update.xml (sha256 a4f1e9b4fe7aa6d5d3f3e2b8c9a7d4e8f5b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3)
C:\Users\dmarsh\AppData\Local\Temp\update.exe (sha256 5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b)
registry value HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateSvc
scheduled task {7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A} (trigger: user_logon) (the three file hashes above are taken directly from edr_wst_ws_031_24h.jsonl's own sha256 fields at the time each file was created — not independently recomputed here, since the files have not yet been collected off the host at the time of writing this runbook; re-hashing at collection time, per Section 9, is what confirms they still match.)
how:
  robocopy C:\Users\dmarsh\Downloads  \\evidence\IR-2026-0414-01\malware\  update.zip
  robocopy C:\Users\dmarsh\AppData\Local\Temp  \\evidence\IR-2026-0414-01\malware\  update.xml update.exe
  reg export HKCU\Software\Microsoft\Windows\CurrentVersion\Run \\evidence\IR-2026-0414-01\disk\run_key_export.reg
  schtasks /query /tn "{7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A}" /xml ONE > \\evidence\IR-2026-0414-01\disk\scheduled_task_export.xml
where: /evidence/IR-2026-0414-01/malware/ (the three files) and /evidence/IR-2026-0414-01/disk/ (the registry and scheduled-task exports)
hash cmd: certutil -hashfile <file> SHA256 on the host at collection time, re-verified with sha256sum after transfer, for all five items
ordering: must happen before eradication, not before memory/network capture — these artifacts are persistent (they survive a reboot or a process kill), so they are not lost by the delay of Sections 1-3, but they would be destroyed the moment anyone deletes the dropper, clears the Run key, or removes the scheduled task as part of cleanup. This section is the last preservation step precisely because eradication is the next phase that would destroy it.
9. Verification
Every file captured in Sections 1-8 is re-hashed from its location inside /evidence/IR-2026-0414-01/:
  sha256sum /evidence/IR-2026-0414-01/*/* > verification_run.txt
  diff IR-2026-0414-01-hashes.txt verification_run.txt
Hash values are compared against the values recorded in IR-2026-0414-01-hashes.txt at capture time.
Any mismatch is not silently corrected or re-captured over the existing entry — per the timeline's append-only rule, a mismatch is logged as a new OBSERVATION entry in incident_timeline.md, referencing the original capture entry, so the discrepancy itself becomes part of the record rather than disappearing.
Only once every hash in Sections 1-8 is confirmed unchanged does this runbook consider preservation complete and containment authorized to proceed.
