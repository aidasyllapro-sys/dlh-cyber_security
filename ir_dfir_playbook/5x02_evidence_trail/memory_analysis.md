Memory Analysis: ART-002 (wst-ws-031.mem) and ART-003 (wst-ws-017.mem)
Status of this analysis

Same constraint as Tasks 3 and 4: neither wst-ws-031.mem nor wst-ws-017.mem is present in this analysis environment, per the same mentor guidance. Every plugin command required by this task is documented with its exact syntax; every output is marked NOT AVAILABLE rather than invented. Per the task's own instruction, SIEM evidence (siem_alert_export.json, part of this module's materials) and, where relevant, EDR telemetry from the 5x01 phase of this same incident are used strictly as investigative context, each labeled with its real source and an evidentiary tier (confirmed / probable / possible). No SIEM- or EDR-sourced fact is presented as a Volatility finding, and no finding here is marked confirmed unless Volatility itself produced it.

Artifact verification
ART-002 hash: NOT AVAILABLE — wst-ws-031.mem not accessible in this environment.
ART-003 hash: NOT AVAILABLE — wst-ws-017.mem not accessible in this environment.
CoC entries updated: NO — no access event logged in chain_of_custody.md; none has occurred.
wst-ws-031.mem findings
ART-002-M01: Process tree (pending direct verification)

Command:

vol -f wst-ws-031.mem windows.pslist.PsList
vol -f wst-ws-031.mem windows.pstree.PsTree

Output: NOT AVAILABLE.

Investigative context (not a Volatility finding): siem_alert_export.json (this module's own materials) reports powershell.exe (PID 7812) as parent of MSBuild.exe (PID 8104). EDR telemetry from 5x01 (edr_wst_ws_031_24h.jsonl, not part of 5x02 materials) adds that powershell.exe (PID 7812) was itself a child of update.exe (PID 7204, launched by the scheduled task at 2026-04-14T02:44:03Z), and that MSBuild.exe launched at 2026-04-14T02:46:57Z. Certainty: probable — consistent process-create telemetry from two independent sources (SIEM alert and EDR agent), but not yet independently confirmed by reading the live process list from memory. ATT&CK: T1127.001 (Trusted Developer Utilities Proxy Execution: MSBuild), T1059.001 (PowerShell).

ART-002-M02: Command-line arguments (pending direct verification)

Command:

vol -f wst-ws-031.mem windows.cmdline.CmdLine

Output: NOT AVAILABLE.

Investigative context: siem_alert_export.json records a truncated encoded PowerShell command line for PID 7812 and msbuild.exe C:\Users\dmarsh\AppData\Local\Temp\update.xml for PID 8104. Certainty: probable — the SIEM's own process-tree snapshot, not a live memory read of the process object's command-line field. ATT&CK: T1027 (Obfuscated Files or Information — base64-encoded PowerShell).

ART-002-M03: Network connection (pending direct verification)

Command:

vol -f wst-ws-031.mem windows.netscan.NetScan

Output: NOT AVAILABLE.

Investigative context: siem_alert_export.json reports an ESTABLISHED TCP connection to 185.220.101.47:443, tagged tor_exit_relay. EDR telemetry from 5x01 ties this connection to MSBuild.exe (PID 8104), first established at 2026-04-14T02:47:02Z, with a second connection at 02:47:30Z. Certainty: probable — SIEM/EDR-reported network telemetry, not a live socket-table read from memory at acquisition time (03:02Z). The connection may or may not still have been open 15 minutes later when the memory was actually captured; only windows.netscan.NetScan output can confirm that. ATT&CK: T1071.001 (Application Layer Protocol: Web Protocols), T1090.003 (Multi-hop Proxy: Tor).

ART-002-M04: DLLs loaded by msbuild.exe

Command:

vol -f wst-ws-031.mem windows.dlllist.DllList --pid 8104

Output: NOT AVAILABLE.

No other evidence source in this incident's record reports a DLL-load list for this process. Certainty: not assessed — nothing is asserted.

ART-002-M05: Injected executable memory (pending direct verification)

Command:

vol -f wst-ws-031.mem windows.malfind.Malfind

Output: NOT AVAILABLE.

Investigative context: EDR telemetry from 5x01 reports a process_memory_region event at 2026-04-14T02:47:14Z for a region tagged PAGE_EXECUTE_READWRITE, has_mz_header: true, with an EDR analyst note "candidate_for_malfind" — the EDR agent's own heuristic already pointed at this process. Certainty: probable — a strong, specific lead, but it is the EDR agent's interpretation of memory at the time of its own scan, not windows.malfind.Malfind's output against the acquired memory dump. It becomes confirmed only once malfind independently reports a matching region (protection flags, MZ header) for PID 8104. ATT&CK: T1055 (Process Injection) — pending confirmation.

ART-002-M06: Handles held by lsass.exe

Command:

vol -f wst-ws-031.mem windows.handles.Handles --pid <lsass_pid>

Output: NOT AVAILABLE. The PID for lsass.exe is itself unknown without a real windows.pslist run — the placeholder cannot be substituted yet.

No other evidence source in this incident's record reports lsass.exe handle activity. Certainty: not assessed — nothing is asserted.

ART-002-M07: NTLM hash exposure

Command:

vol -f wst-ws-031.mem windows.hashdump.Hashdump

Output: NOT AVAILABLE.

No NTLM hash, SAM entry, or LSA secret is recorded anywhere in this document. This is credential material: once real output exists, it must be handled under the same access controls as the artifacts themselves (see chain_of_custody.md), and referenced in this report only by account name and whether exposure occurred — never by pasting the hash values into a document that may be shared with the board.

Certainty: not assessed — nothing is asserted.

wst-ws-017.mem findings
ART-003-M01: Process list and command lines (pending direct verification)

Commands:

vol -f wst-ws-017.mem windows.pslist.PsList
vol -f wst-ws-017.mem windows.cmdline.CmdLine

Output: NOT AVAILABLE.

Investigative context: EDR telemetry from 5x01 (auth_expansion_0334Z.log, not part of 5x02 materials) reports powershell.exe (PID 4402, parent services.exe, PID 720) launched at 2026-04-14T03:23:44Z with a base64-encoded command line, followed by MSBuild.exe (PID 5108, parent PID 4402) at 03:24:12Z running msbuild.exe C:\Users\dmarsh\AppData\Local\Temp\update.xml — the same attack pattern as wst-ws-031.mem, on a different host, reached via the lateral movement already logged in ad_auth_log.jsonl (this module's materials, Kerberos TGS requests for cifs/WST-WS-017 at 03:22:47Z-03:22:48Z). Certainty: probable — EDR-reported process-create telemetry, not a live memory read. ATT&CK: T1127.001, T1059.001, T1021 (lateral movement, technique sub-type pending direct verification against the live session/ticket data in memory).

ART-003-M02: Network connection (pending direct verification)

Command:

vol -f wst-ws-017.mem windows.netscan.NetScan

Output: NOT AVAILABLE.

Investigative context: EDR telemetry from 5x01 reports an ESTABLISHED connection from MSBuild.exe (PID 5108) to 91.234.99.107:443 at 2026-04-14T03:27:13Z — a second, distinct C2 IP from the one seen on wst-ws-031.mem. Certainty: probable. ATT&CK: T1071.001, T1090.

Additional findings

No additional plugin was run beyond the three minimums (pslist, netscan, cmdline), since wst-ws-017.mem is not available. Nothing further is asserted for this artifact.

Outstanding work

This document is incomplete by design and must be revised, not replaced, once wst-ws-031.mem and wst-ws-017.mem are available:

Run all eight required plugins against wst-ws-031.mem; record real output for each ART-002-M0# entry.
Substitute the real lsass.exe PID (from windows.pslist) into the handles command before running it.
Run pslist, netscan, and cmdline against wst-ws-017.mem; consider pstree and malfind as additional findings if the pattern from wst-ws-031.mem repeats.
Upgrade every "probable" certainty above to "confirmed" only where live Volatility output independently matches the SIEM/EDR-sourced context; document any mismatch as a DEVIATION, not a silent correction.
Treat any hashdump output as credential material: do not paste raw hash values into this or any other report; reference only account name and exposure status.
Log the access in chain_of_custody.md the moment any of the above actually runs against the real artifacts, per the append-only rule.
