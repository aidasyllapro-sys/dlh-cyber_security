Task 0 - Triage the First Alert

Goal: Read the initial alert and decide severity, playbook, and the very first action.

Source: alert_A-20260414-9841.json (full alert, confirmed identical to the abridged version provided in the task text) and proxy_24h_dmarsh.log (24-hour proxy activity for the account), both from the official 5x01 lab materials archive.

Facts established directly from the alert
2026-04-14T02:46:41Z - powershell.exe (PID 7812) starts on WST-WS-031 under MEDDEFENSE\dmarsh, with -ep bypass -w hidden -enc <base64>. Signed by Microsoft. Decoding the base64 payload (UTF-16LE, PowerShell's encoding for -enc) gives the literal string $s="https://ms0365-support[]login-verification[]click/auth"; - the exact same domain dmarsh visited in the browser the evening before, now embedded directly in the PowerShell command line itself.
2026-04-14T02:46:57Z - that PowerShell process spawns MSBuild.exe (PID 8104), signed by Microsoft, run against C:\Users\dmarsh\AppData\Local\Temp\update.xml. MSBuild executing an XML project file to run code is a documented LOLBAS abuse pattern (MITRE ATT&CK T1127.001), already tagged on the alert alongside T1059.001 (PowerShell).
2026-04-14T02:47:02Z - MSBuild opens an outbound TCP connection to 185.220.101.47:443, established, 4198 bytes sent / 11203 bytes received. Internal threat intel tags this IP as a Tor exit relay, active as such since 2024-11-08, with 22/91 malicious detections on VirusTotal and an AbuseIPDB confidence of 84.
2026-04-13T18:14:02Z (the evening before) - the same account, dmarsh, visited ms0365-support[]login-verification[]click/auth, a login-page-style URL, logged with HTTP 200 in the proxy log.
Host: WST-WS-031, a high-criticality clinical workstation owned by the West Campus Laboratory, domain-joined.
The alert's own recommended_playbook field says PB-CRED-001 Credential Exposure.
Severity

Initial severity: SEV2, against the MedDefense severity matrix (severity_matrix.md, Module 5x00):

Patient Safety Impact: low. The host is a clinical workstation at the West Campus Laboratory, but nothing in the alert shows an interruption to patient care or lab operations at this point.
Data Exposure: suspected, not yet confirmed. A C2-style connection with bytes exchanged in both directions is a strong signal, but the alert does not show what, if anything, left the host - that is unverified.
Service Availability: none. No service degradation is reported.
This matches the matrix's own SEV2 example almost exactly: "Confirmed compromise of a clinical-access account" - the account is confirmed to have executed a Tor-connected process, even though downstream data exposure is not yet confirmed.

Escalation condition to flag immediately: if evidence preservation (see below) shows ePHI-reachable systems were touched from this session, or if the account had access beyond its own workstation, this escalates to SEV1 per the matrix's escalate_if criteria.

Playbook: do not take the alert's own recommendation at face value

The alert pre-fills recommended_playbook: PB-CRED-001 Credential Exposure. That label is not wrong as a secondary thread, but it describes only part of what the evidence shows, and taking it uncritically would point the first response at the wrong priority.

What is confirmed: a signed Microsoft binary (MSBuild) executed attacker-controlled content and established an outbound connection to a known-malicious Tor exit node. This is code execution with an active C2-style channel, not merely an exposed credential. It is also confirmed that the same phishing domain dmarsh visited the evening before is hard-coded into the PowerShell command line that kicked off this chain eleven hours later - that is a direct, evidence-backed link between the two events, not a coincidence of timing.
What is still suspected, not confirmed: that dmarsh's actual credentials were harvested and are what gave the attacker the access needed to run code under this account - the alert alone does not show that; it shows the phishing domain reappearing in the attacker's own script, which is consistent with credential theft but does not prove it by itself.

Recommendation: open this incident under an execution/C2 containment track first (the active channel to 185.220.101.47 is the most time-sensitive fact, and it is what is actually running right now), while treating credential exposure as a strongly-linked parallel track to confirm immediately via auth_24h_dmarsh.json - not as a separate, lower-priority afterthought. Treating this as pure credential exposure (the alert's own default) risks under-prioritizing the fact that a process is, right now, talking to Tor; treating it as unrelated to credential exposure would ignore the domain match just established above.

First action

Preserve volatile evidence on WST-WS-031 before any containment action - specifically, a memory capture of PID 8104 (MSBuild.exe) and PID 7812 (powershell.exe), and a live snapshot of the host's active network connections and process tree.

This follows the module's core rule (evidence before containment) rather than the instinct to immediately kill the process or pull the network cable. Nothing in the alert shows an irreversible action in progress (no encryption activity, no mass data movement beyond the 11KB received) that would justify skipping evidence capture as an emergency exception. The connection is already established and has already exchanged some data; a few more minutes spent capturing volatile evidence costs little compared to losing the memory contents of the two processes involved - which is exactly the evidence needed to confirm what the decoded PowerShell payload and the MSBuild project file actually did.

What remains an open question, not an assumption
The phishing domain reappearing inside the attacker's PowerShell payload is confirmed by direct decoding of the command line (see above) - but whether dmarsh's actual credentials were harvested and used is still not established by this alert alone. auth_24h_dmarsh.json and auth_expansion_0334Z.log are the next sources to check before concluding either way.
Whether any ePHI-reachable system was reached from this session is not established here - this is why the severity above is held at SEV2 and not escalated preemptively.
