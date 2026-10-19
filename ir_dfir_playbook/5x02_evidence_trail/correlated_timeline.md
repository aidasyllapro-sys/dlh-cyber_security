Correlated Incident Timeline: LH-2026-0414-01
Methodology note

Every row below is sourced from one of three places: this module's own supplementary logs (proxy_log.jsonl, ad_auth_log.jsonl, siem_alert_export.json — all read in full and cited by line number or field path), the disk/memory analyses from Tasks 3-5 of this module (all currently NOT AVAILABLE, since wst-ws-031.dd, wst-ws-031.mem, and wst-ws-017.mem are not present in this environment), or EDR telemetry from the 5x01 phase of this same incident (cited explicitly as such, and never upgraded past "probable"). Certainty follows the three-tier standard used throughout this investigation:

confirmed — a direct, verifiable log entry in a file this analyst has actually read.
probable — corroborated by an independent source, but not yet confirmed by the disk/memory evidence this specific event would normally rest on.
possible — a plausible inference consistent with confirmed downstream effects, with no direct observation of its own.

No row claims disk or memory evidence that Tasks 3, 4, or 5 do not actually contain.

Timeline
Timestamp (UTC)	Source	Event	ATT&CK	Certainty	Evidence Ref
2026-04-13T18:14:02Z	proxy_log.jsonl	dmarsh clicks phishing link to typosquat domain ms0365-support.login-verification.click, referred from an Outlook email	T1566.002	confirmed	proxy_log.jsonl line 7
2026-04-13T18:14:41Z	proxy_log.jsonl	dmarsh submits credentials to the fake login form (/auth/submit, HTTP 302)	T1566.002	confirmed	proxy_log.jsonl line 10
2026-04-13T18:14:41Z	ad_auth_log.jsonl	Azure AD sign-in to O365 Portal from 45.63.9.88 (Russia), same second as credential submission; risk flagged impossibleTravel but not blocked (device marked compliant)	T1078	confirmed	ad_auth_log.jsonl line 3
2026-04-13T18:14:43Z	proxy_log.jsonl	update.zip (421,004 bytes) downloaded from the phishing domain	T1566.002 / T1105	confirmed	proxy_log.jsonl line 11
2026-04-13T18:15:02Z-18:15:05Z	persistence_analysis.md / filesystem_analysis.md (EDR-corroborated, 5x01)	update.xml and update.exe dropped to C:\Users\dmarsh\AppData\Local\Temp\	T1105	probable — Task 3 disk evidence NOT AVAILABLE in this environment	filesystem_analysis.md, Temp section (EDR-sourced, not disk-confirmed)
2026-04-13T18:15:12Z-18:15:14Z	persistence_analysis.md (EDR-corroborated, 5x01)	Run key WindowsUpdateSvc and scheduled task {7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A} (trigger user_logon) installed	T1547.001 / T1053.005	probable — Task 4 registry evidence NOT AVAILABLE in this environment	persistence_analysis.md ART-001-R01, ART-001-R02
2026-04-14T02:44:02Z-02:44:03Z	ad_auth_log.jsonl	dmarsh Kerberos AS-REQ and interactive logon to WST-WS-031, flagged unusual_hour_for_user; this logon is what fires the user_logon-triggered scheduled task above	T1078	confirmed	ad_auth_log.jsonl lines 5-6
2026-04-14T02:44:17Z	ad_auth_log.jsonl	VPN logon using dmarsh credentials from external IP 45.63.9.88 (same IP as the 18:14:41Z sign-in); conditional access passed despite RU origin	T1133 / T1078	confirmed	ad_auth_log.jsonl line 7
2026-04-14T02:46:41Z	siem_alert_export.json	powershell.exe (PID 7812) executes with hidden window and base64-encoded command	T1059.001 / T1027	confirmed	siem_alert_export.json, alert.correlated_events[1]
2026-04-14T02:46:57Z	siem_alert_export.json	MSBuild.exe (PID 8104) spawned by powershell.exe (PPID 7812), running update.xml	T1127.001	confirmed	siem_alert_export.json, alert.process_tree.child
2026-04-14T02:46:58Z	proxy_log.jsonl	First outbound CONNECT from MSBuild.exe (PID 8104) to 185.220.101.47:443, a known Tor exit relay — C2 beacon starts	T1071.001 / T1090.003	confirmed	proxy_log.jsonl line 12
between 02:47Z and 03:22Z (no direct observation)	memory_analysis.md	NTLM hash and/or Kerberos ticket material accessible in lsass.exe memory	T1003.001	possible — inferred only from the fact that ticket reuse later succeeds (see 03:41:52Z row); Task 5 memory evidence NOT AVAILABLE, no direct handles/hashdump output exists	memory_analysis.md ART-002-M06, ART-002-M07 (not available)
2026-04-14T03:22:47Z-03:22:48Z	ad_auth_log.jsonl	Kerberos TGS requests for cifs/WST-WS-017 and host/WST-WS-017, source WST-WS-031	T1550.003	confirmed	ad_auth_log.jsonl lines 8-9
2026-04-14T03:23:01Z	ad_auth_log.jsonl	Network logon (type 3) to WST-WS-017 using dmarsh's ticket — lateral movement	T1021.002	confirmed	ad_auth_log.jsonl line 10
2026-04-14T03:27:13Z	proxy_log.jsonl	Second C2 beacon: MSBuild.exe (PID 5108) on WST-WS-017 connects to 91.234.99.107:443	T1071.001 / T1090	confirmed	proxy_log.jsonl line 15
2026-04-14T03:40:18Z	ad_auth_log.jsonl	Kerberos TGS request for cifs/LIS-WSIDE-01, source WST-WS-017	T1550.003	confirmed	ad_auth_log.jsonl line 11
2026-04-14T03:41:52Z	ad_auth_log.jsonl	Second TGS request for the same SPN, explicitly flagged second_request_with_ticket_reuse — the direct Pass-the-Ticket indicator	T1550.003	confirmed	ad_auth_log.jsonl line 12
2026-04-14T03:42:08Z	ad_auth_log.jsonl	Network logon (type 3) to LIS-WSIDE-01	T1021.002	confirmed	ad_auth_log.jsonl line 13
2026-04-14T03:43:30Z	ad_auth_log.jsonl	14 patient lab report PDFs opened under C:\LIS\reports\daily\ via share LIS_REPORTS$	T1005	confirmed	ad_auth_log.jsonl line 14
Notes on the probable and possible rows

The three rows marked probable or possible are exactly the findings Tasks 3, 4, and 5 could not confirm because wst-ws-031.dd, wst-ws-031.mem, and wst-ws-017.mem are not available in this environment. They remain in this timeline because excluding them would understate the attack chain this incident's own earlier evidence (5x01) already pointed to — but their certainty level is the honest signal of what is and is not yet independently proven by this module's own forensic work. Any of the three should be upgraded to confirmed, or revised, the moment real disk/memory analysis becomes possible, per the "Outstanding work" sections of filesystem_analysis.md, persistence_analysis.md, and memory_analysis.md.
