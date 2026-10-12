HEALTHBANE Attack Reconstruction Report

MedDefense Health Systems — Incident Response & Threat Hunting, Module 4x05 Prepared for: Dr. Morales (CISO) and the Board, via James Chen Report date: 2026-10-12 Status: FINAL — grounded exclusively in evidence files under 4x05/ and in the tested reconstruction scripts 0-evidence_index.sh, 5-stages_1_2.sh, 7-stage_4.sh, 8-unified_timeline.sh, 9-attack_techniques.sh, 12-data_exposure.sh

Scope note on this report's own completeness. This report was assembled from the outputs of Tasks T0, T5, T7, T8, T9 and T12, all of which exist, were executed against the real evidence set, and are cited below. Tasks T6 (Stage 3 / Malware Deployment) was formally removed from the task list after being built; its content is folded into the Unified Timeline (Section 4) as raw-evidence events instead of a standalone stage writeup, per instruction. Tasks T10, T11, T13 and T14 were never specified or built in this engagement — no script, output, or source document exists for them in the evidence set reviewed here. Sections 5 (ATT&CK Analysis, partially), 7 (Defensive Posture Evaluation) and 8 (Remediation Plan) therefore contain explicit [DATA NOT AVAILABLE] markers rather than invented content. This is a conscious choice: the alternative — fabricating a defensive-posture narrative or a remediation timeline with no underlying evidence — would misrepresent this as a complete deliverable when it is not.

1. Executive Summary (for the Board)

What happened. Between 2026-04-14 and 2026-05-15, an attacker group ("HEALTHBANE") compromised MedDefense Health Systems through a spearphishing email to records-department employee Diane Marsh (workstation WS-RECV-03). The attacker established command-and-control, waited, then over several weeks dumped credentials from memory, moved laterally to the health-records database, the insurance database, and the domain controller, staged three archives of exfiltrated data, and transmitted all three to an external server before being detected and contained.

How far the attacker got. Four servers were reached from WS-RECV-03: SRV-HEALTH-DB (patient health records, CRITICAL/PHI), SRV-INS-DB (insurance/billing records, HIGH), and SRV-DC-01 (domain controller, HIGH/auth data) were all confirmed accessed and exfiltrated from. SRV-FILE-01 (file server, employee HR data) shows no evidence of attacker access. In total, 34.4 MB of staged data across three archives were transmitted in full to an external IP (185.220.101.45) over HTTPS — this is not a partial or interrupted exfiltration; all three transfers completed before containment (see Section 4 and Section 6).

How it was stopped. WS-RECV-03 was isolated on 2026-05-15 at 13:42 CDT, memory was captured by 14:18 CDT, and disk imaging completed by 19:45 CDT the same day (ir_team_notes.txt Entries #001–#003). This containment action occurred after all three exfiltration events (2026-05-08, 2026-05-11, 2026-05-13) had already completed — it stopped further persistence and activity, not data already in transit.

What happens next. This report identifies the evidence needed for regulatory notification (Section 6) and flags several unresolved items — a cross-document IP mapping discrepancy (Section 6, Section 3), an unresolved internal date contradiction in the hunting report (Section 3, Section 4), and an unverified claim of debug_tool.exe on two other hosts (Section 3) — that should be resolved before this report is finalized for external use. No defensive-posture evaluation or remediation plan exists in this evidence set (see Sections 7–8); producing those is the immediate next step, not something this report can respond to in Section 9.

Key metrics (all independently computed from the evidence, see Section 4):

Metric	Value
Total dwell time (first click to IR isolation)	31 days, 5h 23m 55s
Breakout time (first C2 beacon to first lateral movement)	20 days, 22h 20m 08s
Time to persistence (first C2 beacon to scheduled task)	21 days, 21h 55m 55s
Time to data staging (first C2 beacon to exfiltrator staged)	14 days, 22h 22m 30s
ATT&CK coverage, within original 29-technique model	27% → 80% → 96% (see Section 5 — the commonly-cited "40%" starting figure does not match what this evidence set actually supports)
Confirmed exfiltrated records	47,138 patient records + 51,002 insurance records + 1,184 AD accounts
2. Methodology

Evidence sources used (full inventory produced live by 0-evidence_index.sh, 13 sources):

#	File	Reliability
01	4x00_phishing_summary.txt	MEDIUM (derived summary)
02	4x01_network_timeline.txt	MEDIUM (derived summary)
03	4x02_attack_mapping.json	MEDIUM (derived summary)
04	4x03_malware_summary.txt	MEDIUM (derived summary)
05	4x04_hunting_report.txt	MEDIUM (derived summary)
06	disk_forensics_report.txt	HIGH (primary evidence)
07	firewall_sessions_ws_recv_03.json	HIGH (primary evidence)
08	ir_team_notes.txt	LOW (preliminary, partly unverified)
09	memory_artifacts.txt	HIGH (primary evidence)
10	attck_navigator_80pct.json	HIGH (reference)
11	healthbane_ioc_master.json	HIGH (reference)
12	meddefense_asset_inventory.txt	HIGH (reference)
13	network_topology.txt	HIGH (reference)

Temporal coverage gaps identified at inventory time: no evidence source covers Week 14 or Week 17, and phases 4x00–4x04 are each covered by only one source until the 4x05 IR evidence (memory/disk/firewall) arrives — a collection limitation flagged from the outset, before any correlation work began.

Analytical approach:

All figures in this report are extracted live (via grep -oP / jq) from the evidence files at the time each script ran — nothing below is a value typed from memory.
A three-tier confidence framework is used throughout: CONFIRMED/CONVERGED (two or more independent sources agree, including byte-exact or timestamp matches), PROBABLE/SINGLE-SOURCE (one direct source, no contradiction), POSSIBLE (capability present but use unconfirmed or use ruled out by direct evidence).
Where sources disagree, this report states both values and which is used, rather than silently picking one (see Sections 3, 4, 6 for three such cases).

Limitations and assumptions:

Timestamps are reconciled across a documented ~4-second clock skew between firewall logs and PCAP/Wazuh timestamps (established in prior tasks T3–T4, reused here).
"Confirmed access" to a host means direct evidentiary interaction (lateral-movement session + byte-matched data artifact), not merely credential scope or network reachability — several hosts assessed in Section 6 are rated differently from the task's own template for this reason, with the evidentiary basis stated explicitly.
Sections 5, 7 and 8 are incomplete due to missing source tasks (T10, T11, T13, T14) — see the scope note at the top of this report.
3. Attack Reconstruction
Stage 1: Initial Access (Phishing)

Source: 4x00_phishing_summary.txt, cross-checked against 4x01_network_timeline.txt

2026-04-14T13:18:05Z — Diane Marsh (WS-RECV-03, account dmarsh) clicks a spearphishing link in an email spoofing the MedDefense portal (lookalike domain meddefense-portal.com, registered 2 days before the campaign, SPF hardfail / DKIM missing / DMARC fail). Technique: T1566.001. Confidence: CONFIRMED (email headers + DNS/TLS resolution in PCAP).
2026-04-14T13:18:42Z — Credentials submitted to meddefense-portal.com/login.aspx. Confirmed by two independent sources with an exact timestamp match (4x00 domain analysis and 4x01 PCAP HTTP POST, 743 bytes). Technique: T1078. Confidence: CONVERGED.
2026-04-14T13:20:00Z — dmarsh password rotated by IR (Robert Kim), 1m 18s after submission. 4x00 explicitly states the credential was not reused post-rotation — Stage 2 arrives via a separate delivery mechanism, not credential reuse.
Stage 2: C2 Establishment

Sources: 4x01_network_timeline.txt and firewall_sessions_ws_recv_03.json

2026-04-15T08:43:18Z — Second-wave dropper (HEALTHBANE_S2_invoice.docm) delivered, released from quarantine by a helpdesk operator 19h 24m 36s after Stage 1.
2026-04-15T08:51:11Z — RAT binary (svchost_update.exe) downloaded following a DNS query for update.healthbane-c2.net → 185.220.101.45.
2026-04-15T08:51:38Z — First C2 beacon (185.220.101.45:443, JA3 72a589da586844d7f0818ce684948eea, ~300s ±10s interval, 289 further beacons observed). Techniques: T1071.001, T1573.001. Confidence: CONFIRMED (single source, direct PCAP capture).
Firewall cross-check: the firewall export only starts 2026-05-02, i.e. 16 days after Stage 2 established — it cannot corroborate the establishment moment itself (a genuine evidence gap, not a contradiction), but it does corroborate the same beacon pattern continuing (same IP, same JA3, same interval) from 2026-05-02T08:14:08Z onward.
2026-05-07T06:48:11Z — A secondary C2 channel to 203.0.113.47:8443 appears, firewall-only, not present in any prior IOC list. This is 21d 21h 56m 33s after Stage 2's establishment — it was not part of initial C2 setup but deployed later as standby/fallback infrastructure (PROBABLE confidence; a transient earlier use cannot be fully excluded given the 2026-04-16→2026-05-02 collection gap).
T1568 (Dynamic Resolution): explicitly NOT OBSERVED — both C2 domains resolve to a single static IP throughout; no fast-flux or DGA pattern in any source.
Stage 3: Malware Deployment

No dedicated Stage 3 task exists in the current scope (T6 was removed from the task list). Per instruction, these events are carried as raw, directly-cited evidence items in the Unified Timeline (Section 4) rather than as a standalone narrative: RAT reboot-persistence (2026-04-22, 4x03_malware_summary.txt + memory_artifacts.txt [K1]), exfiltrator staged on disk (2026-04-30, 4x03 + disk_forensics_report.txt [F5]), and the Windows Defender exclusion for C:\Windows\Temp (2026-05-04, memory_artifacts.txt [K5]). See Section 4, events #07–#09.

Stage 4: Lateral Movement, Credential Access, Data Staging and Exfiltration, Persistence, Containment

Source: 4x04_hunting_report.txt, cross-checked against firewall_sessions_ws_recv_03.json, disk_forensics_report.txt, memory_artifacts.txt, ir_team_notes.txt

Lateral movement chain:

Date/Time (CDT)	Event
2026-05-05 03:22	Credential dump #1 (debug_tool.exe → LSASS)
2026-05-06 02:12	PsExec session #1: WS-RECV-03 → SRV-HEALTH-DB
2026-05-09 03:40	PsExec session #2: WS-RECV-03 → SRV-INS-DB (disputed timestamp, see below)
2026-05-12 02:45	Credential dump #2 (LSASS re-dump)
2026-05-13 01:56	PsExec session #3: WS-RECV-03 → SRV-DC-01

Corroborated by PsExec64.exe prefetch (first run 2026-05-06 02:11:42 CDT, matching event #1) and by 47 LATERAL_MOVEMENT firewall sessions. Technique: T1021.002, T1047, T1021.006. An analyst note in the firewall evidence flags that this cross-VLAN access (records-VLAN to server-segment) has no legitimate business reason and that the firewall rule permitting it is overly permissive.

Credential access: debug_tool.exe opened LSASS (PID 648) with the canonical Mimikatz-class access mask; the on-disk binary's SHA256 is recorded in disk_forensics_report.txt [F2]. The partially-recovered LSASS dump (~11 MB of ~23 MB original) confirms plaintext svc_healthsync strings. Technique: T1003.001.

Data staging and exfiltration (byte-exact matched between disk-recovered archives and firewall EXFIL_BURST sessions — see Section 6 for full detail):

2026-05-08T07:38:14Z — 14,219,484 bytes — staging_export_001.zip — 47,138 patient records
2026-05-11T08:17:18Z — 11,802,944 bytes — staging_export_002.zip — 51,002 insurance records
2026-05-13T07:34:14Z — 8,419,232 bytes — query_results.csv — 1,184 AD records

These three are described in the evidence itself as "the highest-confidence individual exfil events in the entire campaign." Techniques: T1074.001, T1560.001, T1041, T1005.

Persistence and defense evasion:

Scheduled task "HealthSync Update Service" created 2026-05-07 01:47:33 CDT, daily 02:00 CDT trigger, hidden, re-runs the exfiltrator. T1053.005.
Windows Defender exclusion for C:\Windows\Temp added 2026-05-04 18:11 CDT, ~9 hours before the first LSASS dump, written under records03's locally-admin token (a long-standing misconfiguration). T1562.001.
Security event log cleared 2026-05-09 03:01:42 CDT (12-minute $MFT-reconstructed gap). T1070.001.
Disk-forensics' own analyst assessment: the attacker performed basic anti-forensics (deletion, log clearing, AV exclusion) but not advanced anti-forensics (no VSS/USN/prefetch deletion) — consistent with a financially-motivated commodity actor rather than nation-state tradecraft, and the reason disk forensics recovered as much as it did.

Containment: WS-RECV-03 isolated 2026-05-15 13:42 CDT; memory capture complete 14:18 CDT; disk imaging complete 19:45 CDT (ir_team_notes.txt Entries #001–#003).

Internal contradictions flagged, not silently resolved:

4x04_hunting_report.txt's own header states the hunt was initiated 2026-05-18, while its own body (Recommendations) states containment actions R1–R3 were already carried out on 2026-05-15 — three days before the header's stated hunt-start date. Three independent, mutually consistent sources (memory-capture header, disk-image header, ir_team_notes.txt) place isolation at 2026-05-15. This report treats 2026-05-15 as correct and flags 2026-05-18 as an unresolved documentation error in the 4x04 report, not as an alternative fact.
PsExec session #2's timestamp is given three different ways across sources: 4x04's narrative text says 03:40 CDT; disk prefetch and the firewall log agree with each other (within ~7 seconds, consistent with the documented clock skew) at ~02:46 CDT. This report uses the two-source-converged time and flags 4x04's narrative figure as a likely transcription error.
Robert Kim's claim (ir_team_notes.txt Entry #004) of having seen debug_tool.exe on WS-RECV-04 and WS-RECV-07 is unresolved, not disproven: the 4x04 hunt's own queries found WS-RECV-03 as the sole source host for all 21 anomalous events, but those hosts were out of scope for the evidence set reviewed here.
4. Unified Timeline

Source: 8-unified_timeline.sh, merging Stage 1-2 (T5) + Stage 4 (T7) plus directly-cited Stage-3 raw events. 22 events total.

#	Timestamp (UTC)	Event	ATT&CK	Confidence	Sources
01	2026-04-14T13:18:05Z	Diane clicks phishing link	T1566.001	CONF	4x00
02	2026-04-14T13:18:42Z	Credentials submitted	T1078	CONV	4x00, 4x01
03	2026-04-14T13:20:00Z	dmarsh password rotated (IR)	—	CONF	4x00
04	2026-04-15T08:43:18Z	Stage-2 dropper delivered	T1566.001	CONF	4x01
05	2026-04-15T08:51:11Z	RAT binary downloaded	T1105	CONF	4x01
06	2026-04-15T08:51:38Z	First C2 beacon	T1071.001	CONF	4x01
07	2026-04-22T06:14:17Z	RAT persists across reboot	T1547.001	CONV	4x03, memory[K1]
08	2026-04-30T07:14:08Z	Exfiltrator staged on disk	T1105	CONF	4x03, disk[F5]
09	2026-05-04T23:11:08Z	Defender exclusion added	T1562.001	CONF	memory[K5], disk[R3]
10	2026-05-05T08:22:14Z	Credential dump #1 (LSASS)	T1003.001	CONV	4x04, memory, disk, firewall
11	2026-05-06T07:11:46Z	PsExec#1 → SRV-HEALTH-DB	T1021.002	CONV	4x04, disk-prefetch, firewall
12	2026-05-07T06:47:33Z	Scheduled task created	T1053.005	CONV	memory[K2], disk[Sec4]
13	2026-05-07T06:48:11Z	Secondary C2 first connection	T1071.001	SNGL	firewall-only
14	2026-05-08T07:38:14Z	Exfil burst #1 (47,138 records)	T1041	CONV	firewall, disk[D1]
15	2026-05-09T07:46:18Z	PsExec#2 → SRV-INS-DB	T1021.002	CONV	4x04, disk-prefetch, firewall
16	2026-05-09T08:01:42Z	Security log cleared (12m gap)	T1070.001	CONV	disk-MFT, firewall-gap
17	2026-05-11T08:17:18Z	Exfil burst #2 (51,002 records)	T1041	CONV	firewall, disk[D2]
18	2026-05-12T07:45:01Z	Credential dump #2 (LSASS)	T1003.001	CONV	4x04, memory, disk-prefetch
19	2026-05-13T07:08:58Z	PsExec#3 → SRV-DC-01	T1021.002	CONV	4x04, disk-prefetch, firewall
20	2026-05-13T07:34:14Z	Exfil burst #3 (1,184 AD records)	T1005	CONV	firewall, disk[D3]
21	2026-05-15T07:00:14Z	Last attacker activity (empty config)	T1053.005	SNGL	firewall-only
22	2026-05-15T18:42:00Z	IR isolation of WS-RECV-03	—	CONV	ir_team_notes, firewall-deny

Convergence: 13/22 events (59%) have converged (multi-source) evidence; 9/22 (41%) are single-source.

Temporal metrics: dwell time 31d 5h 23m 55s; breakout time 20d 22h 20m 08s; time to persistence 21d 21h 55m 55s; time to data staging 14d 22h 22m 30s. Detection-to-containment could not be cleanly computed due to the 4x04 header/body date contradiction (Section 3). Attacker operational tempo clusters between 01:45–03:45 CDT (off-hours) on eight distinct dates.

Identified gaps:

GAP 1 (2026-04-15→2026-04-22, ~6d 21h): no attacker activity beyond routine beaconing between C2 establishment and reboot-persistence; assessed as a dormant/waiting period, not a collection gap (the PCAP covers this window).
GAP 2 (2026-04-22→2026-04-30, ~8d 01h): the single largest blind spot in the entire reconstruction — no source in the evidence set covers this window at all (PCAP ends 2026-04-16, firewall export starts 2026-05-02). A genuine evidence gap, not an inferred lull.
GAP 3 (2026-05-13→2026-05-15, ~1d 23h): quiescent period, single-source (firewall beaconing only); ir_team_notes.txt speculates "operator reviewing data" but this is explicitly a hypothesis, not a fact, and is kept as such here.
5. ATT&CK Analysis

Source: 9-attack_techniques.sh, re-assessing the 29-technique baseline from attck_navigator_80pct.json against live evidence.

Baseline integrity finding: the baseline file's own summary field claims 23 OBSERVED/3 INFERRED/3 NOT COVERED, but the actual technique array contains 22/3/4. This script uses the verified array counts, not the file's own (incorrect) summary — the same class of internal inconsistency previously found in 4x02_attack_mapping.json (claims 11 observed; actual array has 8).

Coverage evolution (verified where possible):

Post-4x02 (intelligence): the 4x02 file's own summary claims 11/29; the actual techniques array contains 8/29. Using the verified array count: 27% (8/29).
Post-4x03/Post-4x04: no independent Navigator-layer JSON exists for 4x03 in this evidence set, so this figure could not be independently re-verified. Reported as 4x04's own stated claim: 55% → 80% (16/29 → 23/29).
Post-4x05 (this reconstruction), within the original 29-technique model: 96% (28/29), directly verified against the techniques array.

Discrepancy with the task template: this report's instructions reference a coverage progression of "40% → 55% → 80% → 96%". The evidence actually available supports 27% (not 40%) as the earliest independently verifiable figure. This is flagged rather than silently adjusted to match the template — either the 40% figure refers to a source not present in this evidence set, or it is itself one of the summary/array inconsistencies seen elsewhere in these files. I cannot resolve which without an additional source.

Technique changes from this reconstruction:

6 techniques upgraded from INFERRED/NOT COVERED to CONFIRMED: T1041, T1005, T1053.005, T1074.001, T1560.001, T1070.001 — each with a specific disk/memory/firewall artifact cited in 9-attack_techniques.sh's output.
3 new techniques identified outside the original 29-technique model: T1562.001 (Defender exclusion), T1070.004 (staging-file deletion), T1571 (non-standard-port secondary C2).
1 technique corrected downward: T1048.003 (DNS exfiltration) — the baseline rated this INFERRED ("not yet exercised"); the recovered exfiltrator config ("channel":"c2_post", found independently in both memory slack-space and the disk-recovered hb_cfg.json) shows the attacker's own configuration selected HTTPS, not DNS. Reclassified POSSIBLE-NOT-USED.
Remaining gap: exactly 1/29 techniques (T1048.003) — a resolved absence (capability present, direct evidence of non-use), not a collection limitation.

Gap analysis and blind-spot assessment: [DATA NOT AVAILABLE] — a dedicated gap/blind-spot analysis task (T11, if that is what is referenced) was not built in this engagement. The closest available material is the timeline gap analysis in Section 4 (GAPs 1–3) and the single remaining ATT&CK gap above; a fuller blind-spot assessment combining both views has not been produced.

6. Impact Assessment

Source: 12-data_exposure.sh

Preliminary finding — cross-source IP discrepancy. network_topology.txt and meddefense_asset_inventory.txt agree with each other on SRV-HEALTH-DB (10.10.20.15) and SRV-INS-DB (10.10.20.25), but the firewall export's own metadata uses different IPs (10.10.20.30 / .31) that match no documented host at all — 10.10.20.30 is, per the asset inventory, actually SRV-FILE-01's address. This report therefore does not rely on the firewall's internal IP labels for host attribution, using instead (a) hostname-based attribution from Sysmon/PsExec /node:<host> targeting in 4x04_hunting_report.txt, and (b) byte-exact matching between recovered disk archives and exfiltration sessions — both independent of the disputed IPs.

Compromised system mapping:

Host	Role	Data Sensitivity	Access Level
WS-RECV-03	Records Dept WS	LOW (local)	CONFIRMED ACCESS
SRV-HEALTH-DB	Health Records	CRITICAL (PHI)	CONFIRMED ACCESS
SRV-INS-DB	Insurance DB	HIGH (PII+financial)	CONFIRMED ACCESS
SRV-DC-01	Domain Controller	HIGH (auth)	CONFIRMED ACCESS
SRV-FILE-01	File Server	MEDIUM	NO ACCESS

This departs from the task's own template (which suggests PROBABLE/POSSIBLE/PROBABLE for the last three rows): the byte-exact match between D2/D3 and firewall exfil sessions, plus named targeting in the hunting report, justifies CONFIRMED for SRV-INS-DB and SRV-DC-01; the complete absence of any lateral-movement evidence toward SRV-FILE-01 (the only observed access is a benign, unrelated file share) justifies NO ACCESS rather than PROBABLE.

Exfiltration status: 34.4 MB staged across 3 files on WS-RECV-03, and all three transmitted in full to 185.220.101.45:443 over HTTPS, each a byte-exact match to its staged archive:

Burst	Staged (disk)	Transmitted (firewall)	Match
#1	14,219,484 B	14,219,484 B	EXACT
#2	11,802,944 B	11,802,944 B	EXACT
#3	8,419,232 B	8,419,232 B	EXACT

Isolation (2026-05-15, 13:42 CDT) occurred after all three transmissions — it did not interrupt an exfiltration in progress. A claimed "4th exfiltration attempt" on 2026-05-15 (ir_team_notes.txt) is not corroborated by any firewall session from that date; the source document itself labels it a hypothesis, and this report does not treat it as fact.

Data exposure by type:

Type	Status	Scope
Patient health records (PHI)	CONFIRMED EXFILTRATED	47,138 patients (exact figure from firewall annotation; asset inventory's rounded estimate: ~47,000)
Insurance/billing data	CONFIRMED EXFILTRATED	51,002 policies/members (asset inventory: ~51,000)
Employee records	NOT EXPOSED	~320 employees at risk if SRV-FILE-01 had been reached — it was not
Operational/AD data	CONFIRMED EXFILTRATED	1,184 AD accounts (outside direct PHI scope but a major security/credential impact)

Regulatory assessment:

HIPAA breach notification threshold: MET. Basis: PHI covering tens of thousands of individuals confirmed exfiltrated to an unauthorized external IP, far above the 500-individual threshold (45 CFR 164.402/164.408).
Estimated scope: on the order of 50,000–98,000 individuals depending on deduplication between the patient and insurance populations — this overlap is expected but not quantified in the available evidence; a precise figure requires DPO-level deduplication work this report cannot perform from the files alone.
Mitigating factors:
None on the exfiltration-completeness axis — all three transfers finished before containment.
SSN encryption is an open question, not a confirmed mitigating factor: the asset inventory states SSNs are "encrypted at rest," but the exfiltrator's recovered SQL query selects the ssn column directly through a standard application query. Whether this returns usable plaintext (if encryption is transparent/TDE) or an unusable ciphertext (if column-level) cannot be determined from these files; the database team should confirm before any notification letter cites encryption as a mitigant.
Containment occurred after exfiltration completed, so detection speed does not mitigate volume already lost — it limited only further persistence.
Recommended action: notify (threshold exceeded); commission a precise deduplication analysis of the patient/insurance population; obtain technical confirmation of the SSN encryption mode before finalizing any notification letter.
7. Defensive Posture Evaluation

[DATA NOT AVAILABLE] — this section requires Task T13, which was never specified or built in this engagement. No defensive-posture source document (detection-rule performance, control-failure analysis, or "what worked / what failed" writeup) exists in the evidence set reviewed here. The closest adjacent material actually in evidence:

The firewall analyst's own note that the users-to-server-segment rule is "overly permissive" and allowed WS-RECV-03 unrestricted cross-VLAN access to the server segment with no legitimate business justification (Section 3, Lateral Movement).
The disk-forensics analyst's assessment that the attacker used only basic anti-forensics, which is why so much evidence survived for this reconstruction (Section 3, Persistence and Defense Evasion).
The pre-existing local-admin misconfiguration on records03's account that enabled both the Defender exclusion and (implicitly) parts of the lateral-movement chain.

These are evidence-grounded observations, not a structured evaluation against the task's required structure (what worked / what failed / structural lessons), and should not be presented as satisfying Section 7.

8. Remediation Plan

[DATA NOT AVAILABLE] — this section requires Task T14, which was never specified or built in this engagement. No remediation-plan source document exists in the evidence set. Producing a credible prioritized (immediate/short-term/medium-term) remediation plan needs the Section 7 defensive-posture evaluation as an input; building one without it risks a plan disconnected from the actual control failures observed. This is the recommended next deliverable.

9. Conclusions
What Module 4 demonstrated about the gap between detection and understanding. Each individual investigation phase (4x00 through 4x04) produced a plausible, internally-consistent narrative — yet two of those phase reports (4x02, 4x04) contain summary fields that contradict their own underlying data arrays, and 4x04 contains a header-vs-body date contradiction so direct that its claimed hunt-start date comes after the containment actions its own body says the hunt triggered. None of this was visible from inside any single phase; it only surfaced once this reconstruction cross-checked every claim against the primary IR evidence (memory, disk, firewall) collected afterward.
Why investigation in pieces creates blind spots that only reconstruction reveals. GAP 2 in the unified timeline (2026-04-22 to 2026-04-30, Section 4) exists precisely because no single phase's collection window covered it — the PCAP ended before it started and the firewall export began after it ended. A phase-by-phase read of the evidence would not surface this as a gap at all; it is only visible once all sources are placed on one timeline.
Why proactive hunting and forensic readiness are not optional. The 4x04 hunt found what it found because it existed; the IR evidence (memory/disk/firewall) confirmed and extended those findings because it was collected under controlled conditions. Had the collection window been even slightly different, GAP 2 would have swallowed the credential-dump and lateral-movement chain entirely, and the byte-exact exfiltration matches in Section 6 — the strongest evidence in this entire report — would not have been possible to construct.
What remains unknown and what would resolve it:
The true cause of the 4x04 header/body date contradiction (Section 3) — resolvable only by asking whoever authored that report.
Whether debug_tool.exe ran on WS-RECV-04/WS-RECV-07 as Robert Kim claims (Section 3) — resolvable by collecting memory/disk evidence from those two hosts, which was out of scope here.
The true IP-to-hostname mapping dispute across three documents (Section 6) — resolvable by the network team confirming current DHCP/static assignments against change records.
Whether exfiltrated SSNs were usable plaintext or inert ciphertext (Section 6) — resolvable only by the database team confirming the actual encryption implementation.
Attacker activity during GAP 2 (Section 4) — likely unresolvable retroactively given no source covers that window; this argues for continuous logging coverage going forward, not further analysis of data that does not exist.
The full defensive-posture and remediation picture (Sections 7–8) — resolvable by specifying and completing Tasks T13 and T14.
Appendix A: IOC Summary Table

Source: healthbane_ioc_master.json (31 entries) plus 1 IOC discovered during this reconstruction and not yet in the master list.

ID	Type	Value	Confidence	Sources
HB-IOC-0001	domain	meddefense-portal.com	HIGH	4x00/4x02
HB-IOC-0002	domain	meddefense-benefits.com	HIGH	4x00/4x02
HB-IOC-0003	domain	outlook-protection.com	HIGH	4x00
HB-IOC-0004	domain	healthbane-c2.net	HIGH	4x01/4x02/4x03/4x04
HB-IOC-0005	domain	sync.healthbane-c2.net	HIGH	4x01/4x03/4x04
HB-IOC-0006	domain	data-sync.healthbane-c2.net	HIGH	4x03/4x04
HB-IOC-0007	domain	update.healthbane-c2.net	HIGH	4x02/4x03
HB-IOC-0008	ipv4	185.220.101.45	HIGH	4x01/4x03/4x04
HB-IOC-0009	ipv4	185.220.101.46	HIGH	4x03/4x04
HB-IOC-0010	url	https://meddefense-portal.com/login.aspx	HIGH	4x00/4x01
HB-IOC-0011	filename	HEALTHBANE_S2_invoice.docm	HIGH	4x03
HB-IOC-0012	sha256	9a2f3e7b4c1d8a6e5f0b2c9d8e7a4f1b3c6e9a0d2f5b8e1c4a7d0f3b6e9c2a5d	HIGH	4x03
HB-IOC-0013	filename	svchost_update.exe	HIGH	4x03/4x04
HB-IOC-0014	sha256	c8e2a9b4d1f7c0a3e6b9d2c5f8a1e4b7d0c3f6a9e2b5d8c1f4a7e0b3d6c9f2a5	HIGH	4x03
HB-IOC-0015	registry_key	HKCU\Software\Microsoft\Windows\CurrentVersion\Run\HealthSync	HIGH	4x03
HB-IOC-0016	filename	sync_healthdata.ps1	HIGH	4x03/4x04
HB-IOC-0017	sha256	f1e8a4c7b0d3e6a9c2b5d8e1f4a7c0b3d6e9f2a5b8c1d4e7f0a3b6c9d2e5f8a1	HIGH	4x03
HB-IOC-0018	user_account	dmarsh	HIGH	4x00/4x01
HB-IOC-0019	user_account	svc_healthsync	HIGH	4x04
HB-IOC-0020	filename	debug_tool.exe	HIGH	4x04
HB-IOC-0021	filename	PsExec64.exe	HIGH	4x04
HB-IOC-0022	filename	stage1.ps1	HIGH	4x04
HB-IOC-0023	host	WS-RECV-03	HIGH	4x00/4x01/4x04
HB-IOC-0024	host	SRV-HEALTH-DB	HIGH	4x04
HB-IOC-0025	host	SRV-INS-DB	MEDIUM	4x04
HB-IOC-0026	host	SRV-DC-01	MEDIUM	4x04
HB-IOC-0027	ttp	off_hours_ntlm_workstation_to_server	HIGH	4x04
HB-IOC-0028	registry_key	HKLM\SYSTEM\CurrentControlSet\Services\PSEXESVC	HIGH	4x04
HB-IOC-0029	yara_rule	RULE_HEALTHBANE_DROPPER_VBA_v1	HIGH	4x02
HB-IOC-0030	wazuh_rule	100080 — HEALTHBANE: known phishing-related domain or sender contacted	HIGH	4x02
HB-IOC-0031	wazuh_rule	wlb_ntlm_offhours — HEALTHBANE Stage 4 lateral movement detection	HIGH	4x04
(new)	ipv4:port	203.0.113.47:8443 (secondary/fallback C2)	PROBABLE	4x05-IR (firewall only; not present in the master IOC list above as of this report)

Known IOC gaps (per healthbane_ioc_master.json's own ioc_gaps_known_to_4x04 field, all since closed by 4x05 evidence except where noted):

Secondary C2 IP — suspected from 4x02 advisory, now observed (203.0.113.47, row above).
Scheduled-task persistence — now observed (Section 3, Section 4 event #12).
Data staging artifacts — now observed (Section 6, D1/D2/D3).
Anti-forensics / log-gap queries — now observed (Section 3, Section 4 event #16).
Appendix B: Evidence Citation Index
Evidence tag	File	Used in
4x00	previous_findings/4x00_phishing_summary.txt	Section 3 (Stage 1), Section 4
4x01	previous_findings/4x01_network_timeline.txt	Section 3 (Stage 2), Section 4
4x02	previous_findings/4x02_attack_mapping.json	Section 5 (baseline count discrepancy)
4x03	previous_findings/4x03_malware_summary.txt	Section 3 (Stage 3 raw events), Section 5, Section 6
4x04	previous_findings/4x04_hunting_report.txt	Section 3 (Stage 4), Section 4, Section 6
disk	ir_evidence/disk_forensics_report.txt	Section 3, Section 4, Section 6
firewall	ir_evidence/firewall_sessions_ws_recv_03.json	Section 3, Section 4, Section 6
memory	ir_evidence/memory_artifacts.txt	Section 3, Section 4
ir_team_notes	ir_evidence/ir_team_notes.txt	Section 3 (containment, disputes), Section 4
navigator-80pct	reference/attck_navigator_80pct.json	Section 5
ioc-master	reference/healthbane_ioc_master.json	Appendix A
asset-inventory	reference/meddefense_asset_inventory.txt	Section 6
network-topology	reference/network_topology.txt	Section 6
Appendix C: ATT&CK Navigator Layer Reference
Baseline layer used: reference/attck_navigator_80pct.json (29 techniques; file's own summary claims 23/3/3, verified actual array count is 22/3/4 — see Section 5).
This reconstruction's output (9-attack_techniques.sh) produces an updated 32-row inventory (29 baseline + 3 newly identified) suitable for conversion into a new Navigator layer JSON: 31/32 CONFIRMED (96%), 1/32 POSSIBLE (T1048.003, resolved absence).
No separate Navigator layer .json file was generated as part of this report; 9-attack_techniques.sh's tabular output (reproduced in Section 5) is the authoritative source for building one if required.
