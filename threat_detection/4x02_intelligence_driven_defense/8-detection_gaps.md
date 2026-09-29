8 - Detection Gap Analysis
=============================

MedDefense Health Systems -- Intelligence-Driven Defense (4x02)
Task 8: comparing every technique in Task 7's ATT&CK mapping against
MedDefense's *actually documented* detection capability, to find what a
real analyst would miss -- not what could theoretically be built, but
what is confirmed to exist today versus merely recommended, planned, or
absent.

## Methodology and materials actually used

This task's own materials list includes "local outputs from Tasks 5, 9
and 10 after they are created" and "4x01 findings if available." As of
this analysis: **Tasks 5, 9 and 10 of this project (4x02) do not exist
yet** -- no indicator-database actions, YARA rules, or their outputs are
available to cite. Their absence is treated honestly throughout this
document: techniques whose only realistic detection path is a YARA rule
or an indicator-database action are marked NOT DETECTED, with a note
that this status should be revisited once those tasks are produced,
rather than assumed closed or left unexplained.

**4x01 findings are available** and are used extensively: the prior
Wireshark Territory project's `7-detection_rules.sh` (6 fully-specified
detection rules) and `11-network_forensics_report.md` (its own findings
and gap analysis) cover the *same* incident -- confirmed by shared
identifiers (`91.234.99.107`, `dmarsh`, `WS-NURSE-04`, `10.10.2.15`)
appearing in both this project's HC3/MedDefense sources and 4x01's PCAP
evidence. A critical distinction carried through this entire document:
**4x01's 6 detections are documented recommendations with pseudocode,
not rules confirmed running in production.** 4x01's own report calls
them "Detection Rules Recommended" and separately states what "this
investigation found evidence of being in place" (effectively nothing,
for these 6). Treating a well-specified but unconfirmed-deployed rule as
equivalent to a live one would overstate MedDefense's actual coverage --
exactly the overclaiming this project has avoided throughout. This
document therefore reserves the DETECTED status for MedDefense's 3
Wazuh rules that are explicitly documented as deployed, and uses
PARTIALLY DETECTED for a technique covered only by an unconfirmed
recommendation, a narrow/incomplete deployed rule, or a manual (analyst-
run) hunting procedure rather than an automated one.

**MedDefense's actually deployed detection capability**, per
`meddefense_4x00_findings.txt`, is exactly three Wazuh rules:

| Rule | Trigger | Severity |
|---|---|---|
| 100080 | Inbound email from the CDB list `healthbane_domains` (populated from MedDefense's own 3 confirmed domains) | 10 |
| 100081 | Outbound HTTP(S) to the same CDB-listed domains | 12 |
| 100082 | Authentication event for `dmarsh` from a source IP outside MedDefense networks, within 30 days | 14 |

Everything else cited below as a "detection" is either a documented
*recommendation* (4x01's 6 rules, HC3's Section 5 mitigation/hunting
guidance) or genuinely absent.

**Status definitions used in this document:**
- **DETECTED** -- a rule confirmed deployed today fully covers this
  technique.
- **PARTIALLY DETECTED** -- a deployed rule exists but is narrow or
  incomplete for this technique, *or* a fully-specified recommendation
  exists but is not confirmed deployed, *or* the only documented control
  is a manual hunting procedure requiring analyst review rather than an
  automated alert.
- **NOT DETECTED** -- no rule, deployed or even recommended, addresses
  this technique anywhere in the materials available to this project.

---

## 1-3. Techniques by Tactic: Detection Status

**Headline finding, stated up front because it shapes every
recommendation below: of the 25 techniques in Task 7's mapping, zero are
fully DETECTED by a deployed rule with no caveats.** MedDefense's 3
Wazuh rules are real and severity-appropriate, but every one of them is
narrow enough (a 3-domain list; one named account) that this analysis
could not, honestly, mark any technique as cleanly closed. 13 techniques
are PARTIALLY DETECTED (either by a narrow deployed rule or an
unconfirmed-deployed recommendation) and 12 are NOT DETECTED at all.

### Reconnaissance

| Technique | Name | Class | Status | Evidence | Gap | Recommendation |
|---|---|---|---|---|---|---|
| T1589.002 | Gather Victim Identity: Email | OBSERVED | NOT DETECTED | No documented rule or telemetry source in 4x00 or 4x01 addresses pre-attack reconnaissance; this activity occurs entirely outside MedDefense's network before any email is sent. | MedDefense has zero visibility into attacker OSINT/email-harvesting activity by design -- this happens on the attacker's own infrastructure. | Not closable with internal telemetry. Subscribe to a breach/credential-exposure monitoring feed (e.g. HIBP-for-business, a dark-web monitoring service) to learn when staff email addresses appear in leaked datasets, which is the realistic precursor to this technique. |

### Resource Development

| Technique | Name | Class | Status | Evidence | Gap | Recommendation |
|---|---|---|---|---|---|---|
| T1583.001 | Acquire Infrastructure: Domains | OBSERVED | PARTIALLY DETECTED | 4x01's Detection 6 ("TLS to Recently Observed Lookalike Domain") is fully specified with pseudocode, grounded in this incident's own confirmed evidence, and would flag first contact with a newly-registered lookalike domain via a maintained first-seen/IOC table. | Detection 6 is a documented recommendation in 4x01's `7-detection_rules.sh`, not a rule confirmed deployed anywhere in MedDefense's 3 active Wazuh rules (100080-100082). No evidence this analytic is running. | Implement Detection 6 against TLS SNI logs / a maintained first-seen table, per the pseudocode already specified in 4x01 Task 7. Owner: SOC detection engineering; requires TLS metadata collection (proxy or Zeek) plus a periodically-refreshed domain first-seen table. |
| T1585.002 | Establish Accounts: Email | OBSERVED | NOT DETECTED | No rule or telemetry addresses the attacker establishing their own mailboxes (e.g. ops@healthbane-c2.net). | Entirely attacker-side infrastructure with no MedDefense visibility. | Not closable with internal telemetry alone. Passive DNS / certificate-transparency monitoring on newly-registered domains sharing the campaign's naming pattern (per researcher Sec. 7) could surface associated mail infrastructure before it is used against MedDefense specifically. |
| T1587.001 | Develop Capabilities: Malware | OBSERVED | NOT DETECTED | No rule or telemetry addresses attacker-side kit/malware development. | Entirely attacker-side, occurs before any indicator exists for MedDefense to act on. | Not closable with internal telemetry. Sharing captured samples (once obtained) with HC3/industry ISACs, as MedDefense's own 4x00 report already does, is the only realistic mitigation at this stage. |
| T1608.005 | Stage Capabilities: Link Target | OBSERVED | NOT DETECTED | No rule or telemetry addresses attacker staging landing pages prior to email delivery. | Attacker-side staging, invisible until the first email or connection reaches MedDefense. | Not closable with internal telemetry alone; same passive-DNS/certificate-transparency recommendation as T1585.002 would provide earliest possible warning. |
| T1583.003 | Acquire Infrastructure: Virtual Private Server | INFERRED | NOT DETECTED | No rule or telemetry addresses attacker VPS acquisition (Hostinger/DigitalOcean/OVH) -- entirely attacker-side. | No MedDefense visibility into attacker hosting choices prior to first contact. | Not closable with internal telemetry. Same passive-DNS/certificate-transparency recommendation as T1585.002/T1608.005 is the only realistic early-warning path. |
| T1608.001 | Stage Capabilities: Upload Malware | INFERRED | NOT DETECTED | No rule or telemetry addresses the attacker staging `svchost_update.exe` on `healthbane-c2.net` prior to Stage 2 delivery -- entirely attacker-side. | No MedDefense visibility into attacker-controlled infrastructure before the Stage 2 download connection itself occurs. | Not directly closable; the download CONNECTION (T1071.001) is the earliest point of MedDefense visibility for this precursor step -- see that row's recommendation (CDB list expansion) for the nearest practical control. |

### Initial Access

| Technique | Name | Class | Status | Evidence | Gap | Recommendation |
|---|---|---|---|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | OBSERVED | PARTIALLY DETECTED | Wazuh rule 100080 (severity 10) alerts on inbound email from the CDB list `healthbane_domains`, populated from MedDefense's own 3 confirmed domains (meddefense-portal.com, medequip-supplies.net, meddefense-benefits.org). | Rule 100080 is confirmed deployed but is a static, 3-domain exact-match list. It does not cover HC3's other 5 advisory domains, any future rotated domain, or the researcher's operational-pattern signature (Namecheap registration + compound healthcare keyword) that would survive rotation. | Expand the CDB list to the full HC3 8-domain set immediately (low effort, same rule mechanism). Longer term, add a registration-pattern rule (new Namecheap domain matching `meddefense-*`/`medequip-*`/`*-benefits`/`*-portal`) per the researcher's Sec. 7 recommendation. Owner: SOC / email security engineering. |
| T1566.001 | Phishing: Spearphishing Attachment | OBSERVED | NOT DETECTED | No rule in MedDefense's 3 deployed Wazuh rules addresses attachment-based delivery; rules 100080/100081 are domain-based (sender domain / outbound connection), not attachment-content-based. | MedDefense's entire deployed detection surface for this campaign is domain-based. A Stage 2 .docm attachment from a non-campaign-domain sender (e.g. the compromised internal account, per T1534) would not be flagged by any documented rule. | Deploy attachment-type/macro-presence alerting at the email gateway (flag inbound/internal .docm with active VBA content) and require attestation for macro-enabled documents from external senders, per HC3 Sec. 5.3's own recommendation, which is not yet confirmed implemented. Owner: email security / messaging team. |
| T1078.004 | Valid Accounts: Cloud Accounts | INFERRED | PARTIALLY DETECTED | Wazuh rule 100082 (severity 14, MedDefense's highest-severity deployed rule) alerts specifically on "authentication event for dmarsh from a source IP outside MedDefense networks within 30 days." 4x00's own Q2 answer states "Monitoring continues via rule 100082," confirming it was active during the relevant window. | 4x01's independent packet-level investigation found a TLS-wrapped session from an external IP (154.118.42.89, Nigeria/AS37340) to the internal VPN gateway at 2026-04-15 13:45:22 UTC, carrying a plaintext authentication-context marker for `dmarsh` -- inside rule 100082's own 30-day monitoring window. Neither 4x00 nor 4x01's materials confirm this event triggered rule 100082 or produced an alert; 4x00's own F6 finding ("No immediate post-compromise authentication event observed... within the 4x00 window") appears not to have captured this VPN authentication at all. This suggests rule 100082's data source may not ingest VPN gateway authentication logs, only Windows/AD-domain authentication -- but this project cannot confirm that from the materials available, only that the two reports do not show the rule catching an event that packet evidence says occurred. | Priority: confirm with the SOC/IT team whether rule 100082's log source includes the VPN gateway's own authentication log, not only Windows Security/AD events. If it does not, this is the single highest-value, lowest-effort fix in this entire analysis: point an already-deployed, already-highest-severity rule at one more log source. Owner: SOC detection engineering + VPN/network infrastructure team, jointly, on priority given the severity-14 rule already exists and the technique already fired once. |

### Execution

| Technique | Name | Class | Status | Evidence | Gap | Recommendation |
|---|---|---|---|---|---|---|
| T1204.001 | User Execution: Malicious Link | OBSERVED | NOT DETECTED | No rule monitors the click/execution event itself; rule 100080 covers email delivery, not what the recipient does with it. MedDefense's own SIEM connection log evidence for the confirmed click (F5) was found through manual investigation after the fact, not a standing alert. | The confirmed Diane Marsh click was identified retroactively during the 4x00 investigation, not flagged in real time by any deployed rule. | Add real-time alerting on outbound connections to domains present in the CDB list within N minutes of a matching inbound email (link rule 100080 and 100081 together, correlated) rather than relying on retrospective log review. Owner: SOC detection engineering. |
| T1204.002 | User Execution: Malicious File | OBSERVED | NOT DETECTED | No rule or telemetry documented for macro-document execution. 4x00's own EDR scan (2026-04-16) was a one-time retrospective hash search, not continuous monitoring, and found no match regardless. | No standing detection for Office application spawning child processes (the classic macro-execution behavioral signature) is documented anywhere in 4x00 or 4x01. | Deploy Sysmon/EDR process-lineage alerting for Office applications (winword.exe/outlook.exe) spawning cmd.exe/powershell.exe/wscript.exe, a standard and well-understood behavioral rule not yet documented as present. Owner: endpoint/EDR engineering. |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | OBSERVED | NOT DETECTED | No rule or telemetry documented for VBA macro execution specifically. | Same root cause as T1204.002 -- no Office-macro-execution telemetry is documented as deployed. | Covered by the same Sysmon/EDR process-lineage recommendation as T1204.002; additionally enable macro execution logging (Office trust-center audit events) if not already collected. Owner: endpoint/EDR engineering. |
| T1059.001 | Command and Scripting Interpreter: PowerShell | OBSERVED | PARTIALLY DETECTED | HC3's advisory (Sec. 5.5) documents a specific hunting procedure: "Hunt for PowerShell execution with base64-encoded payloads > 1024 characters." | This is a documented manual hunting procedure, not an automated, continuously-running rule -- it requires an analyst to actively run the hunt, and none of MedDefense's 3 deployed Wazuh rules automate it. | Convert HC3's hunting procedure into an automated Wazuh/EDR rule on PowerShell command-line length and base64 content, rather than leaving it as an analyst-run hunt. Owner: SOC detection engineering. |

### Persistence

| Technique | Name | Class | Status | Evidence | Gap | Recommendation |
|---|---|---|---|---|---|---|
| T1053.005 | Scheduled Task/Job: Scheduled Task | OBSERVED | PARTIALLY DETECTED | HC3's advisory (Sec. 5.5) documents a specific hunting string: scheduled tasks named "HealthSync Update Service" or similar variants. | Documented as a manual hunting target, not an automated deployed rule. A trivially renamed task (e.g. "HealthCheck Sync Agent") would evade both the exact hunting string and any naive exact-match rule. | Deploy an automated Windows Event ID 4698 (scheduled task creation) rule alerting on non-administrative task creation with keywords Sync/Update/Service/Health, not just the one exact known name. Owner: endpoint/EDR engineering. |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | OBSERVED | PARTIALLY DETECTED | HC3's advisory (Sec. 5.3) recommends: "Alert on Registry Run-key additions outside installer context." | This is HC3's mitigation recommendation to the sector, not confirmed as an implemented MedDefense rule -- none of the 3 deployed Wazuh rules (100080-100082) address registry modification. | Deploy Sysmon Event ID 13 (registry value set) alerting scoped to Run/RunOnce keys outside a known installer allowlist, implementing HC3's own recommendation. Owner: endpoint/EDR engineering. |

### Credential Access

| Technique | Name | Class | Status | Evidence | Gap | Recommendation |
|---|---|---|---|---|---|---|
| T1056.003 | Input Capture: Web Portal Capture | OBSERVED | PARTIALLY DETECTED | Wazuh rule 100081 (severity 12) alerts on outbound HTTP(S) to the 3 listed campaign domains, which would flag a browser session reaching the credential-harvesting form. | Rule 100081 detects the connection to a known domain, not the form-capture behavior itself, and is limited to the same 3-domain CDB list as rule 100080 -- an unlisted phishing domain's form would not be flagged. | Same CDB-list expansion as T1566.002 closes most of this gap immediately. Longer term, the researcher's PHPMailer 6.6.0 X-Mailer signature (Sec. 3) gives a rotation-resistant detection at the email layer, upstream of the form itself. Owner: SOC / email security engineering. |

### Command and Control

| Technique | Name | Class | Status | Evidence | Gap | Recommendation |
|---|---|---|---|---|---|---|
| T1071.004 | Application Layer Protocol: DNS | OBSERVED | PARTIALLY DETECTED | 4x01's Detections 2 ("DNS Query Length Anomaly") and 5 ("DNS Tunneling TXT Query Pattern") are fully specified with pseudocode and grounded directly in this campaign's confirmed parameters (44-60 character labels, 10-15 second interval). | Both are documented recommendations in `7-detection_rules.sh`, not rules confirmed deployed. None of MedDefense's 3 active Wazuh rules address DNS query structure or frequency. | Implement Detections 2 and 5 against DNS resolver logs or Zeek dns.log, exactly as specified in 4x01 Task 7. Owner: SOC detection engineering / DNS infrastructure team; requires DNS query logging with label and timing granularity, which is not confirmed currently collected. |
| T1071.001 | Application Layer Protocol: Web Protocols | OBSERVED | PARTIALLY DETECTED | Wazuh rule 100081 alerts on outbound HTTP(S) to the CDB-listed domains, which would cover a connection to `healthbane-c2.net` if that domain were in the list. | The CDB list `healthbane_domains` is populated from MedDefense's own 3 originally-confirmed domains only. `healthbane-c2.net` -- the actual Stage 2 download domain per HC3 and the researcher's kit analysis -- is not one of those 3 and is not confirmed added since. | Update the CDB list to include the full HC3 8-domain set (same low-effort fix as T1566.002/T1056.003) -- this single change would close this specific gap immediately using an already-deployed rule. Owner: SOC / detection engineering (configuration change, not new development). |
| T1132 | Data Encoding | INFERRED | PARTIALLY DETECTED | 4x01's DNS-pattern detections (Detections 2 and 5) would incidentally flag the base32/base64-encoded traffic as part of detecting the tunneling pattern itself, since the anomalous query-length signature is a direct consequence of the encoding. | Recommended, not confirmed deployed, and no rule specifically decodes or validates the encoding scheme -- the existing recommendations detect the STRUCTURAL anomaly (length/frequency), not the encoding itself. | No separate rule needed beyond implementing Detections 2/5 (same recommendation and owner as T1071.004); decoding capability for confirmed-anomalous queries should be a documented incident-response runbook step, not a standing detection. |

### Exfiltration

| Technique | Name | Class | Status | Evidence | Gap | Recommendation |
|---|---|---|---|---|---|---|
| T1048.003 | Exfiltration Over Alternative Protocol (Non-C2) | OBSERVED | PARTIALLY DETECTED | Same as T1071.004: 4x01's DNS-pattern detections (Detections 2 and 5) directly target this exfiltration mechanism and are grounded in this campaign's own confirmed parameters. | Recommended, not confirmed deployed. No deployed Wazuh rule addresses DNS-based exfiltration. | Same recommendation as T1071.004 -- implementing Detections 2/5 closes this gap and the C2-channel gap (T1071.004) simultaneously, since both rules operate on the same DNS query stream. Owner: SOC detection engineering. |
| T1041 | Exfiltration Over C2 Channel | OBSERVED | PARTIALLY DETECTED | Same DNS-pattern detections apply, since the DNS tunnel serves as both the C2 channel and the exfiltration channel per HC3's Stage 3 narrative. | Recommended, not confirmed deployed. | Same recommendation and owner as T1071.004/T1048.003 -- this is one detection gap with three ATT&CK labels, not three separate gaps to close independently. |

### Lateral Movement

| Technique | Name | Class | Status | Evidence | Gap | Recommendation |
|---|---|---|---|---|---|---|
| T1021 | Remote Services | INFERRED | PARTIALLY DETECTED | 4x01's Detection 4 ("Cross-Role RDP") is fully specified with pseudocode and directly matches the confirmed RDP session from WS-NURSE-04 (a clinical workstation) to billing-srv-01 at 2026-04-15 14:30:12 UTC. | Recommended, not confirmed deployed. No MedDefense rule addresses RDP connections by source-role/destination-role mismatch. | Implement Detection 4 against RDP connection logs plus a role/subnet mapping (clinical workstations should never RDP directly to billing servers). Owner: SOC detection engineering + network/identity team (role mapping is a prerequisite data source, not yet confirmed to exist). |
| T1534 | Internal Spearphishing | INFERRED | NOT DETECTED | No rule, deployed or recommended, in 4x00 or 4x01's materials addresses mail sent from a legitimately-authenticated internal account to other internal recipients. Rule 100080 only inspects the SENDER DOMAIN against the CDB list, which a genuine internal MedDefense account would never match. | This is the clearest total blind spot surfaced by this analysis: Stage 2's actual delivery mechanism (per HC3's own narrative, Task 6/7) is structurally invisible to every documented MedDefense control, because every control assumes the phishing email comes from an external/lookalike domain. Once T1078.004 succeeds, this entire detection layer is bypassed by design. | Highest-priority new detection to build: alert on outbound/internal mail from an account recently flagged by rule 100082 (or any account-compromise indicator) for an N-hour window, regardless of the message's apparent legitimacy. This directly closes the gap that T1078.004's own detection (once fixed) would otherwise leave open. Owner: SOC detection engineering, dependent on T1078.004's gap being closed first (that alert becomes this rule's trigger condition). |

### Collection

| Technique | Name | Class | Status | Evidence | Gap | Recommendation |
|---|---|---|---|---|---|---|
| T1005 | Data from Local System | INFERRED | NOT DETECTED | No rule or telemetry in 4x00 or 4x01 addresses local file/database access on billing-srv-01 or any host prior to exfiltration. 4x01's own Phase 6 finding explicitly notes no SMB/file-access enumeration was visible in the PCAPs analyzed, and this project's Task 6 already flagged that no source specifies what collection step preceded Stage 3. | Complete blind spot: MedDefense has no documented host-based file-access, database-query, or DLP telemetry for the server ultimately confirmed (by 4x01) to be the exfiltration source. | Deploy file-integrity monitoring and database query-audit logging on billing-srv-01 (and equivalent record-holding systems) as a Collection-tactic control -- currently the only tactic in this entire mapping with zero detection coverage of any kind, deployed or recommended. Owner: database/application owner + endpoint engineering, jointly. |

---

## 4. Prioritized Gap List

### Priority 1 -- OBSERVED and NOT DETECTED (8 techniques)

These are confirmed adversary behaviors in this specific campaign with
no documented detection of any kind, deployed or recommended.

| Technique | Why the gap matters | Detection idea | Required data source | Owner / path |
|---|---|---|---|---|
| T1566.001 (Spearphishing Attachment) | Stage 2's entire delivery mechanism is invisible to MedDefense's domain-based rules the moment the sender is a compromised internal account (see T1534 below) rather than an external lookalike domain. | Flag inbound/internal `.docm`/macro-enabled attachments; require attestation for macro content from external senders (HC3 Sec. 5.3). | Email gateway attachment inspection | Email security / messaging team |
| T1204.001 (User Execution: Malicious Link) | The confirmed click (Diane Marsh, 2026-04-14 15:02:33 UTC) was found by *retrospective* log review during the 4x00 investigation, not flagged in real time. | Correlate rule 100080 (matching inbound email) with rule 100081 (matching outbound connection) within a short time window to alert on click-through in real time, not after the fact. | SIEM correlation across existing rules 100080/100081 | SOC detection engineering |
| T1204.002 (User Execution: Malicious File) | No standing detection exists for a user opening the Stage 2 macro document; the one EDR scan on record was a single retrospective hash search. | Sysmon/EDR process-lineage alert: Office app spawning `cmd.exe`/`powershell.exe`/`wscript.exe`. | Sysmon/EDR process telemetry | Endpoint/EDR engineering |
| T1059.005 (VBA macro execution) | Same root cause as T1204.002 -- no macro-execution telemetry documented at all. | Same Sysmon/EDR process-lineage rule, plus Office macro audit logging if not already collected. | Sysmon/EDR + Office trust-center logs | Endpoint/EDR engineering |
| T1589.002, T1585.002, T1587.001, T1608.005 (Reconnaissance / Resource Development, 4 techniques) | All four occur entirely on attacker-controlled infrastructure before any indicator reaches MedDefense -- these are not closable with internal telemetry, but leaving them undocumented would imply MedDefense has no answer at all, when a real answer (external monitoring) exists. | Subscribe to breach/credential-exposure monitoring (precedes T1589.002) and passive-DNS/certificate-transparency monitoring on the researcher's documented naming pattern (`meddefense-*`, `medequip-*`, `*-benefits`, `*-portal`) to catch new infrastructure before first contact. | External threat-intel feed subscriptions (not an internal log source) | Threat intelligence function / CISO budget decision, not a SOC engineering task |

### Priority 2 -- INFERRED and NOT DETECTED (4 techniques)

These are techniques this project's own analysis concluded are highly
likely given the evidence, but which no source names explicitly and no
control addresses.

| Technique | Why the gap matters | Detection idea | Required data source | Owner / path |
|---|---|---|---|---|
| **T1534 (Internal Spearphishing)** | **The single most important finding in this document.** Every one of MedDefense's 3 deployed rules is built around the assumption that a malicious email comes from an external/lookalike domain. HC3's own Stage 2 narrative describes the attacker sending the follow-up email *from the victim's own compromised, legitimate account* -- a scenario none of the 3 rules can see, by construction. This is a design gap in the detection architecture, not a missing signature. | Alert on outbound/internal mail from any account recently flagged as compromised (e.g. by a fixed T1078.004/rule 100082) for an N-hour window, regardless of how legitimate the message otherwise looks. | Mail flow logs + an account-compromise flag/trigger | SOC detection engineering -- explicitly dependent on closing the T1078.004 gap first (see Priority 3), since that fix is this rule's trigger condition |
| T1583.003 (VPS acquisition) | Attacker-side infrastructure choice, no MedDefense visibility. | Same passive-DNS/certificate-transparency subscription as the Priority-1 Resource Development gaps. | External threat-intel feed | Threat intelligence function |
| T1608.001 (Upload Malware) | Attacker-side staging of `svchost_update.exe`, invisible until the Stage 2 download connection itself. | No independent control; closing T1071.001's CDB-list gap (Priority 3) is the nearest practical detection point. | N/A -- see T1071.001 | SOC / detection engineering |
| T1005 (Data from Local System) | The only tactic (Collection) with zero detection coverage of any kind in this entire mapping. HC3 states patient/insurance records were exfiltrated; nothing documents how they were *found* on the source system first, and this project's Task 6 already flagged this as an evidence gap. | File-integrity monitoring and database query-audit logging on `billing-srv-01` and equivalent record-holding systems. | Host-based FIM / DB audit logs (not currently documented as collected) | Database/application owner + endpoint engineering, jointly |

### Priority 3 -- Partially Detected (13 techniques)

Full detail for every PARTIALLY DETECTED technique is in the tables
above; the three most consequential, ranked by how much detection value
a single small fix would unlock:

| Technique | Why the gap matters | Detection idea | Required data source | Owner / path |
|---|---|---|---|---|
| **T1078.004 (Valid Accounts: Cloud Accounts)** | **The highest-value single fix identified in this analysis.** Rule 100082 already exists, is already MedDefense's highest-severity rule (14), and already targets exactly this technique by design. But 4x01's independent packet evidence shows a matching event (VPN authentication as `dmarsh` from a Nigeria-geolocated IP, 2026-04-15 13:45 UTC) inside the rule's own monitoring window that neither report shows as caught. If rule 100082's log source excludes the VPN gateway, this is a one-log-source fix to an already-deployed, already-correctly-designed rule -- the best effort-to-impact ratio in this entire document. | Confirm and, if needed, add the VPN gateway's own authentication log as a source for rule 100082. | VPN gateway authentication log (ingestion status unconfirmed) | SOC detection engineering + VPN/network infrastructure team, jointly, on priority |
| T1071.001 / T1056.003 / T1566.002 (three techniques, one fix) | Rule 100081 (and 100080) already work exactly as designed -- their only limitation is a 3-domain CDB list that excludes `healthbane-c2.net` and the 5 other HC3-advisory domains MedDefense did not itself observe. | Expand the CDB list `healthbane_domains` to HC3's full 8-domain set. | None new -- configuration change to an existing rule | SOC / detection engineering (same-day change, not new development) |
| T1071.004 / T1048.003 / T1041 / T1132 (four techniques, one implementation effort) | All four are covered by the same two DNS-pattern detections 4x01 already fully specified (query length + TXT frequency), grounded in this campaign's own confirmed parameters (44-60 char labels, 10-15s interval) -- the analytical work is done, only implementation remains. | Implement 4x01's Detections 2 and 5 against DNS resolver logs or Zeek `dns.log`. | DNS query logs with label + timing granularity (not confirmed currently collected) | SOC detection engineering / DNS infrastructure team |

---

## Note on techniques not yet addressable

Several rows above point to Tasks 5, 9 and 10 as the more durable
long-term fix (e.g., a YARA rule for `svchost_update.exe` once a sample
is available, or an indicator-database action that keeps the CDB list
synchronized automatically rather than manually). This document does not
pre-credit those future tasks with closing any gap -- every status above
reflects only what exists today. This section exists so that when Tasks
5, 9 and 10 are produced, this file can be revisited and specific rows
(especially T1566.001, T1204.002, T1059.005, and the CDB-list-dependent
rows) re-evaluated against what those tasks actually deliver, rather
than assuming they will close every remaining gap.
