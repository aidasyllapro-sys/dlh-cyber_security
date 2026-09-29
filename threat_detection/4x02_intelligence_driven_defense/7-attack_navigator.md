7 - The ATT&CK Navigator
===========================

MedDefense Health Systems -- Intelligence-Driven Defense (4x02)
Task 7: mapping the HEALTHBANE campaign to MITRE ATT&CK v15, distinguishing
techniques with direct evidence (OBSERVED) from techniques reasoned from
that evidence but not directly confirmed by any source (INFERRED). The
companion Navigator layer file, `healthbane_layer.json`, encodes the same
25 techniques for visualization: OBSERVED at score 100 (red), INFERRED at
score 50 (amber).

**Why two tiers, and where the line is drawn:** HC3's own advisory (Sec.
4) already distinguishes its 18 OBSERVED techniques from two techniques
(T1078, T1021) it calls LIKELY but excludes from that table "pending
confirmation." This project adopts HC3's own line as the OBSERVED/INFERRED
boundary and extends it: HC3's 18 are OBSERVED here exactly as HC3
classifies them; HC3's own 2 excluded LIKELY techniques are carried
forward as INFERRED; and five further techniques are added as INFERRED
where this project's own analysis (principally Task 6's kill chain
reconstruction) identifies a technique that the evidence clearly implies
but that no source names explicitly in its own OBSERVED table. No
technique in this document was promoted to OBSERVED on this project's own
authority -- OBSERVED is reserved for what a source itself states it
directly witnessed.

ATT&CK technique names, IDs and tactic assignments were verified against
[MITRE ATT&CK](https://attack.mitre.org/) directly (see the reference
list at the end of this document) rather than taken from memory, because
several sub-technique IDs used here are easy to misremember.

---

## 1-2. Techniques by Tactic

### Reconnaissance

| Technique | Name | Class | Evidence / reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1589.002 | Gather Victim Identity: Email | **OBSERVED** | Attacker identified specific staff email addresses at targeted healthcare organizations before crafting spear-phishing lures. | HC3 Sec. 4 | Pre-Stage 1 |

### Resource Development

| Technique | Name | Class | Evidence / reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1583.001 | Acquire Infrastructure: Domains | **OBSERVED** | Lookalike domains (`meddefense-portal.com` et al.) registered at Namecheap 4-10 days before first email use. | HC3 Sec. 4; corroborated by MedDefense F2 (exact registration dates) and researcher Sec. 3/4 (registrar) | Pre-Stage 1 |
| T1585.002 | Establish Accounts: Email | **OBSERVED** | Attacker-controlled mailboxes (e.g. `ops@healthbane-c2.net`) used to receive harvested credentials and coordinate. | HC3 Sec. 4; corroborated by researcher Sec. 2 (`config.php` SMTP forwarding) | Pre-Stage 1 |
| T1587.001 | Develop Capabilities: Malware | **OBSERVED** | Custom phishing kit (`index.php`/`handlers/`/`config.php`) and `svchost_update.exe` payload developed and maintained by the operator. | HC3 Sec. 4; corroborated by researcher Sec. 2 (kit source recovered directly) | Pre-Stage 1 |
| T1608.005 | Stage Capabilities: Link Target | **OBSERVED** | Phishing landing pages staged and live at the lookalike domains prior to email delivery. | HC3 Sec. 4; corroborated by MedDefense (own "ATT&CK Techniques Observed" section) | Pre-Stage 1 |
| T1583.003 | Acquire Infrastructure: Virtual Private Server | **INFERRED** | The researcher's infrastructure fingerprinting identifies Hostinger/DigitalOcean/OVH VPS hosting for every phishing-LP and C2 domain. HC3's OBSERVED table only names domain acquisition (T1583.001), not the VPS hosting layer underneath it, which the researcher's evidence independently supports as a deliberate infrastructure choice. | Researcher Sec. 3, 4 (hosting provider per domain) | Pre-Stage 1 |
| T1608.001 | Stage Capabilities: Upload Malware | **INFERRED** | `svchost_update.exe` had to be staged on the download infrastructure (`healthbane-c2.net`) before Stage 2 delivery could pull it -- a necessary precursor to the OBSERVED download (T1071.001), not itself directly observed or named by any source. | Inferred from HC3 Sec. 2 Stage 2 (download mechanism) -- this project's analysis | Pre-Stage 2 |

### Initial Access

| Technique | Name | Class | Evidence / reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | **OBSERVED** | Initial-access vector for Stage 1 at all 6 HC3-visible organizations; independently confirmed at MedDefense (emails E2, E5, E7). | HC3 Sec. 2 Stage 1; MedDefense F1, F4 (dmarsh clicked) | Stage 1 |
| T1566.001 | Phishing: Spearphishing Attachment | **OBSERVED** | Stage 2 follow-up email carried the `HEALTHBANE_S2_invoice.docm` attachment. | HC3 Sec. 2 Stage 2 | Stage 2 |
| T1078.004 | Valid Accounts: Cloud Accounts | **INFERRED** | HC3 states Stage 1 credentials were used to authenticate to the victim's own cloud email account to send Stage 2 emails -- functionally Valid Accounts (Cloud Accounts). HC3 itself names this (as T1078, unspecified sub-technique) LIKELY but excludes it from its OBSERVED table pending confirmation. Shown here under Initial Access as its primary tactic for this campaign's context (re-entry enabling Stage 2); T1078's full ATT&CK mapping also spans Defense Evasion, Persistence and Privilege Escalation. | HC3 Sec. 2 Stage 2 narrative; Sec. 4 (explicitly named LIKELY) | Stage 2 |

### Execution

| Technique | Name | Class | Evidence / reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1204.001 | User Execution: Malicious Link | **OBSERVED** | Victim clicked the Stage 1 phishing link; at MedDefense this is the confirmed Diane Marsh click (2026-04-14 15:02:33 UTC). | HC3 Sec. 2 Stage 1; MedDefense Scope, F5 | Stage 1 |
| T1204.002 | User Execution: Malicious File | **OBSERVED** | Victim opened the Stage 2 macro-enabled `.docm` attachment, triggering the macro. | HC3 Sec. 2 Stage 2 | Stage 2 |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | **OBSERVED** | The `.docm`'s VBA macro executes on open and pulls the Stage 2 executable. | HC3 Sec. 2 Stage 2 | Stage 2 |
| T1059.001 | Command and Scripting Interpreter: PowerShell | **OBSERVED** | HC3's own hunting guidance (Sec. 5.5) targets PowerShell execution with base64-encoded payloads over 1024 characters, implying PowerShell use post-macro. | HC3 Sec. 4; Sec. 5.5 | Stage 2 |

### Persistence

| Technique | Name | Class | Evidence / reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1053.005 | Scheduled Task/Job: Scheduled Task | **OBSERVED** | Persistence via a scheduled task named "HealthSync Update Service," created by the Stage 2 executable. | HC3 Sec. 2 Stage 2; Sec. 5.5 hunting guidance | Stage 2 |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | **OBSERVED** | Persistence also established via a Registry Run key, alongside the scheduled task. | HC3 Sec. 2 Stage 2 | Stage 2 |

### Credential Access

| Technique | Name | Class | Evidence / reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1056.003 | Input Capture: Web Portal Capture | **OBSERVED** | Credentials captured via the PHPMailer-served HTML form on the Stage 1 landing page and posted to attacker VPS infrastructure. | HC3 Sec. 2 Stage 1; MedDefense (own "ATT&CK Techniques Observed," form POST) | Stage 1 |

### Command and Control

| Technique | Name | Class | Evidence / reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1071.004 | Application Layer Protocol: DNS | **OBSERVED** | Stage 3 C2/exfiltration channel: DNS TXT-record queries and responses to/from `data-sync.healthbane-c2.net`. | HC3 Sec. 2 Stage 3 | Stage 3 |
| T1071.001 | Application Layer Protocol: Web Protocols | **OBSERVED** | Stage 2 payload download over HTTPS from `healthbane-c2.net/update/svchost_update.exe`. | HC3 Sec. 2 Stage 2; corroborated by the commercial feed (confidence 90) and the researcher's `config.php` `EXFIL_ENDPOINT` | Stage 2 |
| T1132 | Data Encoding | **INFERRED** | HC3 describes base32-encoded DNS subdomain labels and base64-encoded C2 response strings -- this matches ATT&CK's Data Encoding description closely, but HC3's OBSERVED table does not name it separately from the DNS channel itself (T1071.004). Kept at the parent-technique level rather than choosing between the .001 (Standard) and .002 (Non-Standard) sub-techniques: MITRE's own examples for Standard Encoding are ASCII/Unicode/Base64/MIME, and base32 specifically is not confirmed to fall in either bucket from the material available to this project. | HC3 Sec. 2 Stage 3 -- this project's analysis | Stage 3 |

### Exfiltration

| Technique | Name | Class | Evidence / reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1048.003 | Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | **OBSERVED** | Patient/insurance data encoded in DNS TXT-record queries -- a protocol distinct from the primary C2 channel. | HC3 Sec. 2 Stage 3 | Stage 3 |
| T1041 | Exfiltration Over C2 Channel | **OBSERVED** | HC3 also lists exfiltration via the C2 channel itself. | HC3 Sec. 2 Stage 3; Sec. 4 | Stage 3 |

### Lateral Movement

| Technique | Name | Class | Evidence / reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1021 | Remote Services | **INFERRED** | HC3 names this LIKELY but excludes it pending confirmation, without specifying which remote service. No source in this dataset identifies a specific protocol (RDP/SMB/SSH/etc.), and MedDefense's own finding F6 (no post-compromise authentication event observed locally) argues against assuming this occurred at every victim. | HC3 Sec. 4 (explicitly named LIKELY, T1021) | Stage 2/3 (unconfirmed) |
| T1534 | Internal Spearphishing | **INFERRED** | HC3's own Stage 2 narrative describes the attacker sending follow-up phishing emails *from* the compromised victim's cloud account *to* their colleagues -- the literal definition of Internal Spearphishing. Classified INFERRED, not OBSERVED, because HC3's own table does not name this technique explicitly, even though the underlying behavior it describes is stated as directly observed. | This project's analysis of HC3 Sec. 2 Stage 2 narrative (Task 6 kill chain) | Stage 2 |

### Collection

| Technique | Name | Class | Evidence / reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1005 | Data from Local System | **INFERRED** | HC3 states Stage 3 exfiltrates "patient and insurance records." Those records must have been located and collected from a local system or database before being tunneled out; no source describes this collection step directly, and Collection is otherwise a completely uncovered tactic in this campaign's evidence. | Inferred from HC3 Sec. 2 Stage 3 (data targeted) -- this project's analysis | Stage 2/3 (unconfirmed) |

---

## 3. Summary

**1. Total techniques identified: 25** (18 OBSERVED, 7 INFERRED).

**2. Observed vs. inferred ratio: 18:7 (approximately 2.6:1, or 72% / 28%).**
Of the 7 INFERRED techniques, 2 (T1078.004, T1021) are HC3's own
explicitly named LIKELY candidates carried forward under this project's
classification; the other 5 (T1534, T1583.003, T1608.001, T1132, T1005)
are this project's own analytical additions, each tied to a specific
piece of evidence already documented in Task 6's kill chain
reconstruction rather than to a generic "this technique is common in this
kind of attack" assumption.

**3. Tactics with the most coverage:**
- **Resource Development -- 6 techniques** (4 OBSERVED, 2 INFERRED). This
  is the best-covered tactic because three independent sources each
  documented a different layer of the same pre-attack infrastructure
  build-out (HC3's domain list, the researcher's hosting/registrar
  fingerprint, MedDefense's WHOIS work), and Resource Development is,
  structurally, the tactic with the most sub-techniques available to map
  distinct infrastructure choices onto.
- **Execution -- 4 techniques** (all OBSERVED). HC3's sandbox analysis of
  the Stage 2 macro and payload gave direct, high-confidence visibility
  into this tactic specifically.

**4. Tactics with the least coverage:**
- **Reconnaissance, Credential Access and Collection -- 1 technique
  each.** Reconnaissance and Credential Access are each covered by
  exactly one technique because the campaign's actual reconnaissance and
  credential-theft methods are simple and well-documented (a single email
  list and a single web-form capture), not because visibility is weak
  there -- unlike the next point.
- **Zero coverage: Discovery, Privilege Escalation and Defense Evasion**
  (as distinct tactic rows; T1078.004's canonical mapping touches
  Privilege Escalation and Defense Evasion, but this document counts it
  once, under Initial Access, per its primary role here). No source in
  this dataset describes *any* discovery-phase behavior (no evidence of
  the attacker enumerating hosts, users, or network topology inside a
  victim environment) or explicit defense-evasion behavior (no described
  AV/EDR bypass, no log tampering). This is a genuine visibility gap, not
  a claim that these tactics did not occur -- see Section 4 below and
  Task 6's own "what is not known" section, which already flags that
  Stage 2/3 endpoint forensics were deferred to 4x01 and are not part of
  this project's materials.

**5. Techniques most important for detection planning**, selected for
having both high evidentiary confidence and a specific, actionable
detection signature already published by a source:

1. **T1071.004 (DNS C2/exfiltration)** -- HC3 provides precise behavioral
   parameters (10-15 second query interval, 44-60 character subdomain
   labels) that are specific enough to hunt for directly and, per the
   researcher's own defensive notes, this kind of pattern-based detection
   "survives rotation" of the underlying domains/IPs.
2. **T1053.005 (Scheduled Task persistence)** -- HC3 gives the literal
   task name ("HealthSync Update Service") as a hunting string; low
   effort, high-confidence detection once deployed.
3. **T1059.001 (PowerShell)** -- HC3's own hunting guidance (base64
   payloads over 1024 characters) is directly actionable and, unlike
   indicator-based blocking, does not depend on infrastructure that
   rotates.
4. **T1056.003 (Web Portal Capture)** -- the earliest point in the
   entire kill chain where the attack can still be fully prevented
   (before any credential is captured); the researcher's PHPMailer 6.6.0
   X-Mailer header signature gives a high-fidelity, rotation-resistant
   detection at the email gateway, ahead of the landing page itself.
5. **T1534 (Internal Spearphishing, INFERRED)** -- flagged here
   specifically *because* it is INFERRED rather than covered by any
   existing HC3 control: none of HC3's Section 5 detection/mitigation
   recommendations address mail sent from a legitimately compromised
   internal account to other internal recipients, which is exactly the
   Stage 2 delivery mechanism. This is the clearest concrete detection
   gap this mapping surfaces, and it is a direct, actionable candidate
   for new detection logic (e.g., alerting on outbound mail from a
   recently-flagged-as-compromised account, or on message clients/times
   inconsistent with the sender's normal pattern) rather than a
   restatement of a control HC3 already recommends.

---

## References

Technique names, IDs and tactic assignments were verified against MITRE
ATT&CK directly:

- [T1583.003 -- Acquire Infrastructure: Virtual Private Server](https://attack.mitre.org/techniques/T1583/003/)
- [T1078.004 -- Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [T1608.001 -- Stage Capabilities: Upload Malware](https://attack.mitre.org/techniques/T1608/001/)
- [T1534 -- Internal Spearphishing](https://attack.mitre.org/techniques/T1534/)
- [T1005 -- Data from Local System](https://attack.mitre.org/techniques/T1005/)
- [T1132 -- Data Encoding](https://attack.mitre.org/techniques/T1132/)

All other technique IDs (the 18 OBSERVED techniques, plus T1021) are
taken directly from HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt Section 4,
which itself cites "MITRE ATT&CK Framework v15 (April 2026)" as its
reference.

**Note on a source discrepancy:** `meddefense_4x00_findings.txt` states
"7 OBSERVED techniques" in its own ATT&CK section header but lists only
6 technique rows (T1566.002, T1204.001, T1056.003, T1583.001, T1585.002,
T1608.005). This document uses the 6 techniques MedDefense actually
lists and flags this count mismatch here rather than silently reporting
"7" or inventing a plausible seventh technique to make the header
accurate.
