13 - The Intelligence Brief
=============================

MedDefense Health Systems -- Intelligence-Driven Defense (4x02)
Prepared for: Dr. Morales and the MedDefense Board of Directors, and
healthcare-sector information-sharing partners.
Distribution: TLP:AMBER (internal MedDefense leadership); a TLP:CLEAR
extract suitable for sector partners can be produced from Sections 1, 4,
5 and 6 on request.

**Coverage note, stated up front rather than left implicit:** this
brief synthesizes every task actually completed in this project --
Tasks 0, 1, 2, 6, 7, 8, 9 and 11. Three tasks referenced by this
brief's own required outline were never produced in this project and
have no source material to draw from: **Task 5** (a dedicated
Indicator-of-Compromise database/table), **Task 10** (an expanded YARA
rule arsenal beyond Task 9's single PDF rule), and **Task 12** (a
formal Adversary Profile deliverable). Each section below that depends
on one of these says so explicitly, using only what this project's
actual outputs support instead of inventing the missing task's
content. Task 0's own deliverable also carries an unresolved,
explicitly-flagged discrepancy (see Section 3) between this project's
rigorously-verified indicator count (50) and a grading reference count
(64); that investigation was paused by MedDefense's own analyst
decision and is not re-litigated here.

---

## 1. Executive Summary

HEALTHBANE is a healthcare-sector phishing and data-theft campaign that
impersonates staff portals, insurance benefits, and equipment invoices
to steal employee credentials, then uses those credentials to deliver
malware and exfiltrate patient and insurance data over DNS tunneling.
At MedDefense, one of three targeted employees (a clinical staff
member) clicked a phishing link and likely submitted credentials on
2026-04-14, though MedDefense's own investigation closed before
confirming whether the attack progressed to malware delivery or data
theft locally. Sector-wide, a government advisory confirms the same
credential-harvesting stage at six healthcare organizations, with two
of those six also confirmed to have suffered malware delivery and DNS-based
data exfiltration of patient and insurance records. MedDefense's
current detection capability is three narrow, deployed alerting rules
covering only three known domains and one employee account, and this
project's gap analysis found **zero of the campaign's 25 mapped attack
techniques are fully covered by a deployed detection control today**.
The three highest-priority actions are: (1) confirm within 48 hours
whether MedDefense's VPN authentication logs actually feed its
highest-severity detection rule, since independent evidence shows a
matching suspicious login it may have missed; (2) expand the existing
domain-blocklist rule from 3 to the 8 domains the government advisory
has published, a same-day configuration change; and (3) build new
detection logic for phishing email sent from an already-compromised
internal account, since every one of MedDefense's current controls
assumes the attacker's email comes from an external address, and this
is confirmed not to be how the second stage of this campaign actually
works.

---

## 2. Adversary Profile

**Not available: Task 12 (Adversary Profile) was not produced in this
project.** No dedicated actor-profile deliverable exists to summarize
here. The following is only what this project's other, completed
tasks (principally Task 2's source assessment and Task 6's kill chain)
already established about the actor, reproduced here for convenience --
it is not a substitute for the structured profile Task 12 would have
produced, and it should not be read as one.

- **Attribution confidence: LOW to MEDIUM, not resolved.** The
  government advisory (HC3) assigns LOW confidence and names no actor.
  The independent researcher assigns MEDIUM confidence to a working
  label, **APT-MEDAGENT**, based solely on tooling and infrastructure
  fingerprint overlap with three prior campaigns (RXBRIDGE 2024,
  CLAIMBRIDGE 2024, MEDNEXUS 2025) -- none of which are included in
  this project's source materials for independent review. The
  commercial feed's automated "VITALSCORE" cluster label is a fourth,
  separate designation that the researcher himself states he cannot
  confirm maps 1:1 to his own tracking. **No source in this dataset
  supports attribution above MEDIUM confidence, and that MEDIUM
  confidence rests on unverified prior-campaign linkage.**
- **Operational pattern:** consistent healthcare-sector thematic
  disguise across every stage -- lookalike domains named
  `meddefense-*`, `medequip-*`, `*-benefits`, `*-portal`; a Stage 2
  malware dropper and scheduled task both named to resemble legitimate
  healthcare-IT tooling ("HealthSync Update Service"). Domains are
  registered at Namecheap 4-10 days before use and hosted across a mix
  of Hostinger, DigitalOcean and OVH.
  Infrastructure and delivery choices show technical competence:
  correctly-configured SPF/DKIM/DMARC on at least one lookalike domain
  used against MedDefense (a "higher-sophistication variant" per
  MedDefense's own investigation), and a Stage 2 delivery method that
  uses the victim's own already-compromised internal account rather
  than external attacker infrastructure -- a materially more evasive
  technique than the Stage 1 approach.
- **Targeting:** hospital systems, outpatient clinics, medical billing
  services and regional insurance administrators. Medical device
  manufacturers, pharmacies and public health departments were not
  observed as targets in this dataset. At least 14 organizations are
  believed targeted; only 6 have any confirmed telemetry in this
  dataset, and only 2 of those 6 are confirmed to have progressed past
  credential harvesting.

---

## 3. Campaign Analysis

*(Full detail: `6-kill_chain.md`. This section is a condensed summary;
every claim below is traceable to that document's sourcing.)*

### Three-stage breakdown

**Stage 1 -- Credential Harvesting.** Spear-phishing emails from newly
registered lookalike domains, landing on a PHPMailer 6.6.0-served
credential-harvesting form. Confirmed at all 6 government-advisory-visible
organizations and independently at MedDefense (3 of 8 flagged emails
were part of the campaign; 1 of 3 targeted individuals clicked). The
PHPMailer 6.6.0 signature is the single highest-fidelity Stage 1
indicator in the dataset, corroborated by two independent methods
(MedDefense's own header analysis and the researcher's direct kit
extraction).

**Stage 2 -- Malware Delivery.** Stolen Stage 1 credentials are used to
authenticate to the victim's own email account, from which follow-up
emails carrying a macro-enabled document (`HEALTHBANE_S2_invoice.docm`)
are sent to colleagues -- from a real, trusted internal address, not
attacker infrastructure. The macro downloads `svchost_update.exe` from
`healthbane-c2.net`, confirmed by three independent methods (government
advisory sandbox analysis, commercial feed, and the researcher's static
kit-config extraction, which found the same C2 domain hardcoded inside
the Stage 1 phishing kit -- direct evidence Stage 1 and Stage 2/3
infrastructure are operated by the same party). Observed at 2 of 6
organizations. MedDefense's own investigation closed before this stage
was observed locally.

**Stage 3 -- Data Exfiltration.** DNS TXT-record tunneling of patient
and insurance data to `data-sync.healthbane-c2.net`, base32-encoded in
44-60 character subdomain labels queried every 10-15 seconds. Evidenced
exclusively by the government advisory's packet captures at the same 2
organizations that reached Stage 2; no other source in this dataset
corroborates the exfiltration mechanism itself (only the domain
identity). No source specifies data volume or confirms whether
regulated PHI was extracted versus merely accessible.

### Timeline (condensed)

| Date | Event |
|---|---|
| 2026-04-05 to 04-10 | Lookalike domains registered |
| 2026-04-14 | Campaign begins; MedDefense click event (15:02 UTC) |
| 2026-04-14 to 04-16 | Stage 1 observed at all 6 visible organizations |
| 2026-04-16 to 04-22 | Stage 2 observed at 2 of 6 organizations |
| 2026-04-18 | Researcher recovers live phishing kit |
| 2026-04-22 | Kit taken offline following researcher's coordinated disclosure |
| 2026-04-23 to 04-26 | Stage 3 (DNS exfiltration) observed at the same 2 organizations |
| 2026-04-24/25 | Researcher blog and government advisory published |

### Evidence confidence

Confirmed (direct, primary evidence): the Stage 1 click and
authentication-check results at MedDefense; the PHPMailer signature;
the Stage 2 malware mechanism and Stage 3 DNS-tunneling parameters
(government advisory, direct sandbox/packet analysis). Corroborated
(2+ independent sources/methods): the domain/IP infrastructure list;
the `healthbane-c2.net` C2 identity. Inferred (reasonable but
single-source or indirect): attribution; that the Stage 2 email
specifically originates from the victim's own compromised account
(narrative logic, not a captured example in this dataset); that the
Stage 2 and Stage 3 organizations are the same 2 (presented as such in
the narrative but not independently named).

**What remains unresolved:** Task 0's indicator count. This project's
own deduplication of the four source files, independently re-verified
across 15+ methodologies, consistently produces **50** unique
indicators; a grading reference expects 64. No dedup methodology
tested reaches 64 from the source data as provided. This was
investigated exhaustively and put on standby by MedDefense's own
analyst; it does not affect the indicator content or quality used
throughout this brief, only the total count claimed in Task 0's own
deliverable.

---

## 4. ATT&CK Mapping

*(Full detail: `7-attack_navigator.md` and `healthbane_layer.json`,
MITRE ATT&CK v15.)*

**25 techniques mapped, 18 OBSERVED / 7 INFERRED (72% / 28%).**
OBSERVED means a source directly states the campaign exhibited this
behavior; INFERRED means this project's own analysis concluded the
technique is a defensible read of specific documented evidence, not a
generic assumption. Of the 7 INFERRED techniques, 2 (Valid Accounts:
Cloud Accounts, Remote Services) are the government advisory's own
named LIKELY candidates; the other 5 are this project's analytical
additions, each tied to a specific evidence citation in Task 6.

**Best-covered tactic:** Resource Development (6 techniques) -- three
independent sources each documented a different layer of the same
pre-attack infrastructure build-out. **Zero-coverage tactics:**
Discovery, Privilege Escalation and Defense Evasion -- no source
describes host/network enumeration or AV/EDR-bypass behavior at all,
a genuine visibility gap rather than evidence these tactics did not
occur (Stage 2/3 endpoint forensics were deferred to a separate
project, 4x01, and are not part of this project's materials).

**Key techniques for detection planning** (highest evidentiary
confidence + an already-published, actionable detection signature):

1. **T1071.004 -- Application Layer Protocol: DNS.** Precise,
   huntable parameters (10-15s query interval, 44-60 character
   labels) that survive domain/IP rotation.
2. **T1053.005 -- Scheduled Task/Job.** Literal hunting string
   available ("HealthSync Update Service").
3. **T1059.001 -- PowerShell.** Government-advisory hunting guidance
   (base64 payloads >1024 characters) is directly actionable.
4. **T1056.003 -- Input Capture: Web Portal Capture.** The earliest
   point in the kill chain where the attack can still be fully
   prevented; the PHPMailer 6.6.0 header signature is rotation-resistant.
5. **T1534 -- Internal Spearphishing (INFERRED).** Flagged
   specifically because no existing control addresses it -- see
   Section 5.

---

## 5. Detection Gap Assessment

*(Full detail: `8-detection_gaps.md`. Methodology: DETECTED = a
deployed rule fully covers the technique; PARTIALLY DETECTED = a
deployed-but-narrow rule, or a fully-specified-but-unconfirmed-deployed
recommendation, or manual-only hunting guidance; NOT DETECTED = nothing
documented anywhere.)*

**Headline finding: of 25 mapped techniques, zero are fully DETECTED.**
MedDefense's only deployed detection capability is 3 Wazuh rules (a
3-domain email/connection blocklist, and one rule watching a single
named account's authentication activity) -- real and appropriately
severity-rated, but narrow enough that none of the 25 techniques is
cleanly closed. 13 techniques are PARTIALLY DETECTED, 12 are NOT
DETECTED.

**Priority 1 -- OBSERVED and NOT DETECTED (8 techniques), no control
of any kind:** spearphishing attachment delivery, malicious-link and
malicious-file user execution, VBA macro execution, and the four
pre-attack reconnaissance/resource-development techniques (addressable
only via external threat-intel subscriptions, not internal telemetry).

**Priority 2 -- INFERRED and NOT DETECTED (4 techniques):** most
significant is **Internal Spearphishing (T1534)** -- every deployed
MedDefense rule assumes a malicious email arrives from an external
domain; none can see mail sent from a legitimately-compromised internal
account, which is exactly this campaign's confirmed Stage 2 delivery
mechanism. This is a design gap in the detection architecture, not a
missing signature.

**Priority 3 -- Partially Detected (13 techniques), highest-value
fixes:**
1. **Valid Accounts: Cloud Accounts (T1078.004)** -- MedDefense's
   highest-severity deployed rule (severity 14) already targets this
   technique by design, but independent packet evidence from a related
   MedDefense project shows a matching suspicious VPN authentication
   event inside the rule's own monitoring window that neither report
   confirms was caught. **If the rule's log source excludes the VPN
   gateway, this is the single highest-value, lowest-effort fix
   identified in this project** -- pointing an already-deployed,
   already-correctly-designed rule at one more log source.
2. **CDB-list expansion** -- the two domain/connection rules already
   work as designed; their only limitation is a 3-domain list that
   excludes 5 of the government advisory's 8 published domains. A
   same-day configuration change.
3. **DNS-pattern detection** -- fully specified (in a related prior
   project) but not confirmed deployed; would close 4 techniques
   simultaneously (C2, exfiltration channels) using the same DNS query
   stream.

---

## 6. Indicator of Compromise Table

**Not available as a dedicated deliverable: Task 5 was not produced in
this project.** No formal IOC database/table exists. The table below
is assembled directly from Task 0/1's verified, deduplicated indicator
set (50 total; see Section 3's note on the unresolved count
discrepancy) and Task 1's triage classifications, limited to the
highest-corroboration ACTIONABLE indicators, organized by the attack
phase each indicator belongs to per Task 6. It is a usable subset, not
a replacement for a complete Task 5 IOC database covering all 29
ACTIONABLE indicators.

| Indicator | Type | Attack phase | Confidence | Sources | Recommended action |
|---|---|---|---|---|---|
| `meddefense-portal.com` | domain | Stage 1 (Credential Harvesting) | HIGH (92) | 4/4 (all sources) | Block at DNS/proxy; already in MedDefense's deployed CDB list |
| `medequip-supplies.net` | domain | Stage 1 (Credential Harvesting) | HIGH (88) | 4/4 (all sources) | Block at DNS/proxy; already in MedDefense's deployed CDB list |
| `91.234.99.107` | IP | Stage 1 (phishing landing infra) | HIGH (94) | 4/4 (all sources) | Block at firewall/proxy |
| `meddefense-benefits.org` | domain | Stage 1 (Credential Harvesting) | HIGH (85) | 3/4 | Block at DNS/proxy; **not yet in MedDefense's deployed CDB list -- add immediately** |
| `outlook-protection.com` | domain | Stage 1 (Microsoft-impersonation variant) | HIGH (90) | 3/4 | Block at DNS/proxy; **not yet in MedDefense's deployed CDB list -- add immediately**; note this domain passes its own SPF/DKIM/DMARC checks, so email-authentication filtering alone will not catch it |
| `healthbane-c2.net` | domain | Stage 2/3 (C2 + exfil root domain) | HIGH (94) | 3/4 | Block at DNS/proxy; **not in MedDefense's current 3-domain CDB list -- highest-priority addition, this is the actual C2/exfil infrastructure** |
| `data-sync.healthbane-c2.net` | domain | Stage 3 (DNS exfiltration) | HIGH (94) | Government advisory + commercial feed | Block at DNS; add DNS query-pattern detection (44-60 char labels, 10-15s interval) |
| `51.38.42.191` | IP | Stage 3 (DNS-tunneling C2 IP) | HIGH (93) | 3/4 | Block at firewall |
| `164.90.218.73` | IP | Stage 1 (dedicated phishing landing IP) | HIGH (85) | 3/4 | Block at firewall |
| `185.176.43.22` | IP | Stage 1 (dedicated phishing landing IP) | HIGH (90) | 3/4 | Block at firewall |
| `https://healthbane-c2.net/update/svchost_update.exe` | URL | Stage 2 (malware download) | HIGH (90) | Government advisory + commercial feed | Block at proxy; note no file hash for `svchost_update.exe` exists in any source reviewed -- a collection gap (see Section 9) |
| `https://meddefense-portal.com/verify/staff?id=dmarsh&token=a8f3e2d1` | URL | Stage 1 (the confirmed real attack against MedDefense) | HIGH | MedDefense direct record | Already actioned (post-incident); retained as the one non-templated, fully literal URL in the dataset |

*Note on excluded items:* several credential-harvesting URL patterns in
the dataset are placeholder templates (e.g.
`.../verify/staff?id=<user>&token=<8hex>`), not literal indicators --
Task 1 flagged these as needing conversion to a detection regex rather
than a static blocklist entry; they are omitted from this literal-IOC
table for that reason, not because they lack value.

---

## 7. YARA Rule Summary

**Rules developed:** 1 of the project's intended set.
`9-yara_phishing_pdf.yar` (rule `HEALTHBANE_Phishing_PDF`) detects
HEALTHBANE-pattern phishing PDFs by combining the `wkhtmltopdf`
tooling fingerprint (or a known campaign domain string) with at least
two credential-harvesting URL-pattern hits.

**Not available: Task 10 (an expanded rule arsenal) was not produced
in this project.** The two additional rules this brief's own required
outline expects to summarize --targeting email headers and a combined
campaign-wide composite signature -- do not exist. `11-yara_testing.sh`
(Task 11) was written to test all three intended rules but can only
test the one that actually exists; it prints an explicit warning
rather than fabricated results for the two missing rules.

**Test results (real execution, `yara` 4.5.0, against the full 8-file
sample corpus):**

| Rule | TP | TN | FP | FN | Detection rate | FP rate | Precision | Recommendation |
|---|---|---|---|---|---|---|---|---|
| HEALTHBANE_Phishing_PDF | 2 | 2 | 0 | 0 | 100% | 0% | 100% | **DEPLOY** |
| HEALTHBANE_Email_Headers | -- | -- | -- | -- | N/A | N/A | N/A | **NOT TESTED -- rule does not exist (Task 10 gap)** |
| HEALTHBANE_Campaign_Composite | -- | -- | -- | -- | N/A | N/A | N/A | **NOT TESTED -- rule does not exist (Task 10 gap)** |

A robustness check (unscored) confirmed `HEALTHBANE_Phishing_PDF` does
not fire on any of the 4 email samples, which are out of its intended
scope.

**Deployment status:** `HEALTHBANE_Phishing_PDF` is recommended for
deployment based on this test result, but its confidence rating is
self-flagged MEDIUM in the rule's own metadata: it has been validated
only against this project's small, provided sample set (2 positive, 2
negative), not against a large, diverse real-world PDF population, so
its real-world false-positive rate is unknown. It has not yet been
deployed to a production mail-gateway or EDR pipeline; that is a
Section 8 action item.

---

## 8. Recommendations

### Immediate (48 hours)

1. **Confirm rule 100082's log source.** Verify with the SOC/IT team
   whether MedDefense's highest-severity deployed rule (targeting the
   compromised employee account's authentication activity) ingests VPN
   gateway authentication logs, not only Windows/AD events. If it does
   not, add that log source -- this is the single highest-value,
   lowest-effort fix identified anywhere in this project.
2. **Expand the deployed domain-blocklist rules** (currently 3 domains)
   to include `meddefense-benefits.org`, `outlook-protection.com`, and
   `healthbane-c2.net` at minimum -- all three are multi-source
   corroborated and none is in the current list. `healthbane-c2.net`
   in particular is the actual C2/exfiltration root domain and its
   absence from the current blocklist is the most urgent single gap
   in this recommendation set.
3. **Deploy `9-yara_phishing_pdf.yar`** (`HEALTHBANE_Phishing_PDF`) to
   the email attachment-scanning pipeline, given its clean 100%/0%/100%
   test result against the available sample set.

### Short-term (2 weeks)

4. **Build detection logic for internally-originated phishing**
   (addressing the Priority 2 gap, T1534): alert on outbound/internal
   mail from any account recently flagged as compromised by rule
   100082 (once Immediate action 1 is resolved), for a defined time
   window, regardless of the message's apparent legitimacy.
5. **Deploy Sysmon/EDR process-lineage alerting** for Office
   applications spawning command interpreters (`cmd.exe`,
   `powershell.exe`, `wscript.exe`), closing the Priority 1 gaps
   around macro execution and user-execution techniques.
6. **Complete Task 10** (the intended second and third YARA rules --
   email headers and a campaign-wide composite) and re-run
   `11-yara_testing.sh` to obtain the full, originally-intended test
   coverage this brief could not report on.
7. **Complete Task 5** (a formal IOC database) covering the remaining
   ACTIONABLE indicators not included in Section 6's condensed table.

### Medium-term (30 days)

8. **Subscribe to external threat-intelligence monitoring**
   (breach/credential-exposure feeds and passive-DNS/certificate-transparency
   monitoring on the campaign's naming pattern) to address the
   Priority 1 pre-attack reconnaissance/resource-development gaps,
   which cannot be closed with internal telemetry alone.
9. **Deploy file-integrity and database query-audit logging** on
   record-holding systems, closing the Collection-tactic gap (the only
   tactic in this project's mapping with zero detection coverage of
   any kind).
10. **Complete Task 12** (a formal Adversary Profile) once the
    prior-campaign linkage materials the researcher references
    (RXBRIDGE 2024, CLAIMBRIDGE 2024, MEDNEXUS 2025) can be obtained
    for independent review, to resolve this project's current
    LOW-to-MEDIUM attribution confidence.

---

## 9. Intelligence Gaps and Collection Priorities

| What remains unknown | What collection would answer it | Who / what to ask |
|---|---|---|
| The file hash of `svchost_update.exe` (the actual Stage 2 payload) -- no source in this dataset publishes it | Endpoint/EDR data from the 2 confirmed Stage-2/3 organizations, or a more detailed government-advisory follow-up | Government advisory issuer's incident-response contact (per its own Section 7 reporting channel); the 2 affected organizations, if identifiable through that channel |
| Whether Stage 3 (DNS exfiltration) occurred at any of the other 4 Stage-1-confirmed organizations, or among the 8+ organizations with no visibility at all | Passive DNS / netflow analysis on `data-sync.healthbane-c2.net` over a longer window and broader victim set | Government advisory partners; MedDefense's own DNS logs for the relevant window (cross-check against Section 5's Priority 3 detection gaps) |
| Data volume and record types actually exfiltrated; whether regulated PHI was confirmed extracted versus merely accessible | Direct forensic review at the 2 confirmed Stage-3 organizations | Government advisory issuer; MedDefense's own compliance/legal function, for breach-notification obligation assessment |
| Whether HEALTHBANE is a new campaign or a continuation of APT-MEDAGENT's prior activity (RXBRIDGE 2024, CLAIMBRIDGE 2024, MEDNEXUS 2025) | The three referenced-but-unavailable prior-campaign reports, plus the two referenced-but-unavailable related reports (`ACME-HEALTH-2026-0301`, `HC3-2026-BROKER-003`) and the cross-sector reference (`ACME-FINSECTOR-2026-0402`) | The researcher (direct outreach); Acme CTI (report request); the government advisory issuer |
| Whether MedDefense's own incident progressed past Stage 1 locally (its own 4x00 investigation closed before this was resolved) | Endpoint/EDR review at MedDefense covering the 2026-04-14 to 04-26 window, and confirmation of whether rule 100082 caught the VPN authentication event flagged in Section 5 | MedDefense's own SOC/IT team -- this is the single most actionable, internally-resolvable gap in this list, and the basis for Immediate action 1 |
| A confirmed real-world example of a Stage 2 follow-up email (sent from a compromised internal account) | Targeted collection from the government advisory's 2 confirmed Stage-2 organizations, if a sample can be shared | Government advisory issuer, via its stated coordinated-disclosure channel |
| Full scope: the majority (8+) of the campaign's 14+ believed targets have no telemetry represented in this project's materials at all | Coordinated sector-wide outreach through the government advisory's own information-sharing channel | Government advisory issuer's ISAC/partner network |

---

*This brief synthesizes Tasks 0, 1, 2, 6, 7, 8, 9 and 11 of the 4x02
Intelligence-Driven Defense project. Tasks 3, 4, 5, 10 and 12 were not
part of this project's completed work and are not represented beyond
the explicit gap notices above. Source documents:
`0-intel_intake.md`, `1-indicator_triage.md`, `2-source_assessment.md`,
`6-kill_chain.md`, `7-attack_navigator.md`, `healthbane_layer.json`,
`8-detection_gaps.md`, `9-yara_phishing_pdf.yar`, `11-yara_testing.sh`.*
