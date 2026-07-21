# MedDefense Health Systems: The ALE Workshop

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO, and Robert Kim, CFO **Source material:** The gaps, vulnerabilities, and threats identified across Projects 0x00, 1x01, and 1x02, quantified using the same SLE/ARO/ALE methodology validated in Task 5, now applied to MedDefense's own specific risks rather than provided exercise data **Purpose:** This is the point where three projects of analysis convert into numbers that drive budget decisions. Every risk below traces to a specific gap, a specific vulnerability finding, and a specific threat actor already established in this program's prior work, and every proposed control is priced against the same remediation costs this program has already calculated.

---

## Risk 1: Ransomware Compromises the Network via the VPN Gateway

yaml

```yaml
Risk: Ransomware encrypts the EHR system and billing server together via
  a single VPN compromise
Source: GAP-014 (no network segmentation) and GAP-016 (no perimeter
  patch management), exploiting Findings 001, 003, and 031 (1x02),
  Ransomware Groups, Kill Chain 1 (1x01)

Asset: The FortiGate VPN as entry point, reaching the EHR System and
  billing-srv-01 together (0x00 Asset Registry)
Asset Value (AV): $9,548,000
  Replacement/recovery cost: included within the combined figure below
  Revenue loss during downtime: included within the combined figure below
  Regulatory penalties: included within the combined figure below
  Reputation/patient trust impact: included within the combined figure
    below
  This figure is the sum of the billing-server ransomware AV ($473,000)
  and the EHR breach AV ($9,075,000) already calculated in Task 5,
  Scenarios 1 and 2, since the FortiGate is the confirmed entry point
  for the kill chain that reaches both assets together.

Exposure Factor (EF): 100%
  Reasoning: A successful VPN compromise on a fully flat network is
  assumed to enable the full combined campaign, both ransomware and
  data exfiltration, not a partial subset of it, consistent with Task
  5's own reasoning for this same scenario.

SLE: AV x EF = $9,548,000 x 1.0 = $9,548,000

ARO: 0.3
  Reasoning: VPN compromise is the number-one initial access vector in
  38% of healthcare ransomware attacks sector-wide, the same figure
  used in Task 5.

ALE: SLE x ARO = $9,548,000 x 0.3 = $2,864,400

Proposed Control: Full network segmentation separating server,
  workstation, medical device, and site traffic into restricted VLANs,
  directly closing GAP-014.
Control Annual Cost: $40,000 (a full organization-wide segmentation
  project, broader than the MRI-specific portion already budgeted at
  $25,000 in 1x02's remediation plan)
Estimated ALE After Control: Segmentation does not prevent the VPN
  compromise itself, so ARO remains 0.3, but it prevents that compromise
  from cascading into the full combined EHR-plus-billing outcome,
  reducing EF from 100% to 35%. New SLE = $9,548,000 x 0.35 =
  $3,341,800. New ALE = $3,341,800 x 0.3 = $1,002,540.
Net Benefit: $2,864,400 - $1,002,540 - $40,000 = $1,821,860
```

---

## Risk 2: EHR Database Breach via Unrestricted Network Access

yaml

```yaml
Risk: The complete patient database is read or exfiltrated by any actor
  who reaches ehr-db-01 over the internal network
Source: GAP-003 (EHR database network-wide exposure), Finding 003
  (1x02), all six threat actor types (1x01), Kill Chains 1, 3, and 5

Asset: The EHR System, ehr-db-01 specifically (0x00 Asset Registry,
  the #1-ranked Critical Asset)
Asset Value (AV): $9,075,000
  Replacement/recovery cost: not applicable, this is a data-
    confidentiality event, not a destruction event
  Revenue loss during downtime: not applicable to this specific risk
  Regulatory penalties: $25,000 fixed HIPAA notification cost plus
    $200,000 estimated litigation exposure
  Reputation/patient trust impact: $8,250,000 (50,000 records at $165
    per record, Ponemon 2024) plus $600,000 estimated reputational
    attrition cost, reused directly from Task 5, Scenario 2

Exposure Factor (EF): 100%
  Reasoning: A breach event realistically triggers the full record-cost,
  notification, litigation, and reputational components together, as
  established in Task 5.

SLE: AV x EF = $9,075,000 x 1.0 = $9,075,000

ARO: 0.45
  Reasoning: The sector baseline of roughly 0.33 is adjusted upward to
  reflect MedDefense's specific, confirmed compounding weaknesses,
  GAP-014, GAP-004, and GAP-003 itself, exactly as reasoned in Task 5.

ALE: SLE x ARO = $9,075,000 x 0.45 = $4,083,750

Proposed Control: Restrict pg_hba.conf to accept connections only from
  ehr-srv-01's specific address, with a host-based firewall rule
  enforcing the same restriction, already scheduled as an Immediate-tier
  action in 1x02's remediation plan (Task 20).
Control Annual Cost: $500 (already costed in 1x02, Task 19)
Estimated ALE After Control: This control does not change how often an
  attacker attempts access (ARO stays 0.45), but it closes the
  network-wide access path, meaning only an attacker who also
  compromises ehr-srv-01 itself (a materially narrower path) can still
  reach the database. EF drops from 100% to 20%. New SLE = $9,075,000 x
  0.20 = $1,815,000. New ALE = $1,815,000 x 0.45 = $816,750.
Net Benefit: $4,083,750 - $816,750 - $500 = $3,266,500
```

---

## Risk 3: Ransomware Entry via the Billing Server's Unpatched Apache

yaml

```yaml
Risk: Ransomware gains initial access through billing-srv-01's Apache
  vulnerability, the confirmed Step 1 of Kill Chain 1
Source: GAP-016 (no perimeter patch management), Findings 001 and 002
  (1x02), Ransomware Groups, Kill Chain 1

Asset: billing-srv-01 (0x00 Asset Registry)
Asset Value (AV): $473,000
  Replacement/recovery cost: $85,000
  Revenue loss during downtime: $288,000 (18 days at $16,000 per day,
    CISA average hospital ransomware downtime)
  Regulatory penalties: $100,000 (mid-range HIPAA penalty)
  Reputation/patient trust impact: not separately itemized here, since
    this asset's primary exposure is financial rather than direct patient
    data, consistent with Task 5's own reasoning

Exposure Factor (EF): 100%
  Reasoning: A successful attack realistically triggers the full
  downtime, recovery, and penalty components together.

SLE: AV x EF = $473,000 x 1.0 = $473,000

ARO: 0.29
  Reasoning: Sector rate of one attack every 3 to 4 years for a
  similarly-profiled hospital, midpoint used, exactly as calculated in
  Task 5.

ALE: SLE x ARO = $473,000 x 0.29 = $137,170

Proposed Control: Patch Apache to version 2.4.52 or later, closing both
  Finding 001 and the chained Finding 002, already scheduled in 1x02's
  remediation plan (Task 20).
Control Annual Cost: $5,000 (already costed in 1x02, Task 19, including
  staging validation)
Estimated ALE After Control: This control does not change what happens
  if ransomware succeeds by some other route (AV and EF unchanged), but
  it removes this specific, documented entry technique, reducing ARO
  from 0.29 to 0.10 to reflect that this exact path is closed while
  acknowledging other entry vectors to this server remain possible. New
  ALE = $473,000 x 0.10 = $47,300.
Net Benefit: $137,170 - $47,300 - $5,000 = $84,870
```

---

## Risk 4: Backup Infrastructure Compromise Prevents Recovery

yaml

```yaml
Risk: Ransomware destroys or encrypts NAS-01 during an active incident,
  removing MedDefense's ability to recover without a full rebuild
Source: GAP-006 (backup single point of failure), Finding 015 plus
  CVE-2024-10441 discovered through OSINT research (1x02, Task 9),
  Ransomware Groups, Kill Chain 1 (the documented, doctrinal
  backup-neutralization step in this actor's own affiliate playbook,
  1x01 Task 2)

Asset: NAS-01, MedDefense's sole backup infrastructure (0x00 Asset
  Registry, the #5-ranked Critical Asset)
Asset Value (AV): $1,090,000
  Replacement/recovery cost: $150,000 (a full rebuild from scratch with
    no restore point available, higher than the $85,000 baseline
    recovery cost used in Risk 3, since no functioning backup exists to
    restore from)
  Revenue loss during downtime: $240,000 (an estimated 15 additional
    days of extended downtime beyond a baseline ransomware event,
    at $16,000 per day; this daily figure is reused conservatively from
    billing-srv-01's own established rate and likely understates true
    organization-wide impact, since backup loss affects every system,
    not just billing, a limitation stated directly here rather than
    hidden)
  Regulatory penalties: $100,000 (mid-range HIPAA penalty, reused from
    Risk 3)
  Reputation/patient trust impact: $600,000 (reused from Task 5,
    Scenario 2, given an extended, unrecoverable outage plausibly drives
    the same patient-attrition dynamic already modeled there)

Exposure Factor (EF): 100%
  Reasoning: If backups are destroyed during an active ransomware event,
  this full extended-impact scenario realistically follows.

SLE: AV x EF = $1,090,000 x 1.0 = $1,090,000

ARO: 0.25
  Reasoning: This risk only materializes if a ransomware event already
  succeeds and specifically targets backups, which BlackReef's own
  documented playbook confirms as standard practice; set slightly below
  the base ransomware ARO of 0.29 to reflect that in some fraction of
  successful ransomware events, the backup-neutralization step
  specifically fails or is caught before completion.

ALE: SLE x ARO = $1,090,000 x 0.25 = $272,500

Proposed Control: Patch CVE-2024-10441 on NAS-01 and establish a
  genuinely isolated, immutable backup copy separate from the primary
  device, extending beyond the $5,000 patch-and-restrict remediation
  already costed in 1x02 (Task 19).
Control Annual Cost: $13,000 ($5,000 for the confirmed patch and network
  restriction, plus an estimated $8,000 for a true offline or immutable
  secondary backup solution)
Estimated ALE After Control: An isolated, immutable backup copy means
  even if NAS-01 itself is compromised, a clean recovery point exists
  elsewhere, dramatically reducing the likelihood of the full
  extended-catastrophe outcome. EF drops from 100% to 15%, while ARO
  stays 0.25 since this control does not prevent the ransomware event
  itself. New SLE = $1,090,000 x 0.15 = $163,500. New ALE = $163,500 x
  0.25 = $40,875.
Net Benefit: $272,500 - $40,875 - $13,000 = $218,625
```

---

## Risk 5: Medical Device Patient Safety Incident

yaml

```yaml
Risk: An opportunistic attacker exploits default credentials and flat
  network access on the BD Alaris infusion pump fleet, ranging from a
  denial-of-service event to a genuine patient safety incident
Source: GAP-001 (medical IoT zero coverage), Finding 010 (1x02),
  Unskilled/Opportunistic actor (1x01)

Asset: BD Alaris infusion pumps (0x00 Asset Registry, the #3-ranked
  Critical Asset)
Asset Value (AV): combined across two sub-scenarios, reused directly
  from Task 5, Scenario 4
  Replacement/recovery cost: not the primary driver, since this
    vulnerability forces manual operation rather than destroying devices
  Revenue loss during downtime: $100,000 (5 days at $20,000 per day for
    the denial-of-service sub-scenario)
  Regulatory penalties: $150,000 (FDA investigation cost, patient-safety
    sub-scenario only)
  Reputation/patient trust impact: included within the $2,750,000
    midpoint liability estimate for the patient-safety sub-scenario

Exposure Factor (EF): 100% for both sub-scenarios
  Reasoning: If either event occurs, its full associated cost
  realistically follows, as established in Task 5.

SLE: DoS sub-scenario, $100,000 x 1.0 = $100,000. Patient-safety
  sub-scenario, $3,000,000 x 1.0 = $3,000,000.

ARO: DoS, 0.1 (1 in 10 years, given directly in Task 5's source data).
  Patient safety, 0.02 (1 in 50 years, given directly).

ALE: DoS, $100,000 x 0.1 = $10,000. Patient safety, $3,000,000 x 0.02 =
  $60,000. Combined ALE = $70,000.

Proposed Control: Change default administrative credentials fleet-wide
  and implement network isolation restricting pump traffic to clinical
  workstations and the PACS server only, both already scheduled in
  1x02's remediation plan (Task 20).
Control Annual Cost: $3,200 ($3,000 for network segmentation labor,
  already costed in 1x02, plus an estimated $200 for credential-change
  documentation and fleet-wide audit labor)
Estimated ALE After Control: Removing the default-credential path
  eliminates the specific, no-skill entry technique this finding
  describes; DoS ARO drops from 0.1 to 0.02, and patient-safety ARO
  drops from 0.02 to 0.005, reflecting that a targeted patient-safety
  event becomes considerably harder, though never zero, since the
  underlying firmware vulnerability itself remains unpatched by the
  vendor. New ALE (DoS) = $100,000 x 0.02 = $2,000. New ALE (patient
  safety) = $3,000,000 x 0.005 = $15,000. New combined ALE = $17,000.
Net Benefit: $70,000 - $17,000 - $3,200 = $49,800
```

---

## Risk Prioritization by ALE

|Rank|Risk|ALE Before Control|Control Cost|ALE After Control|Net Benefit|
|---|---|---|---|---|---|
|1|EHR database breach (unrestricted access)|$4,083,750|$500|$816,750|$3,266,500|
|2|Ransomware via VPN gateway (combined EHR + billing)|$2,864,400|$40,000|$1,002,540|$1,821,860|
|3|Backup infrastructure compromise|$272,500|$13,000|$40,875|$218,625|
|4|Ransomware entry via billing-srv-01 Apache|$137,170|$5,000|$47,300|$84,870|
|5|Medical device patient safety incident|$70,000|$3,200|$17,000|$49,800|

**A note on how to read this table, worth stating directly before it drives budget decisions:** ranking by raw ALE alone would put the two largest, most catastrophic risks first, which is appropriate for understanding total exposure, but ranking by Net Benefit tells a different and equally important story for a fixed $120,000 budget: **Risk 2's control costs only $500 and returns $3,266,500 in net benefit**, the single highest return of any control in this entire program, precisely because it is the cheapest fix analyzed here attached to the largest exposure. Every control proposed above returns its cost many times over, but Risk 2 in particular should be understood as the closest thing to a free decision this entire risk analysis produces.
