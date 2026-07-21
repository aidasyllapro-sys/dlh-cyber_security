# MedDefense Health Systems: The Cost-Benefit Analysis

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO, and Robert Kim, CFO **Source material:** The ALE calculations from Task 6, extended with new, explicitly-stated estimates for controls and risk components not yet quantified in prior work **Purpose:** A control is financially justified when the ALE it eliminates exceeds its annual cost. This is not a judgment call once the numbers are on the table, it is arithmetic. Eight proposed controls are evaluated below on that basis alone.

**A methodology note, stated upfront rather than buried:** several of these controls address the same underlying risks already quantified in Task 6 (Risks 1, 3, and 5 in particular). Where a control's benefit is not already established in prior work, a new estimate is built here with its assumptions stated explicitly, following the same reasoning discipline used throughout this program, and every new dollar figure is derived from a stated logic, not asserted.

---

## Control 1: Network Segmentation

yaml

```yaml
Control 1: Network Segmentation (VLAN implementation for server,
  workstation, medical device, and guest zones)
CIS Control Reference: 12 (Network Infrastructure Management)
Annual Cost: $40,000 (license: $0, this is architecture work, not a
  software purchase; labor: switch reconfiguration, VLAN design, and
  firewall rule authoring across all three sites; maintenance: ongoing
  rule review folded into the initial estimate), reused directly from
  Task 6, Risk 1's proposed control
Risk(s) Addressed: Risk 1 (Ransomware via VPN gateway), Task 6
ALE Reduction: $2,864,400 - $1,002,540 = $1,861,860, calculated
  directly in Task 6 by reducing this risk's Exposure Factor from 100%
  to 35%
Net Value: $1,861,860 - $40,000 = $1,821,860
Verdict: Justified
Recommendation: Implement. This is the single highest-value control in
  this entire analysis and is already the top-funded line item in this
  program's own remediation plan.
```

---

## Control 2: MFA Deployment (VPN and Administrative Accounts)

yaml

```yaml
Control 2: MFA deployment on VPN and administrative accounts, using
  existing O365 E3 licenses
CIS Control Reference: 6 (Access Control Management)
Annual Cost: $2,000 (license: $0, already included in MedDefense's
  existing O365 E3 subscription, confirmed in Project 0x00; labor: an
  estimated one-time configuration effort amortized across the year,
  plus minor ongoing administrative overhead)
Risk(s) Addressed: Risk 1 (Ransomware via VPN gateway), Task 6, evaluated
  against Risk 1's original baseline rather than Control 1's already-
  reduced figures, to keep this control's individual business case clean
ALE Reduction: MFA directly breaks credential-based VPN entry, the
  documented weak point behind GAP-017. Reducing Risk 1's ARO from 0.3 to
  0.15 (halving the likelihood of a credential-based compromise
  succeeding, though not eliminating it entirely, since some
  authentication-bypass techniques, illustrated by the FortiOS CVE found
  through OSINT research in 1x02, Task 9, defeat MFA regardless):
  ALE before = $9,548,000 x 0.3 = $2,864,400. ALE after = $9,548,000 x
  0.15 = $1,432,200. Reduction = $1,432,200.
Net Value: $1,432,200 - $2,000 = $1,430,200
Verdict: Justified
Recommendation: Implement immediately. This is close to a free decision:
  the licensing cost is already sunk, and the ALE reduction is the second
  largest in this entire analysis.
```

---

## Control 3: Enterprise SIEM Deployment (Wazuh, Open-Source)

yaml

```yaml
Control 3: Enterprise SIEM deployment (Wazuh, open-source, labor cost
  only)
CIS Control Reference: 8 (Audit Log Management), extending to 13
  (Network Monitoring and Defense)
Annual Cost: $25,000 (license: $0, Wazuh is open-source; labor and
  infrastructure: deployment, tuning, log storage infrastructure, and
  ongoing triage represent a substantial real cost for a two-person
  security team, even with no software fee, estimated conservatively
  given the significant time investment "free" open-source tooling
  still requires to run well)
Risk(s) Addressed: Directly closes GAP-004, the detection gap this
  program has identified as one of "The Critical Three" across all
  prior work. Evaluated against Risk 1 and Risk 3's original baselines.
ALE Reduction: A SIEM does not prevent initial compromise, but it
  interrupts an attack mid-sequence rather than letting it run to full
  completion undetected, exactly the failure mode that let the
  billing-srv-01 cryptominer run unnoticed (0x00, Task 2). Modeled as an
  Exposure Factor reduction rather than an ARO reduction, since the
  attack still begins but does not complete: Risk 1's EF drops from 100%
  to 55% (ALE reduction of $1,288,980); Risk 3's EF drops from 100% to
  60% (ALE reduction of $54,868). Combined reduction = $1,343,848.
Net Value: $1,343,848 - $25,000 = $1,318,848
Verdict: Justified
Recommendation: Implement. This directly closes a gap independently
  confirmed as one of the three most consequential in this entire
  program, at a fraction of its value in reduced risk.
```

---

## Control 4: Offsite Backup Replication (AWS S3 Glacier, Immutable)

yaml

```yaml
Control 4: Offsite backup replication (cloud immutable storage, AWS S3
  Glacier)
CIS Control Reference: 11 (Data Recovery)
Annual Cost: $4,000 (license/service: an estimated $1,800/year for
  Glacier storage and retrieval covering an estimated 5-10TB of critical
  backup data at deep-archive pricing, an assumption stated directly
  since exact backup volume was not established in prior work; labor:
  approximately $2,200/year for setup and ongoing replication
  maintenance)
Risk(s) Addressed: Risk 4 (Backup infrastructure compromise), Task 6,
  evaluated as an alternative or complementary path to the same
  protective outcome as Task 6's on-premises isolated-copy control
ALE Reduction: True offsite, geographically-separate replication
  achieves at least the same protective effect as an on-premises
  isolated copy, and arguably more, since it survives even a physical
  or site-wide incident an on-premises isolated copy would not. Modeled
  with EF dropping from 100% to 10% (slightly better than Task 6's
  15% estimate for the on-premises alternative): ALE after = $1,090,000
  x 0.10 x 0.25 = $27,250. Reduction = $272,500 - $27,250 = $245,250.
Net Value: $245,250 - $4,000 = $241,250
Verdict: Justified
Recommendation: Implement, either instead of or alongside Task 6's
  on-premises isolated-copy option; both target the same underlying
  risk, and the choice between them (or both together) is an operational
  decision, not a financial one, given either clears this bar
  comfortably.
```

---

## Control 5: Endpoint Detection and Response Upgrade

yaml

```yaml
Control 5: EDR upgrade (Sophos basic to Sophos Intercept X, all
  endpoints including servers)
CIS Control Reference: 10 (Malware Defenses)
Annual Cost: $23,000 (license: approximately $19,500/year, estimated at
  roughly $65 per endpoint per year across an estimated 300 endpoints
  including servers, an assumption stated directly since MedDefense's
  exact endpoint count was not itemized in prior work beyond the
  approximately 280 clinical workstations already established; labor:
  approximately $3,500/year for deployment and ongoing management)
Risk(s) Addressed: Directly closes GAP-005 (no server-class endpoint
  protection), the confirmed root cause of the cryptominer compromise on
  billing-srv-01 (0x00, Task 2). Evaluated against Risk 1 and Risk 3's
  original baselines.
ALE Reduction: Unlike Control 3, EDR can actively block malicious
  execution before it establishes a foothold, not merely detect it
  after the fact, so this is modeled as an ARO reduction for Risk 3:
  ARO drops from 0.29 to 0.15 (ALE reduction of $66,220), reflecting
  that server-class EDR would very plausibly have prevented the exact
  compromise MedDefense has already experienced once. For Risk 1, a more
  modest EF reduction from 100% to 70% is applied, since EDR's strength
  is endpoint-level blocking rather than network-level containment (ALE
  reduction of $859,320). Combined reduction = $925,540.
Net Value: $925,540 - $23,000 = $902,540
Verdict: Justified
Recommendation: Implement. This control directly closes the exact gap
  behind MedDefense's only confirmed historical compromise, not a
  hypothetical risk.
```

---

## Control 6: Dedicated Firewall for Westside Clinic

yaml

```yaml
Control 6: Dedicated firewall for Westside Clinic, replacing the
  consumer router
CIS Control Reference: 12 (Network Infrastructure Management)
Annual Cost: $1,800 (equipment/install: $5,000 one-time cost, reused
  from 1x02's own remediation estimate, amortized over a 5-year hardware
  life at $1,000/year; maintenance: an estimated $800/year in ongoing
  licensing and support, typical for an enterprise-grade firewall
  appliance)
Risk(s) Addressed: GAP-021 (Westside's consumer-grade perimeter device),
  a risk not separately quantified in Task 6 and estimated fresh here
ALE Reduction: A compromise originating from Westside's own consumer
  router grants a similar, though smaller-scope, tunnel into Central's
  server network as the main VPN gateway risk. AV estimated at
  $3,000,000 (a partial-compromise scenario reflecting Westside's
  smaller footprint relative to the full aggregate EHR-plus-billing
  exposure modeled in Risk 1), with ARO at 0.15 before the control
  (lower than the main gateway's 0.3, given Westside is a smaller,
  less obviously targeted site). ALE before = $3,000,000 x 0.15 =
  $450,000. Enterprise-grade equipment closes the specific consumer-
  router weakness this risk depends on, reducing ARO to 0.03. ALE
  after = $3,000,000 x 0.03 = $90,000. Reduction = $360,000.
Net Value: $360,000 - $1,800 = $358,200
Verdict: Justified
Recommendation: Implement. Low absolute cost against a gap this
  program has already flagged as Critical (GAP-021, 0x00, Task 15).
```

---

## Control 7: 24/7 Security Operations Center Staffing

yaml

```yaml
Control 7: 24/7 SOC staffing (outsourced managed SOC)
CIS Control Reference: 13 (Network Monitoring and Defense), extending
  to 17 (Incident Response Management)
Annual Cost: $120,000 (service fee only, estimated at approximately
  $10,000/month for a healthcare-experienced managed detection and
  response provider covering MedDefense's endpoint and server count, a
  mid-range estimate for genuine round-the-clock coverage, not a
  budget-tier offering)
Risk(s) Addressed: Nominally the same detection-dependent risks as
  Control 3, but evaluated here as the incremental value beyond Control
  3 (SIEM) already in place, since 24/7 human monitoring requires a log
  source to watch in the first place, and stacking this control's full
  benefit on top of an assumed absence of any detection capability would
  double-count Control 3's own contribution
ALE Reduction: The honest, conservative case for incremental benefit is
  narrow. Once Control 3 exists, the specific advantage of round-the-
  clock human coverage over business-hours review of the same alerts is
  real but modest for MedDefense's actual risk profile: most of the
  value of detection comes from having any capability at all (which
  Control 3 already provides), and MedDefense's own proven historical
  incident (the cryptominer) was caused by zero detection, not
  insufficiently fast detection. The genuine incremental case is
  strongest specifically for a fast-unfolding, after-hours ransomware
  deployment, a real but narrow slice of the overall risk. Estimated
  incremental reduction: $80,000.
Net Value: $80,000 - $120,000 = -$40,000
Verdict: Not Justified
Recommendation: Defer. The incremental detection value beyond an
  in-house SIEM does not cover this control's cost, and the $120,000
  annual fee alone would consume MedDefense's entire security budget,
  leaving nothing for any of the other seven controls evaluated here.
  This should be revisited only after Controls 1 through 6 are funded
  and the security program has matured enough for genuinely full-time
  monitoring to add value beyond what an internal analyst reviewing a
  properly-tuned SIEM already provides.
```

---

## Control 8: Full Medical Device Network Isolation with Dedicated Monitoring

yaml

```yaml
Control 8: Full medical device network isolation with dedicated
  monitoring, covering the BD Alaris pumps, the Philips monitors, and
  the MRI workstation together
CIS Control Reference: 12 (Network Infrastructure Management), extended
  to medical devices specifically
Annual Cost: $18,000 (infrastructure: dedicated VLAN buildout across all
  device classes; monitoring integration: connecting this segment to
  Control 3's SIEM or an equivalent device-specific monitoring layer;
  ongoing management: a more comprehensive, ongoing commitment than Task
  6's narrower, BD-Alaris-only control)
Risk(s) Addressed: Risk 5 (Medical device patient safety incident), Task
  6, plus the MRI (Finding 004) and Philips monitors (Finding 016), which
  Task 6's narrower control did not cover
ALE Reduction: For the BD Alaris component specifically, where a
  quantified baseline exists, this control achieves at least the same
  reduction as Task 6's narrower control: $70,000 - $17,000 = $53,000.
  The additional protection this broader control extends to the MRI and
  Philips monitors is real, both are Critical or patient-safety-relevant
  assets already established elsewhere in this program, but is not
  separately quantified here, since no dedicated ALE calculation for
  those two asset classes exists yet in this project's work. Stated
  directly: the true net value of this control is very likely higher
  than the figure below, but this document does not claim a number it
  cannot support with a calculation.
Net Value: $53,000 - $18,000 = $35,000 (quantified portion only)
Verdict: Marginal
Recommendation: Defer pending a dedicated ALE calculation for the MRI
  and Philips monitor components specifically. In the meantime, Task 6's
  narrower, cheaper BD-Alaris-specific control ($3,200/year) captures
  most of the quantifiable benefit calculated here at a fraction of this
  control's cost, and is the more defensible near-term choice until the
  broader claim can be supported with numbers.
```

---

## Cost-Benefit Summary Table

|Rank|Control|Annual Cost|ALE Reduction|Net Value|Verdict|
|---|---|---|---|---|---|
|1|Network Segmentation|$40,000|$1,861,860|$1,821,860|Justified|
|2|MFA Deployment|$2,000|$1,432,200|$1,430,200|Justified|
|3|Enterprise SIEM (Wazuh)|$25,000|$1,343,848|$1,318,848|Justified|
|4|EDR Upgrade (Intercept X)|$23,000|$925,540|$902,540|Justified|
|5|Westside Dedicated Firewall|$1,800|$360,000|$358,200|Justified|
|6|Offsite Backup Replication|$4,000|$245,250|$241,250|Justified|
|7|Full Medical Device Isolation|$18,000|$53,000 (quantified)|$35,000|Marginal|
|8|24/7 SOC Staffing|$120,000|$80,000|-$40,000|Not Justified|

**Which controls fit within the $120,000 annual budget:** Controls 1 through 6, plus Control 8, total **$113,800** in combined annual cost, leaving **$6,200** of headroom within the stated budget, and every one of those seven controls independently clears its own cost-benefit bar. Control 7 is excluded on both grounds simultaneously: its net value is negative on the math alone, and its $120,000 cost would, by itself, consume the entire annual security budget this program has to work with, leaving nothing for the six controls that together deliver over $6 million in combined ALE reduction for a fraction of that cost.

**A reconciliation note that must not be skipped over:** several of these eight controls overlap directly with remediation items already costed in Project 1x02's own remediation plan (Task 20), Control 1's segmentation work and Control 6's Westside firewall in particular. The $113,800 figure above should not be read as entirely new spending stacked on top of 1x02's already-committed $71,000 remediation budget; the true incremental new spend, once double-counted items are reconciled against that prior commitment, is smaller than the face value shown here. That full reconciliation against MedDefense's single, real $120,000 annual figure is the explicit task of this project's consolidated budget and roadmap work that follows.
