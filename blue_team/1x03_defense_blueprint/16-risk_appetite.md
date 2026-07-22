# MedDefense Health Systems: The Risk Appetite Debate

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO, and the Board of Directors **Source material:** The Risk Register (Task 10), Cost-Benefit Analysis (Task 7), and Red Team exercise (Task 15) **Purpose:** Not every risk is worth mitigating, and accepting one is not negligence when it is a documented, authorized, monitored decision rather than an oversight. This document defines what level of risk MedDefense's Board is willing to live with, and demonstrates that governance discipline directly against three real entries in the Risk Register.

---

## Part 1: Risk Appetite Statement

MedDefense Health Systems accepts a moderate level of residual operational and financial risk in service of delivering patient care within realistic budget and staffing constraints, but treats any risk carrying a credible, direct path to patient harm as an absolute limit that must always be mitigated or compensated, never simply accepted regardless of cost. Financial risks with an Annualized Loss Expectancy under $50,000 may be accepted at the Deputy CISO's discretion, provided a documented compensating measure and review trigger accompany the decision. Risks with an ALE between $50,000 and $500,000, or any risk touching regulated patient data directly, require the CEO's approval before acceptance. Any risk exceeding $500,000 in ALE, or carrying any plausible patient-safety dimension however small, requires a formal, documented Board-level decision, recorded in the Risk Register and reviewed at minimum annually or immediately upon any material change in circumstance.

---

## Part 2: The Three Decisions

vbnet

```vbnet
Risk: RISK-006 (MRI workstation, WS-RAD-01, unpatchable EOL exposure)
Treatment Decision: Accept (the residual, permanent end-of-life
  condition specifically; the exposure itself has already been
  mitigated as far as currently possible)
Authority: CEO, Dr. Morales. This risk carries a direct patient-safety
  dimension and exceeds the $500,000 ALE threshold this program's own
  appetite statement sets for CEO-level review, and the underlying
  constraint, an active $2.1 million scanner lease with 18 months
  remaining, is itself a Board-level financial commitment that only
  the CEO has standing to weigh against a security recommendation.
Justification: Full mitigation, replacing the device, is contractually
  and financially impossible until the lease expires; early termination
  would cost far more than the risk itself. The compensating
  segmentation control already funded in this program's budget (Task 8)
  reduces practical exposure to a level the Board can reasonably
  tolerate for a defined, bounded period, though not to zero, a
  limitation this program's own Red Team exercise (Task 15) already
  documented honestly rather than overstated.
Compensating Measure: The dedicated medical device VLAN already
  designed in this program's Segmentation Architecture (Task 14),
  restricting WS-RAD-01's traffic to the PACS server only, combined with
  ongoing monitoring of new CISA KEV catalog additions affecting
  Windows XP-era vulnerabilities, the KRI already defined for this risk
  in the Risk Register (Task 10).
Review Trigger: Any new CISA KEV addition confirmed exploitable through
  the segmented PACS communication path specifically, not just a
  generic SMB or RDP flaw already accounted for; or the 18-month scanner
  lease decision point, whichever occurs first.
```

vbnet

```vbnet
Risk: RISK-005 (BD Alaris infusion pumps, patient-safety residual)
Treatment Decision: Accept (the residual risk remaining after credential
  and network-isolation controls are fully implemented)
Authority: CEO, Dr. Morales, with mandatory input from the relevant
  Department Head (Clinical/Biomedical Engineering) as the clinical Data
  Owner for this asset class, consistent with the governance roles
  already defined in this program (Task 4).
Justification: After the credential change (effectively $0 cost) and
  network isolation ($3,200, already funded) are complete, residual ALE
  drops from $70,000 to $17,000 per year (Task 6), well under this
  program's own $50,000 threshold for lower-level acceptance, but
  elevated to CEO review here specifically because of the patient-safety
  dimension involved. Further reduction requires a firmware update only
  BD, the vendor, can issue; no additional MedDefense spending can close
  this gap further, since the underlying authentication flaw sits
  outside MedDefense's own systems entirely.
Compensating Measure: Network isolation already limiting pump
  communication to clinical workstations and the PACS server only, plus
  quarterly vendor security advisory monitoring extended specifically to
  BD's own Product Security Trust Center, the same OSINT discipline this
  program's Task 9 already demonstrated is necessary for exactly this
  category of vendor-dependent risk.
Review Trigger: BD issues a firmware update addressing the underlying
  authentication vulnerability directly, or any confirmed exploitation
  attempt is detected against the pump fleet.
```

vbnet

```vbnet
Risk: RISK-002 (EHR database, residual exposure after mitigation)
Treatment Decision: Accept (the residual ALE remaining after the funded
  control, not a decision to forgo mitigation)
Authority: CEO, Dr. Morales, since the residual ALE of $816,750 exceeds
  this program's own $500,000 threshold for Board-level review, even
  though the mitigation itself was already approved and funded.
Justification: The implemented control, restricting database access to
  ehr-srv-01 specifically, reduced this risk's ALE by $3,266,500 for a
  $500 cost, the single highest return on investment identified anywhere
  in this program (Task 7). The remaining $816,750 in residual exposure
  reflects a scenario requiring a second, independent compromise, an
  attacker who has already breached ehr-srv-01 itself, not merely
  reached the network, a materially harder precondition than the
  original, now-closed exposure. Closing this further would require
  application-layer changes to the EHR software itself, outside this
  program's current scope and budget.
Compensating Measure: SIEM monitoring on ehr-srv-01 and ehr-db-01
  specifically (funded, Task 8), tuned to detect the credential-theft-
  and-reuse pattern this residual risk depends on.
Review Trigger: The SIEM detects any anomalous query pattern originating
  from ehr-srv-01 against ehr-db-01, or a future budget cycle makes
  application-layer EHR hardening newly affordable.
```

---

## Part 3: The Debate

**James Chen's argument for mitigation:** The MRI workstation carries three independently weaponized, CISA KEV-listed vulnerabilities capable of full system compromise, and one of them was added to the federal government's active-exploitation list only weeks before this assessment, a signal of renewed real-world targeting interest in exactly this class of device. A compromise here is not a data breach in the abstract; it is a direct patient-safety incident, since falsified imaging data during an active scan could go undetected by clinical staff who have no reason to distrust it. The $2.1 million lease is a genuine financial constraint, but MedDefense already funded the compensating segmentation control this year; treating that as the finish line rather than an interim measure, for another full 18 months, understates how much is still riding on a device this exposed.

**Robert Kim's argument for acceptance:** The compensating segmentation control is already funded and implemented, meaningfully reducing this risk without requiring the far larger cost of an early lease termination that full mitigation would demand. Spending additional security budget to further harden a device with a fixed, known 18-month remaining lifespan, when that budget is already committed against six other funded priorities this year, is not a rational allocation of limited resources. The math simply does not support incremental spend on an asset already scheduled for replacement on a defined timeline.

**My verdict:** Both arguments have real merit, and neither should simply prevail by force of conviction rather than evidence. Robert is right that terminating the lease early was never actually the rational choice on the table, no one proposed it, and his cost logic on that specific question is sound. But James is right that this program's own Red Team exercise (Task 15) already proved the funded segmentation control does not fully close this risk, since the underlying device remains exploitable by anyone already positioned within its shared VLAN, meaning "we already funded segmentation" is not the same claim as "this risk is adequately mitigated." The correct resolution is neither side simply winning the argument, but converting this disagreement into exactly the kind of documented governance decision Part 2 above already recorded: a formal, CEO-approved acceptance of the specific residual risk, with a named compensating measure and a review trigger that would force this decision to be revisited the moment new evidence, a new KEV addition on this exact exploitation path, makes it insufficient.
