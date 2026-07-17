# MedDefense Health Systems: The 3 Scenarios

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO (for Board presentation) **Source material:** Integrates every prior task of this project — Threat Actor Taxonomy (T1), BlackReef Dossier (T2), The Insider File (T3), The Human Vector (T4), The Supply Chain Question (T5), Threat Actor Matrix (T6), Attack Surface Map (T7), Technical Vectors (T8), Vector-to-Asset Matrix (T9), Kill Chains (T10), STRIDE on the EHR (T11) and Across the Architecture (T12), and the ATT&CK Mapping (T13) alongside the full Project 0x00 posture assessment **Purpose:** 3 complete, board-ready threat scenarios, each involving a different actor type and primary vector, demonstrating exactly what could happen to MedDefense if the documented gaps remain open.

---

## Scenario 1: External - The Ransomware Campaign

```
Title: Operation Flatline — A Double-Extortion Ransomware Campaign
Threat Actor: Organized Crime / Ransomware-as-a-Service, BlackReef
  profile (T2/T6) — MedDefense's #1 priority threat
Motivation: Financial gain (double extortion — ransom demand plus data
  leak threat)
Initial Vector: VPN Exploit — the single most versatile vector in this
  project's Vector-to-Asset Matrix (T9), reaching all 7 mapped Critical
  assets
Attack Surface Exploited: External (T7) — the FortiGate's VPN endpoint

Attack Sequence:
  Step 1: An affiliate purchases a target list including MedDefense from
    an Initial Access Broker, compiled via internet-wide scanning for
    exposed FortiGate management interfaces. (Resource Development)
  Step 2: A spear phishing email impersonating Fortinet support reaches
    Sarah Park (IT Director); she opens a malicious document whose macro
    delivers a reverse shell. (Initial Access → Execution)
  Step 3: A scheduled task disguised as Windows Update re-establishes C2
    connectivity every 30 minutes. (Persistence)
  Step 4: Discovery commands from the compromised HQ workstation map the
    entire 10.10.0.0/16 range via the flat, unsegmented network.
    (Discovery)
  Step 5: Mimikatz dumps cached credentials, revealing a domain admin
    service account's NTLM hash from a prior troubleshooting session.
    (Credential Access)
  Step 6: A pass-the-hash attack authenticates directly to ad-dc-01,
    granting Domain Admin. (Lateral Movement)
  Step 7: ehr-db-01 (35GB) and file-srv-01 (8GB) are exfiltrated via
    Rclone to attacker-controlled cloud storage, with no alerts
    generated. (Collection → Exfiltration)
  Step 8: NAS-01's backup jobs and stored backups are deleted, and
    Volume Shadow Copies are wiped on all Windows systems. (Impact)
  Step 9: A malicious Group Policy Object deploys ransomware to every
    domain-joined Windows system; Linux servers are separately encrypted
    via SSH using credentials found in a plaintext config file.
    (Impact)

STRIDE Categories Triggered: EHR-T1 (direct database tampering via the
  exposed PostgreSQL port), EHR-D1 (ransomware-driven denial of service
  on the EHR), EHR-I1 (mass PHI exfiltration via the same database
  exposure) — all from T11; and, from the Active Directory table in T12,
  the Elevation of Privilege threat (credential harvesting to Domain
  Admin) and the Tampering threat (malicious GPO deployment).
MedDefense Assets Impacted: EHR System (ehr-srv-01/ehr-db-01), Primary
  Domain Controller (ad-dc-01), Backup Infrastructure (NAS-01),
  billing-srv-01, file-srv-01, and the general Windows workstation
  population.
Business Impact:
  - Clinical: Complete EHR unavailability forcing paper-based
    operations organization-wide, with realistic potential for
    ambulance diversion, mirroring the 11-day outage documented in the
    comparable real-world case reviewed in T2.
  - Financial: A ransom demand in BlackReef's documented $1–3M range,
    plus recovery costs historically averaging $2.7M separately from
    the ransom itself (T0).
  - Regulatory: Mandatory HIPAA breach notification for 43GB of
    exfiltrated patient and financial data.
  - Reputational: Public disclosure via BlackReef's data leak site if
    payment is refused, with the real-world precedent (T2) of a
    resulting CEO resignation at a comparably profiled hospital.
Gaps Exploited: GAP-016 (no perimeter patch management enabled Step 2's
  entry point), GAP-017 (no MFA made the harvested hash in Step 5 and
  every subsequent authenticated step sufficient on their own),
  GAP-014 (the flat network enabled Steps 4, 6, and 9's unrestricted
  reach), GAP-003 (ehr-db-01's network-wide exposure enabled Step 7's
  direct database access), GAP-004 (no detection allowed Steps 3–7 to
  proceed for days unnoticed), GAP-006 (NAS-01's co-location made
  Step 8's backup neutralization possible).
Detection Opportunities: Step 2 — an email security gateway with
  lookalike-domain detection could block the phishing email before
  delivery; Step 3 — server/endpoint EDR would flag the disguised
  scheduled task immediately; Step 4–5 — centralized log correlation
  (a SIEM) would surface discovery commands and LSASS access within
  hours; Step 6 — network segmentation alone would prevent this lateral
  movement even if Steps 1–5 succeeded undetected; Step 7 — a DLP
  control would flag a 43GB outbound transfer regardless of whether the
  intrusion itself was detected.
```

---

## Scenario 2: Internal - The Departed Administrator

```
Title: The Departed Administrator — Insider Data Theft and Backup
  Sabotage
Threat Actor: Malicious insider, modeled on the "Ghost Account" profile
  from T3 (Scenario 2) — a database administrator retaining access
  after termination
Motivation: Revenge (primary — triggered by the termination itself,
  mirroring the real-world pattern in T1's Report D) combined with
  financial gain (secondary — the stolen data is sold)
Initial Vector: Legitimate access abused — no exploitation is required
  at any point in this scenario; every step uses access this individual
  was, at some point, properly and legitimately granted
Attack Surface Exploited: Human/Internal (T7) — specifically the IT
  staff row of the Human Surface map, where elevated privileges combine
  with a small team's account-lifecycle gaps

Attack Sequence:
  Step 1: The administrator learns of an upcoming termination and, over
    the following two weeks, reviews the scope of their own standing
    access — including backup-administration rights on NAS-01 and
    domain credentials with broad EHR/billing reach. (Reconnaissance,
    internal — mapped loosely to Valid Accounts, T1078, as this
    represents assessment of pre-existing access rather than a new
    technical intrusion)
  Step 2: During the notice period, the administrator exports a large
    volume of patient and billing records to a personal device, blended
    into otherwise-legitimate daily work activity. (Collection)
  Step 3: The manager submits an account-deactivation ticket on the
    administrator's last day; it sits unprocessed in the IT queue with
    no defined SLA. The administrator's VPN and AD credentials remain
    fully active. (Persistence — Valid Accounts: Domain Accounts,
    T1078.002)
  Step 4: Several days after departure, the administrator connects to
    the VPN from home using the still-active credentials. (Initial
    Access, re-entry via valid, un-revoked credentials)
  Step 5: Using standing backup-administrator rights, the administrator
    disables scheduled backup jobs and deletes several recent backup
    sets on NAS-01 — an act of deliberate sabotage rather than data
    theft. (Impact — Inhibit System Recovery, T1490)
  Step 6: The administrator disconnects and does not return; the
    previously exported records are later offered for sale. (Exfiltration
    — the data left the organization in Step 2, but its criminal
    monetization occurs here)

STRIDE Categories Triggered: EHR-R1 and EHR-R2 (Repudiation — no MFA and
  no proactive log review mean the administrator's actions, both the
  data export and the backup sabotage, are difficult to attribute or
  even discover in a timely manner) and EHR-I1 (Information Disclosure
  — the exported patient/billing data), all from T11.
MedDefense Assets Impacted: EHR System and billing data (via Step 2's
  export), Backup Infrastructure/NAS-01 (via Step 5's sabotage), and
  System Credentials broadly (the retained account itself).
Business Impact:
  - Financial: Direct cost of the stolen data's eventual resale impact
    (identity theft, insurance fraud exposure for affected patients),
    plus the cost of rebuilding backup capability after deliberate
    deletion.
  - Regulatory: Mandatory breach notification for the exfiltrated
    records, compounded by the difficulty of even determining the
    scope of what was taken, given the absence of proactive log review.
  - Reputational: Lower public visibility than a ransomware event, but
    real internal trust damage and a demonstrated pattern (this is the
    second Ghost Account-pattern incident referenced across this
    project) that could surface in a regulatory investigation as
    evidence of a systemic, uncorrected gap.
  - Clinical: Minimal direct impact from data theft alone, but the
    backup sabotage in Step 5 removes MedDefense's recovery capability
    for any *other* incident that might follow — a compounding risk.
Gaps Exploited: GAP-018 (no automated deprovisioning tied to
  termination — the central enabler of Steps 3–5), GAP-009 (no
  periodic access review that might have caught the retained account
  before Step 4), GAP-019 (no DLP to flag Step 2's export volume),
  GAP-006 (NAS-01's design allows Step 5's sabotage to succeed
  completely, with no immutable or offline copy to fall back on).
Detection Opportunities: Step 2 — a DLP control monitoring export
  volume and destination would flag this activity in real time,
  independent of employment status; Step 3 — automated, HR-triggered
  deprovisioning closes this step entirely, preventing Steps 4–6 from
  being possible at all; Step 4 — even without full deprovisioning, an
  alert on VPN authentication from an account flagged as terminated in
  HR's system would catch this before further damage; Step 5 — an
  immutable or offline backup copy would mean this sabotage step fails
  to achieve its objective even if it is not detected in advance.
```

---

## Scenario 3: Third Party - The Trusted Vendor Path

```
Title: The Trusted Vendor Path — A Supply Chain Compromise via MedTech
  Solutions
Threat Actor: An external, financially motivated actor using a
  compromised vendor as a stepping stone (T5) — not a MedDefense-facing
  intrusion at any point until the final steps
Motivation: Financial gain (data theft for resale), consistent with the
  same underground market dynamics described throughout T0 and T2
Initial Vector: Vendor access pathway — MedTech Solutions' standing,
  SLA-driven remote maintenance access to the EHR (T5)
Attack Surface Exploited: Human surface (T7) — specifically the
  External Contractors row — transitioning into the Internal technical
  surface once the vendor's own access is abused

Attack Sequence:
  Step 1: The attacker identifies MedTech Solutions as a healthcare EHR
    maintenance vendor with standing client remote-access relationships,
    through public case studies, breach forums, or reconnaissance of
    MedTech's own environment. (Reconnaissance)
  Step 2: A MedTech Solutions employee is compromised — via phishing or
    a vulnerability in MedTech's own remote-access tooling — entirely
    within MedTech's environment, outside anything MedDefense directly
    controls or can observe. (Initial Access, external to MedDefense)
  Step 3: Within MedTech's compromised environment, the attacker locates
    stored client remote-access credentials or VPN configuration
    specific to MedDefense. (Discovery, within the vendor's environment)
  Step 4: The attacker uses this legitimate, pre-authorized channel to
    authenticate directly to ehr-srv-01, exactly as a genuine MedTech
    maintenance session would. (Initial Access into MedDefense — Valid
    Accounts, T1078)
  Step 5: From ehr-srv-01, the attacker discovers that ehr-db-01 is
    reachable directly, given its network-wide PostgreSQL exposure, and
    that the wider flat network offers further reach beyond the EHR
    alone. (Discovery)
  Step 6: The attacker queries ehr-db-01 directly for patient records,
    bypassing the EHR application's own access controls entirely.
    (Collection)
  Step 7: Data is extracted through the same vendor remote-access
    channel used for entry, blending with what would appear, to any
    logging in place, as routine maintenance traffic. (Exfiltration)
  Step 8: No anomaly is flagged at any point, since every action in
    Steps 4–7 used access that is, on paper, entirely legitimate and
    expected. (Defense Evasion — by omission, rather than active evasion
    technique)

STRIDE Categories Triggered: EHR-S2 (Spoofing — the database has no way
  to distinguish a legitimate application-tier query from this vendor-
  channel-originated one, since both present as trusted, credentialed
  access) and EHR-I1 (Information Disclosure via the same network-wide
  database exposure exploited in Scenario 1), both from T11; EHR-T1
  (Tampering) remains a secondary, plausible extension of this scenario
  if the attacker chooses to alter rather than only read records.
MedDefense Assets Impacted: EHR System (ehr-srv-01/ehr-db-01) — this
  scenario's blast radius is narrower than Scenarios 1 and 2 by design,
  since it does not depend on the flat network reaching beyond the
  EHR's own immediate environment, though it could extend further given
  GAP-014.
Business Impact:
  - Regulatory: Mass PHI exposure requiring the same mandatory breach
    notification as Scenario 1, but with a materially longer expected
    time-to-detection given the access appears entirely legitimate.
  - Reputational: Arguably more damaging on disclosure than a
    ransomware event specifically because it reveals MedDefense had no
    visibility into what one of its own trusted vendors could do —
    a harder story to explain to the Board or the public than "we were
    hacked."
  - Financial: Breach response costs, plus a likely contractual/
    liability dispute with MedTech Solutions over where responsibility
    for the compromise actually sits.
  - Clinical: Minimal direct impact from data-only exfiltration, though
    the secondary Tampering possibility (T11's EHR-T1) would introduce
    the same patient-safety risk documented in Scenario 1 and Task 11.
Gaps Exploited: No dedicated vendor-access segmentation exists (a T5
  finding not yet assigned its own 0x00 Gap ID, recommended for formal
  addition), GAP-017 (no confirmed MFA requirement on vendor remote
  access enabled Step 4 to succeed with credentials alone), GAP-003 (the
  database exposure enabled Step 6's direct query), GAP-014 (the flat
  network gives this access more potential reach than the vendor's
  contracted scope should allow), GAP-009 (no periodic vendor access
  review means this pattern could continue indefinitely without
  detection).
Detection Opportunities: Step 2 is genuinely outside MedDefense's
  detection capability — this is an honest limitation, not a gap to
  close, since it occurs entirely within the vendor's own environment;
  Step 4 — a dedicated vendor jump-host requiring MFA and full session
  logging (the single control recommended in this project's Supply
  Chain Question, T5) would either block this step outright or generate
  a detailed, reviewable log of it; Step 6 — restricting ehr-db-01's
  access to ehr-srv-01 only would prevent this specific pivot even if
  Step 4 succeeds; Step 7 — a periodic review comparing actual vendor
  access patterns against MedTech's contracted SLA and maintenance
  schedule would eventually surface a session inconsistent with routine
  maintenance, even after the fact.
```

---

## Cross-Scenario Observation

These 3 scenarios were deliberately built around 3 different actors, 3 different initial vectors, and 3 different attack surfaces. Yet all 3 ultimately reach the same asset (the EHR System, via ehr-db-01's network-wide database exposure) and all 3 depend, at some step, on the same 2 structural gaps: **GAP-014 (no network segmentation) and GAP-004 (no centralized detection)**. This is not a coincidence of scenario design; it is the same finding this project has now reached independently through the Threat Actor Matrix (T6), the Attack Surface Map (T7), the Vector-to-Asset Matrix (T9), and the Kill Chains (T10) regardless of who attacks MedDefense or how they get in, these 2 gaps determine whether the resulting incident stays small or becomes the kind of event that reaches the Board.
