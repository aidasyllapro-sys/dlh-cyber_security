# MedDefense Health Systems: The Kill Chains

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** Vector-to-Asset Matrix (Task 9), Threat Actor Matrix (Task 6), BlackReef Ransomware Dossier (Task 2), The Insider File (Task 3), The Human Vector (Task 4), The Supply Chain Question (Task 5), and the full Project 0x00 posture assessment **Purpose:** Construct complete, operational attack sequences, from initial access to final impact, for the 5 most critical threat paths identified in this project, with explicit intervention points where each chain could have been broken.

**Selection rationale:** these 5 chains were chosen to represent the Top 3 priority actors from Task 6 (Ransomware, Unskilled/Opportunistic, Insider Negligent) plus 2 additional high-value, structurally distinct paths (Business Email Compromise and Supply Chain Compromise) that target different assets and objectives than the first 3. Together, they cover 4 of the 6 actor types profiled in this project and 5 of the 8 vectors mapped in Task 9.

---

yaml

```yaml
Kill Chain #1: The Backup-First Ransomware Chain
Threat Actor: Organized Crime / Ransomware-as-a-Service, BlackReef profile
  (T2/T6) — Critical likelihood, Medium-High capability
Target Asset: EHR System (ehr-srv-01/ehr-db-01) AND Backup Infrastructure
  (NAS-01) — a dual target by design, per BlackReef's own documented
  playbook
Expected Impact: Multi-day clinical outage forcing paper-based
  operations, patient data exposure via double extortion, and ransom
  payment pressure driven by the simultaneous loss of both production
  and recovery capability

Step 1 - Initial Access:
  Vector: VPN Exploit
  Surface: External
  Detail: An affiliate purchases or independently discovers an unpatched
    vulnerability in the FortiGate's firmware (patch status unconfirmed
    anywhere in this project) and exploits it to gain internal network
    access — BlackReef's own case studies show this exact vector as
    their most common healthcare entry method.

Step 2 - Establish Foothold:
  Action: Deploy a remote access tool and begin reconnaissance — mapping
    Active Directory, identifying the domain controllers, and
    specifically locating backup infrastructure, per BlackReef's
    explicit playbook instruction to neutralize backups first.
  MedDefense Weakness: No centralized detection exists (GAP-004), so
    discovery tooling and reconnaissance commands generate no alert and
    go unnoticed for the multi-day window BlackReef's own case studies
    show is typically available.

Step 3 - Lateral Movement / Escalation:
  Action: Harvest credentials from memory, escalate to Domain Admin, and
    move from the initial foothold to ad-dc-01, then to NAS-01 and
    ehr-db-01.
  MedDefense Weakness: The flat network (GAP-014) provides unrestricted
    reach once inside; PostgreSQL on ehr-db-01 is exposed network-wide
    rather than restricted to ehr-srv-01 (GAP-003); and the absence of
    MFA (GAP-017) means any harvested credential works everywhere it is
    tried.

Step 4 - Objective Execution:
  Action: Exfiltrate 15–50GB of patient and financial data via an
    encrypted channel, then deploy ransomware via Group Policy from the
    compromised domain controller to all reachable systems simultaneously.
  Data/System Affected: ehr-db-01 (complete patient record database),
    NAS-01 (the backup encrypted alongside production), billing-srv-01,
    and the general workstation population.

Step 5 - Impact:
  Business Impact: Clinical — EHR unavailable, paper-based operations,
    possible ambulance diversion; Financial — a ransom demand in the
    $1–3M range per BlackReef's documented pattern, plus recovery costs;
    Regulatory — mandatory HIPAA breach notification for the exfiltrated
    PHI; Reputational — public disclosure via BlackReef's leak site if
    payment is refused.
  CIA Pillars: Availability (EHR and backup both encrypted
    simultaneously), Confidentiality (data exfiltrated before
    encryption), Integrity (every encrypted file is, by definition,
    modified without authorization).

Gaps Exploited: GAP-016, GAP-004, GAP-014, GAP-003, GAP-017, GAP-006
Break Points:
  - Step 1: Closing GAP-016 (a defined patch SLA for the FortiGate) would
    prevent this specific initial access method entirely.
  - Step 2: Closing GAP-004 (centralized detection/alerting) would
    surface the reconnaissance activity within hours rather than days,
    interrupting the chain before lateral movement even begins.
  - Step 3: Closing GAP-014 (network segmentation) would mean that even
    a successful Step 1–2 compromise could not reach the domain
    controller, the backup, or the EHR database from the initial
    foothold.
  - Step 4: Closing GAP-006 (offsite/immutable backup replication) would
    mean a successful encryption event no longer forces a payment
    decision, since recovery would remain possible independent of the
    compromised production environment.
```

yaml

```yaml
Kill Chain #2: The Accidental Foothold That Could Have Escalated
Threat Actor: Unskilled/Opportunistic Attacker (T1/T6) — Critical
  likelihood (already proven), Low individual capability but automated
  at scale
Target Asset: Primary Domain Controller (ad-dc-01) / Active Directory —
  this chain reframes MedDefense's real cryptominer incident to show
  what the same access could have escalated into, had the attacker's
  objective been domain compromise rather than mining
Expected Impact: Domain-wide authentication compromise reachable from an
  entry point that required zero targeting or skill

Step 1 - Initial Access:
  Vector: Vulnerable Software Exploit
  Surface: External (per Task 7's flagged finding that billing-srv-01's
    Apache service was very likely internet-reachable at the time of
    compromise, contrary to the assumed DMZ-only exposure model)
  Detail: An automated, internet-wide scanner finds and exploits the
    known Apache 2.4.29 remote code execution vulnerability on
    billing-srv-01 — no targeting of MedDefense specifically was involved.

Step 2 - Establish Foothold:
  Action: Drop a disguised persistence mechanism (the process later
    found renamed to resemble a kernel worker) and begin consuming
    server resources.
  MedDefense Weakness: No antivirus or EDR exists on any server (GAP-005),
    so the malicious binary runs indefinitely with no automated barrier
    to its persistence.

Step 3 - Lateral Movement / Escalation:
  Action: (Escalated scenario beyond what was actually observed) Using
    the www-data-level foothold, an attacker pursues local privilege
    escalation, then uses the server subnet's own lack of internal
    boundaries to reach ad-dc-01 directly.
  MedDefense Weakness: The flat network (GAP-014) provides no separation
    even *within* the servers subnet between billing-srv-01 and the
    domain controllers, and the absence of a change/remediation process
    (GAP-025) means the underlying vulnerability was never fixed even
    after the miner itself was discovered — the sysadmin's diagnosis
    treated it as a hardware capacity issue, not a compromise (0x00,
    Task 2).

Step 4 - Objective Execution:
  Action: Harvest credentials on billing-srv-01, move laterally to
    ad-dc-01, and establish a persistent, privileged domain account.
  Data/System Affected: ad-dc-01, and by extension the entire Active
    Directory trust domain.

Step 5 - Impact:
  Business Impact: An access level equivalent to a full ransomware
    precursor, achieved from what began as a zero-effort, non-targeted
    compromise — and per BlackReef's own documented economy (T2),
    exactly this kind of low-skill foothold is what Initial Access
    Brokers buy cheaply and resell to a more capable, higher-impact
    affiliate.
  CIA Pillars: Integrity (unauthorized privileged account creation),
    Confidentiality (domain-wide credential exposure), Availability
    (a foothold this deep enables later disruption at the attacker's
    discretion).

Gaps Exploited: GAP-016, GAP-005, GAP-014, GAP-025, GAP-004
Break Points:
  - Step 1: Closing GAP-016 (patch management, or a web application
    firewall) prevents the RCE exploitation entirely.
  - Step 2: Closing GAP-005 (server-class EDR) would flag or block the
    disguised mining/persistence process immediately rather than letting
    it run for weeks.
  - Step 3: Segmenting even within the servers subnet (isolating
    billing-srv-01 from the identity infrastructure) would prevent this
    specific escalation path independent of Steps 1–2.
  - Step 4: MFA/privileged access controls on Active Directory (GAP-017)
    raise the bar meaningfully even if lateral movement succeeds.
```

yaml

```yaml
Kill Chain #3: The Shadow IT Pivot
Threat Actor: Two-stage chain — Insider (Negligent) creates the exposure
  (T3), then an Unskilled/Opportunistic external actor discovers and
  exploits it (T1/T6)
Target Asset: EHR System and Primary Domain Controller, reachable via
  UNKNOWN-01's documented network position
Expected Impact: A long-duration, unattributable foothold directly
  adjacent to the organization's most sensitive systems

Step 1 - Initial Access:
  Vector: Shadow IT
  Surface: Internal (introduced from within, not an external breach)
  Detail: A former IT intern, at the prior security analyst's request,
    connects an unauthorized personal device (a Raspberry Pi intended as
    a network monitor) to the Central network. Neither the requester nor
    the builder remains at the organization, and the device was never
    formally decommissioned or secured (0x00, Task 11).

Step 2 - Establish Foothold:
  Action: An external actor discovers this abandoned, unmaintained
    device — plausibly the host identified only as UNKNOWN-01 in the
    Project 0x00 network scan — running outdated software with no
    confirmed credential hygiene.
  MedDefense Weakness: No asset-discovery or inventory review process
    ever flagged this device after its creators left (GAP-010); it sat
    unmonitored on the network for months at minimum.

Step 3 - Lateral Movement / Escalation:
  Action: The attacker pivots from the compromised device to nearby
    systems on the same subnet.
  MedDefense Weakness: The flat network (GAP-014) means UNKNOWN-01's
    position on the Central servers subnet (10.10.2.0/24) — the same
    subnet as ad-dc-01 and ehr-db-01 — grants direct reachability to
    both from this single compromised device.

Step 4 - Objective Execution:
  Action: Credential harvesting or direct database access against
    ehr-db-01 via its network-wide-exposed PostgreSQL service (GAP-003),
    or targeting ad-dc-01 for broader domain compromise.
  Data/System Affected: ehr-db-01 patient records, or ad-dc-01 domain
    trust, depending on which path the attacker pursues.

Step 5 - Impact:
  Business Impact: This is potentially the hardest class of breach for
    MedDefense to detect and scope during incident response, precisely
    because the entry device has no documented owner, no baseline
    configuration, and no record of ever having been formally assessed —
    an investigation would have no starting reference point.
  CIA Pillars: Confidentiality (patient data exposure), Integrity
    (potential tampering with Active Directory).

Gaps Exploited: GAP-010, GAP-014, GAP-003, GAP-004
Break Points:
  - Step 1: A network access control policy (802.1X or equivalent)
    restricting connectivity to pre-registered devices only would have
    prevented the Pi from ever joining the network in the first place.
  - Step 2: Routine, scheduled asset-discovery scanning — performed
    regularly rather than as a one-time exercise — would catch a device
    like this within weeks rather than indefinitely.
  - Step 3: Closing GAP-014 would contain this device to an isolated
    segment regardless of its own security posture.
  - Step 4: Restricting ehr-db-01's database access to ehr-srv-01 only
    (closing GAP-003) prevents direct database reach even if the network
    path to it exists.
```

yaml

```yaml
Kill Chain #4: The Wire Transfer Chain
Threat Actor: Organized Crime (a financially motivated external actor
  specializing in Business Email Compromise, T1/T4/T6)
Target Asset: Financial/Billing data and organizational funds directly —
  not a system in the Asset Registry, but the "Financial/Billing &
  Insurance Claims Data" category from the 0x00 Data Map
Expected Impact: Direct, likely unrecoverable financial loss, entirely
  independent of any clinical or patient-data system

Step 1 - Initial Access:
  Vector: Business Email Compromise (executive impersonation)
  Surface: Human
  Detail: The attacker researches MedDefense's publicly available
    leadership structure (names, titles, org chart) and sends an email
    to the CFO that appears to come from the CEO, with a subtly altered
    sender address (T4, Scenario 2).

Step 2 - Establish Foothold:
  Action: No technical foothold is required — the "foothold" here is the
    trust established by the impersonation itself, reinforced by an
    explicit instruction to keep the request confidential and to
    communicate only by email.
  MedDefense Weakness: No email authentication enforcement (DMARC/SPF/
    DKIM) is confirmed anywhere in this project, and no administrative
    policy currently requires out-of-band verification for financial
    requests, regardless of urgency framing.

Step 3 - Lateral Movement / Escalation:
  Action: None required — this is a single-hop social engineering chain,
    not a technical one. The "escalation" is purely psychological:
    urgency and authority reinforcing each other to discourage
    verification.
  MedDefense Weakness: The absence of a mandatory dual-approval process
    for high-value wire transfers means a single email is sufficient to
    trigger the entire transaction.

Step 4 - Objective Execution:
  Action: The CFO processes the wire transfer exactly as instructed.
  Data/System Affected: MedDefense's bank account — $85,000 transferred
    to an attacker-controlled account.

Step 5 - Impact:
  Business Impact: Direct financial loss that is typically very
    difficult to recover once a wire transfer completes; no clinical or
    patient-data impact occurs, but real reputational and internal-trust
    damage follows once discovered.
  CIA Pillars: Integrity only — a fraudulent transaction was processed
    as though it were legitimate and properly authorized. Notably, this
    chain never touches Confidentiality or Availability at all, which is
    itself an important lesson: not every high-impact incident maps to a
    data breach.

Gaps Exploited: No confirmed email authentication/anti-spoofing control;
  no formal financial-transaction verification policy (identified in T4
  but not yet assigned its own 0x00 Gap ID — recommended for formal
  addition); GAP-012 (training does not cover BEC-specific red flags).
Break Points:
  - Step 1: DMARC/SPF/DKIM enforcement with lookalike-domain flagging
    would prevent the spoofed email from reaching the CFO's inbox at
    all, or at minimum visibly flag it as external/suspicious.
  - Step 2/3: A mandatory out-of-band verification policy (calling the
    CEO's previously known number, never a number supplied in the
    suspicious email) for any request above a defined dollar threshold
    breaks this chain regardless of how convincing the email itself is —
    this is the single highest-leverage break point in this entire
    document, because it requires no new technology, only a procedural
    rule consistently followed.
```

yaml

```yaml
Kill Chain #5: The Trusted Vendor Path
Threat Actor: Organized Crime or an actor who purchased compromised
  vendor access (T5/T6) — the specific category matters less here than
  the structural fact that the access itself is pre-authorized
Target Asset: EHR System, reached via MedTech Solutions' legitimate
  maintenance access (T5)
Expected Impact: High-privilege access to the complete patient record
  database without ever needing to breach MedDefense's own perimeter

Step 1 - Initial Access:
  Vector: Supply Chain Compromise
  Surface: External to MedDefense, but via an already-trusted, authorized
    channel
  Detail: MedTech Solutions' own environment — an employee credential, a
    compromised laptop, or a compromised remote-access tool used for
    their maintenance work — is breached independently of anything
    MedDefense directly controls.

Step 2 - Establish Foothold:
  Action: The attacker uses MedTech's legitimate, standing remote
    maintenance access to authenticate directly to ehr-srv-01.
  MedDefense Weakness: No dedicated vendor-access segmentation or
    jump-host exists (T5 finding), and vendor remote access is not
    confirmed to require MFA (GAP-017) — a compromised vendor credential
    alone is sufficient.

Step 3 - Lateral Movement / Escalation:
  Action: From ehr-srv-01, the attacker reaches ehr-db-01 directly, given
    its network-wide PostgreSQL exposure, and potentially pivots further
    across the flat network toward other Critical assets.
  MedDefense Weakness: GAP-003 (database exposure) and GAP-014 (flat
    network) mean the vendor's intended, narrow access scope (EHR
    application maintenance only) does not actually limit the attacker's
    real reach once inside.

Step 4 - Objective Execution:
  Action: Bulk export or manipulation of patient records directly from
    ehr-db-01, using access that appears entirely legitimate — a real
    vendor maintenance session — to whatever logging does exist.
  Data/System Affected: ehr-db-01, the complete patient record database.

Step 5 - Impact:
  Business Impact: This chain is particularly dangerous precisely because
    the access used is authorized and expected — a full-scale PHI breach
    could occur and initially be attributed to routine maintenance until
    forensic investigation proves otherwise, extending the time to
    detection well beyond a typical external intrusion.
  CIA Pillars: Confidentiality (mass PHI exposure) and, if records are
    altered rather than only read, Integrity as well.

Gaps Exploited: No vendor-specific access segmentation (T5 finding, not
  yet assigned its own 0x00 Gap ID — recommended for formal addition),
  GAP-017 (no confirmed MFA on vendor remote access), GAP-003, GAP-014,
  GAP-009 (no periodic vendor access review).
Break Points:
  - Step 2: A dedicated vendor jump-host/bastion requiring MFA and full
    session logging — the single control recommended in Task 5's Supply
    Chain Risk Summary — would contain MedTech's access to only what is
    contractually necessary and log every action for detection.
  - Step 3: Restricting ehr-db-01's access to ehr-srv-01 only (closing
    GAP-003) would prevent the pivot from application-server-level
    vendor access to the raw database, even without Step 2's control.
  - Step 4: A periodic vendor access review (GAP-009) would eventually
    catch an access pattern inconsistent with MedTech's actual
    maintenance schedule and SLA, even after the fact.
```

---

## Cross-Chain Observation

Across all 5 kill chains, the flat network (GAP-014) appears as a Break Point candidate in 4 of 5. Every chain except the purely social-engineering-driven Wire Transfer Chain depends on lateral, unrestricted movement to convert an initial foothold into access to a Critical asset. This confirms, from a fifth independent angle in this project (after Tasks 6, 7, 8, and 9), that network segmentation is not one gap among many. It is the single control most likely to break the largest number of realistic attack sequences against MedDefense, regardless of which actor or vector initiates them.
