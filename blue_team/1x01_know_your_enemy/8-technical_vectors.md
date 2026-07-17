# MedDefense Health Systems: Technical Vector Assessment

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** Project 0x00 Network Scan Summary, Asset Registry, Control Matrix, and Gap Analysis; Threat Actor Matrix (Task 6 of this project) **Purpose:** Catalog MedDefense's non-human (technical) attack vectors per the Security+ 2.2 framework, using concrete evidence rather than generic vulnerability categories. This is what keeps an attacker "in the building" once any entry point (Task 7) is breached.

---

```
Vector Category: Vulnerable Software
MedDefense Evidence: Apache 2.4.29 running on billing-srv-01, with a
  known, publicly documented remote code execution vulnerability;
  Ubuntu 18.04 LTS on the same host, whose standard support ended June
  2023 with Extended Security Maintenance never activated (confirmed by
  the network scan). The FortiGate's own firmware patch status is
  separately unconfirmed anywhere in this project (GAP-016).
Affected Asset(s): billing-srv-01 directly, and — given the flat network
  — every other system reachable from it once compromised.
Actor Most Likely to Exploit: Unskilled/Opportunistic Attacker (T6) —
  this is not hypothetical; this exact vulnerability was already found
  and exploited by automated internet-wide scanning, resulting in the
  cryptominer discovered on billing-srv-01.
Exploitation Scenario: An automated scanner sweeping the internet for
  hosts running vulnerable Apache versions finds billing-srv-01 exposed
  (see Task 7's flagged contradiction regarding this host's external
  reachability), exploits the known RCE without any targeting or manual
  effort, and drops a payload — exactly the documented sequence of
  MedDefense's own prior incident.
Current Protection: None — C-009 (Sophos antivirus) explicitly excludes
  all servers, Windows and Linux alike.
Gap Reference: GAP-005 (no server-class antivirus/EDR), GAP-016 (no
  patch management process for internet-facing or critical services).
```

```
Vector Category: Unsupported Systems
MedDefense Evidence: WS-RAD-01, the MRI control workstation, running
  Windows XP SP3 — unpatched since 2014 for regulatory/certification
  reasons; print-srv-01 running Windows Server 2012 R2, end-of-life
  since October 2023.
Affected Asset(s): The MRI scanner and its control workstation
  (Critical-rated, Top 5 asset per 0x00 Task 8); print-srv-01 (Low-rated).
Actor Most Likely to Exploit: Ransomware Groups (T6) — BlackReef's own
  playbook (T2) actively seeks out exactly this kind of legacy,
  unpatchable system during its reconnaissance phase; Unskilled/
  Opportunistic Attacker for print-srv-01 specifically, given its lower
  value but equal technical exposure.
Exploitation Scenario: Once an attacker gains any internal foothold
  through another vector, WS-RAD-01 presents no technical defense
  whatsoever — no antivirus is possible on this OS, and the compensating
  controls designed for it in Project 0x00 (network segmentation, IDS/IPS
  at the segment boundary) remain unimplemented per the Complete Control
  Matrix. A compromise here directly threatens both the $2.1M asset
  itself and the ~45 daily imaging studies it supports.
Current Protection: None currently implemented — the four compensating
  controls proposed in 0x00 Task 6 (P-001 through P-004) remain
  unimplemented per the Task 10 Control Matrix.
Gap Reference: GAP-002 (MRI/WS-RAD-01, Critical), GAP-013 (print-srv-01,
  Low).
```

```
Vector Category: Open Service Ports
MedDefense Evidence: MySQL (port 3306) on billing-srv-01 and PostgreSQL
  (port 5432) on ehr-db-01, both confirmed reachable from the entire
  internal network rather than restricted to their respective
  application servers; RDP (port 3389) enabled on WS-RECEPT-01/02 and
  WS-ADMIN-01/02/03 at Central, and on ws-srv-01 at Westside, all
  confirmed by the network scan with no documented access restriction.
Affected Asset(s): billing-srv-01, ehr-db-01, reception and admin
  workstations, and Westside's file/scheduling server.
Actor Most Likely to Exploit: Ransomware Groups (T6) — BlackReef's own
  attack lifecycle (T2) names exposed RDP as one of three primary
  initial-access methods against healthcare (9% of incidents), and
  targets exposed database services directly during reconnaissance and
  lateral movement.
Exploitation Scenario: An attacker with any network foothold can
  connect directly to the patient-record or billing databases,
  bypassing the application layer (and any access controls built into
  the EHR or billing application) entirely; separately, exposed RDP on
  reception/admin machines offers a direct remote-access foothold that,
  absent MFA (GAP-017), is vulnerable to credential-stuffing or
  brute-force attempts using credentials obtained through any of the
  social engineering vectors in Task 4.
Current Protection: The perimeter firewall's default-deny policy (C-002)
  governs external traffic only — nothing in the Control Matrix
  restricts these ports at the internal network level.
Gap Reference: GAP-003 (EHR database network-wide exposure), GAP-014
  (flat network provides unrestricted reach to every exposed port from
  any point of compromise).
```

```
Vector Category: Default Credentials
MedDefense Evidence: The Radiology PACS workstation uses a shared,
  never-rotated login ("raduser/radiology1"). Whether MedDefense's
  medical IoT devices (Philips monitors, BD Alaris pumps) retain
  vendor-default credentials on their management interfaces is
  explicitly unconfirmed — flagged in Project 0x00's risk treatment plan
  (Task 14) as an immediate, near-zero-cost verification action, and
  directly modeled on a real-world comparable incident (Task 2's Report
  E research, where default admin/admin credentials on infusion pump
  interfaces were the exact mechanism that exposed patient dosage data).
Affected Asset(s): The PACS workstation; potentially the ~80 Philips
  monitors and ~120 BD Alaris pumps if the credential status is
  confirmed unchanged from vendor defaults.
Actor Most Likely to Exploit: Insider (Negligent or Malicious) for the
  PACS shared account, given its use requires only physical/network
  access already available to Radiology staff; Unskilled/Opportunistic
  Attacker for medical IoT default credentials, mirroring the
  documented real-world pattern precisely.
Exploitation Scenario: The shared PACS login means any misuse of
  imaging-data access cannot be attributed to a specific individual,
  removing accountability as a deterrent entirely; separately, if
  medical device interfaces retain default credentials, any actor who
  reaches that network segment (trivial given the flat network) can
  access device management consoles — including dosage-relevant
  configuration on infusion pumps — with zero technical skill required.
Current Protection: None.
Gap Reference: GAP-022 (PACS shared credentials), GAP-001 (medical IoT —
  the credential audit is the funded quick-win mitigation from 0x00
  Task 14, not yet confirmed complete).
```

```
Vector Category: Unsecure Networks
MedDefense Evidence: The entire internal network operates as a single
  flat broadcast domain (10.10.0.0/16) with no VLANs, empirically
  confirmed by the Project 0x00 network scan ("a device on any subnet
  can reach any other device on any other subnet"). Westside Clinic's
  sole network boundary is a consumer-grade router (Netgear Nighthawk)
  with no dedicated firewall. Central's guest WiFi network exists on a
  separate SSID, but whether it is actually isolated from the internal
  network was never verified — Marcus explicitly noted he was "not
  convinced" and never confirmed it either way.
Affected Asset(s): Every asset in the environment, by virtue of the flat
  architecture; Westside's entire local infrastructure specifically;
  potentially the internal network via the unverified guest WiFi.
Actor Most Likely to Exploit: Ransomware Groups (T6) — this is the
  single architectural condition that determines whether any successful
  intrusion (via any vector) stays contained or becomes an
  organization-wide encryption event, per BlackReef's own attack
  lifecycle (T2).
Exploitation Scenario: Once compromised anywhere — a phished workstation,
  a vulnerable server, a compromised vendor connection (Task 5) — an
  attacker moves laterally with no internal resistance to reach the EHR
  database, domain controllers, and medical devices; separately, if
  guest WiFi isolation has silently failed, a visitor or a device in the
  parking area could represent a direct, low-effort entry point that
  bypasses every other control on this list entirely.
Current Protection: None currently implemented — network segmentation
  Phase 1 is funded in the 0x00 risk treatment plan (Task 14) but not
  yet complete.
Gap Reference: GAP-014 (flat network), GAP-021 (Westside's consumer-grade
  edge equipment).
```

```
Vector Category: Removable Devices / Unmanaged Endpoints
MedDefense Evidence: No Group Policy Object restricts USB storage device
  use on any workstation (Marcus's unfinished notes, 0x00 Task 15); the
  ~25 physician iPads used for patient rounds have no Mobile Device
  Management or Enterprise Mobility Management solution; three
  confirmed shadow IT devices already exist in the environment (Dr.
  Patel's personal NAS, an abandoned Raspberry Pi network monitor, and
  an unidentified device at Westside — all documented in 0x00 Task 11).
Affected Asset(s): Every workstation (USB vector); the iPad fleet
  (mobile data access); whichever network segment each shadow device
  occupies.
Actor Most Likely to Exploit: Insider (Negligent) is the primary actor
  for both the USB and shadow IT vectors, per T6's own classification —
  none of the three confirmed shadow IT devices were introduced with
  malicious intent. Insider (Malicious) remains a secondary possibility
  for deliberate USB-based data exfiltration, and Unskilled/Opportunistic
  Attacker for any shadow device that is externally discoverable.
Exploitation Scenario: An employee — negligent or otherwise — can copy
  Restricted-classification data to a personal USB device with zero
  technical barrier and zero detection, since no DLP control exists to
  flag or block it; separately, a lost or stolen iPad with no remote-wipe
  capability and unconfirmed encryption enforcement represents an
  uncontained exposure of whatever clinical data was accessed on it.
Current Protection: None.
Gap Reference: GAP-024 (no USB restriction, compounded by GAP-019's lack
  of DLP), GAP-008 (no MDM on physician iPads), and the Task 11 shadow IT
  findings directly.
```

---

## Cross-Cutting Observation

Every one of these six technical vector categories terminates in the same place once exploited: the flat network. A vulnerable Apache instance, an unpatched MRI workstation, an exposed database port, a default credential, an unmanaged iPad, or a personal USB drive are each, individually, a contained problem. But none of them are contained at MedDefense, because the "Unsecure Networks" category (GAP-014) removes the boundary that would otherwise limit each one's blast radius to its own system. This mirrors the exact conclusion reached independently in Task 7's Surface Assessment Summary: the technical vector inventory here is not six separate risks to prioritize independently, but six different doors into the same undefended building.
