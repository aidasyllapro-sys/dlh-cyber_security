# MedDefense Health Systems: The Misconfiguration Findings

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** `meddefense-vulnerability-scan.txt`, cross-referenced against Project 0x00 (Physical Walk-Through T3, Control Gaps T5, Asset Registry/Network Scan T7, Gap Analysis T12/T15) and Project 1x01 (STRIDE T11/T12, Kill Chains T10, Exploit Hunt T4) **Purpose:** Analyze 6 findings in the scan report with no CVE assigned, and demonstrate why the absence of a CVE, and therefore the absence of a CVSS score, an NVD page, or an Exploit-DB entry, does not mean the absence of risk. The MongoDB ransomware wave of 2017 (28,000 databases, zero CVEs) and the 2019 Capital One breach (100 million records, a misconfigured WAF rule, zero CVEs) are the reference cases for why this category of finding cannot be deprioritized by default.

---

```
Finding ID: 003
Host: ehr-db-01 (10.10.2.11)
Misconfiguration: PostgreSQL's pg_hba.conf accepts authenticated
  connections from the entire 10.10.0.0/16 range ("host all all
  10.10.0.0/16 md5"), and listen_addresses is set to '*'. No
  network-layer control restricts connections to ehr-srv-01, the only
  system that should ever need to reach this database.
Why No CVE: PostgreSQL's code is not flawed here — it is doing exactly
  what its configuration file instructs it to do. pg_hba.conf is an
  administrator-controlled access control list; PostgreSQL ships with
  no opinion about which hosts should be trusted, because that decision
  is inherently deployment-specific. A CVE is assigned to a defect in
  software logic; this is a deployment decision that happened to be
  insecure, with nothing in the software itself to patch.
Severity Assessment: Critical. ehr-db-01 holds the complete patient
  record database and is the #1-ranked Critical asset in the 0x00
  Criticality Assessment (Task 8). Any compromised host anywhere on the
  flat network can query this database directly, bypassing every
  application-layer access control the EHR software itself provides.
Cross-Reference 1x00: This is GAP-003 in the 0x00 Gap Analysis (Task 12)
  by name — "EHR database network-wide exposure" — independently
  confirmed via the Task 7 network scan and subsequently identified as
  one of "The Critical Three" gaps in the 1x01 Gap-Threat Correlation
  (Task 15), appearing in 5 of 8 documented kill chains and scenarios.
Comparable CVE Risk: Comparable to CVE-2020-1938 (Ghostcat, CVSS 9.8,
  Finding 031) — both allow an attacker with network reach to access
  sensitive data directly, without passing through proper authentication
  or authorization logic. Ghostcat achieves this through a protocol
  parsing flaw; this misconfiguration achieves the identical outcome
  through a configuration choice, arguably making it more dangerous in
  practice, since exploiting it requires no exploit code at all — only
  the network path the flat topology already provides for free.
```

```
Finding ID: 007
Host: ad-dc-01 (10.10.2.20)
Misconfiguration: The domain controller does not require LDAP signing,
  permitting LDAP relay attacks capable of modifying directory objects.
  SMBv1 is also enabled on the same host.
Why No CVE: LDAP signing is an optional hardening feature that Windows
  Server ships disabled by default for backward compatibility with
  older clients — Active Directory is functioning exactly as designed.
  Requiring LDAP signing is an administrative hardening decision that
  every Microsoft security baseline recommends but does not enforce
  automatically; there is no code defect for a CNA to assign an ID to.
Severity Assessment: Critical. ad-dc-01 is the #2-ranked Critical asset
  in the 0x00 Criticality Assessment. An LDAP relay attack, combined
  with the already-confirmed flat network, provides a realistic path to
  full domain compromise using widely available, off-the-shelf tooling.
Cross-Reference 1x00: Connects directly to the STRIDE analysis on
  Active Directory in this project (Task 12), where Elevation of
  Privilege was independently identified as the top threat to this
  exact system, and to GAP-009 (no periodic compliance/hardening
  review) from the 0x00 Gap Analysis — a baseline security review would
  have caught this default configuration long before a scanner did.
Comparable CVE Risk: Comparable to CVE-2019-0708 (BlueKeep, CVSS 9.8,
  Finding 004) — both provide a path to full system compromise from a
  position of mere network access. BlueKeep requires a working exploit
  against a specific unpatched RDP stack; an LDAP relay attack using
  a tool like ntlmrelayx requires no CVE, no exploit development, and
  will never be fixed by a patch, because there is no bug to patch.
```

```
Finding ID: 009
Host: billing-srv-01 (10.10.2.15)
Misconfiguration: SSH permits password-based authentication rather than
  requiring key-only auth, combined with no account lockout policy on
  the Linux system, enabling sustained brute-force attempts.
Why No CVE: OpenSSH's password authentication is a fully supported,
  intentional feature, not a vulnerability — the exposure exists purely
  because an administrator chose not to disable it. The same
  environment proves this directly: ehr-srv-01 has this exact setting
  correctly hardened (SSH key-only), showing this is a configuration
  state that varies host to host, not an unavoidable property of the
  software.
Severity Assessment: High. billing-srv-01 has already been compromised
  twice in this organization's documented incident history (0x00, Task
  2) — a ransomware event and a cryptominer. A brute-forceable SSH login
  is a second, standing entry point into a server already proven to be
  a repeat target.
Cross-Reference 1x00: Directly documented by name in the 0x00 Task 2
  root cause analysis, which explicitly states: "ehr-srv-01 has SSH
  key-only auth properly configured. All other Linux servers still
  allow password auth." This scan finding independently confirms a gap
  the organization already knew about but had not remediated.
Comparable CVE Risk: Comparable to CVE-2021-44790 (Apache mod_lua,
  CVSS 9.8, Finding 001) — on this exact same host. That CVE has no
  confirmed public exploit (verified directly in Task 4 of this
  project), while this misconfiguration requires no exploit development
  whatsoever: brute-forcing or credential-stuffing a password is a
  universally available technique, arguably making it the more
  immediately actionable of the two risks on this server.
```

```
Finding ID: 014
Host: Westside Clinic Netgear router (10.10.10.1)
Misconfiguration: A consumer-grade router serves as Westside's entire
  perimeter device and terminates the site-to-site VPN to Central, with
  its administration interface reachable from the internal network and
  none of the logging, IDS/IPS, or granular access-control capability an
  enterprise device would provide.
Why No CVE: This is an architecture and equipment-selection decision,
  not a defect in the router's own firmware (the firmware may separately
  carry its own CVEs, unrelated to this finding). The scanner is
  flagging that an entire clinical site's network security depends on
  consumer hardware never designed for this role — a deployment choice,
  not a patchable flaw.
Severity Assessment: Critical. Per the finding's own description, a
  compromise here grants "a direct tunnel into the Central server
  network" — the same server subnet holding every 0x00 Top 5 Critical
  asset.
Cross-Reference 1x00: This is GAP-021 ("Westside's consolidated
  site-level risk"), formalized by name in the 0x00 Task 15 predecessor
  review, based on notes the previous analyst left specifically flagging
  this device. It is independently confirmed in this project's own
  Network Infrastructure STRIDE analysis (Task 12) as the top Elevation
  of Privilege threat in the entire environment.
Comparable CVE Risk: Comparable to CVE-2017-0144 (EternalBlue, CVSS
  8.1, Finding 004) — both provide a foothold with broad lateral reach
  into the rest of the network. EternalBlue needs a specific unpatched
  SMB stack and a working exploit; this misconfiguration needs nothing
  more than reaching a device that was never built to resist a
  determined attacker in the first place.
```

```
Finding ID: 015
Host: NAS-01 (10.10.2.41)
Misconfiguration: The Synology DSM backup management interface is
  reachable from the entire internal network (ports 5000/5001) rather
  than restricted to administrative IPs, and the backup data itself is
  stored unencrypted.
Why No CVE: Synology DSM is not defective software here — it ships with
  a management interface by design, and restricting which network
  segments can reach it is the deploying administrator's responsibility.
  Encryption for the backup data is available in DSM but was not
  enabled — again a configuration choice, not a code-level flaw.
Severity Assessment: Critical. NAS-01 is MedDefense's only backup
  infrastructure, the #5-ranked Critical asset in the 0x00 Criticality
  Assessment. This finding compounds the already-known single point of
  failure (GAP-006 — the NAS is co-located with the production systems
  it protects) with a second, independent way to reach and potentially
  destroy the backup entirely.
Cross-Reference 1x00: Ties directly to GAP-006 in the 0x00 Gap Analysis,
  and to Kill Chain #1 in this project (Task 10), where the modeled
  ransomware sequence explicitly uses this exact exposed management
  interface to delete all backup jobs before deploying ransomware
  organization-wide.
Comparable CVE Risk: Comparable to CVE-2023-38408 (OpenSSH, backup-
  srv-01, Finding 020 — the same backup infrastructure). That CVE
  requires a narrow, specific precondition to be exploitable at all
  (ssh-agent forwarding to an attacker-controlled host, per Task 1's
  research). This misconfiguration requires nothing beyond having any
  foothold anywhere on the flat network, making it the more immediately
  exploitable of the two despite carrying no CVSS score whatsoever.
```

```
Finding ID: 023
Host: Approximately 280 clinical workstations (10.10.1.20-42 range)
Misconfiguration: No Group Policy restricts USB mass storage devices,
  allowing any user to connect removable media without restriction on
  nearly the entire clinical endpoint fleet.
Why No CVE: Group Policy is a Windows administration feature working
  exactly as intended — Windows fully supports restricting USB storage
  devices. The absence of a specific GPO enforcing that restriction is a
  policy configuration gap, not a software defect; there is no flaw in
  Windows for a CNA to assign an identifier to.
Severity Assessment: High. This project's own Insider File analysis
  (Task 3) already identified this exact mechanism as the enabling
  condition behind a documented, realistic insider data-theft pattern
  (the "Departed Administrator" / "Quiet Departure" class of scenario),
  and it affects nearly the entire clinical workstation population
  simultaneously, not an isolated system.
Cross-Reference 1x00: Corresponds directly to GAP-024 ("no USB storage
  restriction"), formalized in the 0x00 Task 15 predecessor review from
  notes the previous analyst left unfinished before departing.
Comparable CVE Risk: Comparable in severity tier to CVE-2020-25165 (BD
  Alaris pump DoS, CVSS 7.5, Finding 010) — but where that CVE requires
  an attacker to actively exploit a device over the network, this
  misconfiguration requires nothing but physical proximity to any of
  roughly 280 machines, making sustained, silent data exfiltration
  trivial — and, per this project's own prior analysis, already a
  demonstrated real-world pattern rather than a theoretical one.
```

---

## Why "Our CVE Scan Shows Nothing Critical, We Are Secure" Is Dangerous False Assurance

That statement is false assurance because CVE-based tooling only has a lens for one category of risk (a known, catalogued defect in a specific piece of software) and is structurally blind to the other category entirely: how that software was actually deployed. In this scan alone, roughly half of the 31 findings carry no CVE at all, and the 6 analyzed above show that at least 4 of them are independently Critical severity, sitting directly on the highest-priority attack paths already documented across this entire project. The EHR database exposure, the domain controller's LDAP weakness, and the backup infrastructure's exposed management interface are each central to Kill Chain #1, the single most dangerous threat identified in this program. An organization that filters its risk picture through CVE/CVSS data alone would conclude billing-srv-01, ehr-db-01, ad-dc-01, NAS-01, and the entire Westside site are less exposed than a "Critical" scan finding, when in fact several of them are more immediately exploitable than the CVE-bearing findings sitting right next to them, precisely because no exploit development, no patch research, and no waiting for a public PoC is required. Only the network access the flat topology already grants for free. The MongoDB and Capital One cases exist in this document's introduction for exactly this reason: neither would have shown up on a "Critical CVEs: 0" dashboard, and neither organization was, in fact, secure.
