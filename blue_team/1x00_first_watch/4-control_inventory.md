# MedDefense Health Systems: Security control inventory

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** `meddefense-controls-artifacts.txt`, FortiGate firewall config extract, SSH configuration (ehr-srv-01), password policy document, Sophos antivirus status report, Veeam backup configuration, ClearView Security physical contract, HR training records, and Tom Reeves's verbal log management summary. **Purpose:** Document the security controls MedDefense currently has in place, classified along the dual-axis taxonomy (Category × Function), to complement the gap-focused findings from the walk-through and incident review.

**Taxonomy used:**

- **Category**: Technical (technology-based), Administrative (policy/process-based), Physical (physical-world mechanism).
- **Function**: Preventive (stops an incident), Detective (identifies an incident during/after), Corrective (repairs/restores after an incident), Compensating (alternative when the ideal control isn't feasible), Deterrent (discourages an attempt).

Every control below is directly evidenced in the provided artifacts. No control has been inferred beyond what the artifact text states.

---

## Control inventory

```
Control ID: C-001
Control Name: Perimeter Inbound Web Filtering
Description: FortiGate policy "Allow-Web-Inbound" permits inbound traffic
  from the internet to web-srv-01 only, and only on HTTP/HTTPS. All other
  inbound internet traffic to internal systems is not explicitly allowed
  by this rule.
Category: Technical
Function: Preventive
Asset(s) Protected: Internal network / all internal hosts other than
  web-srv-01 (limits internet-reachable surface to the DMZ web server)
Source: Artifact 1 — FortiGate Configuration Extract, policy edit 1
```

```
Control ID: C-002
Control Name: Default-Deny Firewall Policy
Description: The final firewall rule ("Deny-All") blocks any traffic not
  explicitly permitted by an earlier rule, across all interfaces.
Category: Technical
Function: Preventive
Asset(s) Protected: Entire internal network (baseline protection against
  any unanticipated traffic pattern)
Source: Artifact 1 - FortiGate Configuration Extract, policy edit 5
```

```
Control ID: C-003
Control Name: Firewall Traffic Logging
Description: All firewall policies have logging enabled (logtraffic set
  to "all" or "utm"), recording traffic that matches each rule.
Category: Technical
Function: Detective
Asset(s) Protected: Network perimeter and VPN links (provides the raw
  data needed to investigate an incident after the fact, though, per
  Artifact 8, these logs are stored locally only, with 30-day retention
  and no forwarding/centralization)
Source: Artifact 1 - FortiGate Configuration Extract, all policy edits
```

```
Control ID: C-004
Control Name: SSH Key-Only Authentication (ehr-srv-01)
Description: sshd_config on ehr-srv-01 disables password authentication
  (PasswordAuthentication no) and root login (PermitRootLogin no),
  requiring public-key authentication for all SSH access.
Category: Technical
Function: Preventive
Asset(s) Protected: ehr-srv-01 (EHR application server)
Source: Artifact 2 — SSH Configuration, ehr-srv-01
```

```
Control ID: C-005
Control Name: SSH Authentication Attempt Limiting (ehr-srv-01)
Description: sshd_config limits authentication attempts per connection
  (MaxAuthTries 3) and the time allowed to authenticate (LoginGraceTime
  60 seconds), reducing the window for automated brute-force attempts.
Category: Technical
Function: Preventive
Asset(s) Protected: ehr-srv-01 (EHR application server)
Source: Artifact 2 - SSH Configuration, ehr-srv-01
```

```
Control ID: C-006
Control Name: Verbose SSH Authentication Logging (ehr-srv-01)
Description: sshd_config sets SyslogFacility to AUTH and LogLevel to
  VERBOSE, generating detailed logs of authentication attempts and
  sessions on this server.
Category: Technical
Function: Detective
Asset(s) Protected: ehr-srv-01 (EHR application server)
Source: Artifact 2 — SSH Configuration, ehr-srv-01
```

```
Control ID: C-007
Control Name: Password Complexity, Rotation and History Policy
Description: Organization-wide policy requiring an 8-character minimum
  password with upper/lowercase, numeric and special-character
  complexity, 90-day rotation, and a history of the last 5 passwords to
  prevent immediate reuse. Enforced via Active Directory Group Policy
  for Windows systems.
Category: Administrative
Function: Preventive
Asset(s) Protected: All accounts on MedDefense information systems
  organization-wide (as enforced on Windows/AD; Linux systems are
  configured individually, per the policy document itself)
Source: Artifact 3 — Password Policy, Section 2
```

```
Control ID: C-008
Control Name: Account Lockout on Failed Login Attempts
Description: Accounts lock for 30 minutes after 5 consecutive failed
  login attempts, as specified in the password policy and enforced
  through Active Directory Group Policy.
Category: Technical
Function: Preventive
Asset(s) Protected: All Windows/AD-authenticated accounts organization-
  wide (limits automated password-guessing attacks)
Source: Artifact 3 — Password Policy, Section 2 and Section 5
```

```
Control ID: C-009
Control Name: Sophos Endpoint Antivirus Protection
Description: Sophos Endpoint Protection is deployed on managed Windows
  10/11 workstations (372 devices), blocking or quarantining detected
  malware, adware, phishing URLs and potentially unwanted applications
  (evidenced by 4 detections/actions in the last 30 days).
Category: Technical
Function: Preventive
Asset(s) Protected: Windows 10/11 workstations only (372 of 387 managed
  devices). Explicitly does NOT cover Windows servers (15, license not
  purchased), Linux servers (0, unsupported tier), macOS, or mobile
  devices/iPads (no MDM)
Source: Artifact 4 — Sophos Antivirus Status Report
```

```
Control ID: C-010
Control Name: Nightly Full VM Backup (Veeam)
Description: Veeam Backup & Replication performs a full nightly backup
  (02:00 AM) of six core VMs — ehr-srv-01, ehr-db-01, billing-srv-01,
  ad-dc-01, file-srv-01, and web-srv-01 — to NAS-01, retained for 14
  days.
Category: Technical
Function: Corrective
Asset(s) Protected: EHR application and database, billing/claims
  processing, primary domain controller, file shares, public website/
  patient portal (restores these systems after data loss, corruption,
  or a ransomware event — subject to the significant limitation, noted
  separately, that the NAS backup target shares the same room, rack row
  and network as the source systems)
Source: Artifact 5 — Backup Configuration
```

```
Control ID: C-011
Control Name: Staffed Main Entrance Security Guard (Central)
Description: A uniformed ClearView Security guard staffs Central's main
  entrance Monday–Friday, 07:00–19:00, performing visitor registration
  and badge verification before granting entry.
Category: Physical
Function: Preventive
Asset(s) Protected: Central's main entrance/lobby only. Explicitly does
  NOT cover floors, restricted areas, parking, nights, weekends,
  Westside Clinic, or Corporate HQ
Source: Artifact 6 — ClearView Security Service Agreement Summary
```

```
Control ID: C-012
Control Name: CCTV Camera Coverage (Central Entrances/Parking)
Description: Four analog cameras record Central's main entrance (2), ER
  entrance (1), and parking garage entrance (1) to a standalone DVR with
  30-day retention, reviewed only when someone at the security desk
  chooses to (no active/automated monitoring or alerting).
Category: Physical
Function: Detective
Asset(s) Protected: Main entrance, ER entrance, and parking garage
  entrance at Central only. Explicitly does NOT cover the server room,
  network closets, or the administrative wing
Source: Artifact 6 — Camera System notes (Tom Reeves)
```

```
Control ID: C-013
Control Name: Mandatory Annual Security Awareness Training
Description: "CyberSafe Basics," a 45-minute third-party online module
  covering password hygiene, phishing recognition, physical security
  awareness (tailgating, clean desk), and reporting suspicious activity,
  required annually for all staff.
Category: Administrative
Function: Preventive
Asset(s) Protected: The organization's entire workforce as a human
  attack surface (reduces susceptibility to phishing, social
  engineering, and physical-security lapses) — though completion is
  currently incomplete (see limitations below)
Source: Artifact 7 — Training Records, "CyberSafe Basics" program
```

```
Control ID: C-014
Control Name: FortiGate Local Log Retention
Description: The firewall retains its own traffic/event logs locally
  for 30 days; logs are not forwarded to any external or centralized
  system.
Category: Technical
Function: Detective
Asset(s) Protected: Network perimeter (supports post-incident
  investigation of network-layer events, within a 30-day window)
Source: Artifact 8 — Log Management summary (Tom Reeves)
```

```
Control ID: C-015
Control Name: Web/Application Log Rotation (web-srv-01, billing-srv-01)
Description: Apache logs on web-srv-01 and billing-srv-01 rotate weekly
  via logrotate, with 4 weeks of history retained.
Category: Technical
Function: Detective
Asset(s) Protected: web-srv-01 (public website/patient portal) and
  billing-srv-01 (billing/claims processing) — supports investigation of
  web-tier incidents, such as the billing-srv-01 compromise
Source: Artifact 8 — Log Management summary (Tom Reeves)
```

```
Control ID: C-016
Control Name: EHR Vendor-Managed Audit Log
Description: The EHR application maintains its own audit log, managed
  by the software vendor; MedDefense can request an export, though this
  takes up to 48 hours to fulfill.
Category: Technical
Function: Detective
Asset(s) Protected: EHR application and the patient data it holds
  (supports investigation of unauthorized access or modification to
  clinical records, subject to the 48-hour export delay)
Source: Artifact 8 — Log Management summary (Tom Reeves)
```

---

## Control summary matrix

|Category \ Function|Preventive|Detective|Corrective|Compensating|Deterrent|
|---|---|---|---|---|---|
|**Technical**|C-001, C-002, C-004, C-005, C-008, C-009|C-003, C-006, C-014, C-015, C-016|C-010|_(none identified)_|_(none identified)_|
|**Administrative**|C-007, C-013|_(none identified)_|_(none identified)_|_(none identified)_|_(none identified)_|
|**Physical**|C-011|C-012|_(none identified)_|_(none identified)_|_(none identified)_|

---

## Observations on the empty cells (potential gaps)

The instructions note that empty cells represent potential gaps. Rather than force a control into a cell it does not evidence, the following are flagged as genuine absences based on the artifacts reviewed:

- **No Corrective controls outside technical/backup.** The only corrective control identified organization-wide is the nightly VM backup (C-010). And per Artifact 5, it has never been the subject of a full disaster-recovery test, its retention is only 14 days, and it does not cover pacs-srv-01, ad-dc-02, print-srv-01, Westside's server, medical device configurations, or O365 data. There is no evidenced incident response plan, no documented restoration procedure for anything other than VM-level backups, and no administrative or physical corrective control (e.g., a tested IR runbook) in the artifacts provided.
- **No Compensating controls evidenced anywhere.** Several known unpatchable/high-risk conditions exist elsewhere in this assessment (e.g., the MRI running Windows XP, Linux servers other than ehr-srv-01 still permitting SSH password authentication) with no accompanying compensating control (such as network isolation) documented in these artifacts.
- **No Deterrent controls evidenced anywhere.** No warning signage, visible monitoring notices, or similar deterrent measures appear in the provided material. The security guard (C-011) and cameras (C-012) likely carry some deterrent value in practice, but their documented function in the artifacts is active gatekeeping and passive recording, respectively, not deterrence, so they have been classified by their evidenced function rather than a plausible secondary effect.
- **No Administrative Detective controls.** There is no evidenced periodic access review, audit program, or compliance monitoring process. Training exists (Preventive) but nothing detects when policies are being violated.
- **Antivirus coverage gap.** C-009 is explicitly limited to Windows workstations; Windows servers, Linux servers, and mobile devices have no equivalent technical preventive control against malware in the artifacts reviewed, directly relevant to the cryptominer found on billing-srv-01 (a Linux server) in the prior root-cause analysis.

This inventory should be read alongside the walk-through and incident findings: the controls that do exist are real and functioning, but they are inconsistently applied (e.g., SSH hardening on one server out of many, antivirus on one platform out of several) and are heavily weighted toward Preventive and Detective technical measures, with Corrective, Compensating, and Deterrent controls almost entirely absent across all three categories.
