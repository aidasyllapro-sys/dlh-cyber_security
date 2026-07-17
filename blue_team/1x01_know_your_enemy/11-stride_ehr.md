# MedDefense Health Systems: STRIDE Threat Model - The EHR System

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **System scope:** ehr-srv-01 (application server) + ehr-db-01 (PostgreSQL database) + clinical workstations + the network paths connecting all of them **Source material:** Project 0x00 Asset Registry, Control Matrix, Gap Analysis, Data Map, and Incident Classification; Technical Vectors (Task 8) and Kill Chains (Task 10) of this project **Purpose:** Systematically walk MedDefense's most critical system through all 6 STRIDE categories to produce a comprehensive threat inventory, not an ad-hoc list, but a structured stress-test ensuring no category is skipped.

---

## Threat Inventory

```
Category: Spoofing
Threat ID: EHR-S1
Description: A clinician's EHR login credential, once phished or stolen,
  is fully indistinguishable from the legitimate user's own access —
  there is no second factor to confirm the actual identity behind the
  username and password.
Attack Vector: Phishing / Spear Phishing (T8), combined with the total
  absence of MFA on EHR access.
Impact: An attacker can fully impersonate a physician within the EHR —
  viewing, and potentially entering or altering, patient records
  attributed to that clinician's real identity, corrupting both the
  clinical record and the audit trail's reliability at the same time.
Existing Control: None. C-007 (password policy) governs password
  strength/rotation but does nothing to prevent a stolen-but-valid
  credential from being used successfully.
Gap: GAP-017 (no MFA anywhere in the organization).
```

```
Category: Spoofing
Threat ID: EHR-S2
Description: ehr-db-01's PostgreSQL service authenticates connections by
  credential alone, with no verification of which system is actually
  presenting them — since the database is reachable from the entire
  internal network rather than restricted to ehr-srv-01, any device that
  obtains valid database credentials (e.g., harvested from a compromised
  host elsewhere) can present itself to the database as the legitimate
  application server.
Attack Vector: Vulnerable Software Exploit or VPN Exploit (T8) leading to
  lateral movement across the flat network.
Impact: The database has no way to distinguish a query from the real
  EHR application versus a rogue system spoofing that role, meaning
  trust in the application layer's own access controls is meaningless
  once this layer is bypassed.
Existing Control: None.
Gap: GAP-003 (database reachable network-wide instead of restricted to
  ehr-srv-01), GAP-014 (flat network enabling the reach in the first
  place).
```

```
Category: Tampering
Threat ID: EHR-T1
Description: Direct write access to ehr-db-01, reachable from any point
  on the flat network via its exposed PostgreSQL port, allows an
  attacker to modify patient records, dosages, or lab results directly
  at the database layer — completely bypassing whatever business-logic
  validation the EHR application itself performs.
Attack Vector: Vulnerable Software Exploit or VPN Exploit (T8) resulting
  in network-level database access.
Impact: Falsified clinical data (medication dosages, lab results,
  allergies) directly informs real treatment decisions — this is not a
  hypothetical mechanism; Incident C already demonstrated that
  corrupted dosage data at MedDefense went unnoticed for approximately
  6 hours across all three sites, caught only by chance.
Existing Control: None.
Gap: GAP-003, GAP-014.
```

```
Category: Tampering
Threat ID: EHR-T2
Description: No formal change management process exists for the EHR
  application or its supporting scripts/automation, meaning code or
  configuration changes can reach production without testing or peer
  review — the exact condition already proven to cause real harm at
  MedDefense (the untested database update script behind Incident C).
Attack Vector: Insider (Negligent) or Insider (Malicious) (T6) — an
  internal actor with legitimate deployment access, acting carelessly or
  deliberately.
Impact: Systemic, silent corruption of clinical data across all three
  sites — not a single-record tampering event, but a pattern capable of
  affecting every patient whose data passes through the altered logic.
Existing Control: None.
Gap: GAP-025 (no formal change management process).
```

```
Category: Repudiation
Threat ID: EHR-R1
Description: Because no MFA exists, an EHR login cannot be confidently
  tied to the specific individual who actually performed an action —
  if a password were ever shared informally under staffing pressure
  (a documented accountability pattern already confirmed in a different
  MedDefense system, the shared PACS login), the person responsible for
  a given record access or change could plausibly deny it was them.
Attack Vector: Insider (Malicious or Negligent) (T6), enabled by weak
  identity assurance.
Impact: A clinician or staff member who inappropriately views or alters
  a record retains a credible basis to deny responsibility, since the
  audit log ties the action only to a username, not to a confirmed
  individual.
Existing Control: C-016 (EHR vendor-managed audit log) records access by
  account, providing partial evidence, but does not resolve
  non-repudiation without a second, individually-bound authentication
  factor.
Gap: GAP-017 (no MFA undermines confidence that a logged username
  reflects the actual individual who acted).
```

```
Category: Repudiation
Threat ID: EHR-R2
Description: The EHR's audit log takes up to 48 hours to export and, per
  this project's own findings, is never proactively reviewed —
  MedDefense's demonstrated pattern (Task 3's "Curious Employee"
  scenario) is that inappropriate access is discovered only after an
  external complaint, not through internal audit.
Attack Vector: Insider (Malicious) (T6) — directly matches the already-
  documented pattern of undetected, unreviewed access.
Impact: Delayed or effectively absent accountability for inappropriate
  access, weakening both MedDefense's HIPAA compliance posture and any
  internal disciplinary or legal action that might otherwise follow an
  incident.
Existing Control: C-016 exists (rated Adequate in the 0x00 Control
  Matrix) but its practical value is limited by the export delay and the
  absence of any review process.
Gap: GAP-004 (no proactive log review/alerting), GAP-009 (no periodic
  compliance review).
```

```
Category: Information Disclosure
Threat ID: EHR-I1
Description: PostgreSQL on ehr-db-01 is reachable from the entire
  internal network rather than restricted to ehr-srv-01, meaning any
  compromised device anywhere in the environment — a workstation, a
  medical IoT device, a vendor connection — can directly query and
  exfiltrate the complete patient record database without ever touching
  the EHR application's own access controls or logging.
Attack Vector: Any vector granting internal network access — VPN
  Exploit, Vulnerable Software Exploit, or Supply Chain Compromise (T8/
  T9 all map multiple paths to this exact exposure).
Impact: Mass, application-bypassing PHI exposure — names, medical
  histories, insurance details, and more, for the organization's entire
  patient population — with no corresponding entry in the EHR's own
  audit trail, since the access path never passes through the
  application layer that log is designed to monitor.
Existing Control: None.
Gap: GAP-003, GAP-014.
```

```
Category: Information Disclosure
Threat ID: EHR-I2
Description: An EHR session left open and unlocked at a nurse station —
  already directly observed and documented during the Project 0x00
  physical walk-through (Observation 3) — allows any passerby, patient,
  visitor, or unauthorized staff member to view whatever patient record
  happens to be displayed, with zero technical barrier.
Attack Vector: Physical Access (T8).
Impact: Direct, in-person PHI exposure that leaves no technical trace at
  all — there is no login/logout event to mark the unauthorized viewing,
  making it effectively undetectable and uninvestigable after the fact.
Existing Control: None. No session-timeout or lock-screen enforcement
  control exists anywhere in the 0x00 Control Matrix.
Gap: This threat traces to a control gap never formally assigned its own
  Gap ID in Project 0x00 (automatic session timeout on clinical
  workstations) — related in spirit to GAP-007's physical-access theme,
  but distinct enough to warrant a dedicated gap entry in a future
  update to the Gap Analysis.
```

```
Category: Denial of Service
Threat ID: EHR-D1
Description: Neither ehr-srv-01 nor ehr-db-01 has any antivirus or EDR
  protection, and both sit on the flat, unsegmented network — a
  ransomware deployment (modeled in full in this project's Kill Chain
  #1) could encrypt both systems simultaneously, taking the entire EHR
  offline.
Attack Vector: Ransomware via VPN Exploit or Vulnerable Software Exploit
  (T8/T2/T10).
Impact: Complete loss of electronic patient record access, forcing
  paper-based clinical operations — MedDefense has already experienced
  a 9-hour version of this exact outage during a mismanaged migration
  (Incident E); a malicious version would very plausibly last far
  longer, directly threatening patient safety for the duration.
Existing Control: C-010 (nightly backup) provides some corrective
  capacity, but is itself rated Weak due to co-location with production
  (GAP-006).
Gap: GAP-014, GAP-005, GAP-006.
```

```
Category: Denial of Service
Threat ID: EHR-D2
Description: A resource-exhaustion compromise — the same mechanism
  already proven against billing-srv-01 via a disguised cryptomining
  process — could degrade ehr-srv-01 or ehr-db-01's performance to the
  point of practical unusability without ever producing a clean,
  obvious "outage."
Attack Vector: Vulnerable Software Exploit (T8) — a proven attack class
  at MedDefense, not a theoretical one.
Impact: Clinical staff experience slow or unresponsive EHR access during
  active patient care, causing treatment delays that may not be
  immediately attributed to a security incident — the billing-srv-01
  precedent shows MedDefense's own sysadmins initially misdiagnosed this
  exact symptom as a hardware capacity problem rather than a compromise.
Existing Control: None.
Gap: GAP-005 (no server AV/EDR), GAP-004 (no detection to catch this
  quickly rather than after weeks, as happened previously).
```

```
Category: Elevation of Privilege
Threat ID: EHR-E1
Description: SSH password authentication remains enabled on ehr-db-01 —
  only ehr-srv-01 was migrated to key-only authentication before Marcus
  Webb's departure — meaning a credential-based attack against the
  database server's own operating system could grant direct
  administrative control over the host, a far higher privilege level
  than the application layer is designed to expose.
Attack Vector: Vulnerable Software Exploit / credential attack (T8)
  directly against the database server's SSH service.
Impact: Complete administrative control over the server holding every
  patient record — able to read, modify, or destroy all patient data,
  disable logging entirely, or pivot further into the network from a
  position of full trust.
Existing Control: C-004 (SSH key-only authentication) explicitly covers
  ehr-srv-01 only, per its own documented scope in the 0x00 Control
  Matrix — it provides no protection for ehr-db-01.
Gap: This incomplete hardening rollout was documented as supporting
  evidence under GAP-009 (no periodic compliance review ever caught
  that the SSH migration stalled after a single server) — the
  underlying technical exposure itself traces directly to the original
  finding in 0x00 Task 2.
```

```
Category: Elevation of Privilege
Threat ID: EHR-E2
Description: A standard clinical user of the EHR — a nurse or
  technician with legitimate but limited access — could potentially
  exploit an application-layer authorization flaw of the same class
  already confirmed elsewhere in MedDefense's environment (the broken
  access control on the patient portal that let one patient view
  another's lab results, Incident B) to view or modify records outside
  their assigned patient panel.
Attack Vector: Vulnerable Software Exploit at the application layer
  (T8) — a directly proven vulnerability class at MedDefense, not a
  speculative one.
Impact: Any authenticated EHR user could potentially access records far
  beyond their legitimate clinical need, undermining least-privilege
  access to PHI organization-wide — this risk is elevated by the fact
  that no source in this project confirms whether the EHR's own
  internal authorization logic (as distinct from the patient portal's)
  was ever separately tested or fixed following Incident B.
Existing Control: None confirmed.
Gap: This threat traces to Incident B's underlying application
  vulnerability, which was never formally tracked as its own Gap ID in
  the Project 0x00 Gap Analysis — flagged here as a recommended addition.
```

---

## STRIDE Summary for EHR

**Tampering represents the greatest risk to the EHR system specifically**, even though Information Disclosure exploits the identical technical door (GAP-003's network-wide database exposure) and is, by most conventional breach-cost measures, the more commonly feared outcome. What makes Tampering uniquely dangerous in this healthcare context is that its consequence is not a downstream financial or regulatory cost calculated after the fact. It is an immediate, physical threat to a specific patient, realized the moment a clinician acts on falsified dosage, allergy, or lab data. This is not a theoretical distinction: MedDefense has already experienced exactly this failure mode once, by accident rather than by attack, when Incident C corrupted medication dosage data across all three sites for roughly six hours before a pharmacist happened to notice the discrepancy. Every technical condition that made that accidental incident possible (network-wide database exposure (GAP-003), a flat network (GAP-014), and no change management process (GAP-025)) remains open today and is equally capable of enabling a deliberate version of the same event, except an attacker, unlike a buggy script, could specifically choose which patients and which values to alter, and could time the tampering to evade the kind of chance discovery that caught Incident C.
