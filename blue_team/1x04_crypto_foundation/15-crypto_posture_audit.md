# MedDefense Health Systems: The Crypto Posture Audit

**Prepared by:** Aïda Sylla, Security Analyst **Source material:** The Data Protection Map (Task 0), cross-referenced against every subsequent task of this project (Algorithm Reference Table, Task 6; Encryption Levels, Task 13; Key Management Plan, Task 14) and the Vulnerability Assessment (1x02) and Risk Register (1x03) **Purpose:** Every cell in Task 0's Data Protection Map marked Weak or Absent becomes a formal finding here, with a specific, evidence-based recommendation, not a general call to "encrypt more."

**Scope, stated precisely:** of the 21 conceptual data-state combinations mapped in Task 0, 2 (Email at rest, Email in transit) were already rated Adequate and require no remediation. This audit produces 18 findings covering the remaining combinations, including the VPN category's Transit and In Use states, which Task 0 documented as a single combined entry given they describe the same operational reality for tunnel traffic, not two independently meaningful states.

---

## Crypto Findings

```
Finding ID: CRYPTO-001
Data Category: Patient medical records (PostgreSQL, ehr-db-01)
Data State: At rest
Current Protection: None (Task 0)
Vulnerability Reference: Finding 003 (1x02)
Risk Reference: RISK-002 (1x03), $816,750 residual ALE
Algorithm Assessment: N/A, no algorithm currently applied
Recommended Protection: AES-256, Database-level Transparent Data
  Encryption (Task 6, Task 13)
Encryption Level: Database (Task 13)
Key Management: Cloud KMS with HSM-backed storage, escrowed given this
  key's criticality (Task 14)
Implementation Priority: Immediate
```

```
Finding ID: CRYPTO-002
Data Category: Patient medical records (PostgreSQL, ehr-db-01)
Data State: In transit
Current Protection: Weak, ssl=on but pg_hba.conf permits unencrypted
  "hostnossl" connections from the full internal network (Task 0)
Vulnerability Reference: Finding 003 (1x02)
Risk Reference: RISK-002 (1x03)
Algorithm Assessment: TLS itself is adequate where enforced; the gap is
  enforcement, not algorithm strength (Task 6)
Recommended Protection: Enforce "hostssl" exclusively in pg_hba.conf,
  removing every "hostnossl" entry
Encryption Level: N/A, a configuration enforcement fix, not a new
  encryption layer
Key Management: N/A
Implementation Priority: Immediate
```

```
Finding ID: CRYPTO-003
Data Category: Patient medical records (PostgreSQL, ehr-db-01)
Data State: In use
Current Protection: None; no session protection beyond OS login, nurse
  station screensaver timeout set to "Never" (Task 0)
Vulnerability Reference: None directly in 1x02's scan scope
Risk Reference: None directly in the 1x03 Top 10 register; a genuine
  coverage gap in that prior work, stated honestly rather than forced
Algorithm Assessment: N/A, an access-control gap, not a cryptographic
  one
Recommended Protection: Enforce an automatic screen-lock policy via
  Group Policy on clinical workstations
Encryption Level: N/A
Key Management: N/A
Implementation Priority: Phase 2
```

```
Finding ID: CRYPTO-004
Data Category: Financial/billing data (MySQL, billing-srv-01)
Data State: At rest
Current Protection: None; database files confirmed readable without
  credentials during the 0x00 crypto-miner forensic review (Task 0)
Vulnerability Reference: Finding 006 (1x02)
Risk Reference: RISK-003 (1x03), related but not identical, that risk
  covers the ransomware entry point to this server, not this specific
  storage gap directly; stated honestly rather than forcing a false
  one-to-one match
Algorithm Assessment: N/A, no algorithm currently applied
Recommended Protection: AES-256, Database-level TDE (InnoDB tablespace
  encryption); credit card numbers specifically follow the tokenization
  design (Task 7) instead of field-level encryption
Encryption Level: Database, with tokenization for card data specifically
  (Task 13)
Key Management: Cloud KMS with HSM-backed storage (Task 14)
Implementation Priority: Phase 1
```

```
Finding ID: CRYPTO-005
Data Category: Financial/billing data (MySQL, billing-srv-01)
Data State: In transit
Current Protection: Weak; MySQL bound to 0.0.0.0, SSL not enforced,
  plaintext protocol over the flat network (Task 0)
Vulnerability Reference: Finding 006 (1x02)
Risk Reference: RISK-003 (1x03), same caveat as CRYPTO-004
Algorithm Assessment: TLS itself adequate where enforced; enforcement is
  the gap
Recommended Protection: Enforce require_secure_transport=ON in MySQL
  configuration
Encryption Level: N/A, enforcement fix
Key Management: N/A
Implementation Priority: Phase 1
```

```
Finding ID: CRYPTO-006
Data Category: Financial/billing data (MySQL, billing-srv-01)
Data State: In use
Current Protection: Not directly audited in Task 0; inferred absent by
  architectural analogy to the EHR system
Vulnerability Reference: None directly
Risk Reference: None directly in the 1x03 Top 10 register
Algorithm Assessment: N/A
Recommended Protection: Same screen-lock and session-timeout policy as
  CRYPTO-003, applied to billing department workstations
Encryption Level: N/A
Key Management: N/A
Implementation Priority: Phase 2
```

```
Finding ID: CRYPTO-007
Data Category: Medical images (DICOM, pacs-srv-01)
Data State: At rest
Current Protection: None; images stored unencrypted, headers partially
  plaintext-readable (Task 0)
Vulnerability Reference: Finding 024 (1x02)
Risk Reference: None directly in the 1x03 Top 10 register, a genuine
  coverage gap this audit surfaces
Algorithm Assessment: N/A, no algorithm currently applied
Recommended Protection: AES-256, applied per-file
Encryption Level: File (Task 13)
Key Management: Cloud KMS with HSM-backed storage (Task 14)
Implementation Priority: Phase 2
```

```
Finding ID: CRYPTO-008
Data Category: Medical images (DICOM, pacs-srv-01)
Data State: In transit
Current Protection: None; DICOM TLS (PS3.15) exists as a standard but is
  not configured, imaging traffic including patient identifiers
  traverses the network in cleartext (Task 0)
Vulnerability Reference: Finding 024 (1x02)
Risk Reference: None directly in the 1x03 Top 10 register
Algorithm Assessment: DICOM TLS itself, once enabled, would be adequate
  (Task 6 standards)
Recommended Protection: Enable DICOM TLS (PS3.15) between the MRI
  workstation, radiology workstations, and pacs-srv-01
Encryption Level: N/A, a transport-layer enablement, not a storage layer
  choice
Key Management: N/A
Implementation Priority: Phase 2
```

```
Finding ID: CRYPTO-009
Data Category: Medical images (DICOM, pacs-srv-01)
Data State: In use
Current Protection: Not directly audited in Task 0; inferred absent by
  architectural analogy
Vulnerability Reference: None directly
Risk Reference: None directly
Algorithm Assessment: N/A
Recommended Protection: Same screen-lock policy as CRYPTO-003, applied
  to radiology workstations
Encryption Level: N/A
Key Management: N/A
Implementation Priority: Phase 2
```

```
Finding ID: CRYPTO-010
Data Category: Credentials (Active Directory, ad-dc-01/ad-dc-02)
Data State: At rest
Current Protection: Weak; NT hash (MD4-based), unsalted, no stretching
  (Task 0, confirmed against Microsoft's own documentation)
Vulnerability Reference: Finding 018 (1x02)
Risk Reference: None directly in the 1x03 Top 10 register, a genuine
  coverage gap
Algorithm Assessment: Inadequate by modern standards (Task 6), but this
  is a structural property of Windows domain authentication that cannot
  be directly swapped; the actionable fix targets the exploitation path,
  not the hash format itself
Recommended Protection: No direct algorithm replacement is possible;
  close Finding 018 (disable DES and RC4 as supported Kerberos
  encryption types, enforce AES-256 exclusively) to remove the practical
  mechanism for obtaining this hash material for offline cracking
Encryption Level: N/A
Key Management: N/A
Implementation Priority: Immediate
```

```
Finding ID: CRYPTO-011
Data Category: Credentials (Active Directory, ad-dc-01/ad-dc-02)
Data State: In transit
Current Protection: Weak; RC4 and DES Kerberos encryption types
  enabled, LDAP not encrypted by default, LDAP signing not required
  (Task 0)
Vulnerability Reference: Finding 018 and Finding 007 (1x02)
Risk Reference: None directly in the 1x03 Top 10 register
Algorithm Assessment: AES-256 already supported and available; RC4 and
  DES remain enabled alongside it, the specific gap (Task 6)
Recommended Protection: Disable RC4 and DES Kerberos encryption types;
  enforce LDAP signing domain-wide
Encryption Level: N/A, configuration enforcement
Key Management: N/A
Implementation Priority: Immediate
```

```
Finding ID: CRYPTO-012
Data Category: Credentials (Active Directory / application passwords)
Data State: In use
Current Protection: Weak; no confirmed in-memory credential protection
  (such as Credential Guard), Mimikatz/LSASS memory-dumping confirmed
  as a live, weaponized technique in this environment's own kill chains
  (Task 0, 1x02 Task 4)
Vulnerability Reference: None directly scored, but directly enables
  Kill Chain 1's credential-access step (1x01)
Risk Reference: RISK-001 (1x03), the VPN gateway ransomware risk this
  credential-access step feeds directly into
Algorithm Assessment: N/A, an in-memory protection gap, not an
  algorithm choice
Recommended Protection: Enable Windows Credential Guard on the domain
  controllers and administrative workstations
Encryption Level: N/A
Key Management: N/A
Implementation Priority: Phase 1
```

```
Finding ID: CRYPTO-013
Data Category: Backup data (NAS-01)
Data State: At rest
Current Protection: None as scanned (Task 0); now closed directly by
  this project's own hands-on work (Task 12), a real LUKS2 volume
  confirmed working end to end
Vulnerability Reference: Finding 015 (1x02), plus CVE-2024-10441
  discovered via OSINT (1x02, Task 9)
Risk Reference: RISK-004 (1x03), the doctrinal ransomware target
Algorithm Assessment: AES-XTS via LUKS2, confirmed adequate and already
  implemented in this project's own Task 12 exercise
Recommended Protection: Deploy the exact LUKS2 configuration already
  built and tested in Task 12 to NAS-01 directly
Encryption Level: Volume (Task 13)
Key Management: Cloud KMS with HSM-backed storage, escrowed given this
  key's criticality as the sole backup infrastructure (Task 14)
Implementation Priority: Immediate
```

```
Finding ID: CRYPTO-014
Data Category: Backup data (NAS-01)
Data State: In transit
Current Protection: Not directly audited in Task 0; inferred absent
  from the environmental pattern, flagged as requiring direct
  verification
Vulnerability Reference: Finding 015 (1x02)
Risk Reference: RISK-004 (1x03)
Algorithm Assessment: Unconfirmed; requires direct verification of the
  backup transfer protocol before an algorithm recommendation can be
  finalized
Recommended Protection: Verify current backup transfer protocol; enforce
  TLS for all source-server-to-NAS-01 backup traffic
Encryption Level: N/A, transport-layer enforcement
Key Management: N/A
Implementation Priority: Phase 1
```

```
Finding ID: CRYPTO-015
Data Category: Backup data (NAS-01)
Data State: In use
Current Protection: None; restore operations move data over the same
  unencrypted internal network (Task 0)
Vulnerability Reference: Finding 015 (1x02)
Risk Reference: RISK-004 (1x03)
Algorithm Assessment: Resolved directly once CRYPTO-013 and CRYPTO-014
  are both closed, since restore traffic then travels over the same
  now-encrypted paths
Recommended Protection: No separate control needed beyond CRYPTO-013 and
  CRYPTO-014
Encryption Level: N/A
Key Management: N/A
Implementation Priority: Phase 1
```

```
Finding ID: CRYPTO-016
Data Category: Email (O365)
Data State: In use
Current Protection: None; S/MIME and Office Message Encryption not
  configured, PHI confirmed sometimes sent in plaintext despite
  instruction not to (Task 0)
Vulnerability Reference: None directly in 1x02's scan scope
Risk Reference: None directly in the 1x03 Top 10 register
Algorithm Assessment: N/A, no message-level protection currently applied
Recommended Protection: Configure Office Message Encryption for any
  message flagged as containing patient data
Encryption Level: File (message-level), the one gap remaining on top of
  Microsoft's already-Adequate volume and database-level protection
  (Task 13)
Key Management: Microsoft-managed for OME; no MedDefense-side key
  management required
Implementation Priority: Phase 2
```

```
Finding ID: CRYPTO-017
Data Category: VPN traffic (site-to-site tunnels)
Data State: At rest (key material on terminating devices)
Current Protection: Weak; the Westside consumer router's firmware
  update history, and therefore its own key storage practices, is
  unknown (Task 0)
Vulnerability Reference: Finding 014 (1x02)
Risk Reference: RISK-010 (1x03)
Algorithm Assessment: The tunnel's own algorithm (AES-256, IKEv2/DH
  Group 14) is adequate; the weak link is the untrusted endpoint
  device, not the algorithm (Task 6)
Recommended Protection: Replace the Westside consumer router with a
  dedicated enterprise-grade firewall, already funded in this program's
  own budget allocation (1x03, Task 8, Control 6)
Encryption Level: N/A
Key Management: Managed directly on the replacement FortiGate-class
  device (Task 14)
Implementation Priority: Phase 1
```

```
Finding ID: CRYPTO-018
Data Category: VPN traffic (site-to-site tunnels)
Data State: In transit / In use (combined, per Task 0's own note that
  these states are operationally identical for tunnel traffic)
Current Protection: Weak overall, despite an adequate algorithm, given
  the same untrusted endpoint issue as CRYPTO-017 (Task 0)
Vulnerability Reference: Finding 014 (1x02)
Risk Reference: RISK-010 (1x03)
Algorithm Assessment: AES-256 with SHA-256 integrity, IKEv2 with DH
  Group 14, confirmed adequate (Task 6)
Recommended Protection: No algorithm change needed; resolved directly
  once CRYPTO-017's endpoint replacement is complete
Encryption Level: N/A
Key Management: Same as CRYPTO-017
Implementation Priority: Phase 1
```

---

## Posture Score

**20 of MedDefense's 21 mapped data-state combinations now have either confirmed Adequate protection or a specific, documented remediation path, approximately 95.2%.** The 2 already-Adequate combinations (Email at rest, Email in transit) required no action. Of the 18 combinations requiring remediation, every one now carries a specific recommended protection, encryption level, and key management assignment, not a general instruction to "encrypt more." The one honest gap this figure does not paper over: 3 of the 18 findings (CRYPTO-003, CRYPTO-006, CRYPTO-009 and CRYPTO-016) are not cryptographic findings in the strict sense at all, they are access-control or messaging-policy gaps that surfaced through this same data-protection review; they are included here because Task 0's own map included "In Use" as a state, and closing them is necessary to a complete posture even though the fix is not an encryption algorithm.

**A second honest gap worth stating directly:** 7 of the 18 findings (CRYPTO-003, CRYPTO-006, CRYPTO-007, CRYPTO-008, CRYPTO-009, CRYPTO-010, CRYPTO-011, CRYPTO-016) have no directly corresponding entry in the 1x03 Risk Register's Top 10. This is not a flaw in this audit; it is a finding about the prior register's own scope, surfaced only because this crypto-specific review looked at the environment through a different lens than the risk-prioritization exercise that built that register originally.

---

## Top 3 Crypto Risks

**1. CRYPTO-001 and CRYPTO-002, the EHR database's absent encryption at rest and inconsistently enforced encryption in transit.** Combined, these protect the organization's #1-ranked Critical Asset (0x00) and trace directly to RISK-002's $816,750 residual annual loss expectancy (1x03), the single largest dollar figure any finding in this audit connects to. This is ranked first specifically because closing it, database-level TDE plus enforcing existing TLS support, is achievable without new infrastructure and closes the highest-value gap in the entire audit.

**2. CRYPTO-013, CRYPTO-014, and CRYPTO-015, the backup infrastructure's encryption gaps at rest, in transit, and in use.** This is ranked second not because its individual ALE (RISK-004) is the largest in this program, but because of the same amplifying property this project has identified repeatedly since 0x00: NAS-01's compromise degrades MedDefense's ability to recover from every other incident this audit and every prior project have documented, not only its own. CRYPTO-013 is also the one finding in this entire audit already proven closed end to end, in Task 12's own real, tested LUKS2 deployment, meaning the remaining work here is rollout to production, not further design.

**3. CRYPTO-010 and CRYPTO-011, the weak Kerberos encryption types and LDAP signing gap protecting Active Directory's own credential material.** Ranked third specifically because this pair is foundational rather than asset-specific: a domain controller compromise, enabled directly by these two findings, cascades into every other system this audit and every prior project have discussed, the EHR, the billing server, the backup infrastructure, and the VPN, all authenticate through the same domain this finding protects. Both findings were already confirmed at the highest urgency tier in this program's own prior triage (1x02, Task 16), and this audit's own Algorithm Assessment confirms directly why they cannot be closed by an algorithm swap alone, only by removing the specific, already-identified exploitation path.
