# MedDefense Health Systems: The Data Classification Matrix

**Prepared by:** Aïda Sylla, Security Analyst **Source material:** Current 2026 HIPAA cloud residency guidance researched directly for Part 4, cross-referenced against the Obfuscation Toolkit's masking design (Task 7), the Encryption Levels map (Task 13), and the Certificate Lifecycle plan (Task 17) **Purpose:** Encryption is a spectrum, not a switch. This document defines the classification that drives every encryption, access-control, and key-management decision this project has made, and makes that logic explicit and repeatable rather than case-by-case.

---

## Part 1: Data Type Inventory

```
Type: Regulated (HIPAA/PHI)
Examples: Patient diagnoses and treatment records (ehr-db-01), medical
  imaging and embedded DICOM headers (pacs-srv-01), any billing record
  containing a diagnosis or procedure code, audit logs of who accessed
  patient data (themselves a HIPAA Security Rule requirement, not
  merely operational logging)
Overlaps: Nearly always overlaps with PII (a diagnosis is meaningless
  without the identifiable patient it belongs to) and frequently with
  Financial (billing records tied to a diagnosis code are PHI, not
  merely financial data, under HIPAA's own definition)
```

```
Type: PII (Personally Identifiable Information)
Examples: Patient names, dates of birth, Social Security Numbers,
  addresses, employee records, vendor contact information
Overlaps: Overlaps with Regulated whenever the individual is a patient;
  overlaps with Financial whenever the PII is a payment credential
  (a credit card number is both PII and Financial simultaneously)
```

```
Type: Financial
Examples: Billing records (billing-srv-01), credit card numbers, MedDefense's own budget and Board financial reporting (1x03), payroll data
Overlaps: Overlaps with Regulated when tied to a patient's diagnosis or
  treatment, overlaps with PII when it identifies a specific person's
  account or payment method
```

```
Type: Intellectual Property
Examples: Genuinely thin for MedDefense, stated honestly rather than
  forced: this project's own prior work (1x03, Task 2, CIS Control 16)
  already confirmed MedDefense has no internally developed software.
  The closest legitimate example is any proprietary internal clinical
  care protocol or pathway MedDefense has developed itself, if one
  exists; this category should not be inflated with data that more
  accurately belongs elsewhere.
Overlaps: Minimal by the same reasoning above
```

```
Type: Legal
Examples: Vendor contracts (BD, Philips, MedTech Solutions), Business
  Associate Agreements, the Incident Response Plan (1x03, Task 13),
  breach notification records, employment records
Overlaps: Overlaps with Confidential-level operational data (contract
  terms are both legal and business-sensitive) and with Regulated when
  the document is a BAA specifically governing PHI handling
```

```
Type: Operational
Examples: Network diagrams and the segmentation architecture (1x03,
  Task 14), the Security Strategy Document (1x03, Task 17), staff
  schedules, meeting minutes, the certificate inventory this project's
  own Task 17 (1x04) just established
Overlaps: Overlaps with Confidential for anything revealing MedDefense's
  own security posture to a potential attacker, and with Legal for
  governance-related operational records
```

---

## Part 2: Classification Levels

```
Level: Public
Who Can Access: Anyone, including the general public and patients with
  no account or relationship to MedDefense (hospital address, visiting
  hours, general service listings)
Encryption Required, At Rest: None required for confidentiality, since
  the data has no confidentiality requirement by definition; integrity
  protection (a signed or checksummed publication process) is still
  good practice to prevent tampering.
Encryption Required, In Transit: Standard TLS for the public-facing web
  presence, the same baseline this project's own Task 11 already
  established for the patient portal generally, not for confidentiality
  of this specific content but for general web security hygiene.
If Exposed: Minimal impact; this data is already intended for public
  disclosure, so "exposure" in the confidentiality sense does not
  meaningfully apply, though unauthorized tampering (altering posted
  visiting hours, for example) remains a real, separate risk.
```

```
Level: Internal
Who Can Access: MedDefense staff generally, without a documented,
  role-specific need beyond simply being an employee (staff directory,
  meeting schedules, general internal announcements)
Encryption Required, At Rest: AES-128 or AES-256 (Task 6), applied at
  the File or Database level depending on the system (Task 13); not a
  strict compliance mandate, but consistent baseline practice.
Encryption Required, In Transit: TLS 1.2 or higher for any internal
  system carrying this data across the network.
If Exposed: Minor internal awkwardness or a small competitive
  disadvantage if a competitor saw internal scheduling; not a
  regulatory event and not a patient-safety concern.
```

```
Level: Confidential
Who Can Access: Specific departments or leadership roles with a
  documented business need, mapped directly to this program's own
  governance structure (1x03, Task 4): Finance for financial reports,
  Legal or James Chen for vendor contracts, IT leadership for security
  architecture documents
Encryption Required, At Rest: AES-256 mandatory (Task 6), Database or
  File level depending on the specific system (Task 13), key managed
  through the KMS this project's own Task 14 already designed.
Encryption Required, In Transit: TLS 1.2 minimum, TLS 1.3 preferred
  (Task 11), no exceptions for internal-only traffic given this
  project's own Task 0 finding that "internal" traffic on MedDefense's
  historically flat network was never actually isolated from broader
  exposure.
If Exposed: Real business harm: financial loss, breach of a vendor
  contract's confidentiality terms, or, for security architecture
  documents specifically, direct uplift to an attacker planning against
  MedDefense's own defenses, the exact concern this project's own Task
  15 (1x03) red team exercise demonstrated is not hypothetical.
```

```
Level: Restricted
Who Can Access: Named individuals or roles with a specific, documented
  need-to-know, exactly the role-based visibility this project's own
  Task 7 already designed in detail (a nurse sees a full diagnosis, a
  billing clerk sees only a masked SSN fragment, reception sees
  neither); patient records, credentials, and encryption keys all
  belong at this level.
Encryption Required, At Rest: AES-256 mandatory, no exception, Database
  or Volume level per this project's own Task 13 recommendation for
  each specific system, key management through KMS with HSM-backed
  storage and escrow for the highest-criticality keys (Task 14).
Encryption Required, In Transit: TLS 1.2 minimum, TLS 1.3 preferred,
  enforced without exception, directly closing the enforcement gaps
  this project's own Task 15 audit already found (PostgreSQL and MySQL
  both permitting unencrypted connections despite supporting TLS).
If Exposed: A reportable HIPAA breach requiring mandatory patient
  notification and OCR reporting, carrying the exact financial exposure
  this program's own Risk Register already quantified directly
  (RISK-002, 1x03, $816,750 annual expected loss for the EHR database
  specifically), not a hypothetical worst case.
```

---

## Part 3: The Classification Decision Tree

```
START: A MedDefense employee has a new type of data and needs to
classify it.

Q1: Does this data identify a specific patient and relate to their
    health, treatment, or payment for care?
    YES -> RESTRICTED. Stop here; this is PHI under HIPAA and no other
           question in this tree can lower that classification.
    NO  -> continue to Q2

Q2: Does this data include credentials, encryption keys, or other
    material that could be used to directly access a Restricted-level
    system?
    YES -> RESTRICTED. A key or password protecting patient data
           inherits that data's classification, since compromising the
           key has the same practical effect as compromising the data
           itself (this project's own Task 14 key management design
           depends on this principle directly).
    NO  -> continue to Q3

Q3: Does this data include financial account numbers, Social Security
    Numbers, or other information that could directly enable identity
    theft or financial fraud if exposed?
    YES -> CONFIDENTIAL at minimum; escalate to RESTRICTED if the data
           is also tied to a specific patient (in which case Q1 already
           applies) or if it is a live credential (in which case Q2
           already applies).
    NO  -> continue to Q4

Q4: Is this data covered by a signed contract, legal agreement, or
    active legal proceeding that restricts its disclosure?
    YES -> CONFIDENTIAL.
    NO  -> continue to Q5

Q5: Is this internal operational data (schedules, internal
    communications, non-sensitive planning documents) not covered by
    any of the above?
    YES -> INTERNAL.
    NO  -> continue to Q6

Q6: Is this data already intended for public disclosure, with no
    confidentiality requirement at all?
    YES -> PUBLIC.
    NO  -> Default to INTERNAL and escalate to the Deputy CISO for a
           manual classification decision; an ambiguous case should
           never default to a lower classification than its actual risk
           warrants, consistent with this program's own consistent
           practice of stating uncertainty honestly rather than
           assuming the safer-sounding answer.
```

---

## Part 4: Sovereignty and Geolocation

**Why data sovereignty matters for healthcare, stated directly.** Data sovereignty matters because the physical and legal jurisdiction where data is stored determines which government's laws, courts, and compulsory disclosure powers can reach it, independent of whatever technical protections MedDefense itself applies; a hospital's patient records stored in a foreign jurisdiction could become subject to that jurisdiction's own legal demands for access, entirely outside MedDefense's control or even its knowledge.

**HIPAA implications if the AWS region sits in a different state or country, verified directly rather than assumed.** HIPAA itself does not explicitly mandate that PHI remain within the United States; the HIPAA Security Rule requires appropriate safeguards for electronic PHI without specifying geography directly. The real mechanism governing this in practice is the Business Associate Agreement MedDefense must have with AWS before storing any PHI there at all, and AWS's own BAA covers only its specifically designated "HIPAA-eligible" services, with eligibility that can vary by region, meaning MedDefense must verify eligibility for the exact region chosen, not merely assume any AWS region is automatically covered. A region within the United States but in a different state introduces comparatively modest additional complexity (primarily state-level privacy law variation); a region outside the United States entirely introduces the jurisdictional exposure described above directly, which is why, in practice, most healthcare organizations' BAAs specify US-only processing and storage as a deliberate, explicit contractual choice, not an oversight.

**Does encryption mitigate the sovereignty concern? Partially, and this distinction matters.** Encryption is necessary, both HIPAA's Security Rule and AWS's own BAA require it directly, and this project's own Task 12 and Task 14 work already builds exactly this control for NAS-01's backup data specifically. But encryption reduces the risk of unauthorized technical access to the data; it does not eliminate the separate, legal question of which jurisdiction's courts and government agencies have authority to compel disclosure of that data, encrypted or not, from whoever holds the keys or the infrastructure. **The correct, complete answer for MedDefense's cloud backup migration is therefore not encryption alone: it requires encryption (already designed in this project's own Task 12 and Task 14 work) combined with a deliberate, contractually specified US-region requirement in the BAA itself**, closing the technical risk and the jurisdictional risk as two separate, both-necessary controls, not one control standing in for the other.
