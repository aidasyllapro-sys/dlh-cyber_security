# MedDefense Health Systems: The HIPAA Crypto Checkpoint

**Prepared by:** Aïda Sylla, Security Analyst **Source material:** 45 CFR §164.312, verified directly against the eCFR and Cornell Law School's own published text of the HIPAA Security Rule, cross-referenced against the Crypto Inventory (Task 0), the Crypto Posture Audit (Task 15), and Finding 003, Finding 005, Finding 018, and Finding 024 (1x02) **Purpose:** "Addressable" does not mean optional. This checkpoint maps the specific regulatory text MedDefense is measured against to its actual, current state, not an assumed one.

**A current regulatory development worth stating directly, since it strengthens rather than weakens the case for treating every requirement below as effectively mandatory today:** the January 2025 Notice of Proposed Rulemaking to the HIPAA Security Rule proposes converting every currently "addressable" implementation specification, including encryption at rest and in transit, into a "required" one outright. This proposal has not yet taken final effect at the time of this checkpoint, but MedDefense's compliance posture should not be built around exploiting the "addressable" label's current flexibility, given where the regulation is already headed.

---

## HIPAA Crypto Compliance Table

```
HIPAA Requirement: Encryption and decryption of ePHI
Citation: 45 CFR §164.312(a)(2)(iv), an Addressable implementation
  specification under the Access Control standard
What It Mandates: A mechanism to render ePHI unusable, unreadable, or
  undecipherable to unauthorized persons while stored, and to enable
  authorized decryption when needed.
Current MedDefense State: None, confirmed directly across every major
  ePHI store this project's own Crypto Inventory (Task 0) examined: the
  patient database (ehr-db-01), the billing database where diagnosis-
  linked billing records also constitute ePHI, and medical imaging on
  pacs-srv-01 all showed "Encryption at rest: None."
Compliant?: No.
Gap / Remediation: This is the single largest gap this checkpoint
  identifies. Remediation is already designed in this project's own
  Task 13 (Database-level TDE for the EHR and billing databases,
  File-level for DICOM imaging) and partially proven in Task 12 (the
  real, tested LUKS2 volume encryption already built for backup
  storage); what remains is production deployment, not further design.
```

```
HIPAA Requirement: Transmission security
Citation: 45 CFR §164.312(e)(1), a Standard (not merely an
  implementation specification): "Implement technical security measures
  to guard against unauthorized access to electronic protected health
  information that is being transmitted over an electronic
  communications network."
What It Mandates: Technical measures protecting ePHI generally while it
  moves across any network, a broader standard than the specific
  encryption implementation specification listed separately below.
Current MedDefense State: Inconsistent and, in several confirmed cases,
  absent. PostgreSQL connections to ehr-db-01 permit unencrypted
  "hostnossl" connections alongside encrypted ones with no way to
  confirm which path any given connection uses (Finding 003); DICOM
  imaging traffic, including embedded patient identifiers, traverses
  the network in cleartext entirely (Finding 024).
Compliant?: No.
Gap / Remediation: Remove every "hostnossl" entry from pg_hba.conf,
  enforcing "hostssl" exclusively; enable DICOM TLS (PS3.15) between the
  MRI workstation, radiology workstations, and pacs-srv-01, both already
  identified as specific, named findings in this project's own Crypto
  Posture Audit (Task 15, CRYPTO-002 and CRYPTO-008).
```

```
HIPAA Requirement: Encryption of ePHI in transit
Citation: 45 CFR §164.312(e)(2)(ii), an Addressable implementation
  specification under the Transmission Security standard: "Implement a
  mechanism to encrypt electronic protected health information whenever
  deemed appropriate."
What It Mandates: The specific encryption mechanism supporting the
  broader Transmission Security standard above, distinct from it in the
  regulation's own structure even though closely related.
Current MedDefense State: Partially addressed for one specific channel,
  absent for others. The patient portal's own TLS configuration was
  confirmed weak in Finding 005 (TLS 1.0 permitted alongside TLS 1.2)
  but this project's own Task 11 has already designed the specific
  hardened configuration to close it. The database and DICOM channels
  above remain unaddressed by that specific fix.
Compliant?: No, though closer to compliant than the at-rest requirement
  above, given the portal-specific remediation already exists in
  documented, ready-to-deploy form.
Gap / Remediation: Deploy the hardened Apache TLS configuration this
  project's own Task 11 already built (TLS 1.2/1.3 only, ECDHE cipher
  suites, HSTS); this alone does not close the database or DICOM
  transit gaps, which require the separate remediations listed above.
```

```
HIPAA Requirement: Authentication
Citation: 45 CFR §164.312(d), a Standard: "Implement procedures to
  verify that a person or entity seeking access to electronic protected
  health information is the one claimed."
What It Mandates: Verification that whoever is accessing ePHI is
  genuinely who they claim to be, not merely that a password matched.
Current MedDefense State: Materially weakened by two confirmed,
  specific gaps rather than absent outright: Active Directory's NT hash
  is unsalted (confirmed directly against Microsoft's own documentation
  in this project's Task 3), and RC4/DES remain enabled as Kerberos
  encryption types (Finding 018), together enabling Kerberoasting, an
  offline attack against exactly the authentication mechanism this
  standard requires to be trustworthy. MFA for remote and administrative
  access was funded in this program's own budget allocation (1x03, Task
  8) as one of the six controls selected, though this checkpoint cannot
  confirm production deployment status without a direct system check.
Compliant?: Partial. The standard's intent, verifying identity, is
  undermined by Finding 018's still-open exploitation path regardless of
  whether MFA has completed deployment, since Kerberoasting operates
  entirely offline, bypassing any MFA prompt at the point of initial
  authentication.
Gap / Remediation: Disable RC4 and DES as supported Kerberos encryption
  types domain-wide, enforcing AES-256 exclusively, closing Finding 018
  directly; confirm and document MFA deployment status for all remote
  and administrative access as a specific, dated verification, not an
  assumed-complete budget line item.
```

---

## Could MedDefense Pass a HIPAA Security Audit Today?

**No, not as currently configured, and this checkpoint's own table already shows why directly rather than as a general impression.** Three of the four requirements examined here are confirmed non-compliant, and the fourth is only partially addressed, with a specific, still-open exploitation path undermining its intent even where a compensating control (MFA) may already be funded. **The single deficiency an auditor would cite first and most critically is the complete absence of encryption at rest for the primary ePHI store, the 50,000-patient EHR database on ehr-db-01.** This is the most citable finding specifically because it is the least ambiguous: unlike the transmission security gaps, which involve a genuine mechanism that exists but is inconsistently enforced, or the authentication gap, which involves a specific but narrower exploitation path, the EHR database's at-rest encryption is not weak, inconsistent, or partially implemented, it is entirely absent, confirmed directly by this project's own Crypto Inventory, protecting the exact data category, patient diagnoses and treatment records, that 45 CFR §164.312(a)(2)(iv) exists specifically to protect. An auditor does not need to evaluate algorithm strength, key management sophistication, or enforcement consistency to cite this finding; the absence itself, on the organization's single largest and most sensitive ePHI store, is sufficient on its own.
