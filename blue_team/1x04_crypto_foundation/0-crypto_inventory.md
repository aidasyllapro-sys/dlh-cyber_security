# MedDefense Health Systems: The Crypto Inventory

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO, and Sarah Park, IT Director **Source material:** `meddefense-crypto-audit-notes.txt` (Sarah Park's working notes), cross-referenced against the Vulnerability Assessment findings (1x02) and the Risk Register (1x03) **Purpose:** Make the invisible visible. Every cell below marked Absent is a gap the rest of this project exists to close.

**A methodology note, stated upfront:** every cell is populated from direct evidence in Sarah's audit notes wherever it exists. Two categories, VPN traffic and backup data, require honest interpretive choices, explained directly in their sections below, rather than left silently unaddressed or invented outright.

---

## Data Protection Map

### 1. Patient Medical Records (EHR data in PostgreSQL)

```
State: At Rest
Protection: None. The PostgreSQL data directory sits on an unencrypted
  ext4 filesystem.
Evidence: Crypto audit notes, "Patient Data" section, direct quote:
  "If someone gets root on the server (or pulls the drive), every
  patient record is readable in plaintext."
Status: Absent
```

```
State: In Transit
Protection: Partial. PostgreSQL is configured with ssl=on, but
  pg_hba.conf contains both "hostssl" and "hostnossl" entries for the
  same 10.10.0.0/16 range, meaning the application can connect without
  encryption and there is no way to confirm which connections actually
  use it.
Evidence: Crypto audit notes; directly compounds Finding 003 (1x02,
  ehr-db-01 network-wide exposure), since an unencrypted connection
  path exists on top of an already-unrestricted network path.
Status: Weak
```

```
State: In Use
Protection: None. Records decrypt in memory on ehr-srv-01 and transmit
  to the browser with no additional session protection. Nurse station
  workstations have no automatic screen lock (screensaver timeout set
  to "Never").
Evidence: Crypto audit notes, direct quote on Group Policy
  configuration.
Status: Absent
```

### 2. Financial/Billing Data (MySQL on billing-srv-01)

```
State: At Rest
Protection: None. The MySQL data directory sits on an unencrypted ext4
  filesystem, containing patient names, dates of birth, Social Security
  Numbers, insurance policy numbers, credit card last-4-digits, and
  three years of billing records.
Evidence: Crypto audit notes. The notes further cite the 0x00 crypto-
  miner incident directly: the forensic responder found all database
  files readable from the filesystem without MySQL credentials at all,
  meaning the crypto-miner operator could have exfiltrated this exact
  data, though no evidence confirms they did.
Status: Absent
```

```
State: In Transit
Protection: Weak. MySQL is bound to 0.0.0.0 and does not enforce SSL;
  the billing application connects via the plaintext MySQL protocol
  over the flat network.
Evidence: Crypto audit notes; directly compounds Finding 006 (1x02,
  MySQL unrestricted network binding).
Status: Weak
```

```
State: In Use
Protection: Not directly audited in Sarah's notes for this specific
  system. Stated honestly rather than invented: the billing application
  shares the same general architecture as the EHR (data decrypted in
  memory for display, per the EHR's own documented pattern above), and
  in the absence of evidence to the contrary, the same absence of
  in-use protection is the reasonable working assumption, flagged here
  as an inference, not a confirmed audit finding.
Status: Absent (inferred by architectural analogy; recommended for
  direct verification)
```

### 3. Medical Images (DICOM on PACS)

```
State: At Rest
Protection: None. PACS stores images on local disk without encryption;
  DICOM headers are partially plaintext and readable with any DICOM
  viewer or even a standard text editor.
Evidence: Crypto audit notes; directly confirms Finding 024 (1x02,
  DICOM service detected without encryption).
Status: Absent
```

```
State: In Transit
Protection: None. DICOM TLS is a defined standard (DICOM PS3.15) but is
  not configured anywhere in MedDefense's environment. Imaging traffic,
  including patient identifiers embedded in DICOM headers (name, date
  of birth, MRN, study description), traverses the network between the
  MRI workstation, radiology workstations, and the PACS server entirely
  in cleartext.
Evidence: Crypto audit notes; directly confirms Finding 024 (1x02).
Status: Absent
```

```
State: In Use
Protection: Not directly audited in Sarah's notes. By the same
  architectural analogy applied to billing data above, radiology
  workstations displaying imaging data have no documented additional
  in-use protection, flagged as an inference rather than a confirmed
  finding.
Status: Absent (inferred by architectural analogy; recommended for
  direct verification)
```

### 4. Credentials (Active Directory, application passwords)

```
State: At Rest
Protection: Weak. Active Directory uses NTHash (MD4-based) for NTLM
  compatibility by default, a legacy, cryptographically weak hashing
  scheme still in active use for backward compatibility.
Evidence: Crypto audit notes.
Status: Weak
```

```
State: In Transit
Protection: Weak. The domain controllers support Kerberos with AES-256
  and AES-128 alongside the legacy RC4 and DES encryption types, both
  still enabled. LDAP is not encrypted by default, and LDAP signing is
  not required.
Evidence: Crypto audit notes; directly confirms Finding 018 (1x02, weak
  Kerberos encryption types, enabling Kerberoasting against RC4-
  encrypted service tickets) and Finding 007 (1x02, LDAP signing not
  required).
Status: Weak
```

```
State: In Use
Protection: Not separately documented in Sarah's notes as a dedicated
  audit item, but directly relevant to this program's own prior work:
  1x02's Exploit Hunt (Task 4) confirmed Mimikatz/LSASS memory-dumping
  techniques as a live, weaponized step in this environment's own
  documented kill chains, meaning in-memory credential material is not
  confirmed protected by any additional control (such as Credential
  Guard) anywhere in this program's evidence base.
Status: Weak
```

### 5. Backup Data (NAS-01)

```
State: At Rest
Protection: None. The Synology NAS stores all backup data on a RAID-5
  array with no encryption layer. Synology's own built-in "shared
  folder encryption" feature (AES-256-CBC) is available but not
  enabled.
Evidence: Crypto audit notes; directly confirms Finding 015 (1x02, NAS
  interface exposure and unencrypted storage).
Status: Absent
```

```
State: In Transit
Protection: Not directly audited in Sarah's notes; her audit documents
  the NAS's storage state and management-interface exposure (Finding
  15) but does not separately address whether the backup transfer
  traffic itself, from source servers to NAS-01, is encrypted in
  transit. Given the consistent pattern across every other system
  audited (PostgreSQL, MySQL, DICOM all confirmed unencrypted or
  weakly enforced in transit), the reasonable inference is that backup
  traffic follows the same pattern, but this is stated explicitly as
  an inference requiring direct verification, not a confirmed finding.
Status: Absent (inferred from environmental pattern; recommended for
  direct verification)
```

```
State: In Use
Protection: None. During a restore operation, backup data moves from
  NAS-01 to a target system over the same internal network already
  documented as unencrypted elsewhere in this map; since encryption at
  rest is not enabled in the first place, there is no decryption step
  to protect during this process either.
Evidence: Derived directly from the At Rest finding above; Sarah's own
  note on the encryption/key-management design problem is directly
  relevant here: "If we encrypt the backups on the NAS and the key is
  stored on the NAS, and ransomware encrypts the NAS, we lose both the
  backups AND the key. This needs to be designed properly."
Status: Absent
```

### 6. Email (O365)

```
State: At Rest
Protection: Adequate. BitLocker on Microsoft's datacenter disks, plus
  per-mailbox encryption with Microsoft-managed keys.
Evidence: Crypto audit notes. Worth noting directly: keys are Microsoft-
  managed, not MedDefense-controlled, a real but acceptable limitation
  for a mid-size hospital's baseline requirements.
Status: Adequate
```

```
State: In Transit
Protection: Adequate. TLS 1.2 enforced for all Exchange Online
  connections, a Microsoft-side enforcement in place since 2023.
Evidence: Crypto audit notes.
Status: Adequate
```

```
State: In Use
Protection: None. S/MIME and Office Message Encryption are not
  configured. Sensitive patient information is sometimes emailed
  between physicians in plaintext despite explicit instruction not to.
Evidence: Crypto audit notes, direct quote: "I've told them not to
  email PHI. They do it anyway."
Status: Absent
```

### 7. VPN Traffic (Site-to-Site Tunnels)

**A note on this category's structure, stated directly:** VPN traffic does not naturally separate into three distinct states the way stored or displayed data does. "At Rest" is reinterpreted here as the protection of the VPN's own cryptographic key material when stored on the terminating devices, since that is the only meaningful "at rest" component a tunnel has. "In Transit" and "In Use" are treated together, since data flowing live through an active tunnel has no separate "processing" state distinct from its transit.

```
State: At Rest (key material storage on terminating devices)
Protection: Unknown/Weak. Not directly audited for the FortiGate
  itself in Sarah's notes. For the Westside endpoint specifically, a
  consumer-grade Netgear Nighthawk router terminates one end of the
  tunnel, and its firmware update history, which governs how securely
  it stores its own key material, is explicitly documented as unknown.
Evidence: Crypto audit notes, direct quote: "The firmware update
  history on this device is unknown." Directly ties to Finding 014
  (1x02) and RISK-010 (1x03 Risk Register).
Status: Weak
```

```
State: In Transit / In Use (combined, per the note above)
Protection: AES-256 with SHA-256 for integrity; IKEv2 key exchange with
  DH Group 14, for both the Central-to-Westside and Central-to-HQ
  tunnels.
Evidence: Crypto audit notes, describing this configuration as
  "appears adequate based on the FortiGate configuration." This
  document rates the overall protection state more cautiously than
  that phrase alone suggests, however: Sarah's own note states directly
  that "if the router's IPSec implementation has a vulnerability, the
  tunnel's encryption could be compromised regardless of the algorithm
  strength." Algorithm choice is adequate; the overall protection state
  is not, given the documented, unverified endpoint.
Status: Weak
```

---

## Gap Summary

|Status|Count|Cells|
|---|---|---|
|Adequate|2|Email (At Rest), Email (In Transit)|
|Weak|8|EHR (In Transit), Billing (In Transit), Credentials (At Rest), Credentials (In Transit), Credentials (In Use), VPN (At Rest), VPN (In Transit/Use, two cells combined per the note above)|
|Absent|11|EHR (At Rest, In Use), Billing (At Rest, In Use), DICOM (At Rest, In Transit, In Use), Backup (At Rest, In Transit, In Use), Email (In Use)|
|**Total**|**21**|**7 categories x 3 states**|

**Overall crypto coverage: 2 of 21 cells (9.5%) rated fully Adequate.** A weighted view, crediting Adequate as full protection, Weak as half, and Absent as none, gives a more complete picture of partial coverage: (2 x 1.0 + 8 x 0.5 + 11 x 0.0) / 21 = 6.0 / 21, approximately **28.6% weighted coverage.**

**The pattern is not random.** The only fully Adequate cells in this entire matrix belong to a system MedDefense does not operate itself: Microsoft's own O365 infrastructure. Every system MedDefense directly controls, the EHR, the billing database, medical imaging, credentials, and backups, has at least one Absent or Weak cell, and the majority are Absent outright. This is the same finding this program's own Vulnerability Profile analysis (1x02, Task 21) already reached through an entirely different lens: MedDefense's core weakness is not primarily defective software, it is a consistent absence of a hardening and protection discipline applied to systems it already owns and operates.
