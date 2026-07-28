# MedDefense Health Systems: The Encryption Levels

**Prepared by:** Aïda Sylla, Security Analyst **Source material:** Cross-referenced against the Crypto Inventory (Task 0), the Obfuscation Toolkit's tokenization design (Task 7), the Disk Encryption Lab (Task 12), and the Algorithm Reference Table (Task 6) **Purpose:** "Encrypt the database" is not one decision, it is a choice between at least six structurally different techniques, each with different performance, key management, and operational tradeoffs. Choosing wrong leaves data exposed or breaks a clinical workflow staff will not tolerate.

---

## Comparison of the Six Encryption Levels

```
Level: Full-disk
Scope: Entire physical or virtual disk
Performance Impact: Low. Modern CPUs' AES-NI hardware acceleration
  makes block-level encryption of an entire disk largely transparent,
  typically a few percent overhead at most, since the encryption
  happens once at the block layer beneath the filesystem.
Key Management: Simplest of the six levels: a single key (or a small
  number of key slots, as LUKS2 itself supports, confirmed directly in
  this project's Task 12) unlocks the entire disk at once. This
  simplicity is also its limitation: anyone with legitimate OS-level
  access sees everything decrypted, with no finer-grained control.
Best choice when: the primary threat is physical loss or theft of the
  device itself while powered off, since full-disk encryption protects
  data at rest but provides no protection once the OS is running and
  the disk is unlocked.
```

```
Level: Partition
Scope: One logical partition
Performance Impact: Effectively identical to full-disk, since the
  underlying mechanism is the same block-level encryption, just scoped
  to less of the physical disk.
Key Management: Similar simplicity to full-disk, but allows different
  partitions on the same physical disk to use different keys or
  policies, for example, encrypting a data partition while leaving a
  boot partition unencrypted so the system can actually start.
Best choice when: different regions of the same physical disk need
  different protection policies, most commonly separating a bootable
  system partition from a sensitive data partition.
```

```
Level: Volume
Scope: Logical volume (may span disks)
Performance Impact: Low, using the identical block-level mechanism as
  full-disk and partition encryption, confirmed directly in this
  project's own hands-on LUKS2 work (Task 12), where AES-XTS handled a
  500MB volume with no perceptible overhead.
Key Management: Same tier of simplicity as full-disk and partition, one
  key unlocks the volume, but with more architectural flexibility, a
  volume can be resized or span multiple physical disks via LVM, unlike
  a fixed partition.
Best choice when: storage needs flexibility a fixed partition cannot
  provide, exactly the case this project's own Task 12 demonstrated
  directly for backup storage that needs to grow over time.
```

```
Level: File
Scope: Individual files
Performance Impact: Low to moderate. Encryption can be applied
  selectively, only to files that actually need it, but requires
  application or filesystem-level support (encrypted filesystem
  overlays, or application-managed encryption), and each file
  open/close operation carries its own encrypt/decrypt cost rather than
  one transparent block-level pass.
Key Management: More granular than disk-level approaches: different
  files, or different users, can have different keys, meaning access
  can be revoked for one file or one user without affecting others, at
  the cost of more keys to track and rotate.
Best choice when: only a subset of files on a shared system are
  sensitive, or different files genuinely need different access
  policies, rather than uniform protection across everything stored.
```

```
Level: Database
Scope: Entire database or tablespace
Performance Impact: Low to moderate. Modern database engines implement
  Transparent Data Encryption (TDE) at the storage engine level,
  encrypting and decrypting largely transparently to the queries
  running against it, though I/O-heavy workloads see some measurable
  overhead beyond pure block-level encryption.
Key Management: A single database-level or per-tablespace key, managed
  either by the database engine itself or an external key management
  service; moderate complexity, since key rotation must be handled
  carefully to avoid locking out the running database.
Best choice when: an entire database needs protection against storage-
  level exposure (a stolen backup file, stolen storage media) while
  every existing SQL query against it continues working exactly as
  before, with no application rewrite required.
```

```
Level: Record
Scope: Individual fields or records
Performance Impact: The highest of the six levels. Encryption and
  decryption happen per-field on every read and write, and encrypted
  fields typically cannot be indexed or searched efficiently with
  normal SQL operators unless a specialized searchable-encryption
  scheme is used, a real functional tradeoff, not just a speed one.
Key Management: The most complex of the six levels, but also the most
  granular: different fields, or the same field for different users,
  can use different keys, enabling the kind of role-based visibility
  this project's own Task 7 already designed directly (a billing clerk
  seeing only the last four digits of an SSN, a nurse seeing none of
  it). This requires the application layer to handle encryption logic
  explicitly; the database engine itself does not do this
  transparently the way it does for database-level TDE.
Best choice when: specific individual data elements are sensitive
  enough to need the strictest, most granular access control available,
  and different roles genuinely need to see different parts of the
  same record, not the whole record or none of it.
```

---

## MedDefense Encryption Level Map

```
Data Store: Patient records in PostgreSQL (ehr-db-01)
Recommended Level: Database (Transparent Data Encryption), as the
  primary layer
Justification: This directly closes the exact gap this project's own
  Crypto Inventory (Task 0) confirmed: "Encryption at rest: NONE" for
  this specific database. Database-level TDE is the correct primary
  choice because it protects the entire patient record store from
  storage-level exposure while remaining fully transparent to the EHR
  application's existing SQL queries, no application rewrite required.
  Record-level encryption is recommended as a supplementary layer
  specifically for the small set of fields this project's own Task 7
  already identified as needing the strictest, role-based visibility
  (an SSN field, if one exists in this schema), not as a replacement
  for the database-level layer, since encrypting every field at the
  record level would impose the performance and searchability cost
  Task 7's own masking design was built specifically to avoid needing.
```

```
Data Store: Backup data on NAS-01
Recommended Level: Volume
Justification: This is not a new recommendation invented for this
  document; it is the exact design this project's own Task 12 already
  built and tested directly, LUKS2 volume encryption with AES-XTS and
  Argon2id key derivation, confirmed working end to end on a real
  system. Volume-level fits this specific use case precisely because
  backup storage needs to grow over time and may need to span multiple
  physical disks, exactly the flexibility a fixed partition does not
  provide.
```

```
Data Store: Financial records in MySQL (billing-srv-01)
Recommended Level: Database (Transparent Data Encryption), as the
  primary layer
Justification: Identical reasoning to the PostgreSQL recommendation
  above: this closes the same category of gap Task 0 confirmed for this
  specific database ("Encryption at rest: NONE"), transparently to the
  billing application's existing queries. One field deserves an
  explicit note rather than a record-level encryption recommendation:
  credit card numbers specifically should follow the tokenization
  design this project's own Task 7 already built, replacing the stored
  value with a non-derivable token rather than an encrypted value,
  since Task 7's own analysis already concluded tokenization is the
  stronger fit for this exact field given billing-srv-01's own
  documented compromise history.
```

```
Data Store: Medical images on PACS (pacs-srv-01)
Recommended Level: File
Justification: DICOM studies are stored and transferred as discrete
  files by their own protocol design, not as rows in a relational
  database the way patient or billing records are, making file-level
  encryption the natural fit for this specific storage architecture,
  directly closing the gap this project's own Crypto Inventory (Task 0)
  confirmed: "Storage: NONE" for PACS image files specifically. This
  also aligns with securing DICOM data consistently at rest and in
  transit, since Finding 024 (1x02) already established the same
  images are also transmitted in cleartext, a related but separate gap
  this level does not itself close.
```

```
Data Store: Email data in O365
Recommended Level: File (specifically, message-level encryption via
  S/MIME or Office Message Encryption), as the one remaining gap
Justification: This project's own Crypto Inventory (Task 0) already
  confirmed Microsoft provides adequate protection at both the volume-
  equivalent level (BitLocker on Microsoft's datacenter disks) and the
  database-equivalent level (per-mailbox encryption), rated Adequate in
  that assessment. The one confirmed gap sits one level up, at the
  individual message: S/MIME or OME is not configured, and Sarah Park's
  own notes confirm sensitive patient information is sometimes emailed
  in plaintext despite being told not to. This is the specific,
  narrower level that needs to be added on top of what Microsoft
  already provides, not a replacement for it.
```

```
Data Store: Employee laptops
Recommended Level: Full-disk
Justification: This is the textbook use case Part 1 of this document
  already describes directly: the realistic threat model for an
  employee laptop is loss or theft of the physical device, most often
  while powered off, exactly the scenario full-disk encryption (via
  BitLocker or LUKS) protects against, without requiring any per-file
  or per-application configuration that clinical and administrative
  staff would need to manage themselves.
```

```
Data Store: BD Alaris pump firmware/configuration
Recommended Level: File (the specific configuration and credential
  storage, not the full device)
Justification: This project's own Task 2 already established the
  reasoning that applies here directly: these are severely resource-
  constrained embedded devices, which is why ECC was recommended over
  RSA for this exact device class. Full-disk or volume-level encryption
  is often impractical on embedded medical device firmware, which
  frequently does not implement a general-purpose filesystem the way a
  server does. The realistic, achievable target is encrypting the
  specific configuration and credential storage where this project's
  own Finding 010 (1x02) already confirmed unchanged default
  credentials sit in plaintext, a narrower but directly actionable
  scope matching the device's actual architecture rather than an
  aspirational recommendation the hardware cannot support.
```
