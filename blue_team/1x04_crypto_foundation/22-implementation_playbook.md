# MedDefense Health Systems: The Implementation Playbook

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** Sarah Park, IT Director, and her team, for direct operational use, Monday morning **Source material:** The 5 highest-priority actions from the Crypto Posture Audit (Task 15), built against the exact procedures and configurations already designed and tested in Tasks 10, 11, 12, and 14 of this project **Purpose:** This is not a strategy document. It is a playbook: do this, then this, then verify, then proceed. Each action below includes a prerequisite check, exact steps, a validation procedure, and a rollback trigger, in the order this team should execute them.

**A correction stated directly before the first action, since precision matters more than consistency with an earlier draft:** this project's own Task 13 recommended "Database-level Transparent Data Encryption" for the EHR database without noting that PostgreSQL, unlike MySQL/InnoDB, does not ship native TDE as a built-in feature. Action #4 below reflects the actual, immediately deployable path for PostgreSQL specifically: volume-level encryption of the underlying data directory using the exact LUKS2 procedure this project already built and tested directly in Task 12, not a database engine feature that does not exist in stock PostgreSQL.

---

## Action #1: Enforce Encrypted-Only PostgreSQL Connections

```
Action #1: Enforce Encrypted-Only PostgreSQL Connections
Priority: Immediate (Task 15, CRYPTO-002)
System Affected: ehr-db-01

Prerequisites:
  - Confirmed that ssl=on is already active in postgresql.conf (Task 0
    Crypto Inventory already confirmed this)
  - A dated backup copy of the current pg_hba.conf exists before any
    edit is made

Steps:
  1. cp /etc/postgresql/14/main/pg_hba.conf /etc/postgresql/14/main/pg_hba.conf.bak-$(date +%Y%m%d)
  2. Edit pg_hba.conf: remove or comment out every "hostnossl" line
     covering the 10.10.0.0/16 range, leaving only "hostssl" entries
     for that range
  3. Validate syntax: sudo -u postgres pg_ctlcluster 14 main reload --dry-run (or the distribution-equivalent config check)
  4. sudo systemctl reload postgresql

Validation:
  - Attempt a connection with sslmode=disable from ehr-srv-01; confirm
    it is rejected
  - Attempt a connection with sslmode=require; confirm it succeeds
  - Confirm the EHR application itself completes normal queries with no
    errors in its own logs in the 15 minutes following the reload

Rollback:
  - cp pg_hba.conf.bak-<date> back to pg_hba.conf, then reload
  - Maximum acceptable downtime before rollback: 15 minutes; this is a
    configuration reload, not a service restart, so any disruption
    beyond this window indicates an unrelated problem requiring
    immediate reversion while it is investigated separately

Maintenance Window: Business hours acceptable, scheduled during a
  lower-traffic period on the clinical calendar; the change itself is a
  near-instant reload with no planned downtime
Communication: James Chen notified before the change; Sarah Park
  confirms completion and validation results to James Chen after
```

---

## Action #2: Close the Active Directory Kerberos and LDAP Signing Gap

```
Action #2: Disable Weak Kerberos Encryption Types, Enforce LDAP Signing
Priority: Immediate (Task 15, CRYPTO-010 and CRYPTO-011; Finding 018 and
  Finding 007, 1x02)
System Affected: ad-dc-01, ad-dc-02

Prerequisites:
  - An inventory of any legacy system or service still depending on
    RC4 or DES for Kerberos compatibility, since Finding 018's own
    original text noted "nobody has documented which systems actually
    require them"; this inventory is itself a required prerequisite
    task, not an assumption that none exist

Steps:
  1. Review current Kerberos ticket issuance via Event ID 4768/4769
     logs to establish a baseline of which encryption types are
     actually in use today
  2. Set Group Policy "Network security: Configure encryption types
     allowed for Kerberos" to AES256_HMAC_SHA1 and AES128_HMAC_SHA1
     only, removing RC4_HMAC_MD5 and both DES types
  3. Apply this policy to a single pilot Organizational Unit first, not
     domain-wide
  4. Monitor authentication failures in the pilot OU for 24 to 48 hours
  5. If no failures are reported, apply the policy via the Default
     Domain Policy domain-wide
  6. Separately, set "Domain controller: LDAP server signing
     requirements" to Require signing

Validation:
  - Confirm via Event ID 4768/4769 logs that only AES-based tickets are
    being issued domain-wide
  - Confirm zero authentication-related helpdesk tickets attributable
    to this change in the 48 hours following domain-wide rollout
  - Attempt an unsigned LDAP bind; confirm it is rejected

Rollback:
  - Revert the Group Policy setting to re-permit RC4/DES temporarily if
    any critical legacy system fails authentication
  - Maximum acceptable disruption before rollback: any authentication
    failure affecting more than 5 users, or any failure on a clinical
    system specifically, triggers immediate rollback of the specific
    policy change, not a wait-and-see period

Maintenance Window: Business hours acceptable for the pilot OU phase,
  given its contained scope; domain-wide rollout scheduled for an
  overnight, low-traffic window given the larger blast radius
Communication: Sarah Park's team and James Chen notified before
  rollout; helpdesk given advance notice to expect and correctly
  triage any authentication-related tickets during the window
```

---

## Action #3: Deploy the Hardened Patient Portal TLS Configuration

```
Action #3: Deploy Hardened TLS Configuration (TLS 1.2/1.3 only)
Priority: Immediate (Task 15, and directly closing Finding 005's
  documented downgrade exposure, Task 16 Attack 1)
System Affected: web-srv-01

Prerequisites:
  - The hardened Apache configuration already built directly in this
    project's own Task 11 (SSLProtocol -all +TLSv1.2 +TLSv1.3, ordered
    cipher suites, HSTS, OCSP stapling) is reviewed and ready
  - The current, backed-up copy of the existing Apache TLS
    configuration file is preserved before any change

Steps:
  1. Deploy the Task 11 hardened configuration to a staging instance
     first, if one is available
  2. Test the staging instance against SSL Labs or an equivalent
     checker, confirming the grade improvement this project's own Task
     11 predicted directly
  3. During the scheduled maintenance window, deploy the identical
     configuration to web-srv-01
  4. sudo systemctl reload apache2 (a reload, not a full restart,
     minimizing active connection disruption)

Validation:
  - Immediately test an external connection confirming TLS 1.0 and 1.1
    are rejected and TLS 1.2/1.3 are accepted
  - Confirm the HSTS header is present in the response
  - Monitor patient session error rates for 30 minutes following
    deployment, specifically watching for any spike attributable to a
    patient device too old to negotiate TLS 1.2 at all

Rollback:
  - Restore the preserved, previous Apache TLS configuration file and
    reload
  - Maximum acceptable disruption before rollback: any measurable spike
    in patient connection failures within the first 30 minutes triggers
    immediate rollback, not a delayed investigation

Maintenance Window: Overnight, low-traffic window, even though the
  change itself is a near-instant reload, given the direct, immediate
  impact any unexpected failure would have on 800 daily patients
Communication: James Chen and Sarah Park's team notified before; front
  desk and reception staff given advance notice specifically so they
  can correctly handle any patient-reported connection issue during the
  window rather than treating it as unrelated
```

---

## Action #4: Encrypt the EHR Database's Underlying Storage Volume

```
Action #4: LUKS2 Volume Encryption for ehr-db-01's Data Directory
Priority: Immediate (Task 15, CRYPTO-001; Finding 003, 1x02; RISK-002,
  1x03, $816,750 residual ALE)
System Affected: ehr-db-01

Prerequisites:
  - A full, verified, tested-restorable backup of the current
    PostgreSQL data directory exists on separate storage before this
    action begins
  - Action #1 (encrypted-only connections) is already complete and
    stable, so this action adds at-rest protection on top of an
    already-enforced in-transit baseline, not in place of it
  - A scheduled outage window has been communicated to clinical
    department heads at least 48 hours in advance

Steps:
  1. sudo systemctl stop postgresql
  2. Take a fresh, final backup of the data directory immediately
     before proceeding, in addition to the pre-existing verified backup
  3. Create the new LUKS2-encrypted volume, following the exact
     sequence already proven in this project's own Task 12:
     cryptsetup luksFormat, then cryptsetup luksOpen, then mkfs.ext4
  4. Mount the new encrypted volume at a temporary path
  5. Copy the PostgreSQL data directory contents onto the new encrypted
     volume
  6. Update the system's mount configuration so the encrypted volume
     mounts automatically at PostgreSQL's expected data directory path
     on boot, using a keyfile retrieved from the KMS this project's own
     Task 14 already designed, not a manually typed passphrase, so the
     service can start unattended after any future reboot
  7. sudo systemctl start postgresql, pointed at the new encrypted path

Validation:
  - Confirm PostgreSQL starts successfully and the EHR application
    completes normal queries with no errors
  - With the volume closed, run strings and a targeted grep against the
    raw underlying disk device, confirming no patient data is readable
    in plaintext, the exact verification method already demonstrated
    directly in this project's own Task 12
  - Confirm query response times are within an acceptable range of the
    pre-migration baseline, not materially degraded

Rollback:
  - Stop PostgreSQL, remount the original, still-intact unencrypted
    data directory location, restart PostgreSQL against it
  - Maximum acceptable downtime before rollback: 2 hours; given this is
    the organization's primary clinical system, an outage beyond this
    window triggers immediate rollback to the pre-migration state
    regardless of how far the migration itself has progressed

Maintenance Window: Overnight, required; this action stops the EHR
  database entirely, unlike Action #1's near-zero-downtime reload
Communication: James Chen, Sarah Park's full team, and clinical
  department heads notified at least 48 hours in advance of the planned
  outage; explicit confirmation sent to all parties once service is
  restored and validated, not merely once the migration technically
  completes
```

---

## Action #5: Encrypt NAS-01 Backup Storage

```
Action #5: LUKS2 Volume Encryption for NAS-01
Priority: Immediate (Task 15, CRYPTO-013; Finding 015, 1x02; RISK-004,
  1x03)
System Affected: NAS-01

Prerequisites:
  - A full, verified, tested-restorable backup of all existing NAS-01
    contents exists on separate, independent storage before this action
    begins; this is the single most important prerequisite in this
    entire playbook, since NAS-01 is itself MedDefense's last line of
    recovery, and a failed migration here carries a materially
    different risk than a failed migration anywhere else in this
    document
  - Confirmed that the CVE-2024-10441 patch already recommended in
    prior remediation work has been applied, so this migration is not
    performed against a system still open to the same compromise it is
    meant to help defend against

Steps:
  1. Confirm the independent backup above is complete and its
     restorability has actually been tested, not merely assumed
  2. cryptsetup luksFormat on the target volume
  3. cryptsetup luksOpen to unlock it
  4. mkfs.ext4 to create the filesystem, following the exact sequence
     already tested directly in this project's own Task 12
  5. Migrate existing backup data onto the new encrypted volume
  6. Reconfigure NAS-01's backup service to write to the new encrypted
     volume going forward
  7. Store the LUKS key in the KMS-backed key management system (Task
     14), explicitly not on NAS-01 itself, directly applying the
     principle Sarah Park's own crypto audit notes already stated
     (Task 0): the data and the key to that data must never share a
     single point of failure

Validation:
  - Confirm the next scheduled backup job completes successfully
    against the new encrypted volume
  - With the volume closed, run strings and grep against the raw volume
    file, confirming no plaintext data is recoverable, the exact
    verification already proven directly in Task 12
  - Perform an actual full test restore from the new encrypted volume,
    not merely a file-listing check, and confirm the restored data
    matches the original exactly

Rollback:
  - Revert the backup service configuration to point at the original,
    still-intact unencrypted volume location
  - Maximum acceptable disruption before rollback: a single missed or
    failed nightly backup cycle triggers immediate rollback; MedDefense
    cannot tolerate any gap in backup coverage given this system's own
    role as the organization's final recovery path

Maintenance Window: Overnight, low-activity window, given the data
  volume involved in the migration itself
Communication: Sarah Park's team and James Chen notified before and
  immediately after; this action is flagged explicitly as the single
  most sensitive item in this entire playbook given NAS-01's role, so
  any issue during execution is escalated immediately rather than held
  for the next business day
