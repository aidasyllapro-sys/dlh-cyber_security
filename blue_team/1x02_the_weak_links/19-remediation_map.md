# MedDefense Health Systems : The Remediation Map

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** The 8 findings prioritized in Tasks 17 and 18, translated into executable remediation plans that account for what remediation itself might break, not just what the vulnerability itself risks **Purpose:** Move from "this is a Critical finding" to "here is exactly what to do about it, who does it, what could go wrong while doing it, and how much it costs."

---

yaml

```yaml
Finding 031 (Ghostcat, CVE-2020-1938, ehr-srv-01):
  Response Type: Configuration Change

  Change Description: The version of Tomcat already running (9.0.31)
    is, notably, the version that shipped the official Ghostcat fix;
    the finding exists because the AJP connector was left active with
    the old, insecure default behavior rather than because the software
    itself is unpatched. The remediation is to either disable the AJP
    connector entirely in server.xml (removing or commenting out the
    Connector element on port 8009) if AJP-based reverse proxy
    integration is not genuinely required, or, if it is required, set a
    strong, unique requiredSecret value and bind the connector to
    localhost or an internal-only address rather than the full network
    interface.
  Impact Assessment: Expected to have zero impact on normal clinician
    access to the EHR, since standard user access runs over HTTPS on
    port 443, not AJP on 8009. The one prerequisite before disabling AJP
    outright is confirming no internal system (a legacy reverse proxy,
    an integration engine) genuinely depends on it; this should be
    verified against IT's own service inventory before the change is
    made, not assumed.

  Timeline: Immediate
  Owner: IT (server administration), with Security validating the
    configuration afterward
  Cost Estimate: $0-1K
```

yaml

```yaml
Finding 003 (PostgreSQL network-wide exposure, ehr-db-01):
  Response Type: Configuration Change

  Change Description: Restrict pg_hba.conf to accept connections only
    from ehr-srv-01's specific IP address (10.10.2.10), replacing the
    current 10.10.0.0/16 range entry, and configure a host-based
    firewall rule on ehr-db-01 dropping any connection attempt to port
    5432 from any other source, exactly as originally recommended in
    the scan finding itself.
  Impact Assessment: No impact expected to legitimate EHR application
    traffic, since ehr-srv-01 remains fully permitted. The real
    operational question to resolve first is whether any database
    administrator workflow currently connects directly from an admin
    workstation for maintenance purposes; if so, that workflow needs a
    documented jump-host or bastion alternative before this change goes
    live, or DBA access will break unexpectedly during a future
    maintenance task.

  Timeline: Immediate, validated in a brief maintenance window to
    confirm the EHR application itself is unaffected before declaring
    the change complete
  Owner: IT (database administration), with Security sign-off
  Cost Estimate: $0-1K
```

yaml

```yaml
Finding 001 (Apache mod_lua, CVE-2021-44790, billing-srv-01):
  Response Type: Patch

  Patch Source: Apache HTTP Server security advisory
    (httpd.apache.org/security/vulnerabilities_24.html); upgrade to
    version 2.4.52 or later.
  Prerequisites: A full backup of billing-srv-01, both configuration
    and application data, before touching the server. Given the billing
    application's compatibility with a newer Apache version is
    unconfirmed, the upgrade should first be tested against a staging
    clone of this server, not applied directly to production. Scheduling
    should avoid an active billing/claims processing cycle window.
  Rollback Plan: If billing-srv-01 is virtualized (a fact 0x00's own
    Asset Registry never confirmed, and worth resolving before this
    remediation begins), a pre-patch snapshot allows immediate rollback.
    If not virtualized, the previous Apache package should be retained
    locally for a fast downgrade via the system package manager, with
    application data backed up independently beforehand.
  Operational Risk: The billing application may rely on specific Apache
    modules or configuration behavior not compatible with 2.4.52 or
    later; an unplanned interruption during patching could delay claims
    processing. This patch does not by itself address Finding 002 (a
    separate CVE on the same host), which needs coordinated remediation
    alongside this one, not as an afterthought.

  Timeline: 7 days (staging validation required first, but no longer,
    given this finding's position as Step 1 of the project's
    highest-priority kill chain)
  Owner: IT (server administration), coordinating scheduling directly
    with the Billing department
  Cost Estimate: $1-10K (staging environment setup and testing labor)
```

yaml

```yaml
Finding 004 (MS08-067 / BlueKeep / EternalBlue, WS-RAD-01):
  Response Type: Compensating Control

  Control Description: Accelerate deployment of the compensating
    controls already proposed for this exact device in Project 0x00
    (Task 6), specifically prioritizing P-001, a dedicated VLAN
    restricting WS-RAD-01's network traffic to the PACS server only.
    Layer in a network-based virtual-patching or IPS capability
    signature-matched to known SMB/RDP exploit traffic for these three
    specific CVEs, since the underlying operating system cannot be
    replaced without a full, separately-tracked device replacement or
    recertification project.
  Residual Risk: Segmentation contains, but does not eliminate, this
    device's exposure. An attacker already positioned on the
    PACS-restricted VLAN (through a compromised PACS server or a
    radiology workstation with a legitimate reason to be on that
    segment) would still reach WS-RAD-01. The device also remains
    permanently exposed to any future Windows vulnerability disclosed in
    shared code, exactly as demonstrated by MS08-067's own KEV listing
    being added only weeks before this assessment despite the CVE being
    18 years old.

  Timeline: 30 days for segmentation deployment; a formal risk
    acceptance covering the residual, permanent EOL exposure should be
    documented in parallel with a 90-day review cycle, pending budget
    allocation for eventual device replacement (already established in
    Task 12 as unlikely to be achievable within a single quarter given
    FDA-regulated device constraints)
  Owner: IT/Network (segmentation execution), Security (formal exception
    documentation), and Clinical/Biomedical Engineering (required
    sign-off, since this is FDA-regulated equipment that cannot be
    reconfigured without their approval)
  Cost Estimate: $10-50K (network segmentation hardware and switch
    reconfiguration, plus IPS signature licensing), materially below the
    $50K+ and multi-quarter cost of a full device replacement
```

yaml

```yaml
Finding 010 (BD Alaris Improper Authentication, CVE-2020-25165, infusion pumps):
  Response Type: Compensating Control

  Control Description: Two parallel actions. First, change the default
    admin/admin web-interface credentials on all 7 scanned pumps
    immediately, and extend this audit to the full estimated 120-pump
    fleet, not only the 7 this scan reached. Second, implement BD's own
    explicitly recommended network isolation, a dedicated VLAN
    restricting pump traffic to clinical workstations and the PACS
    server only, with firewall rules enabled on the Systems Manager
    server per BD's product security whitepaper, exactly as BD's own
    guidance specifies and as Finding 010 itself recommends.
  Residual Risk: The underlying authentication flaw in the firmware
    remains present even after these controls; residual risk is a
    denial-of-service condition forcing a pump into manual operation, a
    bounded but real safety-relevant degradation that only a future
    firmware release beyond 12.1.2 would fully close.

  Timeline: Immediate for the credential changes, which should not have
    been left unaddressed this long and carry effectively zero
    implementation cost or risk; 30 days for the network segmentation
    portion, given coordination required with clinical engineering
  Owner: Clinical/Biomedical Engineering (device-level credential
    changes, since IT does not typically have direct configuration
    access to medical devices) and IT/Network (segmentation)
  Cost Estimate: $1-10K (segmentation labor; credential changes are
    effectively $0 beyond staff time)
```

yaml

```yaml
Finding 015 (Synology DSM exposure plus CVE-2024-10441, NAS-01):
  Response Type: Patch

  Patch Source: Synology Security Advisories Synology_SA_24_20 and
    Synology_SA_24_23 (synology.com/en-global/security/advisory/);
    update DSM to the fixed release for MedDefense's current branch
    (7.1.1-42962-8, 7.2-64570-4, 7.2.1-69057-6, or 7.2.2-72806-1 or
    later, whichever applies).
  Prerequisites: A verified, independent backup of the backup data
    itself before touching NAS-01 at all, given this device is
    MedDefense's sole recovery mechanism and GAP-006 already documents
    its single-point-of-failure design. Confirm DSM update compatibility
    with existing scheduled backup jobs before applying, and schedule
    the update for a window when no backup job is actively running.
  Rollback Plan: Confirm whether NAS-01's specific Synology model
    supports snapshot-based OS rollback before beginning; if it does,
    take a pre-update snapshot. If it does not, export the full backup
    job configuration set beforehand so it can be manually rebuilt if
    the update disrupts it.
  Operational Risk: An interrupted or failed update on the organization's
    only backup infrastructure is itself a meaningful availability risk
    during the maintenance window, which is precisely why the
    backup-of-the-backup prerequisite above is non-negotiable, not
    optional. Apply the network-restriction change recommended in the
    original Finding 015 (restrict the DSM interface, ports 5000/5001,
    to administrative IPs only) as a parallel configuration change
    alongside this patch, and enable backup data encryption at rest
    while the maintenance window is already open.

  Timeline: 7 days (urgent given the direct threat to the organization's
    only recovery mechanism, but the backup-of-backup prerequisite must
    complete first)
  Owner: IT (systems administration), with Security oversight given this
    asset's criticality
  Cost Estimate: $1-10K (labor plus secondary backup media for the
    pre-patch backup-of-backup)
```

yaml

```yaml
Finding 007 (LDAP Signing Not Required, ad-dc-01):
  Response Type: Configuration Change

  Change Description: Enable the LDAP signing requirement
    (LDAPServerIntegrity policy setting) on both ad-dc-01 and ad-dc-02,
    and disable SMBv1 on the domain controller, addressing the second
    issue this same finding flags.
  Impact Assessment: Any legacy application or device that only supports
    unsigned LDAP binds would lose connectivity once enforcement is
    active. Given this environment's already-documented pattern of
    legacy systems (the Windows XP MRI workstation, the Server 2012 R2
    print server), this risk is not hypothetical. Windows Server
    supports an LDAP signing diagnostic logging mode that records which
    clients would be affected without actually blocking them; this audit
    mode should run first to identify any dependencies before hard
    enforcement, rather than enforcing blind and discovering breakage
    afterward.

  Timeline: 30 days (the audit-mode discovery period is a genuine
    prerequisite, not a delay tactic, given this environment's confirmed
    legacy-system footprint)
  Owner: IT (Active Directory administration), with Security validating
    the audit-mode findings before enforcement
  Cost Estimate: $0-1K
```

yaml

```yaml
Finding 008 (PrintNightmare, CVE-2021-34527, print-srv-01):
  Response Type: Configuration Change

  Change Description: Disable the Print Spooler service on print-srv-01
    entirely if network printing from this specific server is not
    genuinely business-critical, the single most effective mitigation
    for the entire PrintNightmare vulnerability family, already
    recommended in Task 12 of this project. A vendor patch is not an
    available option here, since Windows Server 2012 R2's EOL status
    means no fix will ever be issued for this platform. If the print
    role must remain active, restrict the Spooler's network exposure to
    only the specific client subnet that actually needs it, rather than
    the entire flat network.
  Impact Assessment: If the Spooler is disabled outright, any department
    relying on network printing through this specific server needs an
    alternative, either an existing print server or local printing,
    identified before the change, not after. This requires a brief
    confirmation conversation with the departments using this server
    before execution.

  Timeline: 30 days (confirmation of actual business dependency needed
    first; this finding sits in the Actionable Standard tier per Tasks
    16 and 17, not the 24-48h Critical tier)
  Owner: IT (server and print administration)
  Cost Estimate: $0-1K
```

---

## Cross-Cutting Observations

Two patterns repeat across several of these eight plans, worth stating once rather than in each entry. First, the two findings touching MedDefense's most physically sensitive infrastructure (Finding 004 on the MRI, Finding 010 on the infusion pumps) both require Clinical or Biomedical Engineering sign-off before IT can act at all, a coordination dependency that does not exist for any of the other six findings and should be scheduled for accordingly rather than assumed away. Second, three of the eight findings (Findings 001, 015, and, by extension, any future patch to the domain controllers) require a genuine backup-before-you-touch-it discipline specifically because the systems involved are themselves part of the organization's recovery capability or hold data that cannot be easily reconstructed if a patch goes wrong; this is not boilerplate caution, it reflects this project's own repeated finding that MedDefense's backup infrastructure (NAS-01) is a single point of failure, making the margin for error during any remediation touching backup-adjacent systems smaller than it would be in an environment with redundant recovery capability.
