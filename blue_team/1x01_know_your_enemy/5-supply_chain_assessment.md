# MedDefense Health Systems: The Supply Chain Question: Third-Party Risk Mapping

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** Project 0x00 Environment Summary (`0-environment_summary.md`), Control Matrix (`10-complete_control_matrix.md`), Asset Registry (`7-asset_registry.md`), Data Map (`9-data_map.md`), and Gap Analysis (`12-gap_analysis.md` / `13-reality_check.md` / `15-predecessor_review.md`) **Purpose:** Answer James's specific question which is if a given vendor is breached, what exactly can they reach inside MedDefense for 5 vendors with meaningful access to MedDefense's environment or data.

---

yaml

```yaml
Vendor: MedTech Solutions
Service: EHR maintenance (software updates, not hardware; SLA: 4-hour
  response for critical issues, 24-hour for standard — Project 0x00,
  Task 0/4)
Access Type: Network + Application — direct maintenance access to the
  EHR application, almost certainly including remote diagnostic/support
  access given the contracted 4-hour SLA (an on-site-only arrangement
  could not realistically meet that response time consistently)
Access Scope: ehr-srv-01 at minimum, and very plausibly ehr-db-01 as
  well, since EHR "maintenance" routinely includes database-level
  support. Because ehr-db-01's database is already documented as
  reachable from the entire internal network rather than restricted to
  ehr-srv-01 (GAP-003), any legitimate vendor access point onto this
  system sits on the same flat network as every other critical asset.
Compromise Scenario: A compromised MedTech employee credential, laptop,
  or remote-access channel would hand an attacker legitimate,
  maintenance-level access to the EHR application server. From there,
  the absence of network segmentation (GAP-014) provides an unobstructed
  path to the EHR database, and potentially onward to the domain
  controllers and other Critical-rated assets on the same subnet — the
  same "trusted vendor becomes the attack path" pattern that defined the
  SolarWinds incident referenced in this task's introduction.
Existing Controls: None specific to vendor access. No control in the
  0x00 Control Matrix distinguishes or restricts vendor remote access
  from ordinary internal access; no dedicated vendor network
  segmentation exists; no MFA is confirmed for remote maintenance
  sessions (GAP-017 applies organization-wide with no vendor carve-out);
  no periodic review of vendor access exists (GAP-009).
Risk Assessment: Critical — direct access to the single highest-ranked
  critical asset in the entire organization (the EHR System, Task 8's
  #1 Top Critical Asset), on an unsegmented network, with no MFA and no
  access review. This meets the Critical threshold on every dimension
  used elsewhere in this project.
```

yaml

```yaml
Vendor: Microsoft (O365 E3)
Service: Organization-wide email, SharePoint, and OneDrive; identity
  services if Entra ID is federated with on-premise Active Directory
  (Marcus's notes in the Project 0x00 predecessor review reference
  "Entra ID MFA with the existing O365 E3 licenses," indicating this
  tenant relationship exists)
Access Type: Data (cloud-hosted email, file storage) + Identity (if
  Entra ID sync/federation is active, a cloud-side identity compromise
  carries potential implications for on-premise trust)
Access Scope: All organization-wide email traffic, SharePoint document
  libraries, and OneDrive personal storage for roughly 2,000 users. This
  does not include the EHR or core clinical systems (which remain
  on-premise per the Asset Registry), but it does include Confidential-
  classification data (HR records, contracts, corporate communications)
  and very plausibly incidental PHI shared via email attachments — a
  common real-world pattern even when an organization's official record
  system lives elsewhere.
Compromise Scenario: The far more probable path here is not a
  Microsoft-side platform breach (a low-probability event given the
  scale of Microsoft's own security investment) but compromise of
  MedDefense's own O365 tenant — for example, through the phishing or
  smishing vectors already analyzed in Task 4 of this project, combined
  with the confirmed absence of MFA (GAP-017). A compromised tenant
  exposes all organization-wide email and file storage at once, and
  if Entra ID federation is in scope, could extend toward on-premise
  identity trust.
Existing Controls: None independently verified by MedDefense — Task 9's
  Data Map already flags that O365 relies entirely on "Microsoft's own
  (MedDefense-unverified) protections," that O365 data is explicitly
  excluded from MedDefense's own backup strategy on the assumption
  "Microsoft handles it," and that no MFA is enforced on this tenant.
Risk Assessment: High — not Critical, since the EHR and core clinical
  Restricted data do not live in this environment, but the sheer breadth
  of this vendor (the identity and collaboration backbone for the
  entire ~2,000-person workforce), combined with zero MFA and an
  unverified backup assumption, place this well above Medium.
```

yaml

```yaml
Vendor: Sophos
Service: Endpoint protection agent installed on managed Windows 10/11
  workstations, with centralized capability to push updates and policy
  configurations (Project 0x00 Control C-009)
Access Type: Application/Technical — a centrally-managed agent with
  privileged, push-based access across every endpoint where it is
  installed
Access Scope: Approximately 372 Windows 10/11 workstations. Per Task 4's
  Sophos deployment report, this explicitly excludes all servers
  (Windows and Linux alike) and mobile devices — the blast radius is
  bounded to the workstation population, not the organization's most
  critical infrastructure.
Compromise Scenario: If Sophos's cloud management console (Sophos
  Central) were compromised at the vendor level, or if MedDefense's own
  Sophos Central tenant credentials were compromised, an attacker could
  push malicious configuration changes — or, in a worst case, a
  malicious payload disguised as a routine update — to all 372 managed
  endpoints simultaneously. This is structurally the same class of risk
  as the SolarWinds Orion compromise referenced in this task's
  introduction: a trusted software supply channel with broad, privileged
  push access being weaponized against every downstream customer at once.
Existing Controls: Sophos itself is the only control (C-009) addressing
  this vendor relationship, and it is already rated Weak in the 0x00
  Control Matrix due to its coverage gaps. No additional control exists
  to independently verify or restrict what a compromised Sophos
  management plane could push to MedDefense's endpoints.
Risk Assessment: High — not Critical, because this vendor's access is
  explicitly bounded away from servers and the organization's most
  critical assets, limiting the worst-case blast radius; but High given
  the breadth of simultaneous reach (372 endpoints at once) and the
  privileged nature of push-based software deployment, a proven
  real-world vector for mass compromise.
```

yaml

```yaml
Vendor: Siemens (MRI scanner manufacturer)
Service: Periodic maintenance of the MRI control workstation (WS-RAD-01)
  and firmware updates for the MRI scanner itself
Access Type: Physical (on-site maintenance visits) + Application (direct
  access to WS-RAD-01) + Network (unconfirmed — no source in this
  project establishes whether Siemens maintenance includes remote
  diagnostic or update-delivery access, which should be verified
  directly rather than assumed either way)
Access Scope: WS-RAD-01 and the MRI scanner. WS-RAD-01 sits on Central's
  flat network, on the same VLAN as general-purpose workstations (Task 6,
  Task 7), meaning any vendor access to this system — physical or
  network-based — inherits the same unrestricted reach as any other
  device on that segment.
Compromise Scenario: A compromised Siemens technician's credentials or
  equipment, or a compromised firmware update package delivered through
  Siemens's own supply chain (a direct parallel to the SolarWinds
  scenario), could introduce malicious code onto WS-RAD-01 — a system
  that, per this project's Task 6 analysis, cannot be patched, has no
  antivirus (unsupported OS), and currently has zero implemented
  compensating controls (the four proposed controls from Task 6 remain
  unimplemented per Task 10). From that foothold, the flat network
  provides an unobstructed path to every other critical asset at Central.
Existing Controls: None. This is the same asset already identified in
  GAP-002 as having no effective protection of any kind, vendor-related
  or otherwise — a vendor compromise path here inherits that complete
  absence of defense rather than encountering any additional barrier.
Risk Assessment: Critical — a Critical-rated asset (Task 8's Top 5) with
  a vendor access path onto a system that cannot be patched and has no
  implemented compensating controls, sitting on the unsegmented network.
  This is arguably the least defensible vendor exposure on this list,
  since even MedDefense's planned internal mitigations for this specific
  system have not yet been deployed.
```

yaml

```yaml
Vendor: Greenfield Building Management (Corporate HQ landlord)
Service: Manages the underlying network infrastructure at Corporate HQ;
  MedDefense operates its own VLAN on this shared, landlord-controlled
  network (Project 0x00, Task 0/7)
Access Type: Network — physical and logical control over the
  infrastructure (switches, routers) carrying MedDefense's HQ VLAN and
  the site-to-site VPN link back to Central
Access Scope: The transport layer underlying HQ's entire network
  presence. Per Task 0/9, "the site-to-site VPN terminates on whatever
  the building provides," and MedDefense has "no visibility into the
  network security of that shared infrastructure" — meaning the actual
  scope of what Greenfield can reach, or what a compromise of their
  network could expose, is not fully known to MedDefense itself.
Compromise Scenario: If Greenfield's building network were compromised —
  whether through another tenant sharing the same building
  infrastructure, a compromised building management system, or a direct
  attack on the landlord — an attacker would gain a foothold on the same
  underlying infrastructure carrying MedDefense's VLAN and its VPN
  tunnel to Central. Depending on how well Greenfield isolates tenant
  VLANs (unverified by MedDefense), this could enable traffic
  interception or a pivot toward Central's server subnet via the VPN
  termination point.
Existing Controls: None that MedDefense controls or can independently
  verify. This is an explicitly documented Known Unknown from Task 0/9,
  and the VPN's access control lists have never been audited.
Risk Assessment: High — not confirmed Critical on current evidence,
  since HQ hosts no on-premise Critical-rated servers itself (Task 0/7),
  but the combination of an unaudited VPN link directly into Central's
  server subnet and a complete lack of visibility into the landlord's
  own security posture represents a meaningful, largely unquantified
  risk — the uncertainty itself, not a confirmed weakness, is what
  keeps this above Medium.
```

---

## Supply Chain Risk Summary

Of the 5 vendors assessed, **MedTech Solutions represents the single highest-damage compromise scenario**, not because its technical access path is more severe than Siemens's (both are rated Critical), but because of what it connects to: MedTech's maintenance access reaches directly into the EHR System, which Project 0x00's own criticality assessment ranks as MedDefense's single most critical asset overall, and MedTech's SLA-driven, presumably ongoing remote access represents a persistent rather than periodic attack surface, unlike Siemens, whose access is tied to scheduled maintenance visits. A compromise here does not just threaten one device; it threatens the complete clinical record system for every patient MedDefense serves. Across all 5 vendors, the single control MedDefense should implement first is a **dedicated, isolated vendor-access segment**, a jump-host or bastion architecture requiring MFA and generating a full access log for every third-party connection, rather than the current model where vendor access, once granted, inherits the same unrestricted reach as any other device on MedDefense's flat network. This single control would not eliminate the risk that any individual vendor is compromised, but it would close the common thread running through all five assessments above: every one of these compromise scenarios depends on the flat network turning a narrow, legitimate point of vendor access into an unrestricted pivot toward everything else.
