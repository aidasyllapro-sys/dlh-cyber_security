# MedDefense Health Systems: The OSINT Hunt

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** NVD, CISA Known Exploited Vulnerabilities Catalog, and vendor security advisories (Fortinet, Microsoft, Synology), researched directly against live sources on the date of this document **Purpose:** Supplement the automated scan with manual OSINT research into 3 parts of MedDefense's technology stack the scan either could not reach or was never configured to assess, the FortiGate 100F firewall's own firmware, the O365/Entra ID cloud tenant, and the Synology DSM 7 backup NAS's software (as distinct from the network-exposure misconfiguration already found on it).

---

## 1. FortiGate 100F / FortiOS

yaml

```yaml
Source: NVD (https://nvd.nist.gov/vuln/detail/cve-2026-24858), Fortinet
  vendor advisory FG-IR-26-060 (fortiguard.fortinet.com/psirt/FG-IR-26-060),
  CISA Known Exploited Vulnerabilities Catalog, CISA alert
  (cisa.gov/news-events/alerts/2026/01/28/fortinet-releases-guidance-address-
  ongoing-exploitation-authentication-bypass-vulnerability-cve-2026)
CVE: CVE-2026-24858
Affected Product: MedDefense's FortiGate 100F (runs FortiOS). NVD's own
  configuration data confirms FortiOS 7.0.0 through 7.0.18, 7.2.0 through
  7.2.12, and 7.4.0 through 7.4.10/11 are affected, among other Fortinet
  products (FortiAnalyzer, FortiManager, FortiProxy, FortiWeb).
Why the Scan Missed It: SecurePoint's scan targeted the internal
  10.10.0.0/16 range and assessed hosts behind the firewall — nothing in
  the scan report indicates the FortiGate's own management plane or
  firmware version was fingerprinted at all. This is consistent with how
  network vulnerability scanners are typically scoped: they scan through
  a firewall, not the firewall's own OS, unless specifically pointed at
  its management interface with credentials. A device's own firmware is
  exactly the kind of "authenticated access the scan did not have"
  category this task's context describes.
CVSS / Severity: 9.8 CRITICAL (CNA: Fortinet, Inc.), vector
  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. CWE-288 (Authentication
  Bypass Using an Alternate Path or Channel). Listed in CISA's KEV
  catalog: Date Added 2026-01-27, Due Date 2026-01-30 — a 3-day
  remediation window, one of the shortest CISA issues, reflecting
  confirmed active exploitation.
MedDefense Impact: This vulnerability allows an attacker who controls
  any FortiCloud account with a registered device to authenticate into
  other organizations' FortiGate devices that have FortiCloud SSO
  enabled — no valid MedDefense credential is required at all. Given the
  FortiGate 100F is MedDefense's central perimeter device and terminates
  the Westside VPN tunnel (per the 0x00 architecture), a successful
  exploit would grant an external attacker direct administrative control
  over the single device every other network boundary in this project
  depends on — a more severe starting position than any internal kill
  chain already modeled, since it bypasses the network entirely rather
  than pivoting through it. CISA's own advisory on this exact CVE
  documents attacker activity including unauthorized firewall
  configuration changes and unauthorized account creation on compromised
  devices — not a theoretical outcome.
Recommendation: Immediately determine whether FortiCloud SSO
  authentication is enabled on MedDefense's FortiGate 100F (the
  precondition for exploitation) and disable it if not operationally
  required. Confirm the device's current FortiOS version against the
  fixed versions in Fortinet's advisory FG-IR-26-060 and patch on an
  emergency basis given the CISA-confirmed 3-day remediation expectation
  and active exploitation. This should be added to the vulnerability
  assessment scope as a Critical, standalone finding — not folded into
  the existing network scan's findings, since the scan never actually
  assessed this device.
```

---

## 2. Microsoft 365 / Entra ID

yaml

```yaml
Source: NVD (via aggregator confirmation, Tenable CVE database citing
  Mitre/NVD), Microsoft Security Response Center advisory
  (msrc.microsoft.com/update-guide/vulnerability/CVE-2025-55241),
  original researcher disclosure (Dirk-Jan Mollema,
  dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-
  tokens), The Hacker News coverage
CVE: CVE-2025-55241
Affected Product: Microsoft Entra ID, the identity backbone underlying
  MedDefense's entire O365 E3 tenant (authentication, mailbox access,
  SharePoint, Teams, and any application relying on Entra ID sign-in).
Why the Scan Missed It: Explicitly out of scope by design — SecurePoint's
  own methodology notes (Task 0 of this project) state plainly that "this
  scan does NOT cover: cloud services (O365)." This is not a scanner
  limitation so much as a scope boundary: a network vulnerability scanner
  aimed at an internal IP range has no vantage point from which to assess
  a cloud identity provider's backend infrastructure at all — this class
  of finding can only be surfaced by OSINT/vendor-advisory research, not
  by any tool MedDefense could point at its own network.
CVSS / Severity: Reported by multiple secondary sources as a "perfect
  10.0," though the specific CVSS v3.1 vector recorded (AV:N/AC:L/PR:N/
  UI:N/S:U/C:H/I:H/A:H, per Tenable's citation of the Mitre/NVD record)
  calculates to 9.8 CRITICAL under standard CVSS v3.1 math — this
  discrepancy between the widely-reported "10.0" and the precise vector's
  9.8 is noted here rather than silently resolved, since both figures
  appear across reputable sources. Either way, this sits at the maximum
  practical severity tier.
MedDefense Impact: This flaw allowed an attacker who controlled access to
  any Entra ID tenant anywhere to craft an undocumented "Actor token" and
  use it to impersonate any user — including Global Administrators — in
  any other organization's tenant, entirely bypassing MFA and Conditional
  Access policies, with minimal audit trail. Had this been actively
  exploited against MedDefense before Microsoft's emergency global fix
  (deployed server-side in September 2025), it would have rendered every
  identity control MedDefense has or could deploy on O365 irrelevant —
  including the MFA enforcement already recommended as a Quick Win
  throughout this project (GAP-017). This is included here specifically
  because it is a powerful illustration of a risk class, not a live
  exposure: Microsoft's fix was applied globally on Microsoft's own
  infrastructure, not something individual tenants had to separately
  patch, so MedDefense is not currently exposed to this specific CVE.
  What it demonstrates is structural — MedDefense's entire identity
  perimeter rests on a control plane it does not operate or audit, and
  this vulnerability proves that control plane has already had at least
  one flaw capable of defeating every tenant-side defense simultaneously.
Recommendation: No remediation action is required for this specific CVE,
  since Microsoft's fix was applied at the platform level. The
  recommendation is process-level: MedDefense should not treat "we have
  no cloud CVEs open" as equivalent to "our cloud tenant is secure,"
  given this exact class of flaw is invisible to any vulnerability scan
  MedDefense could run itself. Concretely, MedDefense should (1) confirm
  MFA and Conditional Access enforcement anyway, since these remain
  meaningful defenses against the overwhelming majority of real-world
  attack techniques even though this specific flaw bypassed them, (2)
  review Entra ID sign-in and audit logs for the affected period
  (disclosure occurred July 2025, patched September 2025) for anomalous
  cross-tenant or Global Administrator activity, and (3) adopt CISA's
  free SCuBA/ScubaGear baseline assessment tool for M365 tenants going
  forward, specifically because it is designed to catch exactly this
  category of cloud-only exposure that a network scan structurally
  cannot.
```

---

## 3. Synology DSM 7

yaml

```yaml
Source: NVD (https://nvd.nist.gov/vuln/detail/CVE-2024-10441), Synology
  vendor advisories Synology_SA_24_20 and Synology_SA_24_23
  (synology.com/en-global/security/advisory/)
CVE: CVE-2024-10441
Affected Product: NAS-01, MedDefense's Synology DSM backup NAS (0x00 Top
  5 Critical Asset #5).
Why the Scan Missed It: The scan did reach NAS-01 (Finding 015), but only
  identified a network-exposure misconfiguration — the DSM web management
  interface being reachable from the entire internal network. Nothing in
  Finding 015 assesses the DSM software's own patch level or checks it
  against known CVEs; this is consistent with SecurePoint's own
  methodology notes stating medical devices and appliance-class systems
  were "scanned unauthenticated" — an unauthenticated network scan can
  observe that a service is exposed, but generally cannot enumerate the
  exact DSM build number needed to match it against a specific CVE the
  way an authenticated OS-level check could.
CVSS / Severity: 9.8 CRITICAL (CNA: Synology Inc.), vector
  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. CWE-116 (Improper
  Encoding or Escaping of Output). Not currently listed in CISA's KEV
  catalog; CISA's own SSVC assessment on this CVE record notes
  "exploitation: none" (not confirmed exploited in the wild) but
  "automatable: yes" and "technicalImpact: total."
MedDefense Impact: This is an unauthenticated, remote code execution
  vulnerability in DSM's own system plugin daemon, affecting DSM
  versions before 7.1.1-42962-7, 7.2-64570-4, 7.2.1-69057-6, and
  7.2.2-72806-1 — squarely within the "DSM 7" version range already
  confirmed running on NAS-01. Combined with Finding 015's own
  documented exposure (the DSM interface reachable from the entire
  internal network) and the pre-existing GAP-006 (NAS-01 co-located with
  the production systems it backs up), this CVE would let any
  already-compromised host on MedDefense's flat network achieve remote
  code execution directly on the organization's only backup
  infrastructure — no valid credentials needed at all. This is a direct,
  concrete technical mechanism for exactly the "neutralize the backup
  before deploying ransomware" step already modeled in this project's
  Kill Chain #1, materially easier to execute than the kill chain
  originally assumed if this specific CVE remains unpatched.
Recommendation: Confirm NAS-01's exact DSM build number immediately
  (authenticated check, not another network scan) and compare against
  Synology's fixed versions in advisories SA-24-20 and SA-24-23; patch on
  an urgent basis given the CVSS 9.8 rating and unauthenticated,
  no-user-interaction exploitability, independent of and in addition to
  the network-segmentation remediation already recommended for Finding
  15. Patching the software and restricting network exposure are both
  necessary — this CVE is a reminder that fixing Finding 015's
  misconfiguration alone would not address an underlying software flaw
  that could still be reached by any host still on the same subnet as
  NAS-01 before segmentation is complete.
```

---

## Summary Observation

All 3 findings in this OSINT hunt share a common thread worth stating explicitly: each is a CVSS 9.8 CRITICAL vulnerability that a properly-scoped, authenticated vulnerability scan would very plausibly have caught, but SecurePoint's actual scan could not, for 3 structurally different reasons (the firewall's own firmware was never in scope, the cloud tenant was explicitly excluded, and the NAS was only assessed unauthenticated). This is the practical lesson this task sets out to demonstrate: "the scan found nothing critical here" and "this part of the environment has no critical exposure" are not the same statement, and treating them as equivalent is precisely the reasoning gap this OSINT research exists to close.
