# MedDefense Health Systems: The Noise Filter - Full Triage

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** `meddefense-vulnerability-scan.txt` (all 31 findings), triaged using every prior task of this project (CVE/CWE research (T1/T3), CVSS analysis (T2), Exploit Hunt (T4), misconfiguration analysis (T6), taxonomy (T7), Lynis audit (T8), OSINT hunt (T9), critical CVE deep dives (T10), false positives (T11)), legacy systems (T12), web exposure (T13), network posture (T14), and medical IoT (T15) **Purpose:** Sort all 31 findings into 4 action categories, the daily discipline of separating signal from noise when a scan produces more findings than any team can act on simultaneously.

**Category definitions used throughout:**

- **AC (Actionable Critical):** Exploitable (or urgently requires investigation regardless of confirmed exploit), on a critical asset or with high real-world impact → remediate in 24-48h
- **AS (Actionable Standard):** Real vulnerability requiring planned remediation → 7-30 days
- **I (Informational):** Real observation, low risk, document and monitor
- **FP (False Positive):** Not a real vulnerability in this context, per Task 11's analysis → document and dismiss

---

## Full Triage

```
Finding 001 | 9.8 CVSS | billing-srv-01 | Category: AC | Reason: Literal Step 1 of Kill Chain #1, the project's #1-ranked threat, on a host already compromised twice.
Finding 002 | 7.8 CVSS | billing-srv-01 | Category: AC | Reason: Directly chains from Finding 001 (RCE→root) with a confirmed weaponized exploit (EDB-46676); remediated by the same Apache upgrade.
Finding 003 | Critical (no CVSS) | ehr-db-01 | Category: AC | Reason: One of "The Critical Three" cross-project gaps, sitting on the #1 Critical Asset with zero exploit barrier.
Finding 004 | 10.0/9.8/8.1 CVSS | WS-RAD-01 | Category: AC | Reason: Three independently weaponized, CISA KEV-listed CVEs stacked on a Top-5 Critical Asset with no possible patch.
Finding 005 | 7.5 CVSS | web-srv-01 | Category: AS | Reason: Real weak-TLS finding on the organization's one confirmed internet-facing host, but no confirmed active exploit chain.
Finding 006 | High (no CVSS) | billing-srv-01 | Category: AS | Reason: Real network-exposure misconfiguration on financial data, compounding but distinct from Findings 001/002.
Finding 007 | Critical (no CVSS) | ad-dc-01 | Category: AC | Reason: Confirmed top Elevation-of-Privilege threat on the #2 Critical Asset (domain controller) per this project's STRIDE analysis.
Finding 008 | 8.8 CVSS | print-srv-01 | Category: AS | Reason: Weaponized and CISA KEV-listed, but on a non-Top-5-critical asset, keeping it just below the AC bar.
Finding 009 | High (no CVSS) | billing-srv-01 | Category: AS | Reason: Real brute-force exposure on a repeat-compromised host, already flagged by name in this project's own root-cause analysis.
Finding 010 | 6.5-7.5 CVSS | BD Alaris pumps (x7) | Category: AC | Reason: Top-5 Critical Asset with direct patient-safety implications, compounded by a confirmed 100% default-credential failure across every scanned pump.
Finding 011 | High (no CVSS) | billing-srv-01 | Category: AS | Reason: The root administrative cause of Finding 026's 47 unpatched kernel CVEs; fixable via ESM enrollment without a full OS migration.
Finding 012 | Medium (no CVSS) | web-srv-01 | Category: AS | Reason: Real, low-effort defense-in-depth fix that meaningfully reduces this host's compound web-risk profile.
Finding 013 | Medium (no CVSS) | web-srv-01 | Category: AS | Reason: Time-sensitive but not an active exploit; fits comfortably within a 30-day remediation window given its 23-day runway.
Finding 014 | Critical (no CVSS) | Westside router | Category: AC | Reason: The finding's own text confirms compromise grants "a direct tunnel into the Central server network" holding every Top-5 asset.
Finding 015 | Critical (no CVSS + OSINT CVE) | NAS-01 | Category: AC | Reason: Top-5 Critical Asset (sole backup), and the OSINT-discovered CVE-2024-10441 (Task 9) transforms this into a confirmed unauthenticated RCE path.
Finding 016 | Medium (no CVSS) | Philips monitors (x13) | Category: AC | Reason: This project's own Task 15 analysis confirmed a credible escalation path from passive data exposure to direct alarm-threshold tampering — a patient-safety impact, not just a confidentiality one.
Finding 017 | Medium (no CVSS) | ehr-srv-01 | Category: AS | Reason: Not independently dangerous, but historically significant — this is the exact finding that led directly to discovering Finding 031; the underlying Tomcat error-page fix is a real, schedulable remediation.
Finding 018 | Medium (no CVSS) | ad-dc-01, ad-dc-02 | Category: AS | Reason: Real weak-cryptography finding on the domain controllers, but requires an additional offline-cracking step before impact, unlike Finding 007.
Finding 019 | Medium (no CVSS) | 5 hosts | Category: AS | Reason: Real RDP exposure, partially mitigated by NLA already being enabled per the scan's own text.
Finding 020 | 9.8 CVSS (disputed) | backup-srv-01 | Category: FP | Reason: Established directly in Task 11 — SecurePoint's own explicit false-positive caveat, confirmed by the narrow ssh-agent-forwarding precondition this server's operational role makes unlikely.
Finding 021 | Medium (no CVSS) | web-srv-01 | Category: FP | Reason: Established in Task 11 — Cross-Site Tracing requires a companion XSS vulnerability this scan never confirms exists on this host.
Finding 022 | Low (no CVSS) | ehr-srv-01 | Category: I | Reason: A 47-second clock drift is a genuine but minor operational hygiene issue with no meaningful security impact on its own.
Finding 023 | High (no CVSS) | ~280 workstations | Category: AS | Reason: Real, confirmed insider-exfiltration mechanism (this project's own Insider File analysis), fixable via a single GPO deployment.
Finding 024 | Low (no CVSS) | pacs-srv-01 | Category: I | Reason: Real cleartext-DICOM finding, but limited to passive interception risk with no confirmed active exploit path in this assessment.
Finding 025 | Low (no CVSS) | ad-dc-01 | Category: I | Reason: A reconnaissance-enabling misconfiguration, not itself a compromise mechanism.
Finding 026 | Low (no CVSS, 47 CVEs) | billing-srv-01 | Category: AS | Reason: Real and numerous, but the scan's own text confirms exploitation already requires the local access Findings 001/002 provide — a compounding, not primary, entry point.
Finding 027 | Informational | Multiple workstations | Category: I | Reason: An endpoint-management gap (15 inactive Sophos agents), already scored Informational by the scanner itself with no evidence of active exploitation.
Finding 028 | Informational | UNKNOWN-01 (10.10.2.99) | Category: AC | Reason: An unidentified, undocumented device on the same subnet as the domain controller and EHR database warrants immediate investigation regardless of confirmed intent.
Finding 029 | Informational + 7.5 CVSS | Unknown device, Westside | Category: AC | Reason: Combines the same shadow-IT urgency as Finding 028 with a confirmed, real, trivially exploitable path traversal CVE (CVE-2021-43798) on the exposed Grafana instance.
Finding 030 | Informational | ehr-srv-01 | Category: FP | Reason: Established in Task 11 — the scan report's own text confirms this is "an operational issue, not a security vulnerability."
Finding 031 | 9.8 CVSS | ehr-srv-01 | Category: AC | Reason: CISA KEV-listed, confirmed weaponized with a dedicated Metasploit module, directly threatening the #1 Critical Asset's database credentials.
```

---

## Triage Summary

|Category|Count|
|---|---|
|Actionable Critical (AC)|12|
|Actionable Standard (AS)|12|
|Informational (I)|4|
|False Positive (FP)|3|
|**Total**|**31**|

---

## Actionable Findings List (Priority Order)

### Actionable Critical: 4emediate within 24-48h

1. **Finding 031** (Ghostcat, ehr-srv-01): CISA KEV, weaponized Metasploit module, directly threatens the #1 Critical Asset.
2. **Finding 003** (PostgreSQL exposure, ehr-db-01): The #1 Critical Asset itself, zero exploit barrier, "Critical Three" gap.
3. **Finding 004** (WS-RAD-01, MRI): 3 stacked, weaponized, KEV-listed CVEs on a patient-safety-critical device.
4. **Finding 001** (Apache mod_lua, billing-srv-01): Kill Chain #1 Step 1, the project's #1-ranked threat.
5. **Finding 002** (Apache LPE, billing-srv-01): Chains directly from Finding 001, confirmed weaponized.
6. **Finding 015** (NAS-01): Sole backup infrastructure, OSINT-confirmed unauthenticated RCE (CVE-2024-10441).
7. **Finding 007** (LDAP signing, ad-dc-01): Top confirmed Elevation-of-Privilege threat on the domain controller.
8. **Finding 010** (BD Alaris pumps): Patient-safety asset, 100% default-credential failure confirmed.
9. **Finding 016** (Philips monitors): Confirmed alarm-tampering escalation path, direct patient-safety impact.
10. **Finding 014** (Westside router): The confirmed single point of entry into the entire Central server network.
11. **Finding 029** (Unknown device, Westside): Undocumented device plus a confirmed, trivially exploitable CVE.
12. **Finding 028** (UNKNOWN-01, Central): Undocumented device on the same subnet as the domain controller and EHR database.

### Actionable Standard/ Remediate within 7-30 days

1. **Finding 008** (PrintNightmare, print-srv-01): Weaponized and KEV-listed; only its non-critical asset tier keeps it out of AC.
2. **Finding 009** (SSH password auth, billing-srv-01): Real brute-force exposure on a repeat-compromised host.
3. **Finding 006** (MySQL exposure, billing-srv-01): Real financial-data exposure, compounding Findings 001/002.
4. **Finding 011** (Ubuntu EOL/no ESM, billing-srv-01): Root cause of Finding 026; fixable via ESM enrollment alone.
5. **Finding 026** (47 kernel CVEs, billing-srv-01): Real but compounding, requiring prior local access.
6. **Finding 005** (Weak TLS, web-srv-01): The organization's one internet-facing host deserves priority within this tier.
7. **Finding 013** (Expiring certificate, web-srv-01): Time-sensitive, 23-day runway comfortably inside this window.
8. **Finding 018** (Weak Kerberos encryption, ad-dc-01/02): Real, but requires an additional offline-cracking step.
9. **Finding 023** (USB unrestricted, workstations): Confirmed insider-risk mechanism, single-GPO fix.
10. **Finding 017** (Tomcat info disclosure, ehr-srv-01): Low independent severity, but historically proven to hide a Critical finding behind it.
11. **Finding 019** (RDP enabled, 5 hosts): Real, partially mitigated by NLA already.
12. **Finding 012** (Missing security headers, web-srv-01): Lowest-effort, lowest-severity item in this tier.

---

## A Note on the AC Count

Twelve of 31 findings (39%) landing in Actionable Critical is a high proportion for a 24-48h remediation window, and this is worth acknowledging rather than treating as a routine output. It reflects this project's own cumulative findings rather than triage inflation: several of these findings (003, 007, 014, 015) carry no CVSS score at all and would not appear "critical" to any tool filtering on CVSS alone. They are here because 15 prior tasks of cross-referencing against asset criticality, kill chain position, and threat correlation established that they belong here. A security team facing this list should not read "12 Criticals" as a sign the triage failed to discriminate; it should read it as confirmation of this project's own repeated finding that MedDefense's flat network and unmonitored configuration drift have allowed an unusually large fraction of this environment's weaknesses to reach its most critical assets simultaneously.
