# MedDefense Health Systems: First Impressions Summary: Vulnerability Scan Report

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** `meddefense-vulnerability-scan.txt` (SecurePoint Consulting, OpenVAS 22.x), cross-referenced against the Project 0x00 Asset Registry (`7-asset_registry.md`) and Criticality Assessment (`8-criticality_assessment.md`) **Purpose:** Understand the shape of the scan data (scope, distribution, and limitations) before investigating any individual finding. This is a structural read, not a technical analysis; no CVE, exploit, or CVSS detail is independently researched at this stage.

---

## 1. Scan Metadata

| Field          | Detail                                                        |
| -------------- | ------------------------------------------------------------- |
| Scanner        | OpenVAS 22.x (Greenbone Community Edition)                    |
| Scan target    | 10.10.0.0/16 - all internal subnets                           |
| Scan policy    | Full and Deep, authenticated where credentials were available |
| Scan date      | 5 days prior to this review                                   |
| Requested by   | James Chen, Deputy CISO                                       |
| Executed by    | SecurePoint Consulting (third-party)                          |
| Hosts scanned  | 47 responsive hosts                                           |
| Total findings | 31                                                            |

**Authentication coverage was uneven, and this matters.** Linux servers (via SSH) and Windows systems (via domain credentials) were scanned authenticated. Medical devices were scanned **unauthenticated**, no credentials were available for them. This means the depth of inspection differs by asset class: findings on billing-srv-01 or ehr-srv-01 reflect a genuine configuration-level audit, while findings on the BD Alaris pumps or Philips monitors reflect only what is visible from the network layer outward, which is very likely an undercount of their true exposure, not a clean bill of health.

**What was explicitly NOT scanned**, per SecurePoint's own methodology notes: cloud services (O365), mobile devices (iPads), and any asset that was offline during the 02:00–06:00 scan window. No active exploitation was attempted anywhere. Every finding is based on version detection, configuration inspection, and authenticated checks, not confirmed exploitability. SecurePoint also states their own false-positive rate for this OpenVAS configuration typically runs 5–10%, and explicitly recommends manual verification before committing remediation resources to high-value findings.

---

## 2. Finding Distribution

**As stated in the report's own summary header:**

|Severity|Header Count|
|---|---|
|Critical|4|
|High|7|
|Medium|11|
|Low|5|
|Informational|4|
|**Total**|**31**|

**A line-by-line recount of the 31 numbered findings does not reconcile with this header**, and this is worth flagging explicitly rather than passing over:

|Severity|Recounted|Findings|
|---|---|---|
|Critical|4|001, 002, 003, 004|
|High|**8** (not 7)|005, 006, 007, 008, 009, 010, 011, **031**|
|Medium|**10** (not 11)|012, 013, 014, 015, 016, 017, 018, 019, 020, 021|
|Low|5|022, 023, 024, 025, 026|
|Informational|4|027, 028, 029, 030|
|**Total**|**31**||

The totals still sum to 31 either way, but the header's High/Medium split (7/11) does not match the itemized findings (8/10). The most likely explanation is that the header was generated from OpenVAS's automated output _before_ SecurePoint appended **Finding 031**, explicitly labeled "Added by SecurePoint - Manual Finding", which is itself rated High. This is a small but real discrepancy, and exactly the kind of thing a careful read catches and a quick glance does not: **the header should not be quoted to the Board without noting that the itemized findings put High at 8, not 7.**

**Medium is the largest genuine category** (10 findings), not Critical, a fact easy to lose sight of when 4 red "Critical" labels are the first thing anyone reads.

**A second, more consequential observation:** Finding 031 carries a CVSS Base Score of **9.8** (squarely in the Critical band (9.0–10.0) under standard CVSS severity conventions) yet SecurePoint labeled it "High," with no stated justification for the deviation. This stands in direct contrast to Finding 020, which also carries a 9.8 CVSS but comes with an explicit SecurePoint caveat explaining why it is likely a false positive in this environment. Finding 031 has no equivalent caveat. Depending on how MedDefense chooses to apply severity conventions, the true Critical count may be **5, not 4**. This is flagged here as an open question for deeper investigation, not resolved at this stage.

---

## 3. Asset Heat Map

Ranking hosts by number of _findings that name them individually_ (excluding the broad, device-class findings covering dozens of hosts at once, which are discussed separately below):

| Rank | Host                            | Findings                     | Count  | Asset Registry Role (0x00, Task 7)                                                                                                           |
| ---- | ------------------------------- | ---------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | **billing-srv-01** (10.10.2.15) | 001, 002, 006, 009, 011, 026 | 6      | A-004: Billing/claims processing server; already compromised twice in this program's prior incident history (ransomware, then a cryptominer) |
| 2    | **ehr-srv-01** (10.10.2.10)     | 017, 022, 030, 031           | 4      | A-001: EHR application server; the #1-ranked Critical asset in the 0x00 Criticality Assessment                                               |
| 2    | **web-srv-01** (10.10.2.50)     | 005, 012, 013, 021           | 4      | A-011: Public website and patient portal, MedDefense's DMZ-facing host                                                                       |
| 4    | **ad-dc-01** (10.10.2.20)       | 007, 018, 025                | 3      | A-005: Primary Domain Controller, the #2-ranked Critical asset in the 0x00 Criticality Assessment                                            |
| 5    | _(six-way tie, 1 finding each)_ | 003, 004, 008, 015, 020, 024 | 1 each | ehr-db-01 (A-002), WS-RAD-01 (A-019), print-srv-01 (A-008), NAS-01 (A-010), backup-srv-01 (A-009), pacs-srv-01 (A-003)                       |

**On that 5th-place tie:** ranking strictly by finding count is misleading here, and worth saying so directly. WS-RAD-01 (the MRI workstation) shows as "1 finding" in this table only because of how the report grouped it. Finding 004 alone bundles **3 separate, independently weaponized, remote-code-execution CVEs** (EternalBlue, BlueKeep, and MS08-067) into a single entry. By CVE count rather than report-line count, WS-RAD-01 is arguably as significant as the top 4 hosts above it, not a tail entry.

**Findings that span device classes rather than single hosts**. These do not fit a per-host ranking but represent real, broad exposure: Finding 010 covers 7 BD Alaris infusion pumps (A-028, one of the 0x00 Top 5 Critical assets); Finding 016 covers 13 Philips IntelliVue monitors (A-027); Finding 019 covers 5 hosts with RDP enabled; Finding 023 covers approximately 280 clinical workstations with no USB restriction policy; Finding 027 covers all Windows workstations organization-wide.

---

## 4. First Observations

**Critical findings are concentrated on two systems, not spread evenly.** Of the 4 header-labeled Critical findings, 2 (Findings 001–002) sit on billing-srv-01 and 1 (Finding 004) sits on WS-RAD-01; only Finding 003 (ehr-db-01) stands alone. This is not a scatter of unrelated issues, it is 2 systems each carrying a serious, self-contained problem.

**Several findings are explicitly, textually related to each other. The report says so directly, more than once:**

- Findings 001 and 002 (both on billing-srv-01) are described in the report itself as a chain: remote code execution as `www-data` (001) followed by local privilege escalation to root (002). That means an attacker does not need 2 separate opportunities, they need one entry point and then a documented follow-on step.
- Finding 011 (Ubuntu 18.04 EOL, no Extended Security Maintenance) is the explicitly stated _reason_ Finding 026 exists (47 unpatched kernel CVEs). The report cross-references this directly.
- Finding 017 (Medium - Tomcat error pages suggest AJP might be present, unconfirmed) and Finding 031 (High - SecurePoint manually confirmed AJP is active and is CVE-2020-1938/Ghostcat, CVSS 9.8) are the same underlying issue at two stages of verification. Finding 031 exists _because_ someone followed up on Finding 017 rather than dismissing it as informational. A good illustration of why "Medium, unconfirmed" should not automatically mean "low priority."

**2 systems already known to this program from prior work reappear here, and one new fact was added.** Findings 028 and 029 are the same undocumented shadow IT devices already flagged as Shadow IT assets in the 0x00 Asset Registry (A-012 and A-024). This scan adds a genuinely new detail for the Westside device: it is running Grafana 8.2.0, which the report ties to a specific, unauthenticated, trivially-exploitable path traversal CVE. 2 projects' worth of separate investigation just independently converged on the same 2 devices, that convergence itself is worth noting.

**The heat map and the 0x00 criticality ranking don't fully agree, and that gap is itself informative.** billing-srv-01 tops this scan's finding count by a wide margin, yet it does not appear in the 0x00 Top 5 Critical Assets at all. Meanwhile ad-dc-01 and WS-RAD-01, both 0x00 Top 5 assets, show comparatively few findings in raw count. This does not mean billing-srv-01 matters more than the EHR or the domain controller; it more likely means billing-srv-01 has been left unmaintained longer (it is the same server already compromised twice in this program's incident history) and is simply easier for a scanner to find problems on, not that its problems outweigh a domain controller compromise in consequence. Finding _volume_ and asset _criticality_ are not the same axis, and this scan report should not be read as if they were.

**What surprised me most on a first read** is Finding 010's second half: 7 infusion pumps were checked for default credentials, and 7 had never had them changed. That is not a partial finding or a sample, it is a 100% failure rate on the only pumps this unauthenticated scan could reach at all, which raises an obvious and uncomfortable question about the pumps this scan _did not_ reach (see Section 5).

---

## 5. Scan Limitations

**Explicitly stated by SecurePoint:** this scan does not cover cloud services (O365), mobile devices (iPads), or any asset offline during the 02:00–06:00 window. No exploitation was attempted, so every finding here reflects theoretical exploitability based on version and configuration, not confirmed real-world exploitability in MedDefense's specific environment. A 5–10% false-positive rate applies to this OpenVAS configuration by SecurePoint's own admission. Finding 020 is flagged as a likely example.

**A limitation the report does not state outright, but that cross-referencing against the 0x00 Asset Registry makes visible:** this scan's device coverage is a small fraction of MedDefense's actual medical IoT population. The Asset Registry documents approximately 80 Philips IntelliVue monitors and approximately 120 BD Alaris infusion pumps across the organization; this scan reached 13 monitors and 7 pumps, roughly 16% and 6% of each population, respectively. The 100% default-credential failure rate on the pumps this scan _did_ reach (see Section 4) is a sample, not a census, and there is no basis in this report to assume the other 94% of pumps are any better configured.

**This scan is a single point-in-time snapshot, five days old at the time of this review.** It reflects what was true on one night; it says nothing about vulnerabilities disclosed since, configuration drift since, or any of the roughly 80 CVEs published daily across the broader software ecosystem this environment depends on. Authenticated depth also varies sharply by asset class. Linux and Windows systems received a genuine configuration audit, while every medical device on this list was assessed from the network layer only, with no credentialed insight into firmware, running processes, or local configuration at all.

**Bottom line for what comes next:** this scan tells us a great deal about MedDefense's servers and workstations, meaningfully less about its network and Windows infrastructure's configuration hygiene, and comparatively little about the true state of its medical device fleet. The gap between "13 monitors checked" and "80 monitors in service" is the single largest blind spot this report leaves open.
