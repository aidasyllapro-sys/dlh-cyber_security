# MedDefense Health Systems : The Priority Matrix

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO (for direct handoff to the IT Director) **Source material:** All 24 Actionable findings from Task 16's triage (12 Actionable Critical, 12 Actionable Standard), organized by remediation deadline rather than by scan-assigned severity alone **Purpose:** The document that goes on the IT Director's desk Monday morning. No ambiguity, no "it depends." Every finding here has a deadline, an action, an owner, and a cost.

---

## Immediate (24-48 hours)

Weaponized exploit, critical asset, active threat.

|Finding|Description|Remediation Action|Owner|Cost|
|---|---|---|---|---|
|031|Ghostcat (CVE-2020-1938), unauthenticated file read on the EHR application server|Disable or secure the AJP connector on ehr-srv-01|IT|$500|
|003|PostgreSQL accepts connections from the entire internal network on ehr-db-01|Restrict pg_hba.conf to ehr-srv-01 only, add host firewall rule|IT|$500|
|010|Default admin credentials confirmed unchanged on 100% of scanned BD Alaris pumps|Change default credentials fleet-wide; begin network isolation planning|Clinical/Biomedical Engineering|$3,000|
|004|Three weaponized, KEV-listed CVEs on the unpatchable MRI workstation|Emergency interim ACL restricting WS-RAD-01 to PACS-only traffic, pending the full 30-day VLAN project below|IT/Network|$25,000 (covers both the interim ACL and the full segmentation project)|
|028|Unidentified device (UNKNOWN-01) on the same subnet as the domain controller and EHR database|Isolate at the switch port immediately, then investigate origin and purpose|IT/Security|$250|
|029|Unidentified device at Westside running a vulnerable Grafana instance (CVE-2021-43798)|Isolate immediately; patch or decommission Grafana once origin is confirmed|IT/Security|$500|

**Immediate tier subtotal: $29,750**

---

## Short-term (7 days)

Critical/High CVE with a public proof of concept, on an important asset.

|Finding|Description|Remediation Action|Owner|Cost|
|---|---|---|---|---|
|001|Apache mod_lua RCE (CVE-2021-44790), Step 1 of the project's highest-priority kill chain|Patch Apache to 2.4.52 or later, staged and tested first|IT|$5,000|
|002|Chained local privilege escalation (CVE-2019-0211) on the same host, confirmed weaponized|Resolved by the same Apache upgrade as Finding 001|IT|$0 (bundled)|
|015|Synology DSM RCE (CVE-2024-10441), sole backup infrastructure|Patch DSM after a verified backup-of-the-backup|IT|$5,000|
|006|MySQL bound to all interfaces on billing-srv-01, exposing financial data network-wide|Restrict MySQL bind address; scheduled in the same maintenance window as Finding 001|IT|$500|
|009|SSH password authentication enabled on a repeat-compromised host|Enforce key-only authentication, same maintenance window|IT|$500|
|013|SSL certificate on the patient portal expiring in 23 days, no auto-renewal|Renew and configure automatic renewal|IT|$250|

**Short-term tier subtotal: $11,250**

---

## Medium-term (30 days)

High/Medium CVE or significant misconfiguration.

|Finding|Description|Remediation Action|Owner|Cost|
|---|---|---|---|---|
|007|LDAP signing not required on the domain controller|Enable signing requirement after an audit-mode discovery period for legacy dependencies|IT|$500|
|008|PrintNightmare (CVE-2021-34527), weaponized and KEV-listed, on a non-critical print server|Disable the Print Spooler service, or restrict its network exposure if printing is required|IT|$500|
|016|Philips IntelliVue monitors expose unauthenticated web interfaces and an unauthenticated HL7 feed|Segment medical monitoring devices onto a dedicated VLAN|IT/Network|$4,000|
|018|Weak Kerberos encryption types supported on both domain controllers|Disable DES and RC4, enforce AES only, same review cycle as Finding 007|IT|$500|
|005|TLS 1.0 still supported on the internet-facing patient portal|Disable TLS 1.0 and 1.1, confirm TLS 1.3 support|IT|$500|
|012|Missing security headers on the patient portal|Add CSP, X-Frame-Options, HSTS, and related headers|IT|$250|
|017|Tomcat default error pages disclosing version and path information|Suppress default error page detail|IT|$250|
|019|RDP enabled on 5 hosts, partially mitigated by NLA already being active|Review necessity per host, restrict to required sources only|IT|$500|
|023|No Group Policy restriction on USB mass storage across roughly 280 clinical workstations|Deploy a single GPO restricting USB mass storage fleet-wide|IT|$3,000|

**Medium-term tier subtotal: $10,000**

---

## Long-term (90 days)

Architecture changes, EOL migrations, systemic fixes.

|Finding|Description|Remediation Action|Owner|Cost|
|---|---|---|---|---|
|011|Ubuntu 18.04 past standard support, Extended Security Maintenance not enrolled, on the organization's most-compromised host|Full OS migration to a current Ubuntu LTS release (the quarter's recommended migration target per this project's Task 12 analysis), not merely an ESM subscription|IT|$15,000|
|026|47 unpatched kernel CVEs on billing-srv-01, a direct consequence of Finding 011|Resolved by the same migration as Finding 011|IT|$0 (bundled)|
|014|Consumer-grade router as Westside's sole perimeter device, terminating the site-to-site VPN|Replace with enterprise-grade firewall/VPN endpoint; interim admin-interface access restriction can be applied sooner as a stopgap|IT/Network|$5,000|

**Long-term tier subtotal: $20,000**

---

## Budget Summary

**Total estimated cost of all 24 remediations: $71,000.**

This is measured against the **$120,000 annual security budget established in Project 0x00**, but a straight comparison against the full $120,000 would be misleading and is deliberately avoided here. Project 0x00's own risk treatment decisions (Task 14) already committed **$84,900 of that budget to prior remediation decisions**, leaving only **$35,100 in remaining reserve**, itself already earmarked in that same prior analysis for "GAP-005 server AV starter and MRI compensating controls." This new $71,000 remediation plan is not competing against a fresh $120,000; it is competing against an already-depleted $35,100.

**Even the Immediate tier alone ($29,750) very nearly consumes the entire remaining reserve on its own**, and notably, Finding 004's $25,000 segmentation cost aligns almost exactly with the "MRI compensating controls" line item this reserve was already set aside for in Project 0x00, meaning that specific allocation was correctly anticipated, not a new surprise. Adding the Short-term tier ($11,250) brings the combined Immediate-plus-Short-term total to **$41,000, a $5,900 shortfall against the $35,100 remaining reserve**, before the Medium-term ($10,000) or Long-term ($20,000) tiers are even considered.

**What must be deferred, and why:**

Given this shortfall, the recommendation is to fund the **Immediate tier in full ($29,750)**, consistent with its already-anticipated budget purpose and its 24-48 hour deadline, which leaves no realistic room for delay regardless of funding source. Within the Short-term tier, **Findings 006, 009, and 013 (combined $1,250) should be deferred into the Medium-term window** rather than held to a strict 7-day deadline; none of the three carries the same weaponized-exploit or kill-chain-position urgency as Findings 001, 002, or 015, and this project's own Task 17 environmental analysis already established that asset criticality, not raw CVSS, should drive final urgency, a standard these three findings do not meet at the same tier as the rest of this list. This deferral closes roughly $10,000 of the shortfall, leaving an approximately **$5,900 gap that requires either a supplemental Board request or reallocation from the Medium-term or Long-term tiers**. Given Project 0x00's own CISO Briefing already demonstrated the Board responds well to a specific, well-justified request (the MFA budget correction that revealed a recommended control was available at $0 cost through existing licensing), a similarly narrow, specific request, covering exactly the $5,900 gap and framed against the same "2% of comparable breach recovery cost" business case already used successfully once, is the recommended path forward rather than deferring any Immediate-tier item past its safety-relevant deadline.

**Medium-term and Long-term tiers ($10,000 and $20,000 respectively) are not requested against the current fiscal year's remaining reserve at all** and should instead be built into next year's security budget planning cycle, with Finding 011's $15,000 migration project flagged as the single highest-priority line item to carry forward, given this project's own Task 12 analysis already identified it as this quarter's most feasible and highest-leverage remediation, only delayed here by the current year's funding exhaustion rather than by any technical or operational obstacle.
