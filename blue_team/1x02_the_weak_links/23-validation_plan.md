# MedDefense Health Systems: The Validation Plan

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** The Remediation Map (Task 19) and Priority Matrix (Task 20) of this project **Purpose:** A patch that was deployed but failed silently is worse than no patch at all, because everyone believes the problem is solved when it is not. This plan defines exactly how MedDefense confirms a fix actually worked, and how the vulnerability management program continues after this one assessment closes.

---

## 1. Post-Patch Verification

Three of the six Immediate-tier remediations from Task 20 are detailed here as representative examples of the verification methodology MedDefense should apply to every remediation, not only these three.

**Finding 031 (Ghostcat, AJP connector on ehr-srv-01).** If the AJP connector was disabled entirely, verification requires a direct connection attempt to port 8009 from another host: the port should now report closed or filtered, not open. If instead the connector was kept active with a required secret configured, verification requires attempting an unauthenticated AJP request and confirming it is rejected. The definitive check, matching this task's own example directly, is re-running the specific exploit tooling already confirmed in Task 5 of this project (the dedicated Metasploit module, EDB-49039) against the patched server in a controlled test and confirming it now fails where it previously would have succeeded.

**Finding 003 (PostgreSQL exposure, ehr-db-01).** From a host other than ehr-srv-01, attempt a connection to port 5432 on ehr-db-01 and confirm it is refused or times out. Separately, and just as important, confirm from ehr-srv-01 itself that the connection still succeeds, since a verification process that only checks the block and never checks that legitimate access still works risks discovering a broken EHR application days later instead of immediately. Directly inspect pg_hba.conf to confirm the entry now specifies ehr-srv-01's exact IP rather than the previous 10.10.0.0/16 range, and review host firewall logs to confirm drop events are actually being recorded for any unauthorized connection attempt, not just silently discarded.

**Finding 010 (BD Alaris default credentials).** Attempt to log into the web management interface of each pump using the previous default admin/admin credentials and confirm access is now denied. This alone is not sufficient: separately confirm the new credentials were recorded in a secure, shared credential vault rather than known only to whoever changed them, a real operational risk specific to device fleets where the person who performed the change may not be the person troubleshooting the device six months later. For the network isolation portion of this remediation, a follow-up scan initiated from a general clinical workstation should confirm the pumps are no longer reachable outside their designated VLAN.

---

## 2. Compensating Control Validation

Compensating controls require a verification standard the patch-based examples above do not, because there is no single moment where a vulnerability is definitively closed; the control must be confirmed both effective and non-disruptive on an ongoing basis, not validated once and assumed permanent.

**For Finding 004 (MRI workstation segmentation).** From a general clinical workstation not on the PACS-restricted VLAN, a port scan against WS-RAD-01 should return no response at all, confirming isolation. Separately, and this is the step most likely to be skipped under time pressure, confirm from the PACS server itself that the imaging workflow still functions correctly end to end, since a segmentation change that blocks the attacker but also silently breaks the legitimate imaging handoff is a failed remediation regardless of its security effectiveness. If a network-layer virtual-patching or IPS signature was deployed for the underlying SMB/RDP exploits, test it directly using a benign, signature-matching test packet through an authorized testing tool, never a live exploit against a production clinical device, to confirm the control actually triggers and logs the event rather than passing traffic through unnoticed.

**For Finding 010 and Finding 016 (medical device segmentation broadly).** The same two-part standard applies: confirm restricted reachability from outside the designated VLAN, and confirm that alerting fires when an unauthorized device attempts to reach the segment, which tests the control's detection capability, not only its blocking capability. A compensating control that blocks silently, with no log entry generated, gives MedDefense no way to know how often it is actually being tested by real traffic, which is itself a gap worth closing alongside the control's deployment.

**The general principle underlying both examples above:** every compensating control needs two checks, not one, does it actually stop the risk it was deployed against, and does it leave legitimate clinical operation intact. Validating only the first risks discovering the second has failed only when a clinician reports it, which is the wrong way for MedDefense to learn that a security control broke patient care.

---

## 3. Rescan Schedule

A single rescan frequency does not fit MedDefense's environment, given the wide gap in criticality between, for example, the EHR system and a general print server. A tiered cadence is recommended instead.

**Critical assets** (the 0x00 Top 5: the EHR system, the domain controller, the medical device fleets, and the backup infrastructure) should receive an authenticated vulnerability scan **weekly**. This is justified directly by a figure already established in this project's own introduction: roughly 80 new CVEs are disclosed industry-wide every day, meaning a monthly cadence alone leaves up to 30 days of blind spot on newly disclosed vulnerabilities affecting the systems MedDefense can least afford to have exposed, and a weekly cadence closes that gap specifically where the consequence of missing something is highest.

**The full network** should receive a complete scan, matching this assessment's own scope, **monthly**. This exceeds common regulatory minimums (quarterly is a frequent baseline elsewhere) deliberately, given this project's own findings already demonstrated a materially higher-than-typical concentration of misconfiguration-driven risk in this specific environment.

**Event-driven rescans**, outside the calendar schedule entirely, should trigger immediately after any remediation is marked complete, confirming the fix rather than waiting for the next scheduled cycle to discover it failed, and immediately following any CISA KEV catalog addition or vendor advisory matching software confirmed present in MedDefense's asset inventory (Section 4 below).

This tiered approach is deliberately calibrated against the same budget reality established in Task 20 of this project: a daily, full-network, fully authenticated scanning regime would be the technically ideal answer but is not realistic given a remediation budget that already strains the available security reserve; the weekly-critical, monthly-full, plus event-driven model concentrates the highest-frequency monitoring where the consequence of a miss is greatest, rather than spreading a constrained budget evenly across assets of very different importance.

---

## 4. Continuous Intelligence

This project's own OSINT research (Task 9) found three Critical vulnerabilities, on MedDefense's firewall, its cloud identity provider, and its backup NAS, that the internal scan never touched at all. That was a one-time research exercise for this assessment; it needs to become a standing practice, not a single event.

**CISA KEV catalog monitoring.** MedDefense should subscribe directly to CISA's KEV catalog update feed. Any new addition should be checked immediately against MedDefense's own asset inventory (the 0x00 Asset Registry); a match should trigger the same 24-48 hour Immediate-tier response already defined in Task 20 of this project, regardless of where in the normal scan-and-triage cycle that finding would otherwise have surfaced.

**Vendor advisory subscriptions**, specific to MedDefense's actual technology stack rather than a generic security news feed: Fortinet's PSIRT advisories (the firewall), Microsoft's MSRC (Entra ID and the O365 tenant), Synology's Product Security bulletins (the backup NAS), BD's Cybersecurity Trust Center and Philips' product security notices (the medical device fleets), and the Apache and Ubuntu security notice lists (the servers this assessment already found carry the highest finding density). A maintained mapping of which vendor advisories correspond to which specific assets in MedDefense's inventory turns a new advisory into an immediate, answerable question, is this asset affected, rather than the from-scratch research effort this project's Task 9 necessarily was as a first pass.

**A recurring OSINT research cycle**, run quarterly, specifically targeting the categories this assessment's own scan could not reach at all: cloud services, firewall and network appliance firmware, and medical device firmware. This project's own experience is the direct justification: every one of the three OSINT-discovered vulnerabilities in Task 9 fell into exactly one of these three categories, meaning a scan-only vulnerability management program will structurally miss this class of risk indefinitely unless a deliberate, recurring research step is built in to compensate for it.

---

## 5. Lifecycle Diagram

MedDefense's ongoing vulnerability management program should run as a continuous cycle, not a project with an end date. The six stages below, Scan, Triage, Prioritize, Remediate, Validate, Repeat, are described here with the party responsible for each, and the cycle should be understood as overlapping in practice, with different findings at different stages simultaneously, rather than a strict step-by-step sequence applied to the entire finding set at once.

**Scan.** A Security Analyst initiates and reviews the scheduled or event-driven scan, per the cadence in Section 3, and reads the raw output in full before touching any individual finding, exactly the discipline this project's own Task 0 established at the very start of this assessment.

**Triage.** The Security Analyst classifies every finding into an action category (Actionable Critical, Actionable Standard, Informational, or False Positive, per the methodology built in Task 16 of this project), escalating any confirmed weaponized, KEV-listed, or critical-asset finding for immediate attention rather than waiting for the full triage pass to complete before acting on the most urgent items.

**Prioritize.** The Security Analyst applies threat and environmental context (asset criticality, kill chain position, exploit availability, and existing compensating controls, per the methodology built in Tasks 17 and 18 of this project) to produce a final priority order. Management, specifically the Deputy CISO and IT Director, reviews and approves that order, particularly wherever a budget tradeoff is involved, as it was directly in Task 20 of this assessment.

**Remediate.** IT Operations executes the approved patches and configuration changes. Vendor involvement is required wherever MedDefense cannot directly modify the affected system itself, medical device firmware updates from BD or Philips being the clearest example. Clinical or Biomedical Engineering sign-off is required specifically for any change touching a medical device, a coordination dependency this project's own Task 19 identified as unique to that asset class.

**Validate.** The Security Analyst performs the specific verification checks described in Sections 1 and 2 above, confirming both that the vulnerability is closed and that legitimate operation was not disrupted. IT Operations confirms operational functionality independently, since the team executing a change is not always well positioned to notice its own side effects, a second set of eyes matters here.

**Repeat.** The cycle restarts on the schedule defined in Section 3, plus any event-driven trigger from Section 4, with newly-scanned findings feeding directly back into Triage rather than starting the process over from a blank slate each time. This is the point at which a vulnerability assessment stops being a project MedDefense completed once and becomes a capability MedDefense maintains continuously, which is the actual goal this entire body of work has been building toward from its first task.
