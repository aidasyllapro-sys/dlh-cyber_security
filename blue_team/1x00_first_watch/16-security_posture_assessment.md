# MedDefense Health Systems

## Security Posture Assessment
## 1. Executive Summary

MedDefense Health Systems currently operates with a security posture that is **inconsistent with the risk it carries as a regional hospital group handling protected health information for over 50,000 patients.** The organization has made real investments in security (a firewall, backup software, antivirus, and a password policy all exist) but these investments are narrow, unevenly applied, and built almost entirely around _preventing_ incidents, with very little capacity to _detect_ one already in progress or to _recover_ quickly if prevention fails. This is not a hypothetical concern: a cryptocurrency-mining infection was found running undetected on a critical financial server for an extended period earlier this year, discovered only because a staff member happened to investigate an unrelated performance complaint.

**The single most critical finding of this assessment** is that MedDefense's internal computer network has no internal boundaries. Every device, from a nurse's workstation to the servers holding the complete patient record system to the infusion pumps delivering patient medication, sits on one shared network with no restrictions between them. This means that a single compromised device, anywhere in the organization, can potentially reach every other system, including the most sensitive ones. This single condition is the reason nearly every other finding in this report is more dangerous than it would otherwise be.

**Top 3 recommended actions:**

1. **Give MedDefense the ability to detect a problem before it becomes a crisis.** Right now, incidents are found by accident, not by design. A basic monitoring capability is the single highest-value investment available.
2. **Divide the internal network into separate, restricted zones**, starting with the medical devices connected directly to patient care, so that one compromised computer cannot reach everything else.
3. **Fix the 2 weakest links in identity security** require a second form of verification (not just a password) for remote and administrative access, and automatically cut off system access the moment an employee leaves.

**Budget implication:** The security priorities in this report can be funded within MedDefense's existing $120,000 security budget for this fiscal year, but full remediation of the risks identified here is a multi-year effort. Sustaining a comparable level of security investment in future years is necessary to complete the work this budget begins.

---

## 2. Scope and Methodology

### What was assessed

This assessment covers all 3 MedDefense sites (MedDefense Central Hospital (350-bed acute care facility), Westside Clinic (outpatient facility), and Corporate HQ (administrative offices)) and the approximately 2,000 employees across clinical, administrative, and IT functions who work there. The technical scope includes servers, network infrastructure, endpoints (workstations, laptops, and mobile devices), medical IoT devices (patient monitors, infusion pumps, imaging equipment), applications (the EHR, PACS, billing system, and patient portal), and the sensitive data these systems hold as patient medical records, financial and billing data, employee records, imaging data, and system credentials.

### Sources of information used

This assessment is built from: MedDefense's own IT documentation (asset lists, network diagrams, service contracts, and internal notes); a physical security walk-through of MedDefense Central conducted with the Deputy CISO; a technical network scan of all MedDefense subnets; direct review of firewall, authentication, backup, antivirus, and physical security configuration artifacts; interviews with IT staff regarding undocumented systems; a documented incident history from the past six months; an unfinished internal assessment left by the previous Security Analyst; and validation against three anonymized, real-world healthcare sector breaches drawn from public CISA, HHS, and industry reporting.

### Limitations and Assumptions

This assessment is based on documentation review, a network scan, and physical observation. **It does not include active penetration testing, and no vulnerabilities were exploited to confirm exploitability**.** The network scan itself was described by the IT Director as a partial capture ("there might be devices that were powered off during the scan"), and several details remain confirmed unknowns rather than established facts, including the operating system of the CT scanner, the network visibility of physician iPads, and the exact scope of two unidentified network devices discovered during the scan. Cost estimates in this report are rough order-of-magnitude figures, except where a specific vendor quote is cited directly. Where this assessment could not verify a claim with confidence, it says so explicitly rather than presenting an assumption as fact. Several such items are flagged throughout as requiring direct follow-up verification.

---

## 3. Asset landscape

### Asset Inventory Summary

MedDefense's technical environment comprises the following, consolidated from a full asset registry of 38 distinct entries (individual systems and grouped device populations):

|Asset Type|Approximate Count|Primary Location(s)|
|---|---|---|
|Servers|12 (11 IT-managed + 1 unidentified)|Central (server room)|
|Network Devices|5 (firewall, switches, access points, edge routers)|Central, Westside|
|Endpoints (workstations, laptops, thin clients, tablets)|~700+|All three sites|
|Medical IoT Devices (monitors, infusion pumps, imaging equipment, nurse call, badge readers)|~215+|Central primarily|
|Applications / Data Stores|3 (EHR, O365, PACS application layer)|Central (hosted), cloud|
|Physical Infrastructure (badge access, cameras)|Multiple, uneven coverage|Central|
|Undocumented / Shadow IT|5 confirmed (2 network devices, 1 personal storage device, 1 unofficial cloud service, 1 abandoned monitoring device)|Central, Westside, cloud|

### Top 5 Critical Assets

1. **The EHR System** (application and database): the authoritative clinical record for every patient at Central and Westside; a prior outage already forced a full return to paper records for 9 hours, and a separate data-integrity incident displayed incorrect medication dosage information at all three sites for approximately 6 hours.
2. **The Primary Domain Controller**: nearly every other system depends on this asset for authentication; its compromise would not fail one system, it would undermine trust in logins across the entire organization simultaneously.
3. **Infusion Pumps (~120 units)** of every asset in this environment, this is the one where a security failure translates most directly into physical harm to a patient; the manufacturer has already issued a security advisory recommending network isolation that has not been implemented.
4. **The MRI Scanner and its Control Workstation**: a $2.1 million clinical asset running software that has not received a security update in over a decade, for regulatory reasons tied to its medical device certification, supporting approximately 45 patient studies per day.
5. **Backup and Recovery Infrastructure**: the only documented path back to normal operations for six of MedDefense's most important systems, currently stored in the same room, on the same network, as the systems it is meant to protect.

### Data Classification Summary

MedDefense holds data across all four standard sensitivity levels, with the large majority falling into the highest category:

- **Restricted** (5 categories): Patient medical records, medical imaging data, financial/billing and insurance claims data, system credentials, and real-time medical device/vital-signs data.
- **Confidential** (3 categories): Employee HR records, security/system audit logs, and corporate/administrative/vendor data.
- **Public** (1 category): Public website content.

This assessment found the widest gap between data sensitivity and actual protection in the handling of **System Credentials**. Administrative passwords for core network infrastructure were found physically posted, in plain view, inside an unlocked equipment closet.

---

## 4. Current Security Controls

### Control Inventory Summary

MedDefense currently has **17 implemented security controls**, plus 4 additional controls that have been designed but not yet put in place. The distribution across the standard security control framework (Technical, Administrative, and Physical categories; Preventive, Detective, Corrective, Compensating, and Deterrent functions) is as follows:

|Category|Preventive|Detective|Corrective|Compensating|Deterrent|
|---|---|---|---|---|---|
|Technical|6 controls|5 controls|1 control|0|0|
|Administrative|2 controls|0|0|0|0|
|Physical|2 controls|1 control|0|0|0|

### Overall Maturity Assessment

**Where MedDefense is comparatively stronger:** Basic preventive technical controls exist and are reasonably configured (a firewall with a default-deny policy, a documented password policy, and endpoint antivirus protection) where they apply.

**Where MedDefense is weak, and this is the core finding of this section:** Every single detective control identified in this assessment, across network, server, and physical security alike, was rated as having limited real-world effectiveness, primarily because none of them are centrally monitored or configured to generate an alert. MedDefense currently has the _raw materials_ for detection (logs exist in multiple places) but not the _capability_ to act on them. Corrective capability (the ability to recover and restore after an incident) is limited to a single, structurally compromised backup system. Compensating controls (alternatives for systems that cannot be directly secured, such as the MRI) and deterrent controls (measures that discourage an attack attempt in the first place) are almost entirely absent across the entire organization.

### Key Control Effectiveness Findings

- Endpoint antivirus protection **excludes every server in the organization**, Windows and Linux alike, which is the exact gap that allowed an unauthorized cryptocurrency-mining program to run undetected on a financial server.
- The organization's only backup system is physically co-located with the servers it protects, has never been the subject of a full disaster-recovery test, and explicitly excludes several important systems, including the medical imaging archive.
- Multi-factor authentication, a widely regarded baseline control for any organization handling sensitive data, is deployed on exactly one individual's personal account, configured by that person themselves, and nowhere else.
- Physical access to the server room housing nearly all of MedDefense's critical infrastructure uses the same generic badge issued to every employee on their first day, regardless of role, with no camera and no visitor log.

---

## 5. Gap Analysis

This assessment identified **25 distinct security gaps**, distributed as follows:

|Risk Level|Count|
|---|---|
|Critical|15|
|High|7|
|Medium|2|
|Low|1|
|**Total**|**25**|

### Critical-Risk Gaps

| Gap ID  | Description                                                                                                                                         | Affected Asset(s)                                         | Potential Impact                                                                                                   | Recommended Treatment                                                                      |
| ------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| GAP-001 | Medical IoT devices (infusion pumps, patient monitors) have zero security control coverage                                                          | ~120 infusion pumps, ~80 patient monitors                 | Direct, immediate threat to patient safety via falsified dosage or monitoring data                                 | Mitigate: Device credential audit (immediate) + network isolation (phased)                 |
| GAP-002 | MRI workstation runs an operating system unpatched since 2014, with no compensating controls yet implemented                                        | MRI scanner and control workstation                       | Halted diagnostic imaging capability (~45 studies/day); unpatchable entry point on the shared network              | Mitigate: Compensating control strategy designed, funding pending                          |
| GAP-003 | The EHR database is reachable from the entire internal network, bypassing application-level protections                                             | ehr-db-01, all patient records                            | Mass exposure of patient records if any device on the network is compromised                                       | Mitigate: Restrict database access to the application server only                          |
| GAP-004 | No centralized security monitoring or alerting exists anywhere in the organization                                                                  | Every critical system                                     | Incidents are discovered by accident, not by design — already demonstrated once                                    | Mitigate: Deploy centralized log monitoring (see Section 6)                                |
| GAP-005 | No antivirus/endpoint protection exists on any server                                                                                               | All servers, including the domain controller and EHR      | Repeat malware compromise, following the exact pattern already experienced once                                    | Mitigate: Deferred to next fiscal year; phased rollout starting with highest-value servers |
| GAP-006 | The only backup system is a single point of failure, co-located with production systems                                                             | All backed-up critical systems                            | Total, unrecoverable data loss in a site-level incident                                                            | Mitigate: Offsite backup replication (see Section 6)                                       |
| GAP-007 | The server room and core network closet have no camera or differentiated physical access control                                                    | All infrastructure housed in these rooms                  | Undetected physical tampering or theft of core infrastructure                                                      | Mitigate:Deferred to next fiscal year                                                      |
| GAP-010 | Multiple unidentified, unmanaged devices operate on the same network as critical systems                                                            | Two unidentified network devices                          | Unknown-duration, unmonitored foothold adjacent to the most sensitive systems in the organization                  | Mitigate: Immediate investigation, near-zero cost                                          |
| GAP-014 | The entire internal network has no segmentation, allowing any compromised device to reach any other                                                 | Every critical asset in the organization                  | The organization-wide amplifier behind nearly every other finding in this report                                   | Mitigate: Network segmentation project (see Section 6)                                     |
| GAP-015 | No formal, tested incident response plan exists                                                                                                     | Organization-wide response capability                     | Extended, costly, improvised response to any future incident                                                       | Mitigate: Plan development and tabletop exercise (see Section 6)                           |
| GAP-017 | Multi-factor authentication is not required anywhere in the organization                                                                            | All remote and administrative access                      | A single stolen or retained password is sufficient for unauthorized access                                         | Mitigate: Phased MFA rollout (see Section 6)                                               |
| GAP-018 | No automated process disables system access when an employee leaves                                                                                 | Identity and account infrastructure                       | Extended unauthorized access by former employees, already a documented real-world cause of a comparable breach     | Mitigate: Process fix (see Section 6)                                                      |
| GAP-019 | No controls exist to detect or prevent bulk export of sensitive data                                                                                | The EHR and other Restricted-data systems                 | Undetected large-scale data theft, mirroring a documented real-world insider breach                                | Mitigate: Deferred to next fiscal year (technology purchase)                               |
| GAP-021 | Westside Clinic's consumer-grade network equipment directly extends risk into Central's core infrastructure via an overly permissive VPN connection | Central's entire server subnet, via the Westside VPN link | A compromise at the smaller, less-defended clinic becomes a direct path into the hospital's most sensitive systems | Mitigate: Deferred to next fiscal year; requires a managed firewall at Westside            |
| GAP-025 | No formal process governs changes to servers or network configuration                                                                               | Organization-wide                                         | Already caused one documented, costly failure (a backup left unusable for weeks due to an untested change)         | Mitigate: Establish a basic change approval and testing process                            |

### High-Risk Gaps

| Gap ID  | Description                                                                                                  | Affected Asset(s)                                                    | Potential Impact                                                                                                          | Recommended Treatment                                             |
| ------- | ------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| GAP-008 | Physician tablets (~25 iPads) have no device management, encryption enforcement, or remote-wipe capability   | Physician iPads                                                      | Uncontained data exposure if a device is lost or stolen                                                                   | Mitigate: Deferred; requires a mobile device management solution  |
| GAP-009 | No process exists to verify that security policies are actually followed in practice                         | Organization-wide credential and access practices                    | Silent, ongoing drift between stated policy and actual practice, already observed                                         | Mitigate: Deferred; requires a periodic compliance review process |
| GAP-011 | Employee HR records have no clearly documented storage location or system owner                              | Employee personal data                                               | Inability to confirm data protection or investigate a breach affecting employee records                                   | Mitigate: Deferred; requires an internal data-inventory exercise  |
| GAP-016 | No process exists to track or apply security updates to perimeter network equipment                          | The organization's main firewall and remote-access equipment         | The exact root cause of a real-world hospital ransomware breach reviewed in this assessment                               | Mitigate: Establish a basic patch tracking process, low cost      |
| GAP-020 | The security configuration of the internet-facing patient portal server has never been fully verified        | Patient portal, and by extension the internal network it connects to | Unconfirmed risk of the same misconfiguration that enabled a real-world medical-device breach reviewed in this assessment | Mitigate: Immediate verification, near-zero cost                  |
| GAP-023 | The patient portal supports an outdated, weaker encryption protocol (TLS 1.0) alongside the current standard | Patient portal                                                       | Interception risk under a forced downgrade or legacy-client scenario                                                      | Mitigate: Disable the outdated protocol, near-zero cost           |
| GAP-024 | USB storage devices are unrestricted on all workstations, with no complementary data-loss protection         | All workstations                                                     | An open, largely undetectable path for sensitive data to leave the organization                                           | Mitigate: Deferred; policy-level restriction                      |

### Medium and Low-Risk Gaps

Two Medium-risk gaps were identified: incomplete security awareness training coverage (ranging from 58% to 94% completion across sites, with no phishing simulation program) and a shared login credential in the Radiology department that limits, but does not eliminate, individual accountability for imaging system access. One Low-risk gap was identified: an end-of-life print server, which carries limited direct risk given its narrow function and internal-only accessibility, though it should still be migrated during a routine maintenance window.

### Gap Distribution Analysis

The most consistent pattern across all 25 gaps is a near-total absence of **detective capability**, the ability to notice something is wrong, across every category of control (technical, administrative, and physical alike). This single theme underlies the network monitoring gap, the physical security camera gap, and the policy-compliance gap alike, and it was independently confirmed as the one factor present in all three real-world healthcare breaches used to validate this assessment. The second most concentrated area is **Identity and Network Core Infrastructure** (the systems responsible for authentication and network connectivity) reflecting that MedDefense's foundational architecture, not any single application, is the organization's primary point of exposure.

---

## 6. Risk Treatment Recommendations

Given a $120,000 annual security budget, MedDefense cannot address all 25 identified gaps this fiscal year. The following 7 priorities were selected because they were independently validated as the highest-leverage weaknesses against real-world healthcare breach data, and because each is achievable within this year's funding.

| Priority | Gap ID  | Recommendation                                                                               | Treatment | Est. Cost   | Timeline               |
| -------- | ------- | -------------------------------------------------------------------------------------------- | --------- | ----------- | ---------------------- |
| 1        | GAP-004 | Deploy centralized, open-source security monitoring                                          | Mitigate  | ~$20,000    | Long-term (>1 month)   |
| 2        | GAP-014 | Network segmentation, Phase 1 (Central: servers, workstations, priority medical-device zone) | Mitigate  | ~$35,000    | Long-term (>1 month)   |
| 3        | GAP-006 | Offsite/cloud backup replication                                                             | Mitigate  | ~$14,400    | Short-term (<1 month)  |
| 4        | GAP-001 | Medical device credential audit                                                              | Mitigate  | ~$500       | Quick Win (<1 week)    |
| 5        | GAP-017 | Multi-factor authentication, Phase 1 (remote/privileged accounts)                            | Mitigate  | ~$8,000     | Short-term (<1 month)  |
| 6        | GAP-018 | Automated account deprovisioning process                                                     | Mitigate  | ~$3,000     | Quick Win / Short-term |
| 7        | GAP-015 | Incident response plan and tabletop exercise                                                 | Mitigate  | ~$4,000     | Short-term (<1 month)  |
|          |         | **Subtotal**                                                                                 |           | **$84,900** |                        |
|          |         | **Remaining budget**                                                                         |           | **$35,100** | _reserved - see below_ |

### Budget allocation against the $120,000 Annual Budget

This plan commits **71% of the annual security budget ($84,900 of $120,000)**, deliberately leaving $35,100 in reserve rather than fully committing funds to estimates that may shift during implementation. The recommended use of this reserve is: a down payment (~$25,000) toward beginning server-level endpoint protection (GAP-005), starting with the domain controller and the previously compromised financial server; a small allocation (~$3,000) toward the lowest-cost components of the MRI compensating-control strategy (GAP-002); and a genuine contingency reserve (~$7,100).

### Quick Wins (Implementable within 1 Week)

- Medical device credential audit (GAP-001): Verify and change any default credentials on patient monitor and infusion pump management interfaces.
- Investigate and resolve the 2 unidentified network devices discovered during the technical scan (GAP-010), near-zero cost.
- Verify the patient portal's outbound network rules (GAP-020) and disable the outdated encryption protocol still enabled on it (GAP-023), both near-zero cost, using existing staff time.
- Institute an interim, mandatory monthly review of dormant user accounts (part of GAP-018) while the automated process is built.

### Short-Term priorities (Within 1 Month)

- Activate offsite backup replication (GAP-006).
- Roll out multi-factor authentication to remote-access and privileged accounts (GAP-017).
- Draft and formally approve an incident response plan, with an initial tabletop exercise (GAP-015).
- Complete the automated account deprovisioning integration (GAP-018).

### Long-Term Roadmap (Beyond 1 Month, Multi-Year)

- Complete network segmentation Phase 1 at Central, followed by Westside and Corporate HQ in subsequent phases (GAP-014, GAP-021).
- Deploy and tune centralized security monitoring to full production readiness (GAP-004).
- Extend endpoint/malware protection to all servers (GAP-005).
- Complete the MRI compensating-control strategy (GAP-002).
- Upgrade physical security at the server room and network closet (GAP-007).
- Deploy data-loss prevention controls and organization-wide MFA (GAP-019, full-scope GAP-017).
- Replace Westside's consumer-grade network equipment with managed, enterprise-grade infrastructure (GAP-021).

---

## 7. Conclusion and Next Steps

In business terms, MedDefense today carries the same risk profile as several hospitals that have already experienced serious, costly, and public security incidents. The specific combination of an unsegmented network, no active monitoring, and weak identity controls found in this assessment was independently confirmed, through direct comparison against real-world breach cases, to be the same combination that has produced multi-day clinical outages, multi-million-dollar recovery costs, regulatory investigations, and in one case a CEO's resignation at comparable organizations. **If the recommendations in this report are not implemented, MedDefense is not avoiding a cost. It is deferring one, and very likely increasing it,** since every gap identified here that has already been exploited once (the undetected compromise of a financial server) demonstrates these are not theoretical risks.

This assessment answers the question of what MedDefense needs to protect and where its defenses currently fall short. It does not yet answer the second half of that question: **who is actually likely to target an organization like MedDefense, and how.** The previous Security Analyst began this exact work before his departure (tracking healthcare-sector threat intelligence and beginning to map MedDefense's specific gaps against known attacker techniques) but ran out of time to complete it. The recommended next phase of this program is to finish that work: a formal **External Threat Landscape Assessment**, translating the internal weaknesses identified in this report into a clear picture of which threats are most likely to exploit them first, so that MedDefense's continued security investment is not only well-structured, but correctly aimed.
