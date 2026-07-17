# MedDefense Health Systems: ## Threat Landscape Report

**Prepared for:** The Board of Directors, MedDefense Health Systems **Prepared by:** Aïda Sylla, Security Analyst, Office of the Deputy CISO **Sponsor:** James Chen, Deputy CISO **Companion document:** Security Posture Assessment (Project 0x00), read together, these 2 reports answer "what do we have to protect and where are we weak" (0x00) and "who is trying to hurt us and how" (this report) **Classification:** Internal - Board Distribution Only

---

## 1. Executive Summary

MedDefense operates in the single most targeted sector for ransomware in the United States, and internal analysis shows the organization currently matches the preferred victim profile of the criminal groups most active against hospitals today. Not approximately, but closely, on nearly every dimension these groups themselves use to select a target. 3 regional hospitals within 200 miles of MedDefense have already been hit by ransomware in the past 8 months; the same structural weaknesses that made those attacks succeed are present, unresolved, at MedDefense right now.

**The single most dangerous threat to MedDefense** is a ransomware-as-a-service group exploiting an unpatched remote-access device to enter the network, then moving freely because nothing stops them to the systems holding every patient's complete medical record and the only backup capable of restoring it. This is not a hypothetical: the same organization has already experienced a smaller-scale version of this exact pattern once this year, when a hidden intrusion ran undetected on a financial server for weeks.

**Top 3 recommendations:**

1. **Finish dividing the internal network into separate zones** so that one compromised computer can no longer reach every critical system at once. This single change would blunt the majority of the realistic attack paths identified in this report.
2. **Deploy the ability to detect an intrusion in progress**, not just after the damage is visible. Every serious threat analyzed in this report depends on going unnoticed for days or weeks.
3. **Close the two remaining identity gaps**: require a second login step everywhere, and automatically cut off access the moment someone leaves the organization or a vendor relationship ends.

This report should be read alongside the Security Posture Assessment produced in Project 0x00. That report showed what MedDefense has and where it is weak; this report shows, specifically, who would exploit that weakness, how, and in what order of priority.

---

## 2. Scope and Methodology

### Intelligence Sources Used

This report draws on: a raw threat intelligence dossier compiled from CISA advisories, HHS Health Sector Cybersecurity Coordination Center (HC3) analyst notes, and HHS breach portal statistics; a detailed operational profile of a realistic Ransomware-as-a-Service group (BlackReef); eight anonymized real-world intelligence incident reports used to build actor-classification skill; seven MedDefense-specific social engineering scenarios; MedDefense's own vendor contracts and service agreements; the Project 0x00 network scan and asset registry; two detailed attack narratives used for MITRE ATT&CK technique mapping; and the three real-world healthcare breach case studies previously used to validate the Project 0x00 posture assessment.

### Analytical Frameworks Applied

- **STRIDE threat modeling**, applied in depth to the EHR system (12 threats across all six categories) and at triage level to Active Directory, PACS/Medical Imaging, and Network Infrastructure.
- **MITRE ATT&CK**, mapping two complete attack narratives (an external ransomware campaign and an internal data-theft case) to specific tactics and techniques, verified against MITRE's published documentation.
- **Kill chain analysis**, constructing five complete, step-by-step attack sequences from initial access to final impact, each with identified intervention points.
- **CompTIA Security+ 2.1/2.2 taxonomies**, used to classify threat actor attributes (internal/external, resources, sophistication, motivation) and social engineering vectors consistently throughout.

### Connection to the Security Posture Assessment (Project 0x00)

This report is built directly on top of, not parallel to, the 0x00 posture assessment. Every gap ID, every asset criticality rating, and every control effectiveness finding referenced throughout this report traces back to that assessment's Asset Registry, Criticality Matrix, Control Matrix, and Gap Analysis. Where 0x00 asked "how exposed is this asset and what's missing," this report asks "who would actually exploit that, through what technique, and to what end" and, in its final analytical section, uses that threat evidence to recalibrate several of 0x00's own gap priorities.

---

## 3. Healthcare Sector Threat Overview

### Why Healthcare Is Targeted

Four structural factors, independently confirmed across every intelligence source reviewed in this project, make healthcare a preferred target sector rather than an incidentally frequent one:

1. **Clinical urgency inflates payment pressure.** Healthcare organizations pay ransoms at a 60% rate versus a 46% cross-industry average, the same encrypted data that costs another industry money to lose costs a hospital its ability to safely treat patients.
2. **Patient data holds durable, premium value.** A patient record ($250–$1,000 on underground markets) bundles identity, insurance, and medical history, enabling both identity theft and insurance fraud and unlike a stolen credit card, medical identity theft can go undetected for months.
3. **Legacy systems and connected medical devices expand the attack surface.** Healthcare uniquely combines conventional IT with clinical devices that often cannot be patched on a normal cycle, producing a structurally larger population of long-lived vulnerabilities than most other industries.
4. **Widespread cyber insurance coverage creates a funded counterparty.** Attackers size ransom demands against a sector known to carry the financial capacity to pay.

### Current Trends

**Double extortion is now the dominant model, not the exception**. 73% of healthcare ransomware incidents involve data exfiltration before encryption, meaning even a fully backed-up organization still faces a confidentiality threat. **Financial scale is escalating**: average ransom demands doubled from $1.2M to $2.5M between 2022 and 2024, and healthcare now accounts for 25% of all ransomware incidents across all 16 U.S. critical infrastructure sectors. **The skill floor for effective attacks is dropping**, as AI-assisted tooling makes previously sophisticated attacks accessible to low-skill actors — a trend directly corroborated by MedDefense's own experience, where an unsophisticated, non-targeted automated scan already compromised a financial server this year.

### Sector Statistics Contextualizing MedDefense's Exposure

89% of healthcare organizations experienced at least one cyberattack in the past 12 months. Insiders account for approximately 35% of healthcare data breaches. Most concretely: 3 regional hospitals within 200 miles of MedDefense have been hit by ransomware in the past 8 months: 2 paid, one lost 3 weeks of data with an 11-day ambulance diversion. MedDefense is not a statistical abstraction in this threat landscape; it is inside the same active targeting radius as organizations that have already been hit.

---

## 4. MedDefense Threat Actor Profiles

|Actor Type|Likelihood|Capability|Priority Rank|
|---|---|---|---|
|Ransomware Groups (Organized Crime)|Critical|Medium–High|**1**|
|Unskilled/Opportunistic Attacker|Critical (proven)|Low|**2**|
|Insider (Negligent)|Critical|Low/None|**3**|
|Insider (Malicious)|High|Low (technical)|4|
|Nation-State APT|Low (conditional)|Very High|5|
|Hacktivist|Low|Low–Medium|6|

### Top 3 Detailed Profiles

**Ransomware Groups (Organized Crime).** Operate a structured, multi-role criminal supply chain (developers, affiliates, Initial Access Brokers, and negotiators) rather than a single group. MedDefense matches the documented preferred victim profile (mid-size, regulated data, constrained security budget) closely. Primary vector: exploitation of unpatched public-facing infrastructure, particularly VPN appliances. This actor's own documented playbook explicitly instructs neutralizing backup infrastructure before deploying ransomware against production systems, a sequence MedDefense's own architecture does little to prevent.

**Unskilled/Opportunistic Attacker.** Automated scanners and low-skill operators who select vulnerabilities, not organizations. This is the only actor category in this report already proven active against MedDefense, an automated internet-wide scan compromised a financial server via a known, unpatched vulnerability earlier this year. This category also functions as a feeder into the ransomware ecosystem above it, since compromised access is routinely resold to more capable affiliates.

**Insider (Negligent).** Employees introducing risk through convenience rather than malice shared credentials, unauthorized personal devices, workload-driven shortcuts. Not theoretical: 3 of 5 real MedDefense scenarios examined for this report were negligent in nature, and unauthorized devices have independently surfaced three separate times in this project's asset discovery work. This category's danger is systemic. The same root causes (no change management, no access review) that enable negligent exposure also worsen the 2 higher-ranked threats above it.

---

## 5. Attack Surface Analysis

**External surface:** the patient portal, VPN endpoints (including Westside's consumer-grade edge device), email infrastructure, and public DNS all present internet-reachable entry points. Most significantly, cross-referencing MedDefense's own incident history against its documented firewall rules revealed a likely contradiction: billing-srv-01's web service was probably directly internet-reachable at the time it was compromised, despite the assumed security model restricting external access to a single, different server. MedDefense's actual external surface is very likely larger than currently assumed.

**Internal surface:** dominated by one finding, the internal network has no segmentation, confirmed empirically ("a device on any subnet can reach any other device on any other subnet"). Every exposed service, management interface, legacy system, and shared credential identified in this project inherits unrestricted reach from this single condition.

**Human surface:** clinical staff (broad access, inconsistent training completion as low as 58% at one site), reception staff (first point of contact, highest social-engineering exposure), IT staff (small team, elevated privileges, demonstrated workload-driven shortcuts), executives (explicit Business Email Compromise targets), and external contractors (access outside MedDefense's direct visibility or control) each carry distinct, evidenced exposure.

**Assessment:** the internal surface represents the greatest overall risk, not because it offers the most entry points, but because it determines whether a breach anywhere else on this map stays contained or becomes catastrophic.

---

## 6. Critical Attack Paths

Five complete kill chains were constructed, each identifying at least two points where an existing or missing control could have interrupted the sequence:

1. **The Backup-First Ransomware Chain**: VPN exploit → credential harvesting → domain compromise → data theft → backup neutralization → organization-wide encryption.
2. **The Accidental Foothold That Could Have Escalated**: An unpatched, internet-facing service compromised by automated scanning, modeling how far the actual cryptominer incident could have escalated toward domain compromise.
3. **The Shadow IT Pivot**: An abandoned, unmanaged device provides a long-duration, unattributable foothold directly adjacent to the domain controllers and EHR database.
4. **The Wire Transfer Chain**: An executive impersonation leading directly to fraudulent financial loss, with no technical exploitation required at any step.
5. **The Trusted Vendor Path**: A compromised vendor's legitimate, standing maintenance access reaches the EHR without ever breaching MedDefense's own perimeter.

**Network segmentation appeared as a break-point candidate in 4 of these 5 chains**. Every chain except the purely social-engineering-driven wire transfer scenario depends on unrestricted internal movement to convert an initial foothold into access to a critical asset.

Cross-referencing every vector against every critical asset independently identified: **the 3 most connected assets** are the EHR System (reachable by 7 of 8 mapped vectors), the identity infrastructure (Active Directory and its domain controller, 6 of 8), and Backup Infrastructure (6 of 8); and **the three most versatile vectors** are VPN Exploit (reaches all 7 mapped assets), Vulnerable Software Exploit (5 of 7), and Phishing (4 of 7, tied closely with Supply Chain Compromise and Physical Access).

---

## 7. STRIDE Analysis Summary

**EHR deep analysis (12 threats across all six STRIDE categories):** the greatest risk to the EHR specifically is **Tampering**, not Information Disclosure, despite both exploiting the identical technical exposure (the patient database being reachable from the entire network rather than restricted to its application server). The reasoning is healthcare-specific: falsified clinical data is an immediate, physical threat to a patient the moment a clinician acts on it, not a downstream cost calculated after the fact. And this is not theoretical, since MedDefense has already experienced an accidental version of exactly this failure mode, when corrupted medication dosage data went unnoticed for roughly six hours across all three sites.

**PACS/Medical Imaging, Active Directory, and Network Infrastructure (triage-level, top threat per system):** PACS's greatest risk is **Denial of Service**, an unpatchable legacy imaging workstation combined with unprotected servers means a ransomware-style compromise could halt diagnostic imaging organization-wide with essentially no technical resistance. Active Directory's greatest risk is **Elevation of Privilege**, credential harvesting to Domain Admin is the explicitly documented, near-trivial chokepoint that converts any single foothold into total organizational compromise. Network Infrastructure's greatest risk is also **Elevation of Privilege**, an overly permissive firewall rule already flagged internally converts a compromise at MedDefense's weakest, least-defended site into full access to its most sensitive infrastructure.

---

## 8. Threat Scenarios

Three complete, board-ready scenarios were constructed, each involving a different actor type and primary vector (full detail available in the accompanying task deliverable):

**Scenario 1 (External): The Ransomware Campaign.** A BlackReef-style affiliate enters via an unpatched VPN, moves laterally across the flat network, and executes a double-extortion attack against the EHR and backup simultaneously. _Business impact:_ multi-day clinical outage, a $1–3M ransom demand, mandatory breach notification, and a real-world precedent of resulting executive resignation at a comparably profiled hospital.

**Scenario 2 (Internal): The Departed Administrator.** A terminated employee, retaining access through MedDefense's un-automated offboarding process, exfiltrates patient data and sabotages backup infrastructure out of grievance. _Business impact:_ direct financial harm from resold data, breach notification, and, critically, the removal of MedDefense's recovery capability for whatever incident happens next.

**Scenario 3 (Third Party): The Trusted Vendor Path.** An external attacker compromises a vendor's own environment and uses that vendor's legitimate, standing maintenance access to reach the EHR without ever touching MedDefense's own perimeter. _Business impact:_ mass PHI exposure with a materially longer expected time-to-detection than a conventional intrusion, since the access itself appears entirely legitimate.

**Cross-scenario finding:** despite three different actors and three different entry points, all 3 scenarios converge on the same asset (the EHR, via its network-wide database exposure) and the same 2 structural gaps (no network segmentation, no centralized detection), independent confirmation, at the scenario level, of this report's central finding.

---

## 9. Gap-Threat Correlation

Cross-referencing every gap identified in the 0x00 posture assessment against the threat evidence gathered in this report recalibrated several priorities:

- **Three gaps were upgraded** on the strength of threat evidence: the absence of perimeter patch management (from High to Critical, it is the literal first step of the highest-priority attack path); the absence of periodic access review (from High to Critical, it enables both the insider and vendor threat paths simultaneously); and incomplete security awareness training (from Medium to High, see "The Surprise," below).
- **No gap was downgraded.** A gap's absence from one of the specific attack paths built in this project was treated as a limitation of this round of scenario-building, not evidence of reduced risk.

**The Critical 3: The gaps whose closure would disrupt the greatest number of distinct attack paths are, in order: **the absence of network segmentation** (present in 6 of 8 kill chains and scenarios, by far the most-referenced single gap in this report), **the EHR database's network-wide exposure** (5 of 8), and **the absence of centralized detection** (present across the widest spread of distinct kill chains). These 3 gaps are not new conclusions. They are the same finding reached independently through at least five separate analyses across this project.

**The Surprise:** incomplete security awareness training was rated only Medium in the original posture assessment, treated as a soft, generic finding. Threat modeling revealed this gap is the literal opening step of MedDefense's single highest-priority attack path. The same lack of phishing-simulation training that made a modeled spear-phishing lure against the IT Director plausible is what allows the entire ransomware kill chain to begin. A Medium rating made sense when judged only against its own isolated impact; it does not survive contact with the threat evidence.

---

## 10. Prioritized Recommendations

### Top 5 Threats and Recommended Actions

|Rank|Threat|Key Gap|Recommended Action|
|---|---|---|---|
|1|Ransomware campaign via VPN exploit → EHR + backup|No network segmentation|Complete Phase 1 segmentation at Central (already funded, ~$35,000; long-term, 3–6 months)|
|2|Insider data theft and backup sabotage via retained access|No automated account deprovisioning|Automated HR-triggered deactivation + interim monthly dormant-account review (~$3,000; quick win to short-term)|
|3|Opportunistic exploitation escalating to domain compromise|No server-class endpoint protection|Deploy EDR on domain controllers and previously-compromised systems first (~$25,000 reserve allocation; short-term)|
|4|Supply chain compromise via a trusted vendor|No dedicated vendor-access segmentation|Deploy a vendor jump-host requiring MFA and full session logging (short-term, within 1 month)|
|5|Business Email Compromise / executive wire fraud|No email authentication or transaction-verification policy|Enforce DMARC/SPF/DKIM plus a mandatory out-of-band verification policy for financial requests (quick win for the policy; short-term for full technical enforcement)|

### Strategic 2-Initiative Recommendation

If MedDefense funds only two defensive initiatives this quarter, they should be **completing network segmentation and deploying centralized detection and alerting**. Together, these are the only 2 investments that meaningfully weaken 4 of the 5 threats ranked above simultaneously: segmentation breaks the lateral-movement step common to Ranks 1, 3, and 4, while centralized detection is the one capability that could have caught Ranks 1, 2, and 3 during the multi-day window each currently enjoys undetected, including the intrusion that has already compromised MedDefense once this year.

### Connection to the Next Phase

This report identifies _who_ threatens MedDefense and _how_. It does not replace the technical work of confirming exactly which specific, exploitable vulnerabilities exist on each system today. That is the explicit purpose of the next phase of this program, **Project 1x02: Vulnerability Assessment**, which should take the Critical 3 gaps and Top 5 threats identified here as its starting scope, technically validating and quantifying the exposures this report has identified through analysis and threat correlation rather than direct testing.
