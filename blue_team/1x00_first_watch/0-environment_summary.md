# MedDefense health systems: Structured environment summary

**Prepared by:** Aïda Sylla, Security Analyst **Reviewed for:** James Chen, Deputy CISO **Source material:** Onboarding Documentation Package (HR Onboarding Guide, IT Asset List, Marcus Webb's Notes, IT Service Contracts Summary, Network Diagram, Org Chart) **Purpose:** Baseline environment understanding to support the Board-requested security posture assessment.

> **Scope note:** This summary reflects only what is stated or directly implied in the provided documentation. Where information is missing, stale, or contradictory, it is flagged in Section 4 rather than assumed.

---

## 1. Organization overview

### 1.1 Sites

|Site|Location Type|Function|Approx. Headcount|Facility Notes|
|---|---|---|---|---|
|**MedDefense Central Hospital**|Downtown, urban|350-bed acute care hospital|~1,400 (clinical + support)|6 floors + basement (mechanical/server room); underground staff parking; surface visitor lot|
|**Westside Clinic**|Suburban (12 min from Central)|Outpatient facility: primary care, diagnostic imaging (X-ray, ultrasound — no MRI), blood work, minor procedures, physical therapy|~180|2-story medical office complex; shared parking with adjacent retail plaza; has its own local server closet for "basic needs"|
|**Corporate HQ**|Greenfield Business Park (15 min from Central)|Administrative offices: Finance, HR, Legal, Marketing, Executive Leadership, IT|~220|Leased office space, 3rd floor of a 5-story commercial building; hosts the 12-person IT department; no on-premise servers|

**Total stated organization-wide headcount:** ~2,000 employees (see Section 4 for a discrepancy with site-level totals).

### 1.2 Departments (Central Hospital, clinical)

Emergency, Surgery, Cardiology, Radiology, Oncology, Pediatrics, Maternity, Pharmacy, Laboratory, Administration.

### 1.3 Reporting structure relevant to security

```
CEO: Dr. Patricia Morales
 ├── CFO: Robert Kim
 ├── COO: Angela Torres
 │      └── Clinical Directors (per department)
 ├── General Counsel: David Park
 └── CISO (position vacant)
        ├── James Chen — Deputy CISO (acting)
        │      └── Security Analyst (you) — replacing Marcus Webb
        └── Sarah Park — IT Director
               ├── 3x System Administrators
               ├── 2x Network Technicians
               ├── 1x Database Administrator
               ├── 2x Helpdesk Analysts (incl. Mike Torres, lead)
               ├── 2x Desktop Support Technicians
               └── 1x IT Intern (position currently vacant)
```

**Security-relevant governance note:** the CISO position is vacant. James Chen (Deputy CISO) formally sits above IT in the org chart but, per the documentation, reports _in practice_ directly to the CEO. Sarah Park (IT Director) and James Chen are described as organizational **peers**. James holds authority over security **policy** but **no authority over IT operations**. The documentation explicitly states this "creates friction." This is a structural governance gap: the person responsible for security cannot compel the team that operates the infrastructure.

---

## 2. IT infrastructure identified

### 2.1 Servers

| Name                     | OS / Platform          | Function                        | Site         | Notes                                                                                                                                                       |
| ------------------------ | ---------------------- | ------------------------------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ehr-srv-01               | Ubuntu 20.04 LTS       | EHR application server          | Central      | —                                                                                                                                                           |
| ehr-db-01                | Ubuntu 20.04 LTS       | EHR database (PostgreSQL)       | Central      | Reportedly reachable from the entire 10.10.0.0/16 network (per Marcus's notes), not restricted to ehr-srv-01                                                |
| pacs-srv-01              | Windows Server 2016    | PACS imaging server             | Central      | —                                                                                                                                                           |
| billing-srv-01           | Ubuntu 18.04 LTS       | Billing / claims processing     | Central      | Recurring performance issues, cause undiagnosed ("something is wrong", flagged by both Marcus and James); confirmed target of a January ransomware incident |
| ad-dc-01                 | Windows Server 2019    | Primary domain controller       | Central      | —                                                                                                                                                           |
| ad-dc-02                 | Windows Server 2019    | Secondary domain controller     | Central      | —                                                                                                                                                           |
| file-srv-01              | Windows Server 2016    | Department file shares          | Central      | —                                                                                                                                                           |
| print-srv-01             | Windows Server 2012 R2 | Print server                    | Central      | **[UNVERIFIED]** not physically confirmed in over a year; OS end-of-support was October 2023                                                                |
| backup-srv-01            | Ubuntu 22.04 LTS       | Backup server (Veeam agent)     | Central      | Backs up nightly to a local NAS in the **same server room, same network, same rack** as the primary infrastructure                                          |
| web-srv-01               | Ubuntu 20.04 LTS       | Public website + patient portal | Central      | Sits in a DMZ behind the FortiGate, per the network diagram                                                                                                 |
| ws-srv-01                | Windows Server 2016    | Local file server + scheduling  | Westside     | —                                                                                                                                                           |
| (possible second server) | Unknown                | Unknown                         | Westside     | Unconfirmed (see Section 4)                                                                                                                                 |
| —                        | N/A                    | No on-premise servers           | Corporate HQ | HQ staff use cloud services and connect to Central's infrastructure via site-to-site VPN                                                                    |

### 2.2 Network equipment

| Site         | Equipment                                                                                                                                                                                                              |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Central      | Cisco core switch (model unknown); 2x Cisco access switches per floor; 1x Fortinet FortiGate 100F firewall; 12x Ubiquiti UniFi wireless access points; a separate guest WiFi SSID exists (isolation status unverified) |
| Westside     | 1x unmanaged switch (brand unknown); 1x consumer-grade router (Netgear Nighthawk). This router also carries the site-to-site IPSec VPN to Central; no firewall                                                         |
| Corporate HQ | Network managed by the building landlord; MedDefense operates its own VLAN on that shared infrastructure; connects to Central via a site-to-site VPN                                                                   |

### 2.3 Endpoints

|Site|Devices|
|---|---|
|Central|~320 Windows 10 workstations; ~60 thin clients in clinical areas|
|Westside|~45 Windows 10 workstations|
|Corporate HQ|~120 Windows 10/11 workstations; ~30 remote-capable laptops|
|Org-wide|~25 iPads used by physicians for rounds (MDM-management status unclear)|

Endpoint figures are sourced from the last Active Directory report, which the documentation states is **8 months old**; no current, complete count exists.

### 2.4 Medical devices (IoT): Central

| Device                      | Detail                                                                  |
| --------------------------- | ----------------------------------------------------------------------- |
| Patient monitors            | ~80 units, Philips IntelliVue, network-connected                        |
| Infusion pumps              | ~120 units, BD Alaris, network-connected for dosage updates             |
| MRI scanner                 | 1x Siemens MAGNETOM **runs Windows XP** (flagged as critical by Marcus) |
| CT scanner                  | 1x GE Revolution, OS unknown                                            |
| Nurse call system           | IP-based, integrated with the phone system                              |
| Badge/access control system | HID Global; integrated with Active Directory for some doors             |

### 2.5 Network topology

- Central operates as a **single flat network** (10.10.0.0/16): workstations, servers, and medical devices reportedly share the same broadcast domain, with **no VLAN segmentation** configured at this site (segmentation is described as "planned for next fiscal year" as of ~4 months ago).
- web-srv-01 sits in a DMZ behind the FortiGate 100F.
- Westside connects to the Central FortiGate via IPSec VPN, routed through the consumer-grade Netgear router (no dedicated firewall at Westside).
- Corporate HQ connects to the Central FortiGate via a site-to-site VPN over the building-managed network; HQ's VPN access-control lists have not been audited.
- The available network diagram is explicitly marked by its author as a simplified draft ("real topology is messier").

---

## 3. Data and services

### 3.1 Data types handled

- **Electronic Health Records (EHR)**: clinical documentation (ehr-srv-01 / ehr-db-01, PostgreSQL).
- **Medical imaging data**: PACS (pacs-srv-01), plus imaging modalities (MRI, CT, X-ray, ultrasound at Westside).
- **Billing / financial / claims data**: billing-srv-01 (revenue-cycle processing).
- **Departmental files**: file-srv-01 (shared drives across departments).
- **Patient portal / public-facing data**: web-srv-01 hosts the public website and patient portal, implying some form of patient-facing account/PII data in addition to public content.
- **Identity and authentication data**: Active Directory domain controllers (ad-dc-01/02).
- **Backup copies** of the above: backup-srv-01 + local NAS.
- **Corporate/administrative data** at HQ (Finance, HR, Legal, Marketing): likely includes employee and financial records, though the packet does not itemize these.

**On PHI specifically:** the documentation references a "HIPAA Security Rule" compliance obligation directly, which strongly implies MedDefense handles **Protected Health Information (PHI)** as a matter of regulatory scope. However, the packet itself does not explicitly label any system's data as "PHI". This is a reasonable inference from context (a hospital group referencing HIPAA), not a directly stated fact, and should be confirmed formally in the data classification phase.

### 3.2 Critical services and their dependents

| Service                                   | Underlying systems                                           | Primary users                                                                            |
| ----------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| Direct patient care / clinical monitoring | Patient monitors, infusion pumps, nurse call system          | Clinical staff, patients (life-safety dependency)                                        |
| Electronic Health Records                 | ehr-srv-01, ehr-db-01                                        | Clinical staff org-wide                                                                  |
| Medical imaging                           | pacs-srv-01, MRI, CT, X-ray/ultrasound (Westside)            | Radiology, physicians                                                                    |
| Billing / revenue cycle                   | billing-srv-01                                               | Finance/Administration                                                                   |
| Identity & access                         | ad-dc-01, ad-dc-02, HID badge system                         | All staff, physical + logical access                                                     |
| Public website & patient portal           | web-srv-01                                                   | Patients, general public                                                                 |
| File sharing                              | file-srv-01                                                  | All departments                                                                          |
| Backup / recoverability                   | backup-srv-01, NAS                                           | IT, business continuity (currently a single point of failure — see Section 4/known risk) |
| Site connectivity                         | FortiGate VPN, Netgear router (Westside), building VLAN (HQ) | Westside and HQ staff, dependent on Central for connectivity                             |
| Remote work                               | ~30 remote-capable HQ laptops, O365                          | HQ staff                                                                                 |

**Who depends on IT infrastructure:** essentially the entire organization (~2,000 employees) plus patients interacting with the portal and physicians using mobile devices at the bedside. Clinical operations at Central carry the highest stakes, since monitors, infusion pumps, and imaging are directly tied to patient safety, not just data availability.

---

## 4. Known unknowns

This section lists what the documentation does **not** tell us gaps, stale data, and apparent contradictions, rather than security findings per se.

### 4.1 Missing / Unconfirmed information

1. **Possible undocumented server at Westside.** Referenced only as something "Mike Torres mentioned," never confirmed by Marcus. Existence, function, and OS are unknown.
2. **print-srv-01 status unverified** for over a year: unclear if it is even still in service.
3. **Core switch model at Central** is not documented ("model unknown").
4. **Westside's unmanaged switch brand** is unknown.
5. **WiFi setup at Westside** is undocumented (only Central's 12 UniFi APs are specified).
6. **Endpoint counts are 8 months stale** and explicitly described as incomplete: no current, verified inventory exists for workstations, thin clients, or laptops.
7. **iPad management status is unclear** whether the ~25 physician iPads are enrolled in any MDM/management solution is not stated.
8. **CT scanner OS is unknown.**
9. **Guest WiFi isolation at Central is unverified**. The SSID exists, but network segregation from the corporate network has not been confirmed.
10. **HQ VPN access-control lists have never been audited**, despite the VPN itself appearing "properly configured."
11. **Endpoint protection (Sophos) currency/coverage is unknown**. There is no confirmation it is up to date across all machines.
12. **Cloud service inventory is incomplete.** O365 is confirmed org-wide; Marcus suspected other departments use additional, unlisted cloud services, but none are named.
13. **No formal vulnerability assessment has ever been performed** on any server.
14. **No formal HIPAA Security Rule compliance assessment exists.** Legal asserts compliance but has produced no supporting evidence.
15. **No documented Incident Response, Business Continuity, or Disaster Recovery plan exists.** The January ransomware event on billing-srv-01 was handled ad hoc; there is no documented procedure for clinical operations if Central loses power beyond the ~20-minute UPS runway.
16. **Root cause of billing-srv-01's recurring performance issue is undiagnosed** and flagged independently by both Marcus's notes and James's sticky note, still unresolved.
17. **No completed threat-landscape analysis** for the healthcare sector exists; Marcus started but did not finish this research.
18. **The network diagram is explicitly marked incomplete/simplified** by its own author ("real topology is messier"). The true topology, including any undocumented segments, VLANs, or shadow IT, is not fully known.

### 4.2 Apparent contradictions / Points needing clarification

1. **Headcount discrepancy:** Site-level staff figures sum to **1,400 (Central) + 180 (Westside) + 220 (HQ) = 1,800**, but the HR guide separately states the organization-wide total is **"approximately 2,000."** That leaves roughly 200 employees unaccounted for by site (possibly remote/traveling staff, contractors, or a rounded/approximate figure. It is not stated). **This should be clarified before it is used in any capacity-planning or risk-scoring exercise.**
2. **"No VLANs configured" vs. "MedDefense has its own VLAN" at HQ:** Marcus's notes state Central runs flat with no VLAN segmentation. Separately, the asset list says HQ operates on its own VLAN within the landlord's network. These are not necessarily contradictory (different sites, different statements), but the documentation doesn't clarify whether HQ's "own VLAN" provides genuine security segmentation or is simply a logical/billing separation. **Needs verification.**
3. **Governance ambiguity:** The org chart formally places James Chen (Deputy CISO) above Sarah Park (IT Director) under a vacant CISO node, but the accompanying note says they function as **peers** with James reporting directly to the CEO in practice. The actual, effective reporting line is not fully documented and matters for understanding who can enforce a remediation.

### 4.3 Explicit author caveats (carried over as-is, not resolved)

- Sarah Park: the IT asset list is admittedly incomplete, and anything marked [UNVERIFIED] has not been physically checked in over a year.
- Marcus Webb: multiple notes end with an acknowledgment that documentation, migration, or investigation work was started but not finished due to time constraints before his departure.

---

_End of Structured Environment Summary. This document is a factual extraction of the onboarding packet only. It does not yet contain risk ratings, control mappings, or prioritization. Those are addressed in subsequent deliverables of this project._
