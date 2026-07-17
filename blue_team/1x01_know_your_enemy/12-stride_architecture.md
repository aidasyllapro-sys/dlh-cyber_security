# MedDefense Health Systems: STRIDE Across the Architecture

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** Project 0x00 Asset Registry, Network Scan Summary, Control Matrix, Gap Analysis, and Physical Walk-Through findings; the BlackReef Ransomware Dossier (Task 2) and STRIDE-on-EHR analysis (Task 11) of this project **Purpose:** A triage-level STRIDE pass across 3 additional critical systems, Active Directory, PACS/Medical Imaging, and Network Infrastructure, identifying the single most critical threat per category for each system, without the full depth applied to the EHR.

---

```
System: PACS / Medical Imaging
Architecture Notes: pacs-srv-01 (Windows Server 2016, DICOM ports 4242/
  11112) + the MRI control workstation (WS-RAD-01, Windows XP SP3,
  unpatched since 2014) + radiology workstations, all on Central's flat
  network with no segmentation from general workstations. A shared login
  ("raduser/radiology1") is used across the PACS workstation.

| STRIDE | Threat | Impact | Severity |
|--------|--------|--------|----------|
| S | Anyone possessing the shared "raduser/radiology1" credential can impersonate any radiology technician accessing imaging systems, with no way to distinguish who is actually behind a given session. | Unauthorized individuals can view or interact with imaging data under a legitimate-looking identity, with no accountability. | High |
| T | pacs-srv-01 has no antivirus/EDR (excluded from Sophos coverage) and WS-RAD-01 cannot be patched at all — an attacker reaching either system could alter stored images or their associated patient-ID metadata. | A swapped or altered image tied to the wrong patient ID could directly cause a misdiagnosis or a wrong-patient treatment decision. | Critical |
| R | The shared login removes individual accountability entirely — any configuration change, deletion, or inappropriate access to imaging data cannot be attributed to a specific person. | Inability to investigate or assign responsibility for any imaging-related incident, undermining both internal discipline and regulatory response. | Medium |
| I | DICOM traffic between radiology workstations and pacs-srv-01 has no confirmed encryption, and travels across the same flat network as every other device. | Medical images and the patient identifiers attached to them are exposed to any device that can reach this network segment — which, given the flat architecture, is effectively all of them. | High |
| D | pacs-srv-01 is unprotected and WS-RAD-01 is permanently unpatchable — a ransomware deployment or resource-exhaustion attack (the same class already proven against billing-srv-01) could take the entire imaging chain offline at once. | Diagnostic imaging halted organization-wide, directly stopping the ~45 daily MRI studies and any dependent diagnostic or treatment pathway. | Critical |
| E | Windows XP has over a decade of unpatched, well-documented local privilege escalation vulnerabilities — trivial to exploit once any foothold on WS-RAD-01 is achieved. | Full administrative control of a $2.1M clinical asset, achievable through a well-known, unpatched OS weakness rather than any novel technique. | Critical |

Top Threat: Denial of Service. WS-RAD-01's complete unpatchability and
  pacs-srv-01's lack of any endpoint protection mean this system has
  essentially no technical resistance to a ransomware-style compromise,
  and the resulting outage directly halts patient diagnosis rather than
  merely exposing data — the same Availability/Integrity-driven logic
  that already rated this asset category Critical in the Project 0x00
  criticality assessment.
```

```
System: Active Directory
Architecture Notes: ad-dc-01 (primary) and ad-dc-02 (secondary) domain
  controllers, both Windows Server 2019, serving DNS/Kerberos/LDAP/SMB
  for the entire organization. ad-dc-02 is explicitly excluded from the
  nightly backup job. Password policy: 8-character minimum, 90-day
  rotation, no MFA anywhere in the organization.

| STRIDE | Threat | Impact | Severity |
|--------|--------|--------|----------|
| S | With no MFA and only an 8-character password minimum, an attacker with a phished or brute-forced admin credential can fully impersonate a domain administrator. | Complete, undetectable impersonation of a trusted administrative identity across every system that trusts AD for authentication. | Critical |
| T | An attacker who reaches Domain Admin-equivalent privilege can push a malicious Group Policy Object — the exact, documented mechanism BlackReef uses to deploy ransomware organization-wide. | Simultaneous, organization-wide malicious configuration or payload deployment to every Windows system trusting this domain. | Critical |
| R | Service accounts with excessive privileges (explicitly flagged as a target in BlackReef's own reconnaissance phase) mean actions performed under a shared or over-privileged service identity cannot be tied to a specific person or process. | Actions taken through a compromised or misused service account are difficult or impossible to attribute during an investigation. | Medium |
| I | LDAP (port 389, unencrypted) remains open alongside LDAPS (636), and no source confirms unencrypted LDAP is disabled — directory structure, usernames, and group memberships are potentially queryable in the clear. | Full enumeration of the organization's user accounts, group structure, and administrative relationships by anyone on the flat network. | High |
| D | ad-dc-02 is not included in the nightly backup, and the flat network gives an attacker equal reach to both domain controllers simultaneously. | If both DCs are compromised or destroyed together, MedDefense has no verified path to restore authentication for the entire organization — every dependent system becomes unusable at once. | Critical |
| E | Credential harvesting techniques (Mimikatz, LSASS memory dumps) explicitly named in BlackReef's own playbook, combined with no MFA, provide a well-documented, near-trivial path from any internal foothold to Domain Admin. | Total organizational compromise — Domain Admin access is the single privilege level from which nearly every other system and dataset in this project becomes reachable. | Critical |

Top Threat: Elevation of Privilege. This is the chokepoint threat for
  Active Directory — credential harvesting to Domain Admin is not a
  hypothetical technique but the explicitly documented Phase 3 of
  BlackReef's real attack lifecycle (Task 2), and achieving it converts
  every other threat in this table (Tampering via GPO, further Spoofing,
  and ultimately Denial of Service against both DCs) from possible into
  trivial.
```

```
System: Network Infrastructure
Architecture Notes: FortiGate 100F (Central's sole perimeter device,
  hosting the DMZ rule for web-srv-01 and terminating both the Westside
  and HQ VPN tunnels) + an unidentified-model Cisco core switch +
  Westside's Netgear Nighthawk consumer router (serving simultaneously
  as Westside's only internet gateway and its VPN endpoint, with no
  dedicated firewall) + VPN firewall rules ("Allow-VPN-Westside,"
  "Allow-VPN-HQ") that permit ALL services rather than a restricted set.

| STRIDE | Threat | Impact | Severity |
|--------|--------|--------|----------|
| S | Westside's VPN tunnel terminates on a consumer-grade router with no enterprise security features, making this endpoint significantly easier to spoof or hijack than an equivalent enterprise device would be. | An attacker impersonating or hijacking the Westside VPN endpoint gains a trusted path directly into Central's network. | High |
| T | The core switch's model and firmware are undocumented (a Known Unknown from Project 0x00), and switch management credentials were found physically posted, in plain view, inside an unlocked network closet. | Direct, unauthorized reconfiguration of core switching — including VLAN assignments and routing — affecting the entire site simultaneously. | Critical |
| R | FortiGate logs are retained locally only for 30 days with no forwarding or centralized review. | Any unauthorized configuration change or unusual traffic pattern becomes untraceable once the 30-day retention window passes, with no independent record of who made a given change. | Medium |
| I | The "Allow-VPN-Westside" and "Allow-VPN-HQ" rules permit ALL services rather than a restricted set, meaning traffic interception at Westside's under-defended consumer router could expose a broad range of internal traffic, not just the specific services Westside actually needs. | Significant internal network traffic exposure originating from the weakest, least-defended point in the entire network topology. | High |
| D | The FortiGate is MedDefense's only perimeter device — a single point of failure for both internet connectivity and VPN access to two of the three sites simultaneously. | A targeted attack, crash, or misconfiguration on this single device can cut off Westside and HQ's connectivity to Central at once, with no redundant path. | Critical |
| E | The "Allow-VPN-Westside" rule permitting ALL services (already flagged internally as "too permissive") means a foothold gained at Westside — the least-defended site — inherits the same reach into Central's server subnet as a direct compromise at Central itself. | A weak, peripheral entry point at Westside is effectively elevated to full internal server-subnet access, bypassing the need to ever directly attack Central's own defenses. | Critical |

Top Threat: Elevation of Privilege. The over-permissive Westside VPN
  rule is the single misconfiguration that converts this system's
  weakest link (a consumer-grade router with no enterprise protections)
  into full, unrestricted access to Central's most sensitive
  infrastructure — this is precisely the risk Marcus's own notes flagged
  directly: "If Westside's consumer router gets compromised, the
  attacker has full access to the server subnet."
```

---

## Cross-System Observation

Across all 3 systems, **Elevation of Privilege was named the top threat twice (Active Directory and Network Infrastructure)**, and **Denial of Service once (PACS/Medical Imaging)**. But in every case, the underlying mechanism enabling that top threat is the same architectural condition already identified repeatedly throughout this project: the absence of any boundary that would otherwise contain a single point of compromise. Whether that boundary failure takes the form of no MFA on Domain Admin accounts, an overly permissive VPN rule, or a completely unpatchable legacy workstation, the result across all 3 systems is identical: a single weak point does not stay a single weak point.
