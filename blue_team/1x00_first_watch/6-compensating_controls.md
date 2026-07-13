# MedDefense Health Systems: Compensating control strategy - MRI workstation (Windows XP Embedded)

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Subject asset:** Siemens MAGNETOM MRI scanner, Central Radiology, control workstation running Windows XP Embedded **Purpose:** Propose a compensating control strategy for a critical, unpatchable, unreplaceable medical device operating under real budget, regulatory, and clinical constraints.

---

## 1. Risk analysis

Windows XP has received no security patches since April 2014. Over a decade of publicly known, unremediated vulnerabilities (including remote code execution flaws in core Windows services such as SMB, which have historically been used by self-propagating worms) remain permanently exploitable on this workstation, with no possibility of remediation through patching. This alone would be a contained risk if the device were isolated, but per the current network configuration, the MRI workstation sits on **the same VLAN as the rest of the hospital's general-purpose workstations**. The same flat, unsegmented network architecture already flagged elsewhere in this assessment (Central operates on 10.10.0.0/16 with no VLANs separating device classes). This means any of the hundreds of general workstations at Central (reachable by phishing, an infected USB drive, or lateral movement from another compromised host) has direct network-layer access to the MRI workstation, and the MRI workstation, if compromised, has equally direct access back to everything else on that segment, including domain controllers, the EHR database, and billing systems. In effect, the least-defensible device on the network (unpatchable, decade-old OS) is placed on equal network footing with the most sensitive systems in the environment, meaning a compromise that starts anywhere on that VLAN can reach the MRI, and a compromise that starts at the MRI can reach anywhere else, making this workstation a critical risk to the entire network, not a contained departmental issue.

---

## 2. Compensating control strategy

```
Control: Dedicated VLAN with Restrictive Firewall Ruleset (Micro-Segmentation)
Category: Technical
Function: Compensating (Preventive in effect)
Description: Move the MRI workstation onto its own isolated VLAN, separate
  from general hospital workstations and from other server/device
  segments. Configure firewall/ACL rules that permit traffic only between
  the MRI workstation and the specific PACS server (pacs-srv-01) on the
  specific port(s) that DICOM transmission requires, denying all other
  inbound and outbound traffic, including general internet access and
  any path to other internal subnets.
How it reduces risk without OS modification: This does not touch the
  Windows XP Embedded system at all. The OS, its certification, and its
  regulatory compliance status remain untouched. It instead reduces the
  network's exposure to the device (and the device's exposure to the
  network) by shrinking what the workstation can reach and what can
  reach it down to the single required business function. A compromised
  general workstation elsewhere on the hospital network can no longer
  reach the MRI directly, and if the MRI itself is ever compromised, its
  ability to reach anything beyond pacs-srv-01 is eliminated.
Limitations / Residual Risk: The MRI-to-PACS communication path itself
  remains a residual attack surface — if pacs-srv-01 is compromised, or
  if the DICOM protocol implementation on either end has an exploitable
  flaw, this control does not prevent that specific path from being
  abused. This control also requires available switch ports/VLAN
  capacity and coordination with radiology to schedule any cutover
  without disrupting the ~45 daily studies.
```

```
Control: Network-Based Intrusion Detection/Prevention at the Segment Boundary
Category: Technical
Function: Compensating (Detective, with a Preventive component if
  deployed in-line/blocking mode)
Description: Deploy a network IDS/IPS sensor at the boundary of the new
  MRI VLAN, tuned with signatures for known exploitation techniques
  historically used against unpatched Windows systems (e.g., SMB-based
  exploitation, known worm propagation patterns), monitoring or blocking
  malicious traffic patterns without ever touching the workstation
  itself.
How it reduces risk without OS modification: This is the network-layer
  equivalent of "virtual patching". It does not fix the underlying
  Windows XP vulnerabilities, but it can detect or block the network
  traffic patterns that would attempt to exploit them, entirely outside
  the device. Combined with the segmentation above, this gives MedDefense
  visibility into any attempt to reach the MRI workstation or any
  unusual traffic originating from it, directly closing the detection
  gap already identified in this assessment (no centralized alerting
  exists today).
Limitations / Residual Risk: An IDS/IPS is only as effective as its
  signature/rule set. A novel or unsignatured exploitation technique
  could pass undetected. It also requires someone to actually monitor
  and act on alerts, which ties back to the broader detection gap
  (Gap G-001) already identified: this control provides the visibility,
  but only delivers value if paired with a process to respond to what
  it reports.
```

```
Control: Restricted Physical Access to the MRI Console (Port and Room Control)
Category: Physical
Function: Compensating (Preventive)
Description: Restrict physical access to the MRI control room/console to
  authorized radiology and imaging staff only (distinct badge/key
  control, not the generic all-staff badge currently used for other
  restricted areas per the walk-through findings), and physically disable
  or lock unused USB ports on the workstation to prevent removable-media
  based infection.
How it reduces risk without OS modification: Since the workstation cannot
  be patched against software-based attack vectors, removing or
  restricting a major local infection vector (removable media inserted
  by an unauthorized or careless individual) closes off one of the most
  common ways historically used to compromise isolated or air-gapped-
  style Windows XP systems, without altering the OS or its certified
  configuration.
Limitations / Residual Risk: This does not address network-based attack
  vectors at all (covered by the two technical controls above) and
  depends on consistent enforcement — a legitimate staff member could
  still introduce infected media if port-blocking is not physically
  enforced, or if an exception is made for a legitimate maintenance
  need (e.g., a vendor technician's USB drive during servicing).
```

```
Control: Formal Risk Acceptance, Vendor Coordination, and Isolation Runbook
Category: Administrative
Function: Compensating
Description: Document a formal, leadership-approved risk acceptance for
  the MRI's unpatchable status (tying it to the regulatory/certification
  constraint that prevents remediation), coordinate with the device
  manufacturer's successor entity regarding any available security
  guidance or end-of-life roadmap, and create a specific incident
  response runbook for this device, including a pre-approved procedure
  to immediately isolate the MRI VLAN (not just the workstation) if
  compromise is suspected, since the earlier root-cause analysis showed
  MedDefense's actual incident response today is improvised rather than
  planned.
How it reduces risk without OS modification: This does not reduce the
  technical vulnerability itself, but it ensures the organization has
  made a deliberate, documented decision about this risk (rather than
  the current state (a sticky note that has sat untouched for six
  months) and, critically, ensures that if the other controls fail and
  compromise occurs, the response is fast, pre-approved, and does not
  require improvisation.
Limitations / Residual Risk: A documented plan and risk acceptance does
  not, by itself, stop or detect anything. It is only valuable in
  combination with the technical and physical controls above and
  requires periodic review as the device ages further into its
  operational lifespan.
```

---

## 3. Implementation priority

**If only one control could be implemented immediately: Dedicated VLAN with Restrictive Firewall Ruleset (Micro-Segmentation).**

Justification: The Risk Analysis in Section 1 establishes that the core danger of this device is not that it is unpatched in isolation. It is that its lack of patching is combined with unrestricted network reachability to and from the rest of the hospital. Segmentation is the only proposed control that directly closes that specific, structural exposure: it simultaneously protects the MRI from being reached by a compromised workstation elsewhere in the hospital, and protects the rest of the hospital from being reached by the MRI if it is ever compromised. The IDS/IPS control only adds value once this boundary exists to monitor; the physical control addresses a narrower (local/removable-media) vector; and the administrative control, while necessary for governance, does not reduce technical exposure on its own. Segmentation also does not require ongoing operational effort to be effective once deployed (unlike IDS/IPS, which requires monitoring, or physical controls, which require consistent enforcement), making it both the highest-impact and most durable option under a single-control budget constraint.
