# MedDefense Health Systems: Shadow systems assessment

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** Conversation with Mike Torres (Helpdesk Lead), cross-referenced against the Asset Registry (Task 7), Network Scan Summary, and the Complete Control Matrix (Task 10) **Purpose:** Assess three systems operating outside MedDefense's formal IT governance, determine the appropriate response for each, and update the Asset Registry accordingly.

---

## Shadow System 1: Dr. Patel's Personal NAS (Cardiology, Central)

### Risk Assessment

**Sensitive data possibly present:** Mike Torres described this as storing "research data." In a Cardiology context, this plausibly includes clinical or research data tied to actual patients. But this is not confirmed by any source in this project, and I want to be explicit that I am inferring likelihood from context, not asserting it as fact. This should be verified directly with Dr. Patel as a first step, not assumed.

**Controls from the Complete Control Matrix (Task 10) that do NOT cover this system:**

- **C-010** (Nightly Full VM Backup): only covers 6 named, IT-managed VMs; this personal device is not among them, meaning any data on it has no organizational backup at all.
- **C-009** (Sophos Antivirus): covers only IT-managed Windows 10/11 workstations; a personal consumer NAS is outside its scope entirely.
- **C-007/C-008** (Password policy, account lockout): these apply to AD-authenticated accounts; a personal NAS almost certainly uses its own local administrative account, most likely still on factory-default or self-chosen credentials never reviewed by IT.
- **C-002** (Default-Deny Firewall): governs the perimeter only; it does nothing to isolate this device from the rest of the flat internal network once it is plugged into a wall port.
- No detective control (C-003, C-006, C-014, C-015, C-016) has any visibility into this device at all.

**Worst-case scenario:** Consumer-grade NAS devices are a well-established, common ransomware and botnet target due to frequently unpatched firmware and default credentials. If this device is compromised, MedDefense faces 2 simultaneous problems: (1) if the "research data" includes patient information, this is a PHI exposure with no prior visibility, documentation, or safeguards, and no backup exists anywhere to recover from data loss or encryption; (2) because the device sits on the same unsegmented internal network as the EHR, domain controllers, and every other critical asset (per the confirmed flat-network finding), a compromised NAS is also a viable pivot point for lateral movement into the rest of the environment. The same pattern already responsible for the risk posed by every other unsegmented device in this project.

### Recommended response: **Migrate**

Dr. Patel has a legitimate, stated operational need (the official shared drive is "too slow" for his workflow) by simply removing the device without addressing that need risks him replacing it with another unmanaged device. The correct response is to migrate his data to an approved, IT-managed storage solution (e.g., a properly provisioned share on file-srv-01, or a dedicated high-performance research share if performance is the genuine bottleneck) that already has at least baseline controls (backup, centralized administration) followed by decommissioning the personal NAS once the migration is verified complete and the device is removed from the network. This addresses the root cause of the shadow IT rather than only its symptom.

---

## Shadow System 2: Marketing's shared Google Drive (personal Gmail-linked)

### Risk Assessment

**Sensitive data possibly present:** Media files and press communications are, on their face, lower-classification data (Public/Internal). But a marketing team's file store plausibly also contains **unreleased or embargoed material**, including draft communications related to security or compliance incidents (for example, any future public statement about the incidents already documented in this project). If so, its actual sensitivity could rise to Confidential, not because of its category but because of its timing.

**Controls from the Complete Control Matrix (Task 10) that do NOT cover this system:**

- This service is entirely outside MedDefense's Microsoft/O365 tenant, so **none** of the organization's controls apply to it: not C-007/C-008 (password/lockout policy is enforced through the organization's own Active Directory, not a personal Google account), not the org's MFA posture (which is already weak; only one individual's personal account has MFA per Task and is irrelevant here regardless, since this is a _different_ personal account entirely), and not any backup mechanism (O365 itself is already excluded from MedDefense's backup strategy per Task 4/9; this Google Drive is even further outside that boundary).
- There is no offboarding process tied to this asset: if the employee who owns the personal Gmail account leaves MedDefense, there is no mechanism to revoke access, transfer ownership, or even confirm the data still exists.

**Worst-case scenario:** Personal email accounts are a common target for credential-stuffing and phishing attacks entirely independent of any of MedDefense's own security posture. If that personal Gmail account is compromised, an attacker gains whatever is stored in the linked Drive, including any embargoed or pre-release communications, with zero visibility or response capability on MedDefense's side, since the organization would not even know the compromise occurred. Separately, simple employee turnover could result in a silent, permanent, and un-auditable loss of organizational marketing records.

### Recommended response: **Migrate**

The organization already pays for Microsoft O365 organization-wide ($432,000/year, per the Task 4 service contracts), which while itself imperfect (it is excluded from MedDefense's own backup strategy, per Task 9) is still an organizationally owned, centrally administered platform rather than an individual's personal account. Migrate all Marketing files and communications to a properly provisioned SharePoint/OneDrive location within the existing O365 tenant, then decommission access to the personal Google Drive and confirm no organizational data remains on it.

---

## Shadow System 3: Raspberry Pi "Network Monitor" (2nd floor, central)

### Risk Assessment

**Sensitive data possibly present:** Unclear, and this is a case where the uncertainty itself is the primary risk. If this device was genuinely configured as a network monitor (as Mike Torres describes, at Marcus's request), it may have visibility into network traffic potentially including the same unencrypted, network-wide-reachable database traffic already flagged elsewhere in this project (e.g., PostgreSQL on ehr-db-01, MySQL on billing-srv-01). A monitoring tool with this level of access, left unmaintained, is a risk regardless of what data it currently holds, because a compromised monitoring device could be repurposed by an attacker into a traffic-interception tool.

**A possible (unconfirmed) correlation worth flagging:** The network scan (Task 7) identified an unidentified Linux host on the Central servers subnet (`UNKNOWN-01` (10.10.2.99)) running SSH and two unidentified web services on ports 8888 and 9090. Port 9090 is the commonly used default port for Prometheus, an open-source monitoring tool, which is at least consistent with a "network monitor" description. **I want to be clear this is a plausible hypothesis based on port conventions, not a confirmed match**. The scan groups this IP under the servers subnet rather than a floor-2 designation, and since the network is confirmed flat with no enforced VLANs, IP addressing does not reliably indicate physical location. This should be verified directly (e.g., by physically locating the device Mike Torres described) rather than assumed.

**Controls from the Complete Control Matrix (Task 10) that do NOT cover this system:**

- Not present in the asset registry until this task, and therefore covered by **none** of MedDefense's 17 implemented controls: no backup (C-010), no antivirus/endpoint protection (C-009), no logging or monitoring of the device itself (ironic, given its apparent purpose), and no patch management of any kind.
- Both the person who requested it (Marcus) and the person who built it (the prior intern) have left the organization, meaning, at minimum, it has gone unmaintained since Marcus's departure roughly three months prior to the start of this project (per the Task 0 environment summary), and realistically may be considerably older and less maintained than that.

**Worst-case scenario:** An abandoned, unpatched device, quite possibly running default or long-unrotated credentials, sitting on the same subnet as the domain controllers and EHR database (if the UNKNOWN-01 correlation above is correct) is close to an ideal, low-effort target for an attacker seeking a long-term foothold: nobody is currently positioned to notice a compromise, since by Mike Torres's own account, "nobody has touched it" since both people who understood it left the organization.

### Recommended response: **Decommission**

Unlike the NAS and the Google Drive, this device does not serve a current, accountable operational need. Its requester and builder are both gone, and no one currently uses, maintains, or is responsible for it. It should be located, its actual function and data confirmed (ideally before removal, since it may hold forensically useful information about the network's recent history), and then decommissioned. Separately, the legitimate underlying need it may have been trying to serve, network monitoring, is a real and already-identified gap in this project (Gap G-001, Task 5: no centralized log correlation or alerting exists at MedDefense). That gap should be addressed through a properly scoped, IT-owned monitoring solution, not through an unmaintained device with unknown provenance.

---

## Asset Registry Update

The following entries should be added to the Asset Registry (Task 7), continuing the existing ID sequence:

| Asset ID | Name                           | Type                     | Location                                                         | Owner (Dept)                                                                                        | OS/Platform                                             | Critical Services                                                     | Network Segment                                                                                                                                                                                                                | Status                    | Notes                                                                                                                                                                                                                                                              |
| -------- | ------------------------------ | ------------------------ | ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A-036    | Dr. Patel's Personal NAS       | Data Store               | Central - Cardiology (Dr. Patel's office)                        | Unofficial - individual clinician (Dr. Patel), not IT                                               | Unknown (consumer NAS, vendor/model not disclosed)      | Personal/departmental research data storage                           | Unknown (plugged into a standard wall port; on the flat internal network)                                                                                                                                                      | **Shadow IT (unmanaged)** | Not in any prior IT documentation or network scan; identified via a conversation with Mike Torres (Helpdesk Lead), not through a technical inventory process reinforces that MedDefense's asset visibility gaps extend beyond what network scanning alone can find |
| A-037    | Marketing Shared Google Drive  | Application / Data Store | Cloud (external - outside MedDefense's O365 tenant)              | Unofficial - Marketing team, linked to an individual's personal Gmail account                       | N/A (Google Workspace/personal Google account)          | Media file and press communication storage/sharing                    | N/A (cloud, external to MedDefense's network entirely)                                                                                                                                                                         | **Shadow IT (unmanaged)** | Ownership is tied to a personal, non-organizational account; no organizational offboarding, backup, or access-revocation mechanism exists for this asset                                                                                                           |
| A-038    | Raspberry Pi "Network Monitor" | Server / Unknown         | Central, 2nd floor (exact location per Mike Torres, unconfirmed) | Unofficial - originally requested by Marcus Webb, built by a former IT intern; both have since left | Unknown (likely a Linux-based single-board computer OS) | Unclear - believed to have been intended as a network monitoring tool | Unknown; **possibly corresponds to UNKNOWN-01 (10.10.2.99)** identified in the Task 7 network scan, based on port conventions (9090 = common Prometheus default) - **unconfirmed correlation, requires physical verification** | **Shadow IT (unmanaged)** | Unmaintained since at least Marcus's departure (~3 months prior to this project, per Task 0); original purpose may partially overlap with Gap G-001 (no centralized monitoring/alerting) identified in Task 5                                                      |

---

## Shadow IT policy recommendation

The single most effective policy change MedDefense could make is to pair an explicit prohibition on unauthorized devices and cloud services with a **guaranteed, fast-turnaround IT request process** for legitimate operational needs. All 3 shadow systems in this assessment exist because a real, reasonable need went unmet through official channels: a shared drive that was too slow, a marketing team that needed an easy way to share large files, and a monitoring capability nobody in IT ever formally built. A policy that only prohibits shadow IT without also making the approved path fast and usable will not change behavior. It will simply push the same workarounds further out of sight; a policy that does both directly addresses the root cause documented in all three cases above, not just the symptom.
