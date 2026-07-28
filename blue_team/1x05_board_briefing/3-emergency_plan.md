# MedDefense Health Systems: The 72-Hour Plan

**Prepared by:** Aïda Sylla, Security Analyst 
**Source material:** The Crimson Tide advisory phases (Task 0), the Kill Chain Overlay's Control Interception Map (Task 2), and the Security Strategy's budget allocation (1x03, Task 8) 
**Purpose:** The Security Strategy was a 6-month roadmap. Crimson Tide compressed the timeline to 72 hours. This plan does not attempt the full strategy overnight; it selects the specific actions that convert the maximum number of EXPOSED phases (Task 0) toward PROTECTED, using exactly the people and constraints available right now, not an idealized team.

**Available resources, stated precisely, not assumed:** Sarah Park plus 2 IT staff tonight, no additional headcount. The FortiGate firmware cannot be downloaded until the $2,400 support contract renews. Segmentation requires new switch configurations, a minimum of 2-3 days. Backup isolation via physical disconnect can happen tonight, immediately. AD Kerberos changes require a scheduled maintenance window given the real risk of breaking authentication organization-wide.

---

## Tier 1: Tonight (0-12 hours)

**No budget approval, no procurement, minimal risk of service disruption. These happen before anyone sleeps.**

|Action|Phase Blocked|Owner|Prerequisites|Risk of Action|Risk of Inaction|
|---|---|---|---|---|---|
|Verify the Central FortiGate 100F's exact firmware version|1 (Initial Access)|Sarah Park|None; direct console access already exists|None; a read-only check|MedDefense cannot rationally prioritize anything else tonight without knowing whether it sits inside the vulnerable range (7.2.0-7.2.4 or 7.0.0-7.0.11)|
|Disable SSL-VPN on the FortiGate as an interim mitigation, per CISA's own stated fallback when patching is not immediately possible|1 (Initial Access)|Sarah Park|Firmware check above, confirming exposure|Remote SSL-VPN access for clinicians and administrators goes down until patched; site-to-site IPSec tunnels to Westside and HQ use a separate mechanism and are not expected to be affected, though this should be confirmed directly during execution, not assumed|The pre-authentication RCE remains fully exploitable for as long as SSL-VPN stays enabled unpatched|
|Review FortiGate logs for the specific IOCs the advisory names: unusual CLI commands, unexpected VPN sessions, authentication anomalies|1, 2 (Initial Access, Reconnaissance)|1 IT staff member|FortiGate log access (already available)|None|An already-compromised device could go undetected through the rest of this plan|
|Physically disconnect NAS-01 from the network|5 (Backup Destruction)|1 IT staff member|None; a physical action|No new backups can complete while disconnected; this is an accepted, temporary tradeoff, not an oversight|NAS-01 remains reachable and destructible exactly as Crimson Tide's documented method describes in all 5 prior incidents|
|Rotate credentials for known, high-privilege, SPN-associated service accounts (a targeted action, not a full Kerberos configuration change)|3 (Lateral Movement)|Sarah Park|A list of privileged service accounts, compiled from existing AD documentation|Low; rotating a small, known set of passwords does not carry the same authentication-breaking risk as changing Kerberos encryption types|Any already-cracked or already-Kerberoasted credential remains usable for the full duration of this plan|

---

## Tier 2: Tomorrow (12-36 hours)

**Requires coordination, a possible brief service window, and Board budget approval from tomorrow's 9:00 AM meeting.**

|Action|Phase Blocked|Owner|Prerequisites|Risk of Action|Risk of Inaction|
|---|---|---|---|---|---|
|Board approves the $2,400 FortiGate support contract renewal|1 (Initial Access)|James Chen (recommendation), Robert Kim (approval)|The 9:00 AM Board session itself|None beyond the cost|The firmware patch cannot be legally downloaded from Fortinet at all without this renewal, regardless of any other action taken|
|Download and apply the FortiGate firmware patch|1 (Initial Access)|Sarah Park|Contract renewal (above) completed|A brief connectivity outage across all 3 sites during the required reboot; must be scheduled and communicated in advance, not sprung on clinical staff|The single most critical, actively-weaponized entry point in this entire advisory remains open|
|Verify EDR (Sophos Intercept X) is actually active and current on every server and workstation, not merely funded|6 (Ransomware Deployment)|Sarah Park's team|None; this is a verification pass against an already-funded, already-licensed control (1x03, Task 8, Control 5, $23,000)|None|This program's own Task 0 and Task 2 analysis already flagged this deployment status as unconfirmed; an unverified assumption of protection is not protection|
|Schedule and execute the AD Kerberos hardening maintenance window (disable RC4 and DES encryption types)|3 (Lateral Movement)|Sarah Park's team, James Chen sign-off|Tier 1's targeted credential rotation completed first, to avoid overlapping, confusing AD changes within the same short period|Real: this exact change carries a documented risk of breaking authentication for any legacy system still depending on RC4/DES that MedDefense has never fully inventoried (Finding 018, 1x02)|Kerberoasting remains viable against every future credential, not only the ones rotated in Tier 1|
|Confirm MFA enforcement status on all VPN and remote access accounts|1, 3|Sarah Park's team|None; verification against an already-funded control (1x03, Task 8, Control 2, $2,000)|None|Even after the firmware patch closes Phase 1's specific vulnerability, unenforced MFA leaves remote access broadly weaker against any other credential-based attempt|

---

## Tier 3: This Week (36-72 hours)

**Requires procurement, vendor involvement, or configuration changes needing proper testing.**

|Action|Phase Blocked|Owner|Prerequisites|Risk of Action|Risk of Inaction|
|---|---|---|---|---|---|
|Begin network segmentation switch reconfiguration|2, 3, 5 (Reconnaissance, Lateral Movement, Backup Destruction)|Sarah Park's team, possibly an external vendor given scale|Tier 1's NAS-01 disconnect remains in place until segmentation properly re-integrates it into an isolated zone|Misconfigured switch rules could disrupt legitimate traffic between sites; requires careful, tested rollout, not a rushed one|The flat network remains MedDefense's single most-cited weakness across every prior project in this program|
|Re-integrate NAS-01 into the network within its own isolated, segmented zone, with LUKS2 encryption applied (already built and tested directly in 1x04, Task 12)|5 (Backup Destruction)|Sarah Park's team|Segmentation project (above) reaching the point where an isolated backup zone exists|A migration error could risk backup data integrity if not preceded by a verified, separate backup copy, exactly the precaution this program's own Task 22 (1x04) Implementation Playbook already specifies|NAS-01 remains either disconnected and unusable (an acceptable short-term state, not a permanent one) or reconnected without protection|
|Deploy database encryption at rest for ehr-db-01 and billing-srv-01|4 (Data Exfiltration)|Sarah Park's team|A verified, tested, separate backup of each database completed first, per this program's own Task 22 (1x04) procedure|Requires a scheduled outage window per database; rushing this without the tested procedure already documented risks the EHR system itself, not only the attack surface|The exact exfiltration method Crimson Tide already used against 4 of 5 prior hospitals, copying raw unencrypted files, remains available|
|Replace the Westside consumer router with the enterprise-grade firewall already funded (1x03, Task 8, Control 6, $1,800)|2, 3 (Reconnaissance, Lateral Movement, at the Westside site specifically)|External vendor (procurement/delivery), Sarah Park (installation)|Vendor scheduling; hardware delivery|Standard installation risk for any network hardware change|The Westside tunnel's own untrusted, unpatched consumer-grade endpoint remains a documented, separate weakness (Finding 014, 1x02)|
|Conduct a tabletop exercise simulating this exact Crimson Tide scenario, including the direct extortion contact to named executives|7 (Extortion)|James Chen, Sarah Park, General Counsel (Maria Santos)|None beyond scheduling|None|This program's own Kill Chain Overlay (Task 2) already confirmed no technical control addresses this phase at all; an untested response plan is the only mitigation available, and it remains untested|

---

## Resource Conflict Assessment

**Yes, real conflicts exist, and they are worth naming directly rather than presenting this plan as if three people can do everything simultaneously.**

**Conflict 1: Sarah Park is the single named owner of nearly every technical action across all three tiers.** She is required for the firmware check, the SSL-VPN disable decision, the credential rotation, the firmware patch application, the Kerberos maintenance window, and the MFA verification, six distinct actions that all require her specific administrative access (FortiGate and AD), spread across a 72-hour window with only 2 additional IT staff to delegate to. **Resolution:** the 2 IT staff take direct ownership of the actions that do not require Sarah's specific elevated access, the FortiGate log review and the NAS-01 physical disconnect in Tier 1, freeing Sarah to focus exclusively on the firmware and credential actions only she can perform, in the sequence this plan already establishes rather than in parallel.

**Conflict 2: The FortiGate firmware patch (Tier 2) and the AD Kerberos maintenance window (Tier 2) both require Sarah's direct involvement and both carry real service-disruption risk, but cannot reasonably happen at the same time.** Attempting both within the same 24-hour window risks compounding any troubleshooting needed if either one causes an unexpected issue, making it unclear which change caused which symptom. **Resolution:** strict sequencing, not parallel execution. The firmware patch happens first, since it closes Phase 1, the entry point every other phase in this advisory depends on; the Kerberos hardening happens in a separate, later window, once the firmware patch is confirmed stable, even though this means Kerberoasting exposure (Phase 3) persists a few hours longer than it ideally would.

**Conflict 3: NAS-01's Tier 1 physical disconnect and the Tier 3 segmentation project both touch the same system, but are not actually in conflict if sequenced correctly rather than run independently.** The disconnect is a deliberate, temporary stopgap; the segmentation project is NAS-01's permanent, correct end state. **Resolution:** NAS-01 stays physically disconnected for the full duration between Tier 1 and Tier 3, not reconnected early for convenience, since reconnecting it to the same flat network it was isolated from in the first place would undo Tier 1's own protection for no operational benefit before segmentation is actually ready to receive it.
