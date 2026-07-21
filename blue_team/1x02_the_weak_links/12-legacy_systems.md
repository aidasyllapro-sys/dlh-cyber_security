# MedDefense Health Systems: The Legacy Systems

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** `meddefense-vulnerability-scan.txt`, NVD/vendor advisory research conducted directly for this document, and cross-referenced against Project 0x00 (Asset Registry, Criticality Assessment, Compensating Controls) and Project 1x01 (Threat Actor Matrix, Kill Chains, Threat Priority Assessment) **Purpose:** Assess the unique, permanent risk profile of MedDefense's three end-of-life systems — not as three more findings to patch, but as three systems that no patch will ever fully secure again.

---

## System 1: Windows XP SP3 (WS-RAD-01, MRI Workstation, 10.10.1.70)

### EOL Research

A direct search for CVEs newly published in the last 2 years that explicitly list Windows XP in their affected-product data returns effectively **zero results**, and this absence is itself the finding, not a clean bill of health. Microsoft stopped including Windows XP in new security advisories entirely once extended support ended in 2014; current Microsoft CVE disclosures (dozens published weekly, confirmed directly against NVD's own dashboard for this document) cover Windows 10, 11, and currently-supported Server versions exclusively. This does not mean XP has become secure. It means the vendor has stopped looking for, or at least stopped publishing, new flaws specific to it. The 2 most critical CVEs affecting this system remain the ones already confirmed in this project (Task 1/4): **CVE-2008-4250 (MS08-067, CVSS 10.0)** and **CVE-2019-0708 (BlueKeep, CVSS 9.8)**, both, notably, received rare emergency out-of-band patches from Microsoft even after XP's EOL date, given their severity (BlueKeep's 2019 patch and, unusually, a 2017 WannaCry-era patch covering related SMB flaws). That history does not extend to future flaws, no such exception is guaranteed, or even likely, again.

### Permanent Exposure

An unpatched system is a system with a known gap that a patch could close tomorrow; an EOL system is a system for which no patch will ever be written again, for any flaw, no matter how severe. This is categorically different: "unpatched" describes a temporary state fixable by applying available updates, while "EOL" describes a permanent state where the vendor has formally ended the relationship between disclosed vulnerability and available fix. You cannot patch your way out of this risk because patching requires a vendor to have written a patch in the first place — and for Windows XP, that vendor relationship ended over a decade ago, meaning every vulnerability disclosed in shared Windows code since 2014 exists on this system with certainty and no remediation path except replacing the system itself.

### Scan Findings

Only **Finding 004** names this host, but it bundles three independently critical, independently weaponized CVEs (MS08-067, BlueKeep, EternalBlue) into a single scan entry. All three are exploitable specifically _because_ the OS is EOL in the sense that matters going forward: even though two of the three received historical emergency patches, WS-RAD-01 remains exposed to every SMB/RDP-adjacent Windows flaw disclosed since 2014 that never received, and never will receive, a similar exception, since there is no way to distinguish in advance which future flaw Microsoft might consider severe enough to break its own EOL policy for again.

### Compensating Controls

Project 0x00 (Task 6) proposed 4 compensating controls for the MRI workstation given its regulatory constraints prevent OS replacement in place, with **network micro-segmentation (P-001), a dedicated VLAN restricting traffic to the PACS server only, identified as the top priority**, alongside host-based firewall restrictions, application whitelisting, and enhanced logging given native OS-level security tooling on XP is itself unreliable and unsupported. **These controls meaningfully reduce, but do not fully close, the exposure this scan confirms.** Segmentation would prevent the flat-network-wide reachability this finding currently has, but does not protect against an attacker who is already legitimately positioned on the restricted PACS-only VLAN, for example, via a compromised PACS server itself (Finding 024's unencrypted DICOM traffic on pacs-srv-01 is directly relevant here) or a radiology workstation with a legitimate reason to be on that segment. **Additional controls recommended:** a network-layer virtual-patching/IPS capability specifically signature-matched to known SMB/RDP exploit traffic (a well-established compensating measure for exactly this class of unpatchable legacy medical device, used precisely because it can block known exploit patterns without touching the vulnerable OS itself), and disabling any of the bundled services (RDP in particular) not actually required for clinical operation of the MRI console.

---

## System 2: Windows Server 2012 R2 (print-srv-01, 10.10.2.31)

### EOL Research

Unlike Windows XP, Server 2012 R2 only reached EOL in October 2023, recently enough that new CVEs disclosed for currently-supported Windows Server versions still routinely list 2012 R2 in their affected-product data, because it shares underlying codebase with those supported releases even though it will never itself receive the resulting patch. Direct research confirms two clear, recent examples: **CVE-2025-24035 and CVE-2025-24045**, both Remote Code Execution vulnerabilities in Windows Remote Desktop Services disclosed in Microsoft's March 2025 Patch Tuesday (CVSS 8.1 each), both explicitly listing Windows Server 2012 R2 among affected products per CERT-EU's own advisory on the pair. Microsoft patched these for every currently-supported version listed. 2012 R2 was named as affected but will never receive the fix.

### Permanent Exposure

This is the most concrete illustration in this document of why EOL is categorically different from unpatched: CVE-2025-24035 and CVE-2025-24045 were disclosed in **2025**, more than a decade after 2012 R2 first shipped, proving that new, critical vulnerabilities are still being found in code this OS shares with its supported successors, and will keep being found indefinitely. Patching cannot close this risk because the vulnerability class itself (flaws in shared Windows Server components) has no end date. Only the _support relationship_ for this specific version has one, and that relationship is already over.

### Scan Findings

Only **Finding 008** names this host, bundling the EOL status itself with CVE-2021-34527 (PrintNightmare, CVSS 8.8), already confirmed weaponized with a dedicated Metasploit module in this project's Task 4/5 research. PrintNightmare is exploitable regardless of EOL status (a patch exists for supported versions), but its presence here, unpatched, on an EOL host is the direct, current consequence of the same permanent-exposure pattern: this specific flaw already has no fix coming for this system, and CVE-2025-24035/24045 confirm it will not be the last.

### Compensating Controls

**Project 0x00's Task 6 compensating-controls work was scoped specifically to the MRI workstation and does not cover print-srv-01 at all, a genuine gap in prior work, stated plainly rather than glossed over.** No compensating controls currently exist for this system. Recommended controls, given none are yet in place: disable the Windows Print Spooler service entirely if network printing is not genuinely business-critical from this specific server (the single most effective, widely-recommended mitigation for the entire PrintNightmare vulnerability family, since it removes the vulnerable service rather than merely restricting reach to it); network segmentation consistent with the same flat-network remediation already prioritized elsewhere in this project; and restricting this server's network reachability to only the specific print-consuming clients that require it, rather than the entire internal network.

### Business Case Note

Unlike the MRI, this system carries no regulatory certification burden: A Windows Server print role has no equivalent to a medical device's FDA clearance constraints, making an actual OS migration for this specific host comparatively fast and low-risk to execute.

---

## System 3: Ubuntu 18.04 LTS without ESM (billing-srv-01, 10.10.2.15)

### EOL Research

Ubuntu's own security-notice archive continues to reference "18.04 LTS" as an affected release in multiple 2025-2026 notices (a April 2026 oFono vulnerability notice, for example, explicitly lists "Ubuntu 24.04 LTS, 22.04 LTS, 20.04 LTS, 18.04 LTS, 16.04 LTS" together), confirming the underlying vulnerable code is still present in 18.04's codebase even now. The two most relevant recent examples: a cluster of **Linux kernel vulnerabilities disclosed throughout 2024-2025** (Ubuntu Security Notices document dozens across USN-7166 through USN-7308 and beyond, covering privilege escalation, information disclosure, and denial-of-service classes) and **CVE-2025-38352**, a Linux kernel local privilege escalation flaw confirmed by Ubuntu's own tracker as actively exploited. Note stated honestly: confirming with full certainty that every one of these specific CVEs applies to 18.04's older 4.15 kernel specifically (versus only to the kernel versions used by 20.04/22.04/24.04) was not independently verified line-by-line for this document. The directional evidence (continuous, high-volume kernel CVE disclosure explicitly still referencing 18.04 as a named release) is what matters for this assessment's conclusion regardless of the exact per-CVE applicability.

### Permanent Exposure

The distinction here is procedural rather than purely technical, and worth stating precisely: Ubuntu 18.04 is not abandoned by Canonical entirely — Extended Security Maintenance exists specifically to keep receiving these patches — but MedDefense has not enrolled in it (confirmed directly in Finding 011). This makes billing-srv-01's exposure a **deliberate, reversible-in-principle but currently-unreversed** choice rather than an absolute technical dead end like Windows XP. That distinction matters for the recommendation below: unlike Systems 1 and 2, this system's permanent exposure could be closed through a comparatively simple administrative and financial decision (ESM enrollment) without any hardware or regulatory replacement; though a full OS upgrade remains the more durable long-term fix.

### Scan Findings

This host carries **the highest finding density of any system in the entire 31-finding scan**: Findings 001 (CVE-2021-44790, mod_lua buffer overflow), 002 (CVE-2019-0211, chained privilege escalation), 006 (MySQL network exposure), 009 (SSH password authentication), 011 (the EOL/no-ESM status itself), and 026 (47 unpatched kernel CVEs, directly caused by the missing ESM enrollment). Finding 026 is exploitable specifically _because_ of EOL/no-ESM status by definition; Findings 001 and 002 are software-specific Apache flaws independent of the underlying OS's EOL state, but the kernel-level privilege escalation surface documented in Finding 026 is the direct multiplier that makes Finding 002's local privilege-escalation step (already confirmed weaponized, EDB-46676) more dangerous than it would be on a currently-patched kernel.

### Compensating Controls

As with print-srv-01, **Project 0x00's Task 6 work did not cover billing-srv-01**. No compensating controls currently exist for this system either. Recommended, given this project's own Lynis self-audit (Task 8) independently confirmed the same gap pattern: a web application firewall (ModSecurity) and anti-DoS module (mod_evasive) for Apache specifically, given Finding 001 sits directly on this host with no compensating control today; server-class endpoint detection, given this exact host's documented cryptominer compromise; and immediate network-layer restriction of MySQL (Finding 006) and SSH (Finding 009) to only the specific hosts that require access, independent of and in addition to any OS-level remediation.

---

## Business Decision: Which One System to Migrate This Quarter

**Recommendation: billing-srv-01 (Ubuntu 18.04) should receive the migration budget this quarter.** This is not the system with the highest asset criticality rating. That is WS-RAD-01, the MRI workstation, rated Availability Critical and Integrity Critical as the 0x00 Top 5 Critical Asset #4, a genuine and serious counter-argument. The recommendation rests on three factors together, not asset criticality alone:

1. **Realized versus theoretical threat exposure.** billing-srv-01 is not a hypothetical target. It is the server already compromised twice in MedDefense's documented incident history, and it sits at the literal first step of Kill Chain #1, independently confirmed as the organization's **#1-ranked threat** in the 1x01 Threat Priority Assessment (Task 16). WS-RAD-01 carries a higher raw CVSS ceiling (10.0 versus 9.8), but has not been corroborated across this project's kill chains and scenarios the way billing-srv-01 has, a gap already noted honestly above and in this project's Task 15 correlation work.
2. **Finding density and compounding risk.** No other host in the entire 31-finding scan carries as many distinct, exploitable findings as billing-srv-01 (6, versus 1 for each of the other two EOL systems), meaning a migration here closes the largest single cluster of risk in the report, not just one bundled finding.
3. **Genuine quarter-feasibility.** This is the decisive practical factor. An Ubuntu LTS version upgrade for a standard Linux application server is a well-understood, non-regulated engineering project realistically achievable within a single quarter. Migrating WS-RAD-01, by contrast, almost certainly means replacing or recertifying a regulated medical device platform, a materially longer, more expensive, vendor-dependent undertaking that risks an incomplete, rushed outcome if forced into a single-quarter budget window rather than being planned properly.

**This does not mean WS-RAD-01 is deprioritized. It means its remediation path this quarter is different.** Given a full migration is not realistically achievable in this timeframe regardless of budget, the recommended action for WS-RAD-01 this quarter is accelerating the compensating controls already proposed in 0x00 Task 6 (network micro-segmentation specifically) to their fullest practical extent, while the actual EOL migration budget goes to the system that can be fully and durably fixed within the available window.
