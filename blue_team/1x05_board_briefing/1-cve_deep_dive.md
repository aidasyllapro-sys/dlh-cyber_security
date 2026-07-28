# MedDefense Health Systems: The CVE Deep Dive

**Prepared by:** Aïda Sylla, Security Analyst 
**Source material:** NVD (National Vulnerability Database), Fortinet's own PSIRT advisory (FG-IR-23-097), a direct `searchsploit` verification performed on a Kali Linux workstation, Bishop Fox and Lexfo's published technical exploitation research, and the CISA Known Exploited Vulnerabilities catalog, all verified directly for this document, cross-referenced against the Exploitability Score methodology (1x02, Task 4) 
**Purpose:** CVE-2023-27997 is not a theoretical entry in a database today. It is the confirmed initial access vector Crimson Tide is actively using against hospitals in this region right now. This document researches it with the same rigor applied to every scan finding in 1x02, because the urgency here is real, not academic.

---

## Part 1: NVD Research

**Full description (verified directly against NVD/MITRE):** A heap-based buffer overflow vulnerability (CWE-122) in FortiOS versions 7.2.4 and below, 7.0.11 and below, 6.4.12 and below, and 6.0.16 and below, and in FortiProxy versions 7.2.3 and below, 7.0.9 and below, 2.0.12 and below, and all versions of 1.2 and 1.1, in the SSL-VPN component. An unauthenticated, remote attacker can send a specially crafted request to the SSL-VPN web portal, achieving arbitrary code execution on the device itself. The vulnerability is reachable pre-authentication, meaning it requires no valid credentials at all. It is also known by the researcher-assigned name "XORtigate."

**CVSS v3.1 vector string and base score:**

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Base Score: 9.8 (Critical)
```

Recalculated independently for this document using the published CVSS 3.1 formula against this exact vector, confirming the published 9.8 exactly, not merely citing it secondhand.

**CWE classification:** CWE-122 (Heap-Based Buffer Overflow).

**Affected products and versions:**

- FortiOS: 7.2.0 through 7.2.4; 7.0.0 through 7.0.11; 6.4.0 through 6.4.12; 6.2.0 through 6.2.13; 6.0.0 through 6.0.16
- FortiProxy: 7.2.0 through 7.2.3; 7.0.0 through 7.0.9; 2.0.0 through 2.0.12; all versions of 1.2 and 1.1
- Fixed versions: FortiOS 6.0.17, 6.2.14/6.2.15, 6.4.13, 7.0.12, 7.2.5 and later

**References:**

- Fortinet PSIRT advisory: FG-IR-23-097 (fortiguard.com/psirt/FG-IR-23-097)
- Original technical disclosure: Lexfo Security (Charles Fol and Dany Bach), the researchers who discovered and reported the flaw
- CISA Known Exploited Vulnerabilities catalog entry (cisa.gov/known-exploited-vulnerabilities-catalog, filtered for this CVE)

---

## Part 2: Exploit Assessment

**Is there a public exploit?** A nuanced answer, stated precisely rather than reduced to a simple yes or no. Verified directly with `searchsploit` on a Kali Linux workstation, not inferred from web research alone:

```
$ searchsploit fortios
Fortinet FortiGate FortiOS < 6.0.3 - LDAP Credential Disclosure          | hardware/webapps/46171.py
Fortinet FortiOS 5.6.3 - 5.6.7 / FortiOS 6.0.0 - 6.0.4 - Credentials
  Disclosure                                                             | hardware/webapps/47288.py
Fortinet FortiOS 5.6.3 - 5.6.7 / FortiOS 6.0.0 - 6.0.4 - Credentials
  Disclosure (Metasploit)                                                | hardware/webapps/47287.rb
Fortinet FortiOS 6.0.4 - Unauthenticated SSL VPN User Password
  Modification                                                           | hardware/webapps/49074.py
Fortinet FortiOS < 5.6.0 - Cross-Site Scripting                          | hardware/webapps/42388.txt
Fortinet FortiOS_ FortiProxy_ and FortiSwitchManager 7.2.0 - Authentication
  bypass                                                                 | windows/remote/52239.py
FortiOS SSL-VPN 7.4.4 - Insufficient Session Expiration & Cookie Reuse    | multiple/remote/52336.py
FortiOS_ FortiProxy_ FortiSwitchManager v7.2.1 - Authentication Bypass    | multiple/webapps/51092.sh

$ searchsploit "CVE-2023-27997"
Exploits: No Results
Shellcodes: No Results
Papers: No Results

$ searchsploit --cve CVE-2023-27997
Exploits: No Results
Shellcodes: No Results
Papers: No Results
```

Eight FortiOS-related exploit entries exist in Exploit-DB's local database, spanning credential disclosure, authentication bypass, and cross-site scripting flaws across various versions, but confirmed directly: **none of them is CVE-2023-27997**. Both a direct CVE-string search and the dedicated `--cve` flag return zero results across Exploits, Shellcodes, and Papers. This is a genuine absence, not a search error, unlike some older FortiOS vulnerabilities (for example CVE-2018-13379, which does have dedicated entries EDB-47287 and EDB-47288, both visible in the results above). However, Bishop Fox's own published research confirms directly that their team built a fully working, weaponized internal exploit following the technical path Lexfo's original disclosure laid out, demonstrating remote code execution, a reverse shell, and payload delivery on a live FortiGate 7.2.4 instance. That level of public technical detail is sufficient for a competent attacker to reproduce the exploit independently, which is a materially different, and more dangerous, situation than "no exploit exists" would suggest on its own.

**Is this CVE in the CISA KEV catalog?** Yes, confirmed directly. CISA added this CVE to the Known Exploited Vulnerabilities catalog with a mandated federal patch deadline of July 4, 2023, and it remains listed today.

**What is your Exploitability Score (1-5)?**

Using the same 1-to-5 scale this program established in 1x02, Task 4 (1 = no known exploit, purely theoretical; 2 = a proof-of-concept exists but requires significant modification or expertise to weaponize; 3 = a public exploit exists requiring moderate adaptation; 4 = a weaponized, readily usable exploit is publicly available; 5 = confirmed active exploitation in the wild, including by criminal or ransomware operators):

**Exploitability Score: 5/5.** This is not scored a 4 despite the confirmed absence of a dedicated Exploit-DB entry (verified directly with `searchsploit`, not merely assumed), because the evidence for active exploitation is stronger than a public PoC would be on its own: Fortinet's own advisory confirms exploitation in the wild beginning at disclosure in June 2023; independent research (Field Effect, 2025) documents a newly discovered persistence technique attackers are still using against this exact CVE via symlink manipulation, meaning exploitation has continued for years past initial disclosure, not merely at launch; and this advisory itself names this CVE as Crimson Tide's confirmed, currently active initial access method against 5 real hospitals in the past 10 days. A vulnerability actively weaponized by a named, currently operating ransomware campaign is the maximum practical exploitability a scoring scale of this kind is meant to capture, regardless of whether a convenient point-and-click script also happens to exist in a public database.

---

## Part 3: MedDefense CVSS Contextualization

**Environmental metrics applied:** Confidentiality Requirement (CR), Integrity Requirement (IR), and Availability Requirement (AR) all set to **High**, reflecting the specific facts given directly: the FortiGate is MedDefense's only perimeter defense with no redundancy, it terminates every VPN tunnel across all 3 sites, and it sits on the path of Kill Chains 1, 2, and 3 from this program's own 1x01 threat modeling.

**Calculation, performed directly with the published CVSS 3.1 formula rather than estimated:**

```
Base vector:        AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  ->  9.8
Environmental (CR:H/IR:H/AR:H, same AV/AC/PR/UI/S/C/I/A)  ->  9.8
```

**The adjusted score is identical to the base score: 9.8. Neither higher nor lower, and the precise mathematical reason is worth stating rather than glossed over.** CVSS 3.1's Environmental formula caps the Modified Impact Sub-Score (MISS) at 0.915 regardless of how the Confidentiality, Integrity, and Availability Requirement multipliers are set. Recalculating directly: with the default Medium requirements, the raw MISS value is already 0.9148, sitting almost exactly at that ceiling. Setting all three requirements to High pushes the raw calculation to 0.9959, but the formula's own cap holds the usable value at 0.9150, an increase too small to move the final rounded score at all. In plain terms: this vulnerability's own base impact ratings (Confidentiality, Integrity, and Availability all already rated High) had already consumed nearly the entire numerical range CVSS's environmental adjustment has room to use.

**This does not mean MedDefense's specific context does not matter; it means CVSS is the wrong tool to express how much it matters here.** The environmental facts given, sole perimeter defense with no redundancy, all 3 sites' VPN tunnels depending on one device, and this device sitting on 3 separately mapped kill chains, are precisely the kind of organizational severity this program's own risk quantification work (1x03, ALE/SLE/ARO) is built to capture, not CVSS's environmental score, which was already saturated by the base vulnerability alone. The single fact that changes this analysis's real urgency is not a recalculated CVSS number at all: it is that **the support contract required to obtain the patch has expired**, meaning the fix for a 9.8 vulnerability, actively exploited by name in this exact advisory, cannot be applied today without a $2,400 contract renewal completing first, a business process delay standing between MedDefense and closing the single most critical, actively-weaponized entry point in its entire environment.
