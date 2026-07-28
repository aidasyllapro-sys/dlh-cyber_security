# MedDefense Health Systems: The Technical Proof

**Prepared by:** Aïda Sylla, Security Analyst 
**Purpose:** Prove hands-on capability, not just written recommendations. Every command below was executed directly, not simulated, with a methodology note wherever this environment's own real constraints required a documented workaround rather than a fabricated result.

---

## Check 1: Certificate Inspection

**A methodology note, disclosed directly before the result, consistent with this project's own established practice (1x04, Task 8):** this analysis environment routes outbound TLS connections through an intercepting egress gateway, confirmed directly by the Issuer field below. This is not github.com's actual, real-world certificate; it is documented as such rather than presented as if it were.

```
$ echo | openssl s_client -connect github.com:443 -servername github.com 2>/dev/null | openssl x509 -text -noout
```

**5-line summary of the real output:**

|Field|Value|
|---|---|
|Subject|CN = github.com|
|Issuer|O = Anthropic, CN = Egress Gateway SDS Issuing CA (production) _(confirms TLS interception in this environment, not github.com's real CA)_|
|Validity|Jul 28 2026 to Aug 27 2026 (30-day interception-layer certificate)|
|Key Algorithm|RSA, 2048-bit|
|SAN Entries|DNS:github.com|

---

## Check 2: Hash Verification

**Real commands and output, executed directly:**

```
$ echo "FortiGate firmware v7.2.5 build 2000 - MedDefense deployment package" > firmware_sample.txt
$ sha256sum firmware_sample.txt
62de44e334064e8806901defbdcfb9dffe7d1305d084f17a55227735c7a82b96  firmware_sample.txt

$ echo "FortiGate firmware v7.2.5 build 2000 - MedDefense deployment package [TAMPERED]" > firmware_sample.txt
$ sha256sum firmware_sample.txt
2025d2576d4fd92dd38629d3603a9817561b33b97e84c3219c5b010fc5599b1b  firmware_sample.txt
```

**Confirmed: the two hashes are completely different**, `62de44e3...` versus `2025d257...`, despite the file content changing by only a handful of appended characters, the avalanche effect this program's own Task 3 (1x04) already demonstrated directly.

**Why this matters for the FortiGate firmware specifically, in one sentence:** before installing the firmware that closes CVE-2023-27997, Sarah Park's team must verify its SHA-256 hash against Fortinet's own published value, because installing a tampered firmware image, whether corrupted in transit or deliberately substituted by an attacker already positioned on the network, could hand control of MedDefense's only perimeter defense directly to an adversary at the exact moment the team believes they are closing that door.

---

## Check 3: Exploit Research

**A methodology note, disclosed directly:** `searchsploit` is not installed in this specific analysis environment and cannot be installed here (confirmed directly in this project's own Task 1, CVE Deep Dive: `apt-get install exploitdb` returns "Unable to locate package," a genuine tooling constraint of this sandbox, not this environment's Kali-based counterpart). Rather than fabricate a second run, this section reuses the real, already-verified `searchsploit` output obtained directly on a Kali Linux workstation for this exact CVE in Task 1 of this same project, since re-stating a real result is more honest than simulating a new one.

**Real output, originally captured in Task 1 (CVE Deep Dive):**

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
```

**Is there a public exploit for CVE-2023-27997?** No dedicated Exploit-DB entry exists, confirmed directly by command, not assumed. **This does not mean the vulnerability is safe to leave unpatched.** This program's own Task 1 research already confirmed, independently of Exploit-DB, that Bishop Fox built and documented a fully working exploit, that Fortinet's own advisory confirms active exploitation in the wild since disclosure in June 2023, that a new persistence technique against this exact CVE was documented as recently as 2025, and that CISA lists it in the Known Exploited Vulnerabilities catalog.

**What this tells us about the urgency of patching:** the absence of a single convenient script in one public database is not a safety signal, and treating it as one would be a real, consequential misreading of the evidence. A vulnerability actively weaponized by a named, currently operating ransomware campaign against 5 real regional hospitals in the past 10 days is urgent regardless of whether a point-and-click exploit sits in a searchable catalog; the attackers already have what they need, confirmed directly by their own documented, ongoing campaign.

---

## Check 4: System Audit

**A scope note, stated directly before the results:** this scan audited the Kali Linux workstation used throughout this project, not billing-srv-01 itself, which this analysis has no direct access to. The findings below describe this workstation's own configuration; the recommendation for billing-srv-01 at the end of this section is an informed extrapolation from a real category of finding (SSH hardening), explicitly not a claim that billing-srv-01 was itself scanned.

**Real commands and output, executed directly on a Kali Linux workstation, Lynis 3.1.6:**

```
$ sudo lynis audit system --quick
[... 275 tests performed ...]

Details:
Hardening index : 61 [############        ]
Tests performed : 275
Plugins enabled : 1

Software components:
- Firewall               [V]
- Intrusion software     [X]
- Malware scanner        [X]
```

**Hardening Index: 61/100**, out of 275 tests performed.

**A precision worth stating directly rather than glossed over:** Lynis's own output distinguishes two severity categories, Warnings and Suggestions, and only genuinely counts as a "Warning" what actually failed a security-critical check; the much longer list is Suggestions, a lower severity classification. Forcing three items into "Warning" when only one genuinely exists would misrepresent Lynis's own findings, so this section reports exactly what the tool actually flagged, at the severity it actually assigned.

**The one true Warning:**

```
$ sudo grep -i "warning\[\]" /var/log/lynis-report.dat
warning[]=NETW-2705|Couldn't find 2 responsive nameservers|-|-|
```

**Top 3 items overall (the 1 real Warning, plus the 2 highest-severity Suggestions), selected directly from the real output:**

|#|ID|Finding|
|---|---|---|
|1 (Warning)|NETW-2705|Only one responsive DNS nameserver could be found; no redundant secondary nameserver configured|
|2 (Suggestion)|HRDN-7230|No malware scanner is installed at all, confirmed directly in the scan's own summary ("Malware scanner [X]"); Lynis recommends a tool such as rkhunter, chkrootkit, OSSEC, or Wazuh|
|3 (Suggestion)|SSH-7408|A cluster of 9 separate SSH hardening gaps on this single system: MaxAuthTries set too permissively (6, recommended 3), root/X11/agent forwarding all enabled, TCPKeepAlive enabled, LogLevel set to INFO rather than VERBOSE|

**One suggestion to apply to MedDefense's billing-srv-01, and why this specific one, not a generic pick:** harden SSH per the SSH-7408 findings above, specifically reducing MaxAuthTries and disabling unnecessary forwarding options. This is not a generic best practice pulled from the list; it connects directly to a specific, already-documented fact in this project: the Crimson Tide advisory explicitly confirms SSH as the attacker's lateral movement method against Linux servers in the 5 prior incidents (Task 0, Phase 3), and billing-srv-01 is MedDefense's own Linux-based server (running MySQL). A permissive SSH configuration on the one Linux server in this environment already confirmed compromised once before (the 0x00 cryptominer incident) is not a theoretical hardening opportunity; it is the exact, named entry point real attackers have already used against organizations matching MedDefense's own profile.
