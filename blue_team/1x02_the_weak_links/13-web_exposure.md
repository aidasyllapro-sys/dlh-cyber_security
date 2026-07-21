# MedDefense Health Systems: The Web Exposure

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** `meddefense-vulnerability-scan.txt`, cross-referenced against Project 1x01 (Attack Surface Analysis T7, Kill Chains T10, Scenarios T14) and this project's own Task 9 (OSINT Hunt) and Task 11 (False Positives) **Purpose:** Analyze every web-related finding in the scan report grouped by host, with explicit attention to the fact that identical findings carry different real risk depending on whether the host is internet-facing, internal-only, or internal-but-flat-network-reachable.

**Full inventory of web-related findings identified across the scan**, before grouping by the three primary hosts this task focuses on: Finding 001 (Apache mod_lua RCE, billing-srv-01, port 80), Finding 005 (weak TLS, web-srv-01), Finding 012 (missing security headers, web-srv-01), Finding 013 (expiring certificate, web-srv-01), Finding 014 (consumer router admin page, Westside, a web-based management interface, though not an application vulnerability in the usual sense), Finding 015 (DSM web interface, NAS-01), Finding 016 (Philips monitor web interfaces, medical devices), Finding 017 (Tomcat information disclosure, ehr-srv-01), Finding 021 (HTTP TRACE, web-srv-01), Finding 030 (TLS certificate mismatch, ehr-srv-01 already established as a false positive in Task 11 of this project), and Finding 031 (Ghostcat, ehr-srv-01). The deep per-host analysis below focuses on the three hosts this task specifically frames as requiring distinct exposure-based analysis; Findings 001, 014, and 016 are flagged here as additional web-related findings worth noting but fall outside this task's three-host structure.

---

## Host: web-srv-01 (10.10.2.50): Patient Portal

yaml

```yaml
Host: web-srv-01 (10.10.2.50)
Exposure: Internet-facing. This is MedDefense's public patient portal —
  the one host in this scan explicitly designed for external, public
  access, unlike the other two hosts analyzed here.
Findings:
  - Finding 005: TLS 1.0 supported alongside TLS 1.2 (BEAST, POODLE),
    CVSS 7.5
  - Finding 012: Missing security headers (X-Content-Type-Options,
    X-Frame-Options, Content-Security-Policy, Strict-Transport-Security,
    X-XSS-Protection)
  - Finding 013: SSL certificate expiring in 23 days, no auto-renewal
    configured
  - Finding 021: HTTP TRACE method enabled (already established as a
    false positive on its own in Task 11 of this project, given no
    confirmed XSS vulnerability exists to combine with it — but it
    remains a real, if low-priority, hardening gap)
Combined Risk: No single finding here reaches Critical severity, but the
  combination describes a portal that is soft on nearly every layer of
  web-specific defense simultaneously: weak, interceptable transport
  encryption (F005); no defense-in-depth headers to blunt a future XSS
  or clickjacking attempt (F012); an imminent, unmanaged availability/
  trust failure as the certificate approaches expiry (F013); and a
  secondary attack technique (F021) that, while not independently
  exploitable today, would immediately become relevant the moment any
  XSS vulnerability is ever found on this application. This is the
  clearest example among the three hosts of aggregate risk exceeding
  the sum of individually Medium/High findings.
Attack Scenario: This host does not appear as the primary vector in any
  of the 5 kill chains built in Project 1x01 (Task 10) — stated plainly
  as a genuine coverage gap in that prior work, not stretched to fit. A
  plausible scenario nonetheless follows directly from the findings
  above: a patient connecting from an untrusted network (public Wi-Fi)
  negotiates the still-supported TLS 1.0 downgrade, allowing traffic
  interception; separately, the absence of a Content-Security-Policy
  header increases the odds that any future injection vulnerability on
  this application succeeds, and if it does, the still-enabled TRACE
  method becomes the mechanism for reading back HttpOnly-protected
  session cookies via that injection. This is a portal that is not one
  step from compromise today, but is missing nearly every layer that
  would contain a future one.
Priority: 3rd of the 3 hosts analyzed here. Real risk on the one
  genuinely internet-facing system in this scan should never be ignored,
  but the absence of any confirmed Critical CVE places this behind the
  other two hosts, both of which carry confirmed CVSS 9.8 vulnerabilities
  with active exploit tooling.
```

---

## Host: NAS-01 (10.10.2.41): Backup NAS Management Interface

yaml

```yaml
Host: NAS-01 (10.10.2.41)
Exposure: Internal-only by design, but reachable from the entire
  internal network due to the confirmed absence of segmentation — the
  task's own framing describes this correctly as "internal," and that
  remains true, but internal-only is not the same as low-exposure on a
  flat topology.
Findings:
  - Finding 015: Synology DSM web management interface (ports
    5000/5001) reachable from the entire internal network; backup data
    stored unencrypted
  - CVE-2024-10441 (not in the original scan report — discovered via
    OSINT research in Task 9 of this project): a CVSS 9.8 unauthenticated
    remote code execution vulnerability in DSM's system plugin daemon,
    confirmed affecting the DSM 7.x version range already running on
    this host
Combined Risk: Critical when the two are combined, and this combination
  is the central finding of this host's analysis. Finding 015 alone,
  taken in isolation, describes a misconfiguration — broad network
  reachability of a management page. Layered with CVE-2024-10441, that
  same broad reachability becomes the delivery path for unauthenticated
  remote code execution on MedDefense's sole backup infrastructure. The
  scan report alone would never reveal this combination — it required
  the manual OSINT step documented in Task 9 to surface the CVE that
  transforms Finding 015 from a configuration cleanup item into a
  Critical finding.
Attack Scenario: Explicit and direct. Kill Chain #1 (1x01, Task 10) and
  Scenario 1 (Task 14, "Operation Flatline") both already model this
  exact interface being used to neutralize MedDefense's backups before
  ransomware deployment, following BlackReef's own documented affiliate
  playbook instruction to "identify and neutralize backups before
  deploying payload." CVE-2024-10441 makes that step materially worse
  than either prior document assumed: rather than merely using DSM's own
  legitimate administrative functions to delete backup jobs, an attacker
  with this CVE gains full code execution on the NAS itself, opening the
  possibility of exfiltrating backup contents before destroying them, or
  planting persistence that survives a restore from an earlier,
  uncompromised backup.
Priority: 1st or 2nd of the 3 hosts, and the strongest case for the
  single highest-leverage host in this analysis. ehr-srv-01 (below) edges
  ahead by strict asset-criticality ranking, but NAS-01 carries a unique
  amplifying risk this task should not understate: this is the recovery
  mechanism for every other incident in this entire assessment, meaning
  its compromise doesn't just add one more critical finding — it removes
  MedDefense's ability to recover from any of the others.
```

---

## Host: ehr-srv-01 (10.10.2.10): EHR Application Server

yaml

```yaml
Host: ehr-srv-01 (10.10.2.10)
Exposure: Internal but flat-network accessible — not internet-facing at
  all, but reachable from any compromised host anywhere on the confirmed
  10.10.0.0/16 flat network, exactly as the task's framing describes.
Findings:
  - Finding 017: Apache Tomcat default error pages disclosing version
    (9.0.31) and internal path information, Medium severity
  - Finding 030: TLS certificate Common Name mismatch — already
    established as a false positive in Task 11 of this project (the
    scan report's own text confirms this is "an operational issue, not
    a security vulnerability")
  - Finding 031: Ghostcat (CVE-2020-1938), CVSS 9.8, unauthenticated
    arbitrary file read via the AJP connector, capable of exposing
    ehr-db-01's database credentials
Combined Risk: Critical, and the clearest possible illustration in this
  entire assessment of a Medium finding directly producing a Critical
  one. Finding 017 alone looks like routine information disclosure — a
  version number and some file paths, unpleasant but not independently
  dangerous. It is the direct reason Finding 031 exists in this report
  at all: SecurePoint's own manual follow-up on Finding 017's
  unconfirmed AJP note is what surfaced Ghostcat. Finding 030 is
  correctly set aside as a non-issue (Task 11), leaving 017 and 031 as
  the operative pair on this host.
Attack Scenario: Explicit and central. Scenario 3 (1x01, Task 14, "The
  Trusted Vendor Path") uses exactly this mechanism — a compromised
  vendor's legitimate access reaching ehr-srv-01 and exploiting the AJP
  connector to extract database credentials for ehr-db-01 directly,
  bypassing the EHR application's own access controls entirely. The
  chain begins with exactly what Finding 017 provides: enough version
  and configuration information to know this specific attack is worth
  attempting at all.
Priority: 1st of the 3 hosts. This is the application-tier half of the
  organization's #1-ranked Critical Asset (the EHR System, per the 0x00
  Criticality Assessment), carries a confirmed CVSS 9.8 vulnerability
  independently confirmed weaponized with a dedicated Metasploit module
  (Task 4/5 of this project) and listed in CISA's KEV catalog with one
  of the shortest remediation windows recorded anywhere in this
  assessment (14 days).
```

---

## Why Investigating "Medium" Version-Disclosure Findings Matters

Finding 017 leading directly to the discovery of Finding 031 is not a coincidence worth noting in passing. It is the single clearest, most concrete demonstration in this entire project of a principle this assessment has argued repeatedly on more abstract grounds: **a severity label reflects a scanner's automated assessment of what it directly confirmed, not the full risk of what that finding might lead to if a human investigates further.** A version number or an exposed internal file path is, by itself, genuinely low-impact. Nobody is harmed merely by learning that a server runs Tomcat 9.0.31. But that same version number is also exactly what an attacker's own reconnaissance step is designed to produce, and Finding 031 proves this scan report handed defenders the identical piece of information an attacker would have used, at the identical moment, with the identical next step available: check what CVE-2020-1938 (Ghostcat) requires, and whether this specific version and configuration are vulnerable to it. **SecurePoint chose to take that next step manually rather than closing Finding 017 as a routine, low-priority informational item — and that single decision is the entire reason a CVSS 9.8, CISA KEV-listed, actively-weaponized vulnerability appears anywhere in this report at all.** Had that Medium finding been triaged the way most vulnerability management workflows are tempted to triage "just an information disclosure" items, batched, deprioritized, or closed without a manual follow-up, Finding 031 would not exist in this document, not because the vulnerability wouldn't be there, but because nobody would have gone looking for it. The practical lesson for MedDefense's future vulnerability management practice: any finding that discloses a specific software version or confirms a specific component's presence deserves a brief, deliberate manual check against that version's own known-vulnerability history before it is closed. Not because every such finding hides a Ghostcat, but because this project's own evidence proves at least one of them can, and the cost of checking is trivial next to the cost of missing it.
