# MedDefense Health Systems: The CVSS Deconstruction

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** `meddefense-vulnerability-scan.txt`, NIST/FIRST.org CVSS v3.1 Calculator and Specification Document **Methodology note:** All scores below were computed using a direct implementation of the official CVSS v3.1 base score formula (FIRST.org Specification Document, Section 7), then calibrated against 2 independently known, published scores before being trusted: CVE-2021-44790 (Finding 001) reproduces exactly to **9.8**, and CVE-2021-34527/PrintNightmare (Finding 008) reproduces exactly to **8.8**, both match their published NVD/CNA scores precisely (verified in Task 1 of this project). Every new score calculated in this document uses that same, calibrated formula rather than an estimate.

---

## Exercise 1: Deconstruction

**Vector under analysis (Finding 001, CVE-2021-44790):** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → Base Score **9.8 (CRITICAL)**

```
Metric: AV — Attack Vector
Selected Value: N (Network)
What it stands for: How the attacker must be physically or logically
  positioned to exploit the flaw — the context from which the attack
  can be launched.
What N means here: The vulnerable component (Apache's mod_lua
  multipart parser) is reachable over the network stack, meaning an
  attacker anywhere that can route traffic to port 80 on billing-srv-01
  can attempt exploitation — no local presence, no adjacent network
  segment, no physical access required.
Other possible values and their effect: Adjacent (A, weight 0.62) would
  require the attacker to be on the same physical/logical network
  segment (e.g., the same LAN or Wi-Fi); Local (L, weight 0.55) would
  require the attacker to already have some form of local access to the
  host; Physical (P, weight 0.20) would require physically touching the
  device. Each step down from Network reduces the Exploitability
  sub-score and therefore the final Base Score, since each represents a
  meaningfully harder-to-reach attacker position.
Why Network was selected here: Apache HTTP Server listens on a network
  port by design and accepts requests from any client that can reach
  it — there is nothing about this specific flaw (a malformed multipart
  request body) that requires the attacker to be anywhere other than
  "somewhere that can send an HTTP request to this server."
```

```
Metric: AC — Attack Complexity
Selected Value: L (Low)
What it stands for: Whether conditions beyond the attacker's control
  (timing, specific configuration, prior reconnaissance) must exist for
  the attack to succeed.
What L means here: The attacker can succeed reliably, on demand,
  simply by sending a crafted request — no race condition, no
  dependency on a specific runtime state, no need to defeat another
  security mechanism first.
Other possible values and their effect: High (H, weight 0.44 vs. Low's
  0.77) would apply if exploitation depended on a condition the
  attacker cannot control at will — for example, winning a timing race
  or needing information not readily available. Moving from Low to High
  meaningfully lowers the Exploitability sub-score, since it makes
  successful exploitation less than guaranteed on any given attempt.
Why Low was selected here: The NVD description states a "carefully
  crafted request body" causes the overflow — this describes a
  deterministic, repeatable trigger, not a probabilistic or
  condition-dependent one.
```

```
Metric: PR — Privileges Required
Selected Value: N (None)
What it stands for: What level of access, if any, the attacker must
  already possess on the target system before attempting the attack.
What N means here: The attacker needs no account, no prior
  authentication, and no existing foothold on billing-srv-01 — the
  vulnerable request path is reachable pre-authentication.
Other possible values and their effect: Low (L, weight 0.62 under
  Scope Unchanged) would mean basic/limited user privileges are needed
  first; High (H, weight 0.27) would mean significant, administrative-
  level access is already required. Both would substantially reduce
  the Exploitability sub-score, since requiring any credential at all
  is a real barrier an unauthenticated attacker must first overcome by
  some other means.
Why None was selected here: mod_lua's multipart body parser processes
  the request before any application-level authentication check occurs
  — the overflow happens in request parsing itself, a stage that by
  definition precedes any credential check.
```

```
Metric: UI — User Interaction
Selected Value: N (None)
What it stands for: Whether a human other than the attacker (a
  legitimate user, an administrator) must take some action for the
  attack to succeed.
What N means here: The attacker's crafted HTTP request alone is
  sufficient — no victim needs to click a link, open a file, or
  otherwise participate.
Other possible values and their effect: Required (R, weight 0.62 vs.
  None's 0.85) would apply if, for example, an administrator had to
  browse to a malicious page or approve an action. This would lower the
  Exploitability sub-score, since it introduces dependency on someone
  else's behavior, which the attacker cannot fully control or predict.
Why None was selected here: this is a server-side parsing
  vulnerability triggered directly by the attacker's own request to the
  server — there is no second party in the exploitation path at all.
```

```
Metric: S — Scope
Selected Value: U (Unchanged)
What it stands for: Whether a successful exploit affects resources
  beyond the vulnerable component's own security authority (for
  example, escaping a container or hypervisor into a different
  security context).
What U means here: The impact of this vulnerability is confined to
  the Apache HTTP Server process and what it can itself access on
  billing-srv-01 — it does not, by itself, describe crossing into a
  separate, differently-governed security boundary.
Other possible values and their effect: Changed (C) would apply if
  exploitation let the attacker impact a component governed by a
  different security authority (e.g., breaking out of a web server
  process into the host OS in a way that crosses a defined trust
  boundary, or a browser plugin affecting the browser itself). Scope
  Changed uses an entirely different, more generous formula (Impact ×
  1.08 with a different sub-formula) that generally produces a higher
  score for the same Impact values — so Scope is one of the few metrics
  that changes the *shape* of the calculation, not just a weighted input.
Why Unchanged was selected here: the described impact (buffer overflow
  potentially enabling code execution) is scoped to what the Apache
  process itself can do — nothing in the finding describes it crossing
  into a separately-governed component.
```

```
Metric: C — Confidentiality Impact
Selected Value: H (High)
What it stands for: The degree to which the attacker gains
  unauthorized access to information as a result of the exploit.
What H means here: A successful exploit (remote code execution as the
  Apache process) would grant the attacker essentially unrestricted
  read access to whatever that process — and by extension the billing
  application it hosts — can see, including the financial and PHI-
  adjacent billing data this server processes.
Other possible values and their effect: Low (L, weight 0.22) would
  apply if only some restricted information were exposed; None (N,
  weight 0.0) if no confidentiality impact existed at all. Both would
  substantially lower the Impact sub-score.
Why High was selected here: code execution is the maximum practical
  confidentiality impact — there is no meaningful restriction on what
  an attacker with code execution as the web server process can read.
```

```
Metric: I — Integrity Impact
Selected Value: H (High)
What it stands for: The degree to which the attacker can modify data
  or system behavior without authorization.
What H means here: Code execution equally permits total, unrestricted
  modification — of billing records, of the application itself, or of
  the server's configuration.
Other possible values and their effect: Low or None would apply if
  modification were impossible or narrowly restricted, each lowering
  the Impact sub-score.
Why High was selected here: same reasoning as Confidentiality — remote
  code execution is the maximum practical integrity impact available
  under this scoring system.
```

```
Metric: A — Availability Impact
Selected Value: H (High)
What it stands for: The degree to which the attacker can degrade or
  deny legitimate access to the system or its data.
What H means here: An attacker with code execution can trivially crash
  the process, consume all system resources, or shut the server down
  entirely — total loss of availability is achievable.
Other possible values and their effect: Low or None would apply if
  availability could not be meaningfully affected, lowering the Impact
  sub-score.
Why High was selected here: this is the same logic once more — full
  code execution subsumes the ability to deny service, so the maximum
  value is appropriate.
```

### What if Attack Vector changed from Network to Local?

**New vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

Computed using the calibrated CVSS v3.1 formula:

||Original (AV:N)|Changed (AV:L)|
|---|---|---|
|Exploitability sub-score|3.887|2.5151|
|Impact sub-score|5.8731|5.8731 (unchanged)|
|**Base Score**|**9.8 (CRITICAL)**|**8.4 (HIGH)**|

**Why the score changes, step by step:**

1. **What AV:L actually requires of the attacker.** Attack Vector: Local means the attacker can no longer reach the vulnerability simply by routing an HTTP request to billing-srv-01 over the network. Instead, they must already have some form of local access to the host itself (a valid local account, a local shell, physical console access, or an already-established foothold gained through some other means entirely). This is a fundamentally different attacker position than Network access.
2. **Why that directly reduces the attacker's reach.** Under AV:N, the pool of potential attackers is effectively unbounded: anyone on the internet (or the internal network) who can send a crafted HTTP request can attempt exploitation, with zero prerequisites. Under AV:L, that pool collapses to only those who have _already_ solved a separate, harder problem (obtaining local presence on billing-srv-01 in the first place). The vulnerability itself has not changed, but the realistic population of attackers who could actually use it has shrunk enormously, because reaching the vulnerable code now requires a precondition the attacker cannot satisfy remotely.
3. **How this reduced reach is reflected numerically in the Exploitability sub-score.** CVSS encodes exactly this reduced reach through the Attack Vector weight: Network carries a weight of 0.85, while Local carries a weight of only 0.55 (a deliberate, quantified penalty for requiring local presence instead of remote network reach). Since Exploitability = 8.22 × AV × AC × PR × UI, and only the AV term changes here (0.85 → 0.55), the Exploitability sub-score itself falls from 3.887 to 2.5151 (a drop of roughly 35%, directly proportional to how much harder the attacker's starting position became).
4. **Why the Impact side does not move.** The Impact sub-score stays fixed at 5.8731, because Impact measures _what happens once the exploit succeeds_ (still full compromise of Confidentiality, Integrity, and Availability), not _how hard it is to get there_. Attack Vector only ever affects Exploitability, never Impact. This is precisely why a metric like this can meaningfully lower a score without implying the underlying vulnerability is somehow "less severe" once triggered.
5. **The net result.** Base Score = Impact + Exploitability = 5.8731 + 2.5151 = 8.3883, rounded up to **8.4**. This also crosses a real qualitative boundary, from **Critical (9.0–10.0) down to High (7.0–8.9)**: a concrete illustration that reducing an attacker's reach (Network → Local) has a measurable, quantified effect on urgency, even though the consequence of a successful exploit is identical either way.

---

## Exercise 2: Construction

**Given characteristics, mapped to CVSS v3.1 metrics:**

| Characteristic                                            | Metric | Value             | Reasoning                                                                                                                                                                          |
| --------------------------------------------------------- | ------ | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Exploitable only from the local network, not the internet | AV     | **A** (Adjacent)  | CVSS distinguishes "Adjacent" (same physical/logical network segment) from "Local" (local access to the host itself), a local-network-only constraint maps to Adjacent, not Local. |
| Complex, specific conditions required                     | AC     | **H** (High)      | Directly matches the CVSS definition of Attack Complexity: High applies when success depends on conditions outside the attacker's control.                                         |
| Attacker needs low-level privileges                       | PR     | **L** (Low)       | Matches CVSS's own "Low" tier exactly, some privileges required, but not administrative.                                                                                           |
| No user interaction needed                                | UI     | **N** (None)      | Direct mapping.                                                                                                                                                                    |
| Scope unchanged                                           | S      | **U** (Unchanged) | Given directly.                                                                                                                                                                    |
| Confidentiality completely compromised                    | C      | **H** (High)      | "Completely compromised" is the definition of High.                                                                                                                                |
| No integrity impact                                       | I      | **N** (None)      | Direct mapping.                                                                                                                                                                    |
| No availability impact                                    | A      | **N** (None)      | Direct mapping.                                                                                                                                                                    |

**Constructed vector string:** `CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N`

**Calculated (and NIST-Calculator-verifiable) result:**

|Sub-score|Value|
|---|---|
|Exploitability|1.1818|
|Impact|3.5952|
|**Base Score**|**4.8**|
|**Severity Rating**|**MEDIUM** (4.0–6.9 band)|

This result is intuitive on inspection: every exploitability-side metric here (Adjacent access, High complexity, Low privileges required) works against the attacker compared to the Exercise 1 vulnerability, and on the impact side, 2 of the 3 impact categories are None. A single-pillar (Confidentiality-only) impact caps the Impact sub-score well below what a full C/I/A-High vulnerability like CVE-2021-44790 would produce. The combination lands squarely in Medium territory, not High or Critical, despite the "complete" compromise of confidentiality. A useful reminder that "complete" impact on _one_ pillar does not by itself guarantee a high overall score if the exploitability conditions are restrictive.

---

## Exercise 3: Comparison

**Finding above 9.0:** Finding 001 (CVE-2021-44790, billing-srv-01) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8 (CRITICAL)**

**Finding between 5.0 and 7.0:** No finding in the scan report carries a vendor/NVD-assigned CVSS score that actually falls in the 5.0–7.0 band. Every scored finding in the report is either above 7.0 (Findings 002, 004's three CVEs, 005, 008, 010, 020) or unscored (misconfiguration findings marked "CVSS Base: N/A"). Rather than force an imprecise comparison, a representative CVSS v3.1 vector was constructed here for **Finding 007** (LDAP signing not required on ad-dc-01, enabling LDAP relay attacks capable of modifying directory objects), a genuine finding in the report that the scanner itself did not assign a numeric CVSS to, using the same construction method demonstrated in Exercise 2:

- **AV:N** - LDAP is a network-listening service, reachable to anything that can route to it.
- **AC:H** - a relay attack requires positioning to intercept/relay authentication traffic, a specific condition beyond simply sending a request.
- **PR:N** - no prior credential is needed to attempt a relay.
- **UI:N** - no victim action is required once the attacker is positioned.
- **S:U** - impact is confined to the directory service's own objects.
- **C:L** - some information exposure is plausible via a relay but is not the primary described impact.
- **I:H** - the finding explicitly states this enables _modifying directory objects_, a serious, direct integrity impact.
- **A:N** - no availability impact is described.

**Constructed vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N` → **6.5 (MEDIUM)**, comfortably inside the requested 5.0–7.0 band.

### Side-by-side comparison

| Metric | Finding 001 (9.8) | Finding 007, constructed (6.5) | Same or Different?                            |
| ------ | ----------------- | ------------------------------ | --------------------------------------------- |
| AV     | N (0.85)          | N (0.85)                       | Same                                          |
| AC     | **L (0.77)**      | **H (0.44)**                   | **Different - largest exploitability driver** |
| PR     | N (0.85)          | N (0.85)                       | Same                                          |
| UI     | N (0.85)          | N (0.85)                       | Same                                          |
| S      | U                 | U                              | Same                                          |
| C      | **H (0.56)**      | **L (0.22)**                   | **Different - impact driver**                 |
| I      | H (0.56)          | H (0.56)                       | Same                                          |
| A      | **H (0.56)**      | **N (0.0)**                    | **Different - largest impact driver**         |

**Which components explain the difference, and which matter most:** 3 metrics differ, and all 3 push in the same direction (lower score for Finding 007): **Attack Complexity** dropping from Low to High cuts the Exploitability sub-score's multiplier nearly in half (0.77 → 0.44, nearly a 43% reduction on that factor alone). This is the single biggest driver of the exploitability-side gap between the 2 On the impact side, **Availability dropping from High to None** is the largest single contributor to the reduced Impact sub-score, since it removes an entire pillar of impact outright rather than merely reducing it; **Confidentiality dropping from High to Low** compounds this further. Integrity stays High in both cases and contributes nothing to the difference. **The general lesson:** losing an entire impact pillar (High → None) is a more powerful score reducer than partially reducing one (High → Low), and Attack Complexity is one of the highest-leverage single metrics in the entire exploitability calculation; a fact worth remembering when triaging findings, since 2 vulnerabilities that both "sound bad" in a plain-English description can land in genuinely different urgency tiers once complexity and full-pillar impact are accounted for precisely.

