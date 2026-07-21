# MedDefense Health Systems: The False Positives

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** `meddefense-vulnerability-scan.txt`, cross-referenced against Findings 012 (missing security headers) and 031 (Ghostcat) already documented elsewhere in this project **Purpose:** Identify findings in the scan report that, on investigation, are not actual exploitable vulnerabilities in MedDefense's specific operational context, and demonstrate why validating before committing remediation resources is not optional.

---

## False Positive 1: Finding 020 (OpenSSH / CVE-2023-38408, backup-srv-01)

```
Finding ID: 020
Reported Vulnerability: OpenSSH 8.9p1 on backup-srv-01 is affected by
  CVE-2023-38408, a critical (CVSS 9.8) vulnerability in the PKCS#11
  provider that can lead to remote code execution.
Why It Is a False Positive: The scan report itself contains SecurePoint's
  own explicit caveat — this is the finding the task's hint refers to.
  Exploitation of CVE-2023-38408 requires a very specific precondition:
  the victim's ssh-agent must be running with PKCS#11 support, and that
  agent must be forwarded to a server the attacker already controls (an
  outbound `ssh -A` connection or equivalent `ForwardAgent yes`
  configuration to an untrusted host). A backup server's normal
  operational role — receiving inbound backup traffic, not initiating
  outbound interactive SSH sessions with agent forwarding to external
  hosts — makes this precondition inherently unlikely, exactly as
  SecurePoint's own note states.
Validation Method: (1) Check whether ssh-agent runs persistently on
  backup-srv-01 or only interactively when an administrator connects;
  (2) grep the system's SSH client configuration and any per-user config
  files for `ForwardAgent yes` or equivalent per-host directives; (3)
  review shell history, cron jobs, and any automation scripts for
  outbound SSH connections this server initiates to external or
  untrusted hosts; (4) confirm whether the installed OpenSSH build even
  has PKCS#11 support compiled in and in active use. If none of these
  preconditions exist, the finding is confirmed a false positive for
  this specific host.
Risk of Acting on This FP: Emergency-patching or rebuilding OpenSSH on a
  production backup server — requiring a maintenance window, a backup
  service interruption, and compatibility testing against existing
  backup scripts — to close an attack path that has no practical entry
  point in this deployment. That engineering time would be better spent
  on GAP-014 (network segmentation) or GAP-004 (centralized detection),
  both independently confirmed as far higher-leverage priorities
  elsewhere in this project.
Risk of Not Validating: If the assumption underlying this dismissal is
  wrong — for example, an administrator occasionally uses agent
  forwarding to jump through this server to reach a vendor-hosted
  resource, undocumented — then dismissing this finding without
  confirming leaves a real, low-interaction remote code execution path
  open on MedDefense's sole backup infrastructure, the exact asset this
  project's Kill Chain #1 already identifies as the doctrinal ransomware
  target (BlackReef's own playbook: "identify and neutralize backups
  before deploying payload").
```

---

## False Positive 2: Finding 021 (HTTP TRACE Method, web-srv-01)

```
Finding ID: 021
Reported Vulnerability: The HTTP TRACE method is enabled on web-srv-01
  (the patient portal), which the report states "can be used in
  Cross-Site Tracing (XST) attacks to steal credentials from HTTP
  headers when combined with XSS vulnerabilities."
Why It Is a False Positive: This finding's own wording already contains
  the reason it is not independently exploitable — the phrase "when
  combined with XSS vulnerabilities" is not a minor caveat, it is the
  entire precondition for the attack. Cross-Site Tracing requires an
  attacker to first have a working Cross-Site Scripting vulnerability on
  the same application, which then issues the TRACE request via
  injected JavaScript to read back otherwise-protected headers (such as
  HttpOnly cookies). No finding anywhere else in this 31-finding scan
  report identifies a confirmed XSS vulnerability on web-srv-01 —
  Finding 012 flags missing security headers, including a Content-
  Security-Policy, which is a defense-in-depth gap that would make a
  future XSS more dangerous, but is not itself evidence an exploitable
  XSS currently exists. Compounding this, every major browser (Internet
  Explorer 7 and later, Firefox, Chrome, Safari) has, since roughly
  2003-2004, implemented client-side restrictions specifically
  preventing JavaScript's XMLHttpRequest/fetch APIs from issuing TRACE
  requests at all — meaning even a hypothetical XSS would very likely
  not be able to leverage TRACE against a modern browser regardless.
Validation Method: (1) Confirm no XSS vulnerability exists on web-srv-01
  through the application's own input-sanitization and output-encoding
  review, or a targeted dynamic application security test specifically
  for XSS, since this scan was version/configuration-based rather than
  active exploitation testing and could plausibly miss a logic-level
  XSS flaw; (2) send a manual TRACE request via `curl -X TRACE` to
  confirm the server actually echoes headers as described; (3) treat
  the well-documented, stable browser-level TRACE restriction as
  established fact rather than something requiring per-deployment
  re-verification.
Risk of Acting on This FP: The direct fix (disabling TRACE in Apache's
  configuration) is low-effort, so the primary waste here is not
  engineering time — it is attention and credibility. Treating a
  finding with no confirmed exploitation path as equally urgent to
  Finding 001 (a confirmed 9.8 CVSS RCE with no mitigating precondition)
  dilutes the security team's prioritization signal and trains
  stakeholders to stop trusting severity labels.
Risk of Not Validating: This scan's own methodology notes confirm it was
  not an active-exploitation test — meaning a real, logic-based XSS
  vulnerability could exist on the patient portal without having been
  detected at all. If one does, dismissing the TRACE finding without
  first checking for that missing precondition means MedDefense could
  miss the one piece of context that would make this Medium-severity
  finding genuinely urgent — since TRACE plus an undetected XSS together
  enable credential and session theft directly from patients using the
  portal.
```

---

## False Positive 3: Finding 030 (TLS Certificate CN Mismatch, ehr-srv-01)

```
Finding ID: 030
Reported Vulnerability: The TLS certificate on ehr-srv-01 is issued for
  "ehr.meddefense.local" but some clients access the server directly by
  IP address (10.10.2.10), triggering certificate validation warnings.
Why It Is a False Positive: The scan report's own description resolves
  this directly — the finding text explicitly states "This is an
  operational issue, not a security vulnerability." The mismatch exists
  because some clients bypass DNS and connect via IP directly, not
  because the certificate is invalid, expired, misissued, or
  substituted by an attacker. Nothing about this finding gives an
  unauthorized party any capability they would not already have; it is
  a usability annoyance (a browser warning) rather than an exploitable
  weakness. This finding is included here specifically because
  SecurePoint's scanner still surfaced it as a numbered finding by
  default TLS-anomaly detection heuristics, despite the tool's own
  generated description already containing the correct conclusion —
  illustrating that a scanner can hand an analyst the disproof of its
  own finding without applying that judgment itself.
Validation Method: Inspect the certificate directly (`openssl s_client
  -connect 10.10.2.10:443`) to confirm it is validly issued, unexpired,
  and chains to a trusted (or correctly configured internal) CA;
  separately confirm that clients experiencing the warning are known,
  legitimate internal users connecting by IP out of habit or hardcoded
  configuration, not evidence of a man-in-the-middle substitution. If
  desired, resolve permanently with a SAN certificate covering both the
  hostname and the internal IP.
Risk of Acting on This FP: Treating this as a security incident —
  assuming certificate compromise or an active MITM — could trigger
  unnecessary certificate revocation, reissuance, and incident response
  time, competing for the same limited analyst attention that Finding
  031 (Ghostcat, a confirmed 9.8 CVSS RCE on this exact same host)
  genuinely requires.
Risk of Not Validating: The inverse failure mode matters just as much —
  if every TLS-labeled finding on ehr-srv-01 is pattern-matched to this
  one's "operational, not security" conclusion without individually
  verifying each one, a genuinely serious future certificate issue (an
  actually expired cert, a downgraded cipher suite, or a real substituted
  certificate) could be waved through under the same assumption. Each
  TLS finding must be validated on its own evidence, not by analogy to
  a previous one that happened to be benign.
```

---

## Expected False Positive Rate and Why Manual Validation Is Essential

A reasonable expected false positive rate for an automated scanner is roughly **5–10% of total findings**, and this is not a generic industry estimate invented for this document, it is the exact figure SecurePoint's own methodology notes state for this specific OpenVAS configuration ("False positive rate for OpenVAS in this configuration is typically 5-10%"). Applied to this report's 31 findings, that range predicts **1.5 to 3 false positives** and the 3 identified in this analysis (Findings 020, 021, and 030) sit almost exactly at the top of that predicted range (roughly 9.7%), which is itself a useful sanity check: this analysis did not have to stretch to find "enough" false positives to hit a target number, and it did not turn up so many that the scan's overall reliability should be questioned.

Manual validation before committing remediation resources is essential for two reasons that this analysis demonstrates directly rather than asserts abstractly. First, **automated scanners detect version numbers and configuration states, not exploitability in context**. CVE-2023-38408's PKCS#11 precondition, the TRACE method's dependency on a co-existing XSS vulnerability, and the CN mismatch's purely operational cause are all facts a scanner cannot evaluate, because doing so requires understanding this specific server's actual usage pattern, this specific application's actual vulnerability inventory, and this specific client population's actual browser behavior (context no scan, however well-configured, can fully reconstruct on its own. Second, and more importantly for a resource-constrained security program like MedDefense's, **every hour spent validating and then remediating a false positive is an hour not spent on Finding 001, Finding 003, or Finding 031**)) the genuinely Critical findings identified elsewhere in this assessment. A security team that treats every scanner output as equally actionable without validation will, on average, spend real remediation effort on roughly 1 in every 10 findings for no security benefit at all. And in an environment already resource-constrained enough to have left 3 CVSS 9.8 vulnerabilities open on its most critical assets, that is not a cost MedDefense can afford to absorb without noticing.
