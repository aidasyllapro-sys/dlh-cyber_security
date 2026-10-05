# Threat Hunting Report — HEALTHBANE Stage 4 Investigation
**MedDefense Environment | Module 4x04 Threat Hunting**
**Prepared for: James Chen (SOC) and Dr. Morales (Board)**
**Author: Aïda SYLLA**

> Note on scope: hypothesis labels H1/H3/H4 below are reconstructed from
> the hunt script sequence and headers (H2 and H5 are confirmed verbatim
> from script comments). If the original Task 1/2 hypothesis document
> uses different numbering, only the labels need correcting — every
> finding and figure below is taken directly from the validated output
> of Tasks 4, 6, 9, 10 and 13 against the real SIEM export.

---

## 1. Executive Summary

**What was hunted and why.** Following the HC3 health-sector advisory on
HEALTHBANE, a proactive hunt was run against 14 days of Wazuh/Sysmon
telemetry from the MedDefense environment to answer one question:
did HEALTHBANE Stage 4 (credential theft → lateral movement →
reconnaissance → staging) already happen here, undetected?

**Key finding.** Yes. The hunt found and independently corroborated a
complete Stage 4 kill chain: credential theft from workstation
WS-RECV-03, followed by lateral movement using the stolen service
account `svc_healthsync` to three internal servers, followed by
reconnaissance and file-staging activity consistent with preparation
for further compromise.

**Impact assessment.** Three systems were reached using the stolen
credential: `SRV-HEALTH-DB`, `SRV-INS-DB` and `SRV-DC-01` (a domain
controller). Reconnaissance commands recovered directory listings of
`C:\backup` and `C:\claims` shares and service/AD enumeration output,
indicating the attacker was mapping health records and insurance
claims data and domain accounts. No confirmed data exfiltration volume
was observed in the available telemetry; this is a gap, not a
clearance (see Section 7).

**Remediation status.** Five new detection rules were drafted
(Task 13) directly from the hunt's findings, closing the specific
gaps identified in Task 12. Measured ATT&CK technique coverage for
this kill chain improved from an estimated 55% (reactive, pre-hunt)
to approximately 80% (post-hunt). The remaining 20% is detailed in
Section 7 and is not yet closed.

---

## 2. Hunt Methodology

**Hypothesis-driven approach.** The hunt followed the HC3 HEALTHBANE
advisory's described techniques, mapped each to a MITRE ATT&CK
technique, checked which of them had no corresponding Wazuh rule
(the ATT&CK gap analysis), and built one targeted hunt query per gap
rather than searching the full 14-day export unguided.

**Data sources used.**
- `siem_export/wazuh_alerts_14d.json` — Wazuh-generated alerts
- `siem_export/wazuh_raw_sysmon_14d.json` — raw Sysmon telemetry
  (Event 1 Process Creation, Event 10 ProcessAccess), deduplicated
  against the alerts export by `id` (the two files overlap)
- `reference/service_accounts.txt` — the service-account authorization
  matrix (host, logon type and auth-package rules per account)
- `reference/admin_schedule.txt` — documented admin maintenance
  windows and admin workstation list

**Baseline establishment.** Legitimate activity (Robert Kim's admin
use of PsExec/WMI/PSRemoting from the documented admin workstation,
during documented maintenance windows, and each service account's
authorized host from the matrix) was established first in each hunt
script, so that every flagged event is a genuine deviation from a
known-good baseline rather than a raw keyword match.

---

## 3. Findings per Hypothesis

### H1 — PsExec Lateral Movement (T1021.002)
- **Status:** POSITIVE — HIGH CONFIDENCE
- **Evidence:** 50 total PsExec-pattern events observed; 44 matched the
  documented admin baseline (source = admin workstation, within the
  maintenance window). 6 did not: PsExec execution from `WS-RECV-03`
  (not an admin workstation) against `SRV-HEALTH-DB` and `SRV-INS-DB`.
- **Confidence assessment:** high — the source host is categorically
  outside the authorized admin workstation list; this is not a timing
  or threshold judgment call.

### H2 — Credential Access via LSASS (T1003.001)
- **Status:** POSITIVE — HIGH CONFIDENCE
- **Evidence:** 12 total LSASS-access events; 10 were the expected
  AV/EDR processes running as `NT AUTHORITY\SYSTEM`. 2 were not:
  `C:\Windows\Temp\debug_tool.exe` accessing `lsass.exe` on
  `WS-RECV-03`. The 3 subsequent `svc_healthsync` lateral
  authentications were all independently correlated with PsExec/WMI/
  PSRemoting tooling from the same source host.
- **Confidence assessment:** high — an unsigned, non-standard binary
  under `C:\Windows\Temp` opening a handle to `lsass.exe` has no
  legitimate baseline explanation in this environment.

### H3 — WMI Remote Execution / Reconnaissance (T1047)
- **Status:** POSITIVE — HIGH CONFIDENCE
- **Evidence:** 5 reconnaissance commands with `ParentImage =
  WmiPrvSE.exe` across the three reached servers: directory listings
  of `C:\backup` and `C:\claims` shares, `sc query` service
  enumeration, and an `Get-ADUser` enumeration query on the domain
  controller.
- **Confidence assessment:** high — `WmiPrvSE.exe` as parent process
  is direct host-side evidence of a remotely-triggered command,
  independent of the command's own content.

### H4 — PowerShell Remoting / Staging (T1021.006)
- **Status:** POSITIVE — HIGH CONFIDENCE
- **Evidence:** 2 `Copy-Item` file-staging events, each copying
  `sync_healthdata.ps1` from `WS-RECV-03` to `C:\Windows\Temp\
  stage1.ps1` on `SRV-HEALTH-DB` and `SRV-INS-DB`.
- **Confidence assessment:** high — identical staging path and
  filename pattern on two independent targets rules out coincidence.

### H5 — Service Account Abuse (T1078.002)
- **Status:** POSITIVE — CRITICAL CONFIDENCE
- **Evidence:** `svc_healthsync`: 846 total authentications, 840
  authorized, **6 unauthorized** — all 6 originating from
  `WS-RECV-03` against hosts outside the account's documented
  authorization matrix entry, and all 6 correlated with PsExec/WMI/
  PSRemoting tooling from that same source. The other five documented
  service accounts (`svc_insurance`, `svc_backup`, `svc_patchdeploy`,
  `svc_av`, `svc_ad_replication`) showed zero unauthorized use.
- **Confidence assessment:** critical — this is the one finding that
  independently corroborates with lateral-movement tooling, which is
  why it alone is rated above "high."

---

## 4. Reconstructed Attack Timeline

Full chronology, as reconstructed and independently corroborated in
Task 10 (`10-evidence_correlation.sh`):

| Phase | Timestamp | Host | Event |
|---|---|---|---|
| Credential Access | 2026-05-05T08:22:17Z | WS-RECV-03 | LSASS memory access via `debug_tool.exe` |
| Credential Access | 2026-05-12T07:45:35Z | WS-RECV-03 | LSASS memory access via `debug_tool.exe` |
| Lateral Movement | 2026-05-06T07:14:33Z | WS-RECV-03 → SRV-HEALTH-DB | `svc_healthsync` |
| Reconnaissance | 2026-05-06T07:31:44Z | SRV-HEALTH-DB | `dir \\SRV-HEALTH-DB\C$\backup /B /S` |
| Reconnaissance | 2026-05-06T07:33:56Z | SRV-HEALTH-DB | `sc query type=service state=all` |
| Staging | 2026-05-06T07:52:44Z | SRV-HEALTH-DB | `Copy-Item` → `stage1.ps1` |
| Lateral Movement | 2026-05-09T08:42:17Z | WS-RECV-03 → SRV-INS-DB | `svc_healthsync` |
| Reconnaissance | 2026-05-09T08:55:22Z | SRV-INS-DB | `dir \\SRV-INS-DB\C$\claims /B` |
| Reconnaissance | 2026-05-09T08:57:44Z | SRV-INS-DB | `sc query type=service state=running` |
| Staging | 2026-05-09T09:19:22Z | SRV-INS-DB | `Copy-Item` → `stage1.ps1` |
| Lateral Movement | 2026-05-13T06:58:44Z | WS-RECV-03 → SRV-DC-01 | `svc_healthsync` |
| Reconnaissance | 2026-05-13T07:12:11Z | SRV-DC-01 | `Get-ADUser -Filter * -Properties LastLogon,Enabled` |

**Pivot host:** WS-RECV-03. **Credential used:** svc_healthsync.
**Targets:** SRV-HEALTH-DB, SRV-INS-DB, SRV-DC-01. **Tools used:**
PsExec, WMI, PSRemoting. **Dwell time:** 7 days 22 hours (first
credential theft to last reconnaissance event).

---

## 5. ATT&CK Coverage Update

| Stage | Coverage |
|---|---|
| Before hunt (reactive detection only) | 55% |
| After hunt (hunt-derived rules added) | ~80% |

```
Before:  [███████████░░░░░░░░]  55%
After:   [████████████████░░░]  80%
```

**Newly confirmed techniques** (present in telemetry, previously
without a corresponding alert):
- T1021.002 — Remote Services: SMB/Windows Admin Shares (PsExec)
- T1003.001 — OS Credential Dumping: LSASS Memory
- T1047 — Windows Management Instrumentation
- T1021.006 — Remote Services: Windows Remote Management
- T1078.002 — Valid Accounts: Domain Accounts

---

## 6. Detection Improvements

Five rule drafts were produced in Task 13, each tied directly to a
Task 12 gap and a Section 3 finding above:

| Rule ID | Title | Closes Gap | FP Rate |
|---|---|---|---|
| 100100 | PsExec from Non-Admin Workstation | H1 | VERY LOW |
| 100101 | LSASS Memory Access from Non-System Process | H2 | LOW |
| 100103 | WMI Remote Child Process Anomaly | H3 | MEDIUM |
| 100102 | Service Account Interactive Logon from Workstation | H5 | VERY LOW |
| 9000030 | SMB Lateral Movement — PsExec Service Installation | H1 | LOW |

No rule draft was written this cycle specifically for H4 (PowerShell
Remoting staging via `Copy-Item`) beyond what Rule 100103/9000030
incidentally cover — this is a real, not cosmetic, gap and is carried
into Section 7.

Coverage statistic: 55% → ~80% (Section 5). Gap closure: 4 of the 6
gaps identified in Task 12 (PsExec, LSASS, WMI, service account) now
have a draft rule; 2 (PowerShell-Remoting staging specifically, and
NTLM/pass-the-hash-style activity) remain open.

---

## 7. Remaining Gaps and Recommendations

**What is still unknown (the ~20% uncovered):**
- No dedicated rule yet exists for `Copy-Item`/file-staging activity
  inside a PSRemoting session (H4) — the current rules infer it only
  indirectly through WMI/PsExec correlation.
- No rule exists for NTLM use by an account whose matrix mandates
  Kerberos (Task 12, Gap 6) — observed in the data but not yet closed
  by a Task 13 rule.
- No confirmed measurement of data volume actually copied or
  exfiltrated from `SRV-HEALTH-DB`/`SRV-INS-DB`/`SRV-DC-01`; the
  available telemetry shows staging and enumeration, not a confirmed
  exfiltration channel or volume.
- No visibility into whether `debug_tool.exe` reached WS-RECV-03 via
  phishing, a prior compromise, or physical/removable media — initial
  access vector is outside this hunt's data sources.

**Immediate actions (incident response for WS-RECV-03 — Module 5
bridge):** isolate WS-RECV-03 pending forensic imaging; force a
credential reset for `svc_healthsync` and any account that
authenticated from WS-RECV-03 in the dwell-time window; treat
`SRV-HEALTH-DB`, `SRV-INS-DB` and `SRV-DC-01` as potentially exposed
pending a dedicated incident-response review of those hosts.

**Short-term:** rotate all six documented service-account credentials
on a routine schedule rather than only on suspicion; review and
tighten privileged/service-account access so a single compromised
workstation cannot reach a domain controller.

**Medium-term:** extend Sysmon deployment with full behavioral
analytics (process-ancestry baselining, not just event collection) so
gaps like H4's staging activity are caught by correlation rules
instead of requiring a manual hunt to surface them.

---

## 8. Lessons Learned

**Why 55% ATT&CK coverage created a false sense of security.** A
coverage percentage measures how many techniques have *a* rule, not
whether that rule catches the technique as the attacker actually used
it. Every technique in this kill chain (PsExec, LSASS access, WMI,
service-account logons) already had *some* logging and, in several
cases, a related rule — but each rule was either too narrow (H4) or
never compared against the one piece of context that mattered: a
baseline or authorization list (H1, H2, H5). The dashboard said 55%
and gave no signal that the gap was precisely where this attacker
operated.

**Why reactive detection alone is insufficient against LOLBin
attacks.** Every tool used in this chain — PsExec, WMI, PowerShell
remoting, native Windows logon — is a legitimate administrative tool.
Reactive, signature-style detection has nothing to match against: the
binaries are not malware. Only a baseline comparison (which host,
which account, which time window is authorized) turns identical
telemetry into a detectable anomaly, and reactive rules written
without that baseline will keep missing this entire class of attack.

**Why proactive threat hunting must be a recurring operational
discipline.** This hunt found an attack that had already been running
for nearly 8 days without triggering a single automated alert. A
one-time hunt closes the gaps it finds for the techniques it looked
for; it does not prevent the next LOLBin combination from opening a
new, equally invisible gap. Coverage is a moving target precisely
because it depends on baselines staying current and rules narrowing
exactly to what was last observed — which is why hunting has to repeat
on a schedule, not run once and be considered done.

---

*End of report.*
