# Module 5x03 — Lessons Learned

> In post-incident review practice, a finding is only a "lesson observed" until it changes
> something concrete — a control, a playbook, a detection rule. Only then does it become a
> "lesson learned." This distinction, common in after-action-review methodology, is the
> organizing idea behind this module.

## Scenario recap

Case `LH-2026-0414-01` / incident `IR-2026-0414-01` is closed. The 5x02 phase established, with
direct evidence, the full attack chain against `MEDDEFENSE\dmarsh`: a phishing credential
submission on 2026-04-13T18:14Z, an Azure AD sign-in flagged `impossibleTravel` but allowed
through under a `compliant_device` conditional-access policy, a VPN logon from the same foreign
IP eight hours later, a PowerShell-to-MSBuild LOLBin execution chain that did trigger a
high-severity SIEM alert, Tor-relay and secondary C2 beaconing from two separate hosts,
credential material exposed in LSASS memory, Kerberos ticket reuse (Pass-the-Ticket) into a
second workstation, and confirmed access to 14 patients' lab report PDFs on the laboratory
information system — a HIPAA breach-presumption event under 45 CFR 164.402.

This module does not re-investigate that chain. It asks the harder question: knowing exactly
what happened and when, which of the organization's controls actually worked, which detection
rules need to exist that do not yet, what the open-source threat-intelligence picture says about
who was likely behind this, and what hardening changes are directly justified by these specific
findings — not by a generic checklist.

Task 0 worked through a real post-incident review that failed structurally (no blameless
framing, chair with a conflict of interest, a four-week delay, an outcome memo with no owner,
deadline, or validation method, and no playbook or detection-rule updates) to establish what a
sound PIR requires before producing one here.

## Grounding materials

- `forensic_findings_summary.md` — the authoritative, condensed hand-off from the 5x02
  investigation: evidence IDs, confirmed findings, the consolidated IOC list, and the full
  ATT&CK technique list for this incident.
- `incident_sysmon.jsonl` — Sysmon events captured during the incident window, used as the
  positive sample when testing detection rules.
- `clean_sysmon.jsonl` — a 30-day Sysmon baseline from the same host class, used as the negative
  sample to measure false-positive rate.
- `ioc_enrichment_snapshot/` — saved VirusTotal, AlienVault OTX, AbuseIPDB, and URLhaus lookups
  for this incident's IOCs, used for threat-intelligence enrichment.
- `ad_auth_log.jsonl`, `proxy_log.jsonl`, `siem_alert_export.json` (5x02 materials, same
  investigation) — the raw, timestamped log entries cited directly in `control_effectiveness.yaml`
  for exactly which signals fired and which did not.

## Contents

- `control_effectiveness.yaml` — Task 1: for each of the six phases of the attack chain, the
  controls expected, the controls that actually fired (cited to a specific log field or alert
  record), the controls that missed, and a gap-severity rating with a one-line reason.

See `control_effectiveness.yaml` for the audit itself; later tasks in this module build detection
rules, threat-intel enrichment, and hardening specifications directly from the gaps it documents.
