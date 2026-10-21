# Playbook Updates: IR-2026-0414-01

Source playbook: `ir_dfir_playbook/5x00_incident_response/playbook_credential_exposure.yaml`
(`playbook_id: PB-002`, module 5x00), as it existed before this incident. All "Before" excerpts
below are copied from that real file, abbreviated to the relevant lines where noted; none are
reconstructed from memory or assumption.

---

### Change PB-UPD-001

**Playbook:** playbook_credential_exposure.yaml
**Section:** applies_to.triggers
**Gap closed:** GAP-003
**Finding reference:** control_effectiveness.yaml, phase: VPN access using stolen credentials
from a foreign IP; ad_auth_log.jsonl 2026-04-14T02:44:17Z

**Before:**
```yaml
applies_to:
  triggers:
    - Confirmed phishing report where the user entered credentials on a fake Microsoft login page
    - Azure AD sign-in from an unfamiliar country or ASN within one hour of a reported credential entry
```

**After:**
```yaml
applies_to:
  triggers:
    - Confirmed phishing report where the user entered credentials on a fake Microsoft login page
    - Azure AD sign-in from an unfamiliar country or ASN within one hour of a reported credential entry
    - VPN authentication from a country not seen for this account in the prior 30 days, independent of any phishing report
    - VPN or Azure AD authentication from an external IP/ASN already flagged on this account within the prior 24 hours, regardless of whether a credential entry was separately reported
```

**Reason:** The existing triggers only fire off a *reported* credential entry, within a one-hour
window, against an Azure AD sign-in specifically. The actual incident's VPN logon from
`45.63.9.88` (RU) at 02:44:17Z occurred roughly eight hours after the flagged phishing-adjacent
sign-in, through the VPN rather than Azure AD, and matched no trigger as written — this is the
gap GAP-003 documents, and it let the intrusion proceed unchallenged into the interactive logon
that followed three minutes later.

---

### Change PB-UPD-002

**Playbook:** playbook_credential_exposure.yaml
**Section:** New section, `scope_expansion_checklist` (inserted between `containment_actions`
and `eradication_actions`)
**Gap closed:** GAP-009
**Finding reference:** control_effectiveness.yaml, phase: Lateral movement and PHI access;
ad_auth_log.jsonl 2026-04-14T03:41:52Z (`second_request_with_ticket_reuse`)

**Before:**
```yaml
containment_actions:
  - step: Reset the account's Active Directory password
  ...
  - step: Terminate all active Epic sessions for the account
    ...

eradication_actions:
  - Remove any mailbox forwarding rules or OAuth application consents created during the exposure window
```
(No equivalent section existed between these two — the playbook had no structured step for
expanding containment scope when lateral-movement indicators appear.)

**After:**
```yaml
containment_actions:
  - step: Reset the account's Active Directory password
  ...
  - step: Terminate all active Epic sessions for the account
    ...

scope_expansion_checklist:
  - trigger: A Kerberos ticket-granting-service request for the same SPN is logged twice for the
      same account within a short window (Pass-the-Ticket indicator)
    step: Identify every host targeted by the reused ticket's TGS requests and add each one to
      the containment scope as a newly compromised host, not just the originally reported host
    owner: Technical_Lead
    timebox_minutes: 15
  - step: Repeat evidence_preservation and containment_actions for each newly identified host
      before any remediation action is taken on it
    owner: Technical_Lead
    decision_point: N/A
  - step: Re-check whether any newly identified host has its own network share or application
      access to ePHI systems (Epic, LIS); if so, re-evaluate severity_mapping.escalate_if for
      the incident as a whole, not only for the originally reported account
    owner: Technical_Lead
    timebox_minutes: 10

eradication_actions:
  - Remove any mailbox forwarding rules or OAuth application consents created during the exposure window
```

**Reason:** In this incident, a ticket-reuse pattern (`second_request_with_ticket_reuse`,
03:41:52Z) preceded lateral movement into `LIS-WSIDE-01` and the PHI access that followed 90
seconds later, but the playbook had no step directing the responder to expand containment to a
newly identified host once that pattern appears — the single signal that was logged never
produced a structured response action.

---

### Change PB-UPD-003

**Playbook:** playbook_credential_exposure.yaml
**Section:** containment_actions
**Gap closed:** GAP-009, GAP-008
**Finding reference:** forensic_findings_summary.md, ART-002-M04 (NTLM hash material in LSASS
memory) and ATT&CK T1550.003; ad_auth_log.jsonl 2026-04-14T03:41:52Z

**Before:**
```yaml
containment_actions:
  - step: Reset the account's Active Directory password
    owner: Technical_Lead
    decision_point: N/A
    trade_off: Cuts off on-prem access immediately but signals the account owner is compromised, which may prompt the attacker to accelerate any remaining actions elsewhere
```

**After:**
```yaml
containment_actions:
  - step: Reset the account's Active Directory password
    owner: Technical_Lead
    decision_point: N/A
    trade_off: Cuts off on-prem access immediately but signals the account owner is compromised, which may prompt the attacker to accelerate any remaining actions elsewhere
  - step: If Pass-the-Ticket indicators are confirmed (a Kerberos ticket reused across hosts
      without a fresh interactive logon, or credential material observed accessible in LSASS
      memory), perform a double reset of the krbtgt account password, spaced roughly 10 hours
      apart (verify the exact interval your organization's Kerberos ticket-lifetime policy
      requires before relying on this figure)
    owner: Technical_Lead
    decision_point: N/A
    trade_off: Invalidates every Kerberos ticket issued domain-wide, including for legitimate
      users, forcing a full re-authentication cycle across the organization; a single reset is
      not sufficient because an attacker holding a ticket issued before the first reset can
      still use it until that ticket's own lifetime expires
```

**Reason:** The original playbook's only account-reset step was a simple password reset, which
does not invalidate a Kerberos ticket already issued using the account's prior key material.
This incident involved exactly that gap: NTLM hash material for `dmarsh` was present in LSASS
memory (`ART-002-M04`) and a reused Kerberos ticket (`T1550.003`) enabled lateral movement to a
second host — a password reset alone would not have closed this path.

---

### Change PB-UPD-004

**Playbook:** playbook_credential_exposure.yaml
**Section:** New decision node, `hipaa_breach_assessment` (triggered by the existing
`severity_mapping.escalate_if` conditions referencing ePHI, Epic, or the LIS)
**Gap closed:** GAP-011
**Finding reference:** forensic_findings_summary.md AD-LOG-01 (14 PDF reads, confirmed PHI
access); 5x02 Task 7 regulatory grounding (45 CFR 164.402 breach presumption, OCR four-factor
risk assessment)

**Before:**
```yaml
severity_mapping:
  initial: SEV2
  escalate_if:
    - ePHI was accessible from the compromised account during the exposure window
    - Evidence shows lateral movement originating from the compromised account
    - The account was used to access Epic or the Laboratory Information System during the exposure window

communication_plan:
  ...
  - audience: Legal_Liaison
    trigger: As soon as ePHI access during the exposure window is confirmed or cannot be ruled out
    template: hipaa_assessment_trigger.md
```
(The playbook routes the question to Legal_Liaison via a template, but never specifies what the
assessment itself must cover — there is no branch walking through the four-factor test.)

**After:**
```yaml
severity_mapping:
  initial: SEV2
  escalate_if:
    - ePHI was accessible from the compromised account during the exposure window
    - Evidence shows lateral movement originating from the compromised account
    - The account was used to access Epic or the Laboratory Information System during the exposure window

hipaa_breach_assessment:
  trigger: Any severity_mapping.escalate_if condition referencing ePHI, Epic, or the LIS is true
  owner: Legal_Liaison
  decision_node:
    - factor: Nature and extent of the PHI involved, including the types of identifiers and the
        likelihood of re-identification
    - factor: Who accessed or used the PHI, and whether that party had any legitimate authorization
    - factor: Whether the PHI was actually acquired or viewed, not merely exposed to potential access
    - factor: The extent to which the risk to the PHI has been mitigated (e.g. confirmed deletion,
        confirmed no onward transfer)
  outcome: Per 45 CFR 164.402, unauthorized access, use, or disclosure of PHI is presumed to be
      a breach unless this four-factor assessment demonstrates a low probability of compromise;
      confirmed access alone (without confirmed exfiltration) is sufficient to trigger the
      presumption and does not by itself reduce the notification obligation
  escalates_to: communication_plan.Legal_Liaison, communication_plan.Executive_Sponsor

communication_plan:
  ...
  - audience: Legal_Liaison
    trigger: As soon as ePHI access during the exposure window is confirmed or cannot be ruled out
    template: hipaa_assessment_trigger.md
```

**Reason:** The original playbook correctly routes a potential ePHI exposure to Legal_Liaison,
but leaves the actual regulatory assessment undefined. This incident confirmed PHI access for 14
patients (`AD-LOG-01`) with no evidence of exfiltration — exactly the situation the 45 CFR
164.402 breach-presumption standard and its four-factor exception test are meant to resolve, and
exactly the kind of judgment the playbook should not leave the responder to work out from
scratch during a live incident.
