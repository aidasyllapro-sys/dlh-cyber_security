# HIPAA Breach Risk Assessment: IR-2026-0420-01

Assessment date: 2026-04-20
Conducted by: IR on-call analyst (incident lead, IR-2026-0420-01)
Reviewed by: Helena Reyes, General Counsel (pending)
PHI involved: 1,847 patient files — lab results and clinical notes — accessed from FILE-SVR-01

This assessment applies the four-factor risk analysis required under the HIPAA Breach
Notification Rule (45 CFR §164.402) to determine whether the access described in
`forensic_findings.md` constitutes a reportable breach or falls under the "low
probability of compromise" exception. All evidence IDs reference findings documented
in `forensic_findings.md`.

## Factor 1: Nature and extent of PHI involved

Evidence: FS-002 — 1,847 Event ID 4663 object-access events, 100% `.pdf` file type,
confined to two clinical shares: `\clinical\labs\` (lab panel results) and
`\clinical\notes\` (clinical progress notes, including at least one ED admission
note per the representative sample). FS-001 confirms the full set was accessed within
a single 27-minute window by a single logon session.

Conclusion: the PHI involved is clinical in nature — diagnostic and treatment
information, not limited to demographic or billing data. Lab results and clinical
notes are high-sensitivity categories under HIPAA (they typically include diagnosis,
treatment, and condition information capable of significant harm if disclosed). The
volume (1,847 individual records) represents a substantial, not isolated, exposure.

Confidence: **confirmed** for file count, type, and share location (directly evidenced
by FS-002). **Not available** for the exact identifiers contained within each PDF
(patient name, MRN, DOB, etc.) — the file server access log records which objects were
read, not their content; no document content was independently reviewed as part of
this investigation. This is a gap, not an assumption of absence: the sensitivity
conclusion above is based on the share's known clinical purpose (`\labs\`, `\notes\`),
not on verified content.

## Factor 2: Unauthorized person who used or received the PHI

Evidence: FS-003 — the access was performed under `MEDDEFENSE\jdoe`, authenticated via
Kerberos from CS-WS-101, a host independently confirmed compromised by an external
actor at that same time (SYSMON-001, SYSMON-002, PROXY-002: Cobalt Strike beacon
established on CS-WS-101 on 2026-04-17, three days before this file server access,
with persistent C2 to 45.152.66.114, a destination independently flagged
`cobalt_strike_team_server_known`). jdoe's documented role is scheduling coordinator,
with no legitimate ACL-based need to access `\clinical\labs\` or `\clinical\notes\`
(per `note_for_analyst` in the file server artifact).

Conclusion: the party who obtained this PHI was not a workforce member acting within
or even mistakenly outside their role — it was an external threat actor operating
through a compromised, already-beaconing host, using stolen valid credentials. This is
the highest-risk category under Factor 2: there is no business associate agreement,
no covered-entity relationship, and no reasonable basis to assume the recipient would
not further use or disclose the information.

Confidence: **confirmed** that the access occurred through a compromised host under
external C2 control. **Not available**: the specific identity or affiliation of the
threat actor (attribution not established in the current evidence).

## Factor 3: Whether the PHI was actually acquired or viewed

Evidence: FS-002/FS-003 show 1,847 `ReadData` (0x1) events — the files were opened and
read, not merely listed. PROXY-003 records a 2.4 MB outbound transfer to the same C2
destination (45.152.66.114) 18 seconds after the file server's first beacon
connection, inside the same 27-minute access window.

Conclusion: the read access itself is confirmed. The correlated size and timing of the
outbound transfer strongly suggest the accessed records were also exfiltrated, not
only viewed in place — but this is a timing/volume correlation, not a verified
byte-for-byte match between the 1,847 PDFs and the transferred payload (no packet
capture or content-level reconstruction is available).

Confidence: **confirmed** that the PHI was viewed/read. **Probable**, not confirmed,
that it was acquired (exfiltrated) — consistent with the certainty level already
assigned to PROXY-003 in the forensic findings. Under a four-factor HIPAA analysis,
"probable acquisition" based on strong circumstantial evidence does not lower the risk
determination to the entity's benefit; the standard requires demonstrating a low
probability of compromise, not merely the absence of confirmed acquisition.

## Factor 4: Extent to which the risk to PHI has been mitigated

Evidence: `containment_execution.md` — egress block applied 20:52Z 2026-04-20; network
isolation of all affected hosts completed by 21:22Z 2026-04-20; credential revocation
of `jdoe` (password reset, forced logoff, account disabled) at 21:25Z; C2 beacon
severance verified at 21:30Z (zero connection attempts from any host since isolation).

Conclusion: containment was thorough and verified — but it was applied starting
2026-04-20 at 20:52Z, roughly **43 hours after** the file server access occurred
(2026-04-19, 02:14Z-02:41Z). No mitigating control (encryption of the PHI at rest with
a key unavailable to the attacker, a confirmed-intact recipient with a confidentiality
obligation, immediate recovery of the data before further use) was in place or
achievable during that 43-hour window. Mitigation reduces the risk of *further*
exposure going forward; it does not reduce the risk already incurred by the specific
1,847-file access itself.

Confidence: **confirmed** for all containment actions and their timestamps (sourced
directly from `containment_execution.md`). **Confirmed** that no compensating control
existed during the exposure window — no evidence in any artifact indicates the PHI was
encrypted at the file level or that the recipient's access was otherwise constrained.

## Determination

Applying the four factors together: Factor 1 (broad, sensitive clinical PHI), Factor 2
(confirmed external threat actor via compromised host, no trust relationship), Factor
3 (confirmed viewing, probable acquisition), and Factor 4 (mitigation applied ~43 hours
after exposure, no compensating control during that window) — **this assessment does
not support a low probability of compromise.** Under 45 CFR §164.402, the access is
presumed to be a reportable breach, and the organization has not rebutted that
presumption through this analysis.

**This assessment concludes that notification is required.**

**Final determination authority:** per the incident response team structure
(`ir_team_structure.yaml`), the binding legal determination of reportability — and the
decision on notification scope, timing, and recipients (patients, HHS, media where
applicable) — rests with **Helena Reyes, General Counsel (Legal_Liaison)**. This
document is the technical risk-assessment input to that legal determination, not a
substitute for it. Helena Reyes's determination is expected to be finalized **before
the 07:00 Monday board brief**, so that `executive_brief.md` can state the confirmed
regulatory posture rather than a preliminary one.
