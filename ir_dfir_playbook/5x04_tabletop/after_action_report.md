# After-Action Report: Nexus Supply Chain Compromise Tabletop

**Exercise date:** 2026-10-25
**Report date:** 2026-10-27
**Facilitator:** Aida Sylla
**Participants:** James Chen, Sarah Park, Dr. Patricia Morales, Helena Reyes, Marcus Webb, Robert Kim, Clinical Director representative
**Classification:** Internal

---

## Executive summary

This tabletop exercised MedDefense's response to a supply chain compromise of Nexus Patient
Scheduling, a Business Associate integrated with Epic via HL7 FHIR, across eight organizational
capabilities from initial detection through board-level briefing. Internal technical and legal
reasoning performed well throughout: scope escalation, PHI exposure scoping, and the HIPAA
four-factor assessment were all handled cleanly and, in several cases, without facilitator
prompting. The significant gaps that emerged instead clustered around every process that touches
an external party. The vendor incident communication channel with Nexus has never been jointly
exercised and produced no named owner for tracking Nexus's own 24-hour BAA notification clock.
Separately, the organization has no pre-agreed protocol requiring Legal sign-off before any public
statement; the correct outcome during the simulated media inquiry was achieved only because one
participant happened to intervene in time, not because a safeguard existed. The single most
important recommended action is to formally assign and document named ownership for every
external-facing process this exercise touched - the BAA notification clock, the joint vendor
communication channel, and the crisis communications spokesperson/legal sign-off step - since the
common thread across all three P1 findings is that these processes exist on paper but have no
exercised, individually-owned execution path.

---

## Findings table

| ID | Inject | Capability | Gap | Severity | Recommended Action | Owner | Deadline | Validation |
|---|---|---|---|---|---|---|---|---|
| F-001 | INJ-01 | CAP-02 | The Nexus incident communication channel has never been jointly exercised; no participant raised this risk unprompted | P1 | Schedule a joint incident communication drill with Nexus SecOps before the next annual vendor security review | IT Director | 30 days | Drill conducted and documented; referenced at next tabletop |
| F-002 | INJ-01 | CAP-02 | No individual is assigned to track whether Nexus meets its 24-hour BAA breach notification obligation | P1 | Assign a named BAA-clock tracking owner in the IR playbook's vendor compromise section | General Counsel | 14 days | IR playbook updated with named role; confirmed present at next tabletop |
| F-003 | INJ-03 | CAP-03 | The business continuity decision was made and stated verbally but not captured in writing during the inject window, weakening the record available for the later HIPAA four-factor assessment | P3 | Add a decision-logging step (scribe captures decision, owner, and review time in writing) to the containment workflow | IT Director | 14 days | Decision log template exists and is used in the next exercise |
| F-004 | INJ-03 | CAP-03 | The patient-safety fallback for pre-surgical bookings was assigned to "the team" rather than a named individual | P2 | Require that any patient-safety fallback name a specific individual or role, not a team reference, in the containment decision record | Clinical Director representative | 21 days | Next continuity decision names an individual owner, confirmed in playbook review |
| F-005 | INJ-05 | CAP-07 | No pre-agreed protocol requires Legal sign-off before any external/media statement; the correct outcome in the exercise depended on one participant's in-the-moment intervention | P1 | Formally designate a single media spokesperson role with mandatory Legal co-review before any public statement, documented in the communication plan | CEO, with General Counsel | 30 days | Communication plan updated; spokesperson/sign-off step confirmed at next tabletop |

---

## P1 Finding narratives

### F-001: Untested vendor incident communication channel

During INJ-01, Marcus Webb successfully reached Nexus's 24x7 SecOps line within the inject window,
but no participant noted that this exact channel had never been exercised jointly with Nexus
before today - a fact directly recorded in `nexus_vendor_profile.md`'s last security review
("incident communication path documented at the contact level but not tested in a joint
exercise"). This matters because a documented contact path and a tested one carry very different
reliability under real pressure: response times, escalation behavior, and information quality from
an untested vendor channel are unknown precisely when they matter most. The recommended action is
to schedule and run a joint incident communication drill with Nexus SecOps before the vendor's next
annual security review, so the channel's real-world reliability is known before, not during, the
next live incident.

### F-002: No named owner for the vendor's BAA notification clock

Helena Reyes correctly confirmed during INJ-01 that Nexus's BAA obligates it to notify MedDefense
within 24 hours of discovering a breach, but no one in the room was assigned to actually track
whether Nexus meets that deadline. This matters because knowing a contractual obligation exists is
not the same as monitoring compliance with it; without a named owner, a missed vendor notification
could go unnoticed until it independently affects MedDefense's own regulatory posture. The
recommended action is to add a named BAA-clock tracking role to the IR playbook's vendor compromise
section, closing the gap between documented contractual rights and an actual monitoring process.

### F-005: No pre-agreed spokesperson/legal sign-off protocol

During INJ-05, Dr. Patricia Morales began to confirm an investigation to a reporter before the
statement had been reviewed by Legal; Helena Reyes caught this in time only because she happened to
be attentive at that exact moment. This matters because the exercise's correct outcome depended
entirely on one participant's individual vigilance rather than on any standing organizational
safeguard - a different sequencing, or Reyes's attention elsewhere, would have produced an
unverified public statement during an active, unresolved incident. The recommended action is to
formally designate a single spokesperson role with mandatory Legal co-review built into the
communication plan, so the correct outcome no longer depends on chance.

---

## What worked

- **Scope re-escalation (INJ-02):** When forensic review confirmed the backdoor had been active on
  all three sites for three days, the team re-escalated severity and expanded the notification list
  to executive leadership and legal without any facilitator prompting - the severity matrix's
  judgment-based escalation worked as intended under this specific scenario.
- **PHI exposure scoping and HIPAA notification posture (INJ-04):** Helena Reyes precisely separated
  confirmed access from unconfirmed exfiltration and explicitly opened MedDefense's own four-factor
  risk assessment without waiting for Nexus's individualized notice - correctly treating the
  Business Associate's and the Covered Entity's notification clocks as independent.
- **Resisting false closure under board pressure (INJ-06):** Dr. Patricia Morales caught and
  corrected an overconfident line in her own draft brief ("contained" to "contained to the extent
  currently known") before it reached the board, without being prompted to do so.

---

## Exercise design feedback

The following three design changes, identified while simulating the exercise in Task 7, have been
applied to this module's planning documents:

- **DF-01 (INJ-00 fail indicator removed):** INJ-00's situation text gave no actual cue pointing to
  Nexus, making "vendor not mentioned" an unfair fail indicator at that point; it has been removed
  from INJ-00, since the same expectation is already fairly tested at INJ-01.
- **DF-02 (INJ-03 ownership standard tightened):** INJ-03's pass criterion for the patient-safety
  fallback did not originally require a named individual owner, allowing "the team" to satisfy it;
  the criterion now explicitly requires a named individual or role.
- **DF-03 (INJ-05 near-miss now testable):** INJ-05's original fail indicators did not cover a
  "right outcome, no process" near-miss; a new pass/fail pair now specifically tests whether the
  team references a pre-agreed legal sign-off protocol, rather than crediting a result that
  succeeded only by chance.
