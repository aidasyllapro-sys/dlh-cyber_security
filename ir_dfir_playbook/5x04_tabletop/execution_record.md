# Exercise Execution Record: Nexus Supply Chain Compromise Tabletop

**Simulation date:** 2026-10-27
**Simulated by:** Aida Sylla

---

## INJ-00 (T+0 min)

**Inject delivered:** "The SOC has flagged unusual outbound traffic from the Nexus scheduling server at the Main campus (SCHED-SVR-01) to an unknown external IP address. The alert fired 45 minutes ago. The connection recurs at roughly four-hour intervals. The Nexus system is currently operational. Patient scheduling is running normally at all three sites. No other anomalies have been detected yet."

**Participant responses:**

- James Chen (SOC Lead): Declares a SEV2 incident at T+3, citing the unexplained periodic beaconing as the trigger; requests netflow/PCAP evidence for the connection.
- Sarah Park (IT Director): Confirms the SEV2 declaration, asks Chen to hold off on any host action until evidence collection starts.
- Marcus Webb (Security Analyst): Begins checking whether the other two sites' Nexus agent hosts show the same traffic pattern.
- Dr. Patricia Morales (CEO), Helena Reyes (General Counsel), Robert Kim (CFO), Clinical Director representative: Not yet engaged; no trigger in this inject reaches their roles.

**Evaluation:**

- Pass criterion 1 (incident declared within 5 min, severity reasoned): **PASS** - Chen declares SEV2 at T+3 with explicit reasoning (unexplained periodic beaconing).
- Pass criterion 2 (two roles notified by name): **PASS** - Chen and Park both actively engaged from the start.
- Pass criterion 3 (evidence before containment): **PASS** - no containment action is proposed during the inject.
- Fail indicator 3 (vendor not mentioned as a dimension of the alert): **TRIGGERED** - no participant raises Nexus specifically as a possible source during this inject.

**Facilitator note:** Asked "Has anyone considered whether this traffic could originate from a system you don't fully control yourselves?" No one connected it to Nexus specifically at this point. The gap is resolved naturally once INJ-01 arrives, but the result here is mixed: three clean passes alongside one triggered fail indicator with no corresponding pass criterion to offset it. See Design Feedback DF-01.

---

## INJ-01 (T+20 min)

**Inject delivered:** "Nexus Health Technologies has published a security advisory. Their build pipeline was compromised by a threat actor with access to their code-signing certificate. Software updates distributed through the automatic update channel in the last several days may contain a malicious component. Nexus does not yet have a patch and asks customers to contact their 24x7 SecOps line for guidance."

**Participant responses:**

- Sarah Park (IT Director): Immediately connects this to INJ-00 ("that's our vendor") and directs Marcus Webb to call Nexus SecOps now.
- Marcus Webb (Security Analyst): Calls Nexus SecOps, asks which versions/customers are affected and for a remediation timeline.
- James Chen (SOC Lead): States that certificate-only validation is no longer sufficient grounds to trust future signed updates from Nexus automatically.
- Dr. Patricia Morales (CEO): Asks what MedDefense's contractual rights are under the BAA; directs Helena Reyes to review.
- Helena Reyes (General Counsel): Confirms the BAA's 24-hour vendor notification clock exists, but does not assign anyone to track whether Nexus actually meets it.
- Robert Kim (CFO), Clinical Director representative: Not yet engaged.

**Evaluation:**

- Pass criterion 1 (named owner contacts Nexus SecOps): **PASS** - Webb calls within the inject window.
- Pass criterion 2 (team raises the untested communication path): **FAIL** - no participant spontaneously notes that this channel has never been exercised jointly with Nexus before today.
- Pass criterion 3 (team questions automatic trust in future signed updates): **PASS** - Chen raises it directly.
- Pass criterion 4 (someone assigned to track the 24h BAA clock): **FAIL** - Reyes confirms the obligation exists but no owner is named.

**Facilitator note:** Asked "Who is tracking whether Nexus actually hits their own 24-hour clock, and has this phone line ever been tested before today?" The question revealed that knowing a contractual rule exists is not the same as assigning ownership of it, and that no one would have raised the untested-path risk without direct prompting. Two of four criteria required facilitator intervention to surface - a real finding, not a near-miss.

---

## INJ-02 (T+35 min)

**Inject delivered:** "Forensic review confirms the backdoor delivered through the malicious update has been running on the Nexus agent hosts at all three sites (Main, West Campus, North Site), not only the one originally flagged, since the update was deployed three days ago. Outbound beaconing has been occurring at four-hour intervals the entire time."

**Participant responses:**

- James Chen (SOC Lead): States this is no longer a single-host SEV2 and recommends re-escalation.
- Sarah Park (IT Director): Agrees, says executive leadership and legal need to be looped in now.
- Dr. Patricia Morales (CEO): Asks to be briefed directly and asks Robert Kim to join given the scheduling/billing exposure across all three sites.
- Helena Reyes (General Counsel): Notes the three-day exposure window, not the original 45-minute estimate, changes the regulatory posture.
- Marcus Webb (Security Analyst): Begins drafting a three-site scope summary.
- Robert Kim (CFO): Joins, asks about billing/eligibility-check impact across all three sites.

**Evaluation:**

- Pass criterion 1 (severity re-escalated): **PASS**
- Pass criterion 2 (notification list expanded to exec + legal): **PASS**
- Pass criterion 3 (three-day exposure window explicitly stated): **PASS** - Reyes states it unprompted.

**Facilitator note:** Asked "Does the three-day window change anything about what you already decided, or just what you're about to decide?" Reyes had already connected exposure duration to regulatory posture before the question was asked - the probe confirmed rather than revealed a gap. Clean inject.

---

## INJ-03 (T+50 min)

**Inject delivered:** "Marcus Webb recommends immediately isolating all three Nexus agent hosts and severing the Nexus integration entirely until the compromise is fully understood. The Clinical Director representative objects: tomorrow's appointment schedule, including several pre-surgical bookings, depends on current Nexus data, and no manual scheduling fallback is currently staffed or ready. Robert Kim notes that an extended outage also halts insurance eligibility checks, risking claim denials and billing delays across all three sites."

**Participant responses:**

- Marcus Webb (Security Analyst): Pushes for full isolation now given the confirmed three-site, three-day backdoor.
- Clinical Director representative: Objects strongly; pre-surgical patients cannot be safely rescheduled without advance notice.
- Robert Kim (CFO): Flags the billing/eligibility cost but defers to patient safety as the higher priority.
- Sarah Park (IT Director): Proposes severing only external connectivity from the agent hosts rather than a full host wipe, to preserve forensic value.
- Dr. Patricia Morales (CEO): Makes the final call - sever the Nexus integration's external connectivity immediately, direct the Clinical Director representative's team to manually verify tomorrow's pre-surgical bookings within 2 hours, and revisit the decision at T+4 hours once forensic scope is clearer.
- Helena Reyes (General Counsel): Notes the decision should be documented for the later HIPAA risk assessment.

**Evaluation:**

- Pass criterion 1 (CEO makes and states a documented decision): **PASS**
- Pass criterion 2 (concrete patient-safety fallback named): **PASS** - manual verification of pre-surgical bookings, 2-hour deadline.
- Pass criterion 3 (specific review timeframe stated): **PASS** - T+4 hours.

**Facilitator note:** Asked "Who, by name, is personally responsible for the manual verification in the next two hours?" The Clinical Director representative answered "my team" rather than naming an individual. All three listed pass criteria are technically met, but this probe exposed that "a fallback is named" does not currently require a named *owner* for that fallback - a weaker standard than every other finding in this project, where an owner is always a named person. See Design Feedback DF-02.

---

## INJ-04 (T+65 min)

**Inject delivered:** "Forensic analysis shows the attacker queried locally cached patient demographic data and insurance eligibility records on the compromised agent hosts. It is not yet confirmed whether any data left the environment. Separately, Nexus has not yet confirmed to MedDefense that it has met its 24-hour BAA breach notification obligation; their advisory was general, not an individualized notice."

**Participant responses:**

- Helena Reyes (General Counsel): States the exposure precisely - "Confirmed: read access to demographic and insurance eligibility data on three hosts. Not confirmed: exfiltration." Opens MedDefense's own four-factor HIPAA risk assessment immediately and states it does not wait for Nexus's individualized notice.
- Marcus Webb (Security Analyst): Confirms which specific data fields were queryable from the cache.
- Dr. Patricia Morales (CEO): Asks what MedDefense's own notification timeline looks like once the assessment concludes.
- Sarah Park (IT Director): Confirms IT will support the forensic timeline Legal needs.
- Robert Kim (CFO): Asks about potential OCR fines; Reyes notes that is premature to estimate.

**Evaluation:**

- Pass criterion 1 (PHI exposure stated precisely): **PASS**
- Pass criterion 2 (Reyes states MedDefense's clock is independent of Nexus's 24h): **PASS**
- Pass criterion 3 (four-factor risk assessment explicitly opened): **PASS**

**Facilitator note:** Asked "If Nexus never sends an individualized notice, does that change your timeline?" The team correctly answered no. This is the strongest clean pass of the exercise - likely because INJ-01 already primed Reyes on the BAA terms before this inject arrived.

---

## INJ-05 (T+80 min)

**Inject delivered:** "Scheduling staff report discrepancies in tomorrow's appointment list at the Main campus: at least two patients show conflicting double-booked slots, and one pre-surgical appointment appears to have been silently cancelled with no record of who cancelled it. At the same time, a local news reporter calls the front desk asking MedDefense to confirm or deny 'a data breach involving a scheduling vendor.'"

**Participant responses:**

- Sarah Park (IT Director): Proposes cross-checking flagged records against the pre-compromise backup and prioritizing a direct patient callback for the cancelled pre-surgical slot.
- Dr. Patricia Morales (CEO): Says she will take the reporter call herself and begins to confirm "yes, we are investigating a vendor-related security event" before the statement has been reviewed.
- Helena Reyes (General Counsel): Interrupts in time - "wait, let me vet the language first" - and the unverified statement is not actually given to the reporter.
- Clinical Director representative: Confirms urgency of the cancelled pre-surgical patient callback.

**Evaluation:**

- Pass criterion 1 (verification method named for flagged records): **PASS**
- Pass criterion 3 (no unverified detail actually stated to the reporter): **PASS** - Reyes's interruption succeeded.
- Pass criterion 2 (single designated spokesperson named): **AMBIGUOUS** - Dr. Morales self-appoints as spokesperson reactively, and is caught only because Reyes happened to intervene in time, not because a pre-agreed protocol required legal sign-off before any statement. This does not cleanly match any of the three fail indicators as written ("multiple people respond," "no comment," "unverified detail stated") - none of those actually occurred.

**Facilitator note:** Asked "If Helena hadn't caught that in time, what would have been said?" The team acknowledged nothing would have stopped it. The outcome was correct, but only because one participant happened to be paying attention in the moment, not because of a procedural safeguard. This near-miss falls entirely outside the current fail indicators. See Design Feedback DF-03.

---

## INJ-06 (T+95 min)

**Inject delivered:** "The board has requested a status briefing in 90 minutes. Full forensic confirmation of which patient records were accessed, modified, or exfiltrated across all three sites is not expected for several more days, and Nexus has not yet shared the full scope of its own root-cause investigation into the build pipeline compromise."

**Participant responses:**

- Sarah Park (IT Director): Drafts a brief separating confirmed facts (three-site backdoor, three-day exposure, demographic/insurance data access confirmed, integration severed) from unknowns (exfiltration status, full record-modification scope, Nexus's own root cause).
- Dr. Patricia Morales (CEO): Reviews the draft and strikes a line implying the breach is "contained," replacing it with "contained to the extent currently known."
- Helena Reyes (General Counsel): Confirms the brief does not overstate legal conclusions ahead of the four-factor assessment's completion.
- Robert Kim (CFO): Adds a one-line preliminary financial impact estimate, explicitly caveated as pending full scope.
- Clinical Director representative: Confirms the patient-safety fallback status (manual verification ongoing) is included.

**Evaluation:**

- Pass criterion 1 (confirmed vs unknown explicitly separated): **PASS**
- Pass criterion 2 (references a decision already made): **PASS** - cites the INJ-03 continuity decision.
- Pass criterion 3 (states what's still needed without false closure): **PASS** - the CEO catches and corrects an overconfident line herself.

**Facilitator note:** Asked "If a board member asks 'is this over?' right now, what do you say?" The team unanimously said no, citing the explicit open question. A strong capstone: the team's earlier gaps (vendor-trust ownership, spokesperson protocol) did not resurface here, suggesting the capability being tested at INJ-06 is genuinely distinct from the earlier ones rather than a repeat of the same weakness.

---

## Design feedback

### DF-01: INJ-00's fail indicator has no matching pass criterion

INJ-00's situation text gives no actual cue pointing to Nexus - the alert is simply "unusual outbound traffic to an unknown IP." Expecting participants to spontaneously name the vendor at this point, with no supporting detail in the inject itself, is an unfair test, yet `evaluation_criteria.yaml` currently includes "vendor Nexus is not mentioned as a dimension of the alert" as an INJ-00 fail indicator with no corresponding pass criterion to offset it. Running the simulation produced exactly this: three clean passes plus one triggered fail indicator with no clear way to express an overall partial result.

**Change:** Remove this fail indicator from INJ-00 entirely. The vendor-dimension test belongs at INJ-01, where the published advisory actually gives participants something concrete to connect - and it is already tested there (pass criterion 1, contacting Nexus SecOps).

### DF-02: INJ-03's patient-safety fallback criterion doesn't require a named owner

Every other finding in this project (Gap Register, hardening spec, playbook updates) names a specific individual as owner. INJ-03's pass criterion 2 only requires that "a concrete patient-safety fallback is named," which the Clinical Director representative satisfied by answering "my team" rather than a named person. The criterion technically passed while leaving exactly the kind of untraceable ownership gap this module's own concepts (Finding vs Observation) are built to catch.

**Change:** Reword INJ-03 pass criterion 2 to: "A concrete patient-safety fallback is named with a specific individual or role assigned to execute it, not a team reference," and add a matching fail indicator: "The fallback is assigned to a team or department rather than a named individual or role."

### DF-03: INJ-05's fail indicators don't cover a "right outcome, no process" near-miss

The most realistic organizational failure mode at INJ-05 isn't a visibly bad response - it's a leader self-appointing as spokesperson and getting lucky that someone else intervened in time, with no pre-established protocol requiring legal sign-off before any public statement. None of the current three fail indicators ("multiple people respond," "no comment," "unverified detail stated") catch this, so the simulation produced a result that doesn't map cleanly to pass or fail.

**Change:** Add a fourth pass criterion to INJ-05: "The team states or references an existing pre-agreed protocol requiring legal sign-off before any external statement, rather than relying on in-the-moment intervention," with a matching fail indicator: "A spokesperson self-appoints and proceeds without reference to any pre-agreed sign-off protocol, regardless of whether the statement was ultimately caught in time."
