MedDefense Health Systems: The Phishing Investigation Report Prepared by: Aïda Sylla, Security Analyst Prepared for: James Chen, SOC Lead (and for sharing, in relevant part, with HC3) Source material: All prior deliverables in this investigation — tasks 0 (initial triage), 1 (header analysis), 2 (authentication analysis), 3 (social engineering analysis), 4 (URL/attachment autopsy), 7 (click investigation), 8 (verdict matrix), 9 (campaign thread), and 11 (IOC extraction) Purpose: A single, final, evidence-based narrative of the 8-email batch — what happened, what the evidence supports, what remains unknown, and what should happen next.

Note on scope: Task 12 (a dedicated detection/control-gap analysis) was not produced as part of this investigation and is not available as source material. Section 7 below is built directly from the control weaknesses already documented in tasks 1, 2, 4, 7, and 8, and from the campaign pattern in task 9 — not from a task 12 that does not exist in this record. This is stated explicitly so the gap is not mistaken for something this report verified independently beyond what the earlier tasks established.

1. Executive Summary

Between April 14 and 16, 2026, MedDefense received four coordinated phishing emails built around real internal processes — clinical portal access, vendor invoicing, and benefits enrollment — alongside one brand-impersonation phishing email, one unrelated spam message, and two genuine internal/external emails. One employee, a nurse, clicked a phishing link roughly 15 minutes after receiving it, and it is not yet confirmed whether her credentials were exposed. A federal health-sector advisory independently confirmed that other healthcare organizations in the region are being targeted by a campaign matching the same pattern, which strengthens the case that this was a deliberate, coordinated attack rather than four unrelated incidents. No malware or system compromise has been confirmed at this time, but the financial, credential, and patient-care risk is real and requires the containment and monitoring steps in Section 8. This report recommends immediate containment actions, near-term detection improvements, and longer-term investments to close the visibility gaps this incident exposed.

2. Investigation Timeline
Email collection window: 2026-04-14 07:22 CDT → 2026-04-16 15:22 CDT (57 hours). Six emails were reported by end users via the helpdesk; two were pulled from Proofpoint quarantine over the same window.
Relevant send/delivery dates (internal delivery timestamp, per each email's Received: chain into mx01.meddefense.com):
E2 — Monday, April 14, 2026, 14:47:52 CDT
E3 — Tuesday, April 15, 2026, 09:13:44 CDT
E5 — labeled "Wed, 16 Apr 2026" in its own header, 11:28:37 CDT (the calendar date of April 16, 2026 actually falls on a Thursday; this discrepancy is taken as given from the evidence rather than corrected)
E7 — Thursday, April 16, 2026, 15:22:07 CDT
E8 (HC3 advisory) — received April 16, after E2 and around the same day as E5/E7
Reported click timestamp — Diane Marsh (WS-NURSE-04): 2026-04-14 15:02:33 CDT, approximately 14 minutes 41 seconds after E2 was delivered (14:47:52 CDT), per the workstation's own NTP-synced clock as recorded in the collector's notes.
Investigation scope: All 8 emails in the batch were triaged (task 0); the four flagged SUSPICIOUS (E2, E3, E5, E7) received full header (task 1), authentication (task 2), content/social-engineering (task 3), and URL/attachment (task 4) analysis; the confirmed click by Diane Marsh received a dedicated investigation (task 7); all 8 emails received a final classification (task 8); E2/E5/E7 were cross-referenced as a single campaign against E8's HC3 advisory (task 9); and every actionable indicator was consolidated into an IOC report (task 11). This report does not include endpoint forensics, identity/sign-in log review, live OSINT (WHOIS/VirusTotal/urlscan.io) lookups, or malware sandbox detonation — none of that telemetry or tooling was available to this investigation, and the click assessment in Section 5 reflects that limitation explicitly.
3. Email-by-Email Analysis
Email	Classification	Confidence	Key Evidence
E1	LEGITIMATE	HIGH	Full SPF/DKIM/DMARC pass on a domain matching the From: address exactly; genuine RFC 8058 one-click unsubscribe; recipient's stated 2024-08-11 subscription date.
E2	PHISHING-TARGETED	HIGH	Lookalike domain meddefense-portal.com failing SPF/DKIM/DMARC; PHPMailer infrastructure; pretext referencing nurse-specific systems (scheduling, EHR gateway, shift swaps); confirmed click by Diane Marsh 14m41s after delivery.
E3	PHISHING-OPPORTUNISTIC	HIGH	Brand impersonation of Microsoft on unrelated domain outlook-protection.com; WordPress-path (wp-admin) sending infrastructure; fabricated DKIM-Signature text string; generic "unusual sign-in" template personalized only by name and email, not by role.
E4	LEGITIMATE	HIGH	Sent from the real meddefense.com domain via internal Exchange; full SPF/DKIM/DMARC pass; no embedded link; signed by James Chen, SOC Lead.
E5	PHISHING-TARGETED	HIGH	Weak/failing SPF-DKIM-DMARC on medequip-supplies.net; Reply-To mismatch; PDF attachment embedding the same payment link as the email body; invoice pretext addressed specifically to Accounts Payable with a plausible dollar amount.
E6	SPAM	HIGH	Unsolicited bulk pharmaceutical advertising; gateway spam score 9.8 against a 5.0 threshold; sender's own DMARC policy requests quarantine on failure; bare-IP link with no domain.
E7	PHISHING-OPPORTUNISTIC	HIGH	Lookalike domain meddefense-benefits.org failing SPF/DKIM/DMARC; same WordPress-path hostname convention as E3 (wp-portal); generic org-wide open-enrollment pretext personalized only by name and email; recipient states she never signed up for this service.
E8	LEGITIMATE	HIGH	Full SPF/DKIM/DMARC pass on the genuine hhs.gov domain via HHS's secure mail gateway; addressed to a SOC distribution list; plain-text, link-free body; retained as supporting threat-intelligence context.

Task 0's rapid triage was correct on direction (malicious/spam vs. legitimate) for all 8 emails — no email initially flagged SUSPICIOUS was later cleared, and no LEGITIMATE/SPAM email was later found to be a missed threat. What changed between triage and final verdict was resolution, not direction: the four SUSPICIOUS emails needed the deeper analysis in tasks 1–4 to split correctly into PHISHING-TARGETED (E2, E5 — role-specific pretexts requiring real reconnaissance) versus PHISHING-OPPORTUNISTIC (E3, E7 — generic templates personalized only by name).

4. Campaign Analysis

Why E2, E5, and E7 are likely connected: All three are sent through the identical software fingerprint (PHPMailer 6.6.0), submitted from localhost on a single-hop external relay, and none uses MedDefense's own Exchange platform. All three share PHPMailer's default auto-generated Message-ID format. None carries a DKIM signature and all three fail DMARC alignment (E2 and E7 also fail SPF outright; E5 shows SPF softfail). All three deliberately set X-Priority: 1 (Highest) to force apparent urgency independent of body wording. All three pair a hard deadline with a specific, escalating negative consequence matched to the target's likely fear (clinical system lockout, delivery/payment suspension, benefits coverage lapse). And all three domains land on a keyword — "portal," "supplies," "benefits" — that HC3's independent regional advisory (E8) explicitly lists as observed in this campaign. What is not shared is sending IP: each of the three uses entirely distinct infrastructure (91.234.99.107, 185.176.43.22, 164.90.218.73), so IP reuse cannot be used to prove a single actor — the link is at the level of tooling, technique, and targeting strategy, not shared network infrastructure.

How E8 supports the campaign hypothesis: E8 is a genuine, fully-authenticated HHS/HC3 sector advisory (full SPF/DKIM/DMARC pass on hhs.gov) describing a regional healthcare phishing campaign using newly-registered lookalike domains with keywords including "portal," "benefits," "supplies," and "login"; PHPMailer-based sending on budget VPS hosting; 24–48 hour urgency deadlines; and role-specific targeting of clinical, billing, and HR-adjacent staff. E2's domain, targeting, and urgency window match this description closely; E7's domain and urgency window match closely; E5's domain and role-targeting match, though its 7-day payment deadline is notably longer than HC3's stated 24–48 hour range — a partial mismatch worth flagging rather than glossing over. E8 was received independently of this batch (from HHS, not from the attacker) and was not written with knowledge of MedDefense's specific incidents, which is what makes the keyword and tooling overlap meaningful corroboration rather than circular reasoning.

How E3 should be interpreted: E3 is technically distinct from the E2/E5/E7 trio in its authentication result — it passes SPF, DKIM, and DMARC — but only because those checks validate the attacker's own domain (outlook-protection.com), not Microsoft. A passing result here must never be read as a legitimacy signal; the correct question is which domain passed, not whether one did. E3 also uses PHPMailer 6.6.0 and the same wp--prefixed originating-hostname convention (wp-admin.outlook-protection.com) found on E7 (wp-portal.meddefense-benefits.org) — a shared naming pattern across two otherwise unrelated-looking lures. Task 3's content analysis separately rates E3 SEMI-TARGETED (a generic, reused Microsoft-account-compromise template personalized only by name and email), the same targeting tier as E7. Taken together, E3 should be interpreted as coming from the same broader toolkit or kit-template family as E7 — and by extension, plausibly the same campaign ecosystem as E2 and E5 — without asserting that E3 was sent by the identical infrastructure or the identical individual behind the other three. It is evidence of shared tooling, not proof of a single operator.

What the evidence does not support: the specific identity, location, or affiliation of any threat actor or group; whether MedDefense was individually and deliberately researched, or is one of several regional healthcare organizations hit by the same semi-automated kit HC3 describes. Financial motive (credential resale, direct payment fraud) is the most consistent read given the observed objectives, but this should not be elevated to a confirmed motive without further evidence.

5. Click Incident Assessment

What is known: Diane Marsh (dmarsh@meddefense.com, workstation WS-NURSE-04) received E2 at 14:47:52 CDT on 2026-04-14 and, per the workstation's own NTP-synced clock, navigated to the embedded credential-harvesting URL (hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1) at 15:02:33 CDT — approximately 14 minutes 41 seconds later. The domain is confirmed to be an unaffiliated lookalike of meddefense.com, sent from external IP 91.234.99.107, and to fail SPF/DKIM/DMARC. Diane self-reported the incident, which is what brought it into this investigation.

What can and cannot be concluded from the evidence batch alone: The batch confirms only that the workstation loaded the phishing URL. It does not establish, and this investigation has no way to determine from email evidence alone: whether Diane entered any credentials or partial information on the landing page; whether the page prompted for and captured an MFA code; whether any file was offered, downloaded, or executed; whether the dmarsh account has shown any sign-in activity since the click; whether WS-NURSE-04 has exhibited any new process, network connection, or file activity since the click; or whether the attacker's infrastructure has since contacted any other MedDefense system or account. None of these can be answered without endpoint (EDR/Sysmon) and identity (Entra/AD sign-in log) telemetry, which this investigation was not provided and has not reviewed. Given the credential-harvesting design of the landing page and the operational risk profile of a clinical user with EHR access, this should be treated as a possible credential exposure by default, not downgraded to "no compromise," until those checks are actually performed.

Recommended safe next actions (reversible, and do not require the missing telemetry to act on now):

Force an immediate password reset on dmarsh@meddefense.com and revoke all active sessions/tokens, so any session cookie potentially captured by the phishing page is invalidated even if the password alone would not stop it.
Review and, if warranted, reset MFA registration on the account, and check recent MFA approval history for anything Diane does not recognize.
Conduct a brief, non-punitive interview with Diane: what she recalls seeing, whether she entered anything before leaving the page, and whether anything looked or behaved unusually — often the fastest way to narrow the assessment.
Add meddefense-portal.com and 91.234.99.107 to email and web gateway blocklists.
Apply heightened monitoring on the dmarsh account (sign-in alerts, new inbox-rule alerts, mailbox-forwarding alerts) for an elevated period.
Preserve WS-NURSE-04 in its current state for potential forensic imaging rather than reimaging it immediately.
Loop in Diane's manager and the security-awareness program for supportive follow-up — a self-reported click should be reinforced as good behavior, not penalized, since it is what surfaced this incident at all.
6. IOC Summary

Full detail, confidence grading, and recommended actions per indicator are in 11-ioc_extraction.md. Condensed here for this report:

Domains (block): meddefense-portal[.]com (E2), outlook-protection[.]com (E3), medequip-supplies[.]net (E5), meddefense-benefits[.]org (E7)

IPs (block): 91.234.99.107 (E2), 51.38.42.17 (E3), 185.176.43.22 (E5), 164.90.218.73 (E7)

Sender / Reply-To addresses (block or alert on inbound): noreply@meddefense-portal[.]com, security@outlook-protection[.]com, invoices@medequip-supplies[.]net / billing@medequip-supplies[.]net, hr-notifications@meddefense-benefits[.]org / no-reply@meddefense-benefits[.]org

URLs (block): hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1, hxxps://outlook-protection[.]com/verify, hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891, hxxps://medequip-supplies[.]net/portal/login, hxxps://meddefense-benefits[.]org/enroll

File / hash indicator: INV-2026-04891.pdf (E5 attachment) embeds the same payment URL as the email body via a /S/URI object, and contains a trailing text string resembling a SHA-256 hash outside the PDF's normal object structure. This is not a confirmed, computed file hash — task 4 identified this as an anomaly in the raw evidence, not as a hash independently calculated and verified against VirusTotal or any other source. It should be treated as a follow-up item (compute and check the actual SHA-256 of the attachment against reputation sources) rather than cited as a validated IOC value.

Tool/pattern indicators (for detection rules, not blocklists): PHPMailer 6.6.0 sending fingerprint across E2/E3/E5/E7; wp--prefixed originating-hostname convention shared by E3 and E7; domain-keyword pattern (portal/benefits/supplies/login) matching HC3's independently reported list.

7. Detection and Control Gaps

(Built from the control weaknesses already documented in tasks 1, 2, 4, 7, and 8. Task 12, a dedicated detection/gap-analysis deliverable, was not produced for this investigation and is not used as a source here — see the note at the top of this report.)

What existing controls did not prevent:

All four phishing emails reached their intended recipients' inboxes despite failing or only self-authenticating SPF/DKIM/DMARC. None of the four lookalike domains' own DMARC policies enforce rejection (action=none in every case per task 2), and MedDefense's gateway does not appear to independently quarantine mail that fails DMARC on a domain resembling its own brand — this is the single largest gap this incident exposed.
Nothing stopped Diane Marsh from reaching the credential-harvesting page itself: there is no evidence of URL rewriting/sandboxing, time-of-click protection, or web-proxy category blocking that intercepted the link before her browser loaded it.
The E5 PDF attachment's embedded malicious URI was not caught or flagged at delivery time; it reached Accounts Payable and was only identified as suspicious after the fact, by manual analysis in this investigation (task 4), not by an automated attachment-scanning control.
Post-click visibility is a total gap: this investigation could not confirm or rule out credential submission, MFA capture, or account misuse because no EDR, Sysmon, or identity sign-in log review has been performed on WS-NURSE-04 or the dmarsh account (task 7). The organization currently has no fast way to answer "did this click matter?" after the fact.
E3's fully-passing SPF/DKIM/DMARC result on an attacker-owned domain shows that authentication-result-only filtering, without also checking whether the passing domain has any real relationship to the brand it displays, will not catch a well-configured brand-impersonation phish.

What should be improved:

Move MedDefense's own DMARC posture toward enforcement (p=quarantine or p=reject) and evaluate whether the gateway can be configured to independently quarantine external mail that fails DMARC while displaying a From: domain lexically similar to meddefense.com — this directly addresses the E2/E7 pattern.
Deploy attachment sandboxing/detonation or, at minimum, automated extraction and reputation-checking of embedded URIs in attachments (would have caught the E5 PDF).
Close the post-click visibility gap: deploy or extend EDR coverage to clinical workstations (starting with high-risk roles like nursing, given EHR access) and enable centralized identity sign-in log review, so a click like Diane's can be resolved to "confirmed" or "no compromise" in hours, not left indefinite.
Establish a lightweight vendor/invoice verification process for Accounts Payable (a known-good, independently sourced contact channel) to blunt the E5-style invoice-fraud pattern regardless of email-layer detection.

Detection ideas (derived directly from this investigation's own findings, in the absence of a task 12 deliverable):

A composite detection rule: inbound mail bearing an X-Mailer: PHPMailer signature, combined with a failed or self-only-passing DMARC result, on a From: domain lexically resembling meddefense.com or a well-known vendor/brand — this single rule would have flagged all four suspicious emails in this batch.
A newly-registered-domain watch/hunting rule scoped to MedDefense's own brand plus the keywords portal, benefits, supplies, and login, matching HC3's independently reported regional pattern.
An alert on Reply-To headers that diverge from the From: address on external mail — this flagged both E5 and E7 in this batch and is cheap to implement.
Endpoint alerting on any command-interpreter process (powershell.exe, cmd.exe) spawned as a child of a browser process, and on newly created mailbox-forwarding or inbox rules — both are standard post-phishing-click indicators this organization currently has no visibility into (task 7).
A forced-priority-header signal (X-Priority: 1 on external mail with no corresponding internal ticket/reference) as a secondary, low-weight scoring input only — not a standalone rule, since this header is trivially spoofable and common in legitimate mail too.
8. Recommendations

Immediate — next 24 hours:

Reset dmarsh@meddefense.com's password, revoke all active sessions/tokens, and review/reset MFA registration.
Block the four confirmed domains and IPs (Section 6) at the email and web gateway.
Instruct Angela Rivera / Accounts Payable not to process the E5 invoice, and confirm with Linda Patterson that she entered no data on the E7 link.
Conduct the non-punitive interview with Diane Marsh described in Section 5.
Preserve WS-NURSE-04 in its current state pending a decision on forensic imaging.

Short-term — next 7 days:

Perform the endpoint checks on WS-NURSE-04 and the identity/sign-in log review on dmarsh listed in task 7's decision matrix, to move the click assessment from "possible" to a confirmed outcome.
Stand up the composite PHPMailer + failed-DMARC + brand-lookalike detection rule described in Section 7.
Send a targeted awareness reminder referencing these specific lures (portal re-verification, benefits enrollment, invoice payment) to clinical, billing, and finance staff, reinforcing that Diane's self-report was the right call.
Review organization-wide for any new inbox-forwarding rules created since 2026-04-14 as a precautionary sweep, not limited to the dmarsh account.

Medium-term — next 30 days:

Move MedDefense's DMARC policy toward enforcement and evaluate gateway-level quarantine for brand-lookalike domains failing DMARC.
Deploy or extend EDR coverage to clinical workstations and establish a routine process for identity sign-in log review following any confirmed phishing click.
Stand up a lightweight AP vendor-verification process for invoices above a defined dollar threshold.
Establish a recurring domain-monitoring watch for MedDefense-brand lookalikes and the HC3-reported keyword set, and formalize a process for sharing confirmed IOCs back to HC3 and regional healthcare-sector peers going forward.
