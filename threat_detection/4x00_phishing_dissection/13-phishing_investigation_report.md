# MedDefense Health Systems: The Phishing Investigation Report

| | |
|---|---|
| **Prepared by** | Aïda Sylla, Security Analyst |
| **Prepared for** | James Chen, SOC Lead (and, in relevant part, HC3) |
| **Source material** | Tasks 0, 1, 2, 3, 4, 7, 8, 9, and 11 of this investigation |
| **Purpose** | A single, final, evidence-based narrative of the 8-email batch — what happened, what the evidence supports, what remains unknown, and what should happen next |

> **Note on scope**: Task 12 (a dedicated detection/control-gap analysis) was not produced and is not available as source material. Section 7 is built directly from the control weaknesses already documented in tasks 1, 2, 4, 7, and 8, and the campaign pattern in task 9 — not from a task 12 that does not exist in this record.

---

## 1. Executive Summary

Between April 14 and 16, 2026, MedDefense received four coordinated phishing emails built around real internal processes — clinical portal access, vendor invoicing, and benefits enrollment — alongside one brand-impersonation phishing email, one unrelated spam message, and two genuine emails. One employee, a nurse, clicked a phishing link roughly 15 minutes after receiving it, and it is not yet confirmed whether her credentials were exposed. A federal health-sector advisory independently confirmed that other healthcare organizations in the region are being targeted by a matching campaign, strengthening the case that this was deliberate and coordinated rather than four unrelated incidents. No malware or system compromise has been confirmed at this time, but the financial, credential, and patient-care risk is real. This report recommends immediate containment, near-term detection improvements, and longer-term investment to close the visibility gaps this incident exposed.

---

## 2. Investigation Timeline

**Collection window**: 2026-04-14 07:22 CDT → 2026-04-16 15:22 CDT (57 hours). Six emails were reported via the helpdesk; two were pulled from Proofpoint quarantine over the same window.

| Email | Delivery date/time (CDT) | Note |
|---|---|---|
| E2 | Mon, Apr 14, 2026 — 14:47:52 | — |
| E3 | Tue, Apr 15, 2026 — 09:13:44 | — |
| E5 | 11:28:37, self-labeled "Wed, 16 Apr 2026" | April 16, 2026 is actually a Thursday; discrepancy taken as given from the evidence, not corrected |
| E7 | Thu, Apr 16, 2026 — 15:22:07 | — |
| E8 (HC3 advisory) | Received April 16 | After E2, around the same day as E5/E7 |

**Diane Marsh's click** (`WS-NURSE-04`): 2026-04-14, 15:02:33 CDT — about 14 minutes 41 seconds after E2 was delivered, per the workstation's own NTP-synced clock.

**Investigation scope**: all 8 emails were triaged (task 0); the four `SUSPICIOUS` ones (E2, E3, E5, E7) got full header (task 1), authentication (task 2), content (task 3), and URL/attachment (task 4) analysis; Diane's click got a dedicated investigation (task 7); all 8 emails got a final classification (task 8); E2/E5/E7 were cross-checked against E8's HC3 advisory (task 9); every actionable indicator was consolidated into an IOC report (task 11).

**Not included**: endpoint forensics, identity/sign-in log review, live OSINT lookups (WHOIS/VirusTotal/urlscan.io), or malware sandbox detonation — none of that telemetry or tooling was available. Section 5 reflects this limitation explicitly.

---

## 3. Email-by-Email Analysis

| Email | Classification | Confidence | Key Evidence |
|---|---|---|---|
| E1 | LEGITIMATE | HIGH | Full SPF/DKIM/DMARC pass on a domain matching `From:` exactly; genuine one-click unsubscribe; stated 2024-08-11 subscription date. |
| E2 | PHISHING-TARGETED | HIGH | Lookalike domain `meddefense-portal.com`, fails SPF/DKIM/DMARC; PHPMailer infrastructure; nurse-specific pretext (scheduling, EHR gateway, shift swaps); confirmed click by Diane Marsh 14m41s after delivery. |
| E3 | PHISHING-OPPORTUNISTIC | HIGH | Microsoft brand impersonation on unrelated domain `outlook-protection.com`; WordPress-path (`wp-admin`) infrastructure; fabricated `DKIM-Signature` text; generic template personalized only by name/email. |
| E4 | LEGITIMATE | HIGH | Real `meddefense.com` domain via internal Exchange; full SPF/DKIM/DMARC pass; no embedded link; signed by James Chen. |
| E5 | PHISHING-TARGETED | HIGH | Weak/failing auth on `medequip-supplies.net`; `Reply-To` mismatch; PDF attachment embeds the same payment link as the body; addressed specifically to Accounts Payable. |
| E6 | SPAM | HIGH | Unsolicited bulk pharma ad; gateway spam score 9.8/5.0 threshold; sender's own DMARC requests quarantine; bare-IP link. |
| E7 | PHISHING-OPPORTUNISTIC | HIGH | Lookalike domain `meddefense-benefits.org`, fails SPF/DKIM/DMARC; same `wp-` hostname pattern as E3; generic org-wide pretext; recipient denies signing up. |
| E8 | LEGITIMATE | HIGH | Full SPF/DKIM/DMARC pass on genuine `hhs.gov`; addressed to SOC distribution list; retained as threat-intel context. |

Task 0's rapid triage was correct on direction for all 8 emails — nothing flagged `SUSPICIOUS` was later cleared, and nothing flagged `LEGITIMATE`/`SPAM` was later found to be a missed threat. What changed was resolution, not direction: the four `SUSPICIOUS` emails needed tasks 1–4 to split into `PHISHING-TARGETED` (E2, E5 — role-specific, real reconnaissance) versus `PHISHING-OPPORTUNISTIC` (E3, E7 — generic templates personalized only by name).

---

## 4. Campaign Analysis

### Why E2, E5, and E7 are likely connected

- Identical software fingerprint (`PHPMailer 6.6.0`), submitted from `localhost` on a single-hop external relay — none uses MedDefense's own Exchange platform.
- Same PHPMailer default `Message-ID` format.
- None carries a DKIM signature; all three fail DMARC alignment (E2/E7 also fail SPF outright; E5 shows SPF softfail).
- All three force `X-Priority: 1 (Highest)`, independent of body wording.
- All three pair a hard deadline with a consequence matched to the target's likely fear (system lockout, payment suspension, coverage lapse).
- All three domains match a keyword — "portal," "supplies," "benefits" — that HC3's independent regional advisory (E8) explicitly lists.

**Not shared**: sending IP. Each uses distinct infrastructure (`91.234.99.107`, `185.176.43.22`, `164.90.218.73`), so IP reuse cannot prove a single actor — the link is at the level of tooling and technique, not shared network infrastructure.

### How E8 supports the campaign hypothesis

E8 is a genuine, fully-authenticated HHS/HC3 advisory (`hhs.gov`) describing a regional campaign using newly-registered lookalike domains with keywords "portal," "benefits," "supplies," "login"; PHPMailer on budget VPS hosting; 24–48 hour urgency deadlines; role-specific targeting.

| HC3 pattern | Match in this batch |
|---|---|
| Lookalike domain, matching keyword | E2, E7 close match; E5 close match |
| PHPMailer / budget VPS | Fingerprint matches exactly; hosting provider unconfirmed |
| 24–48h urgency window | E2, E7 match; **E5's 7-day deadline is a partial mismatch** |
| Role-specific targeting | Matches across all three |

E8 was received independently (from HHS, not the attacker) and was not written with knowledge of MedDefense's specific incidents — which is what makes the overlap meaningful corroboration, not circular reasoning.

### How E3 should be interpreted

E3 passes SPF/DKIM/DMARC — but only because those checks validate the attacker's own domain (`outlook-protection.com`), not Microsoft. A pass here is never a legitimacy signal; the question is *which* domain passed. E3 shares PHPMailer 6.6.0 and the same `wp-`-prefixed hostname convention as E7 (`wp-admin.outlook-protection.com` / `wp-portal.meddefense-benefits.org`). Task 3 separately rates E3 `SEMI-TARGETED`, the same tier as E7.

**Conclusion**: E3 is evidence of the same broader toolkit/template family as E7 — and plausibly the same campaign ecosystem as E2 and E5 — but this is evidence of shared tooling, not proof of a single operator or identical infrastructure.

### What the evidence does not support

The specific identity, location, or affiliation of any threat actor; whether MedDefense was individually researched or is one of several regional targets of the same semi-automated kit. Financial motive is the most consistent read but should not be elevated to a confirmed motive.

---

## 5. Click Incident Assessment

**What is known**: Diane Marsh (`dmarsh@meddefense.com`, `WS-NURSE-04`) received E2 at 14:47:52 CDT and navigated to the credential-harvesting URL at 15:02:33 CDT — about 14m41s later, per the workstation's NTP-synced clock. The domain is a confirmed unaffiliated lookalike, sent from `91.234.99.107`, failing SPF/DKIM/DMARC. Diane self-reported the incident.

**What cannot be concluded from the evidence batch alone** — none of the following can be answered without endpoint (EDR/Sysmon) or identity (sign-in log) telemetry, which was not available to this investigation:
- Whether Diane entered any credentials or partial information on the landing page.
- Whether the page captured an MFA code.
- Whether any file was offered, downloaded, or executed.
- Whether the account or workstation has shown any activity since the click.
- Whether the attacker's infrastructure has since contacted any other MedDefense system.

Given the credential-harvesting design of the page and Diane's EHR access, this should be treated as a **possible credential exposure** by default, not downgraded to "no compromise," until endpoint/identity checks are actually performed.

**Recommended safe next actions** (reversible, no missing telemetry required):
- Force an immediate password reset and revoke all active sessions/tokens.
- Review/reset MFA registration; check recent approval history for anything unrecognized.
- Conduct a brief, non-punitive interview with Diane.
- Add `meddefense-portal.com` and `91.234.99.107` to gateway blocklists.
- Apply heightened monitoring on the account (sign-in, inbox-rule, forwarding alerts).
- Preserve `WS-NURSE-04` in its current state for potential forensic imaging.
- Loop in Diane's manager and the awareness program — her self-report should be reinforced as good behavior.

---

## 6. IOC Summary

Full detail, confidence grading, and per-indicator actions are in `11-ioc_extraction.md`. Condensed here:

| Type | Values | Action |
|---|---|---|
| Domains | `meddefense-portal[.]com` (E2), `outlook-protection[.]com` (E3), `medequip-supplies[.]net` (E5), `meddefense-benefits[.]org` (E7) | Block |
| IPs | `91.234.99.107` (E2), `51.38.42.17` (E3), `185.176.43.22` (E5), `164.90.218.73` (E7) | Block |
| Sender / Reply-To | `noreply@meddefense-portal[.]com`, `security@outlook-protection[.]com`, `invoices@medequip-supplies[.]net` / `billing@medequip-supplies[.]net`, `hr-notifications@meddefense-benefits[.]org` / `no-reply@meddefense-benefits[.]org` | Block / alert |
| URLs | `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`, `hxxps://outlook-protection[.]com/verify`, `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891`, `hxxps://medequip-supplies[.]net/portal/login`, `hxxps://meddefense-benefits[.]org/enroll` | Block |
| Tool/pattern | `PHPMailer 6.6.0` fingerprint (E2/E3/E5/E7); `wp-`-prefixed hostname convention (E3, E7); domain-keyword pattern `portal`/`benefits`/`supplies`/`login` | Use in detection rules, not blocklists |

**File / hash indicator**: `INV-2026-04891.pdf` (E5 attachment) embeds the same payment URL via a `/S/URI` object, and contains a trailing text string resembling a SHA-256 hash outside the PDF's normal object structure. **This is not a confirmed, computed file hash** — task 4 flagged it as an anomaly in the raw evidence, not a hash independently calculated and checked against VirusTotal. Treat as a follow-up item (compute and check the real SHA-256), not a validated IOC.

---

## 7. Detection and Control Gaps

*(Built from control weaknesses already documented in tasks 1, 2, 4, 7, and 8 — task 12 was not produced and is not used here.)*

### What existing controls did not prevent

- All four phishing emails reached inboxes despite failing or only self-authenticating SPF/DKIM/DMARC. None of the four lookalike domains' own DMARC policies enforce rejection (`action=none` in every case), and the gateway does not appear to independently quarantine brand-lookalike mail that fails DMARC — **the single largest gap this incident exposed**.
- Nothing stopped Diane Marsh from reaching the credential-harvesting page: no evidence of URL rewriting, time-of-click protection, or web-proxy category blocking.
- The E5 PDF's embedded malicious URI was not caught at delivery — it reached AP and was only identified by manual analysis after the fact, not by an automated attachment-scanning control.
- Post-click visibility is a total gap: no EDR, Sysmon, or identity sign-in log review exists on `WS-NURSE-04` or `dmarsh`. The organization has no fast way to answer "did this click matter?"
- E3's fully-passing auth on an attacker-owned domain shows that authentication-result-only filtering, without checking whether the passing domain has any real relationship to the brand it displays, will not catch a well-configured brand-impersonation phish.

### What should be improved

- Move DMARC posture toward enforcement (`p=quarantine`/`p=reject`); evaluate gateway quarantine for brand-lookalike domains failing DMARC.
- Deploy attachment sandboxing/detonation, or at minimum automated URI extraction and reputation-checking.
- Close the post-click visibility gap: extend EDR to clinical workstations and enable centralized sign-in log review.
- Establish a lightweight vendor/invoice verification process for AP.

### Detection ideas (derived from this investigation's own findings, task 12 unavailable)

- Composite rule: `X-Mailer: PHPMailer` + failed/self-only-passing DMARC + a `From:` domain resembling MedDefense's own brand — would have flagged all four suspicious emails.
- Newly-registered-domain watch scoped to MedDefense's brand plus HC3's keywords (`portal`, `benefits`, `supplies`, `login`).
- Alert on `Reply-To` diverging from `From:` on external mail — flagged both E5 and E7, cheap to implement.
- Endpoint alerting on command-interpreter processes spawned from a browser, and on newly created inbox/forwarding rules.
- Forced `X-Priority` as a *secondary*, low-weight scoring signal only — trivially spoofable on its own.

---

## 8. Recommendations

| Timeframe | Actions |
|---|---|
| **Immediate — next 24h** | Reset `dmarsh` password, revoke sessions/tokens, review MFA · Block the four domains/IPs at gateway · Instruct AP not to process the E5 invoice; confirm Linda Patterson entered no data · Conduct the non-punitive interview with Diane · Preserve `WS-NURSE-04` |
| **Short-term — next 7 days** | Run the endpoint/identity checks on `WS-NURSE-04` and `dmarsh` · Stand up the composite PHPMailer+DMARC detection rule · Targeted awareness reminder to clinical/billing/finance staff · Org-wide sweep for new inbox-forwarding rules since 2026-04-14 |
| **Medium-term — next 30 days** | Move DMARC to enforcement; evaluate gateway quarantine for lookalikes · Extend EDR to clinical workstations; formalize sign-in log review process · Stand up AP vendor-verification process · Establish recurring domain-monitoring watch and a process for sharing IOCs with HC3/peers |
