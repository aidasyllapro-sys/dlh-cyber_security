MedDefense Health Systems: The Campaign Thread
Prepared by: Aïda Sylla, Security Analyst
Prepared for: James Chen, SOC Lead
Source material: Findings from tasks 1 (header analysis), 2 (authentication analysis), 3 (social engineering analysis) and 4 (URL/attachment autopsy) for E2, E5 and E7, cross-referenced against E8's HC3 sector alert
Purpose: Determine whether E2, E5 and E7 — three suspicious emails with different pretexts, different sender domains and different individual targets — are connected as a single coordinated phishing campaign, by comparing shared infrastructure, timing, tooling and targeting rather than by pretext alone.

---

## Campaign Thread Analysis

### Shared Indicators

- **Sending software**: All three (E2, E5, E7) are sent through the identical software fingerprint, `PHPMailer 6.6.0`, from a `localhost`-submitted, single-hop external relay — none uses MedDefense's own Microsoft Exchange platform (task 1).
- **Message-ID pattern**: All three use PHPMailer's default auto-generated format — `PHP-` followed by a hex string, `@`, and the sending domain — rather than a corporate mail system's ID scheme.
- **Authentication posture**: None of the three carries a DKIM signature (`dkim=none`), and all three fail DMARC alignment (`dmarc=fail`) — E2 and E7 also fail SPF outright, E5 shows SPF softfail.
- **Priority headers**: All three explicitly set `X-Priority: 1 (Highest)` in their headers (E2 additionally sets `X-MSMail-Priority: High` and `Importance: High`) — a deliberate, shared technical choice to make the message appear urgent in the recipient's inbox, independent of the wording in the body.
- **Urgency framing in content**: All three pair a hard deadline with a specific negative consequence (E2: 24-hour lockout of clinical systems; E5: 7-day payment deadline with a late fee and delivery suspension threat; E7: same-day enrollment cutoff with coverage lapse) — task 3's shared pattern of matching the lever to the target's likely fear.
- **Targeted business-process lures**: All three build their pretext around a real internal process (portal access, vendor invoicing, benefits enrollment) rather than a generic "you won a prize" template, consistent with reconnaissance of how MedDefense actually operates.
- **What is not shared**: The three sending IPs are entirely distinct (`91.234.99.107`, `185.176.43.22`, `164.90.218.73` — task 4's cross-indicator finding), so IP reuse cannot be used as a link. The `wp-`-prefixed originating-hostname convention documented in task 1 (`wp-portal.meddefense-benefits.org`) appears on E7, matching E3's `wp-admin.outlook-protection.com` — but E2's hostname is plain `localhost` and E5's is `billing-svc.medequip-supplies.net`, so that specific naming convention links E7 to E3, not to E2 or E5.

### Targeting Map

| Email | Recipient | Role/Function | Pretext Alignment |
|---|---|---|---|
| E2 | Diane Marsh | Clinical/nursing staff (WS-NURSE-04) | References systems specific to nursing work (scheduling, EHR gateway, shift swaps) — role-specific. |
| E5 | Angela Rivera | Accounts Payable / Finance | References a vendor invoice and payment process specific to AP's function — role-specific. |
| E7 | Linda Patterson | Billing (recipient's actual department) | References an organization-wide HR benefits enrollment process, not anything specific to Billing — the pretext targets "any employee," not Linda's actual role. |

### Timing Map

Based strictly on each email's internal delivery timestamp (`Received:` hop into `mx01.meddefense.com`):

- **E2**: Monday, April 14, 2026, 14:47:52 -0500 (CDT).
- **E5**: April 16, 2026, 11:28:37 -0500 (CDT) — the header itself labels this "Wed, 16 Apr 2026," though April 16, 2026 falls on a Thursday on the calendar; this day-of-week label is taken as given from the evidence rather than corrected, since the task's date is what matters for the timing map.
- **E7**: Thursday, April 16, 2026, 15:22:07 -0500 (CDT).

E5 and E7 were both delivered on **April 16**, roughly 3 hours 53 minutes apart — not on April 15. E2 landed almost two full days earlier, on April 14. The pattern is one early, isolated hit followed by a same-day pair two days later, rather than an even daily drip.

### Comparison With HC3 Alert

E8's HC3 advisory (received April 16, after E2 and around the same day as E5/E7) describes a regional campaign with these observed patterns, compared directly against E2/E5/E7:

- **Lookalike domain keywords**: HC3 names `"portal"`, `"benefits"`, `"supplies"`, and `"login"` as observed hostname keywords. E2's domain (`meddefense-portal.com`) matches "portal," E7's domain (`meddefense-benefits.org`) matches "benefits," and E5's domain (`medequip-supplies.net`) matches "supplies" — all three of the trio's domains land on a keyword HC3 explicitly lists.
- **Newly-registered domains**: HC3 describes registration ages under 30 days. This cannot be independently confirmed here, since task 4's WHOIS lookups on these lab-fabricated domains returned no registration record at all rather than a real, dated one — consistent with, but not proof of, HC3's description.
- **Sending infrastructure**: HC3 describes PHPMailer-based sending on budget VPS hosting (naming Hostinger and DigitalOcean pricing tiers as examples). The PHPMailer 6.6.0 fingerprint matches exactly across E2, E5 and E7; the specific hosting provider cannot be confirmed without a live WHOIS/ASN lookup against real infrastructure, which this lab's fabricated IPs do not support.
- **Urgency-based social engineering**: HC3 describes 24–48 hour deadlines, lockout threats, and open-enrollment cutoffs. E2 (24-hour lockout) and E7 (same-day enrollment cutoff) match this window closely; E5's 7-day payment deadline is notably longer than the 24–48 hour range HC3 describes, which is a partial mismatch worth flagging rather than glossing over.
- **Role-specific targeting**: HC3 explicitly names clinical staff, billing staff, and HR recipients as receiving role-appropriate lures. E2's clinical targeting is a clean match. E5's targeting (Accounts Payable) and E7's targeting (a Billing employee receiving an HR-themed, not billing-themed, lure) only partially align with HC3's phrasing — the batch shows finance/AP and HR-pretext lures rather than a lure specifically built around Linda's billing function.
- **No malware, credential harvesting as the objective**: Confirmed consistent across all three — task 4 found no malware indicators, only credential- and payment-harvesting links in E2, E5 and E7.

### Attribution Assessment

What the evidence supports: E2, E5 and E7 share a specific, non-default technical fingerprint (PHPMailer 6.6.0, unsigned mail, failed DMARC, deliberately set `X-Priority: 1`) combined with a domain-naming pattern that matches HC3's independently reported regional observations almost keyword-for-keyword. This is a stronger basis than pretext similarity alone, and is consistent with these three emails coming from the same campaign, toolkit, or phishing-kit template — whether operated by one individual, a small team, or a criminal service used by multiple operators.

What the evidence does not support: the specific identity of any threat actor or group, their location, or their affiliation. It also does not establish whether MedDefense was deliberately and individually researched and chosen, or is simply one of several healthcare organizations hit by the same semi-automated kit described in the HC3 alert — the "opportunistic," reused-template nature of E7 (and E3, by the same technical family) argues for at least partial automation rather than entirely bespoke, hand-crafted targeting, even though E2 and E5 show more specific internal-process knowledge. Financial motive (credential resale, direct payment fraud) is the most consistent read given the observed objectives, but this cannot be elevated to a confirmed motive without further evidence. No specific actor, group name, or nation-state affiliation should be inferred from this batch alone.

### Conclusion

The shared technical fingerprint across E2, E5 and E7 — identical mailer software, absent DKIM, failed DMARC, deliberately elevated message priority, and a domain-keyword pattern that matches HC3's regional advisory almost exactly — is sufficient to treat these three emails as connected components of a single coordinated phishing effort against MedDefense, rather than three unrelated, coincidentally similar attacks. The connection is supported at the level of tooling, technique, and targeting strategy; it is not, on this evidence alone, sufficient to name or characterize the actor behind it, and this report does not attempt to.
