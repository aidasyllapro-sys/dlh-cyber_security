MedDefense Health Systems: The IOC Extraction Prepared by: Aïda Sylla, Security Analyst Prepared for: James Chen, SOC Lead Source material: Findings from tasks 1 (header analysis), 2 (authentication analysis), 3 (social engineering analysis), 4 (URL/attachment autopsy), 8 (verdict matrix) and 9 (campaign thread) for E2, E3, E5 and E7, cross-referenced against E8's HC3 sector alert Purpose: Consolidate every indicator of compromise surfaced across this investigation into one structured, shareable report, separating indicators safe to act on automatically (block) from indicators that need a human in the loop (alert, monitor) or exist only to explain the campaign (context only). No indicator below is asserted beyond what a prior task already established — this file adds structure and confidence grading, not new findings.

Note on scope: all domains and IPs in this batch are lab-fabricated evidence. The confidence and action ratings below describe what the evidence pattern would justify against a real detection stack, not a live reputation check against these specific values.

1. Structured IOC Table
#	IOC Type	IOC Value (defanged)	Source Email	Context	Confidence	Recommended Action
1	Domain	meddefense-portal[.]com	E2	Hyphenated lookalike of meddefense.com; fails SPF/DKIM/DMARC; unauthorized to send as MedDefense (task 1, 2).	HIGH	Block (domain + web/email gateway)
2	IP	91.234.99.107	E2	External sending IP / relay for meddefense-portal.com; plain unencrypted ESMTP (task 1).	HIGH	Block (email gateway, firewall)
3	URL	hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1	E2	Credential-harvesting link; per-recipient token in query string; confirmed clicked by Diane Marsh 14m41s after delivery (task 4, 7).	HIGH	Block (web proxy/URL filter)
4	Email address	noreply@meddefense-portal[.]com	E2	Sender/Return-Path address on the lookalike domain (task 1).	HIGH	Block / alert on inbound
5	Domain	outlook-protection[.]com	E3	Microsoft-brand impersonation on unrelated domain; SPF/DKIM/DMARC pass for this domain only, not for Microsoft (task 1, 2).	HIGH	Block (domain + web/email gateway)
6	IP	51.38.42.17	E3	External sending IP / relay for outlook-protection.com (task 1).	HIGH	Block (email gateway, firewall)
7	URL	hxxps://outlook-protection[.]com/verify	E3	Credential-harvesting "Verify account" link styled to imitate Microsoft (task 4).	HIGH	Block (web proxy/URL filter)
8	Email address	security@outlook-protection[.]com	E3	Sender/Return-Path address impersonating "Microsoft Account Protection" (task 1).	HIGH	Block / alert on inbound
9	Infrastructure note	Originating host wp-admin.outlook-protection.com (WordPress admin path)	E3	Message submitted from a WordPress installation, not a Microsoft mail platform; same naming convention reused in E7 (task 1, 9).	MEDIUM	Context only (supports attribution/pattern-matching, not a standalone blocklist entry)
10	Domain	medequip-supplies[.]net	E5	Invoice-fraud domain; SPF softfail, DKIM none, DMARC fail; Reply-To diverges from From (task 1, 2).	HIGH	Block (domain + web/email gateway)
11	IP	185.176.43.22	E5	External sending IP / relay for medequip-supplies.net (task 1).	HIGH	Block (email gateway, firewall)
12	URL	hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891	E5	Direct "pay now" link driving the invoice-fraud pretext (task 4).	HIGH	Block (web proxy/URL filter)
13	URL	hxxps://medequip-supplies[.]net/portal/login	E5	Secondary "portal login" link to the same fraud destination (task 4).	HIGH	Block (web proxy/URL filter)
14	Email address	invoices@medequip-supplies[.]net	E5	Sender/From address on the fraud domain (task 1).	HIGH	Block / alert on inbound
15	Email address	billing@medequip-supplies[.]net	E5	Reply-To address, distinct from the From address — replies are silently redirected here (task 1).	HIGH	Block / alert on inbound
16	File/attachment artifact	INV-2026-04891.pdf (PDF /S/URI object embeds Indicator 12's payment URL; anomalous trailing text resembling a SHA-256 hash outside normal PDF object structure)	E5	Attachment duplicates the phishing URL inside an embedded link object, giving the lure a second delivery path if the body link is stripped (task 4).	HIGH	Alert (attachment/content filter rule on embedded-URI-matches-known-bad-domain); do not open or execute
17	Domain	meddefense-benefits[.]org	E7	Lookalike of meddefense.com; fails SPF/DKIM/DMARC; recipient denies ever signing up for the service (task 1, 2).	HIGH	Block (domain + web/email gateway)
18	IP	164.90.218.73	E7	External sending IP / relay for meddefense-benefits.org (task 1).	HIGH	Block (email gateway, firewall)
19	URL	hxxps://meddefense-benefits[.]org/enroll	E7	Credential-harvesting "COMPLETE ENROLLMENT" link (task 4).	HIGH	Block (web proxy/URL filter)
20	Email address	hr-notifications@meddefense-benefits[.]org	E7	Sender/From address impersonating internal HR (task 1).	HIGH	Block / alert on inbound
21	Email address	no-reply@meddefense-benefits[.]org	E7	Reply-To address, distinct from the From address (task 1).	HIGH	Block / alert on inbound
22	Infrastructure note	Originating host wp-portal.meddefense-benefits.org (WordPress path)	E7	Same wp--prefixed naming convention as E3's wp-admin.outlook-protection.com — shared kit/template pattern across two unrelated-looking lures (task 1, 9).	MEDIUM	Context only
23	Tool / sending-software fingerprint	PHPMailer 6.6.0 (X-Mailer header; Message-ID pattern PHP-<hex>@<sending domain>)	E2, E3, E5, E7	Identical mailer fingerprint across all four suspicious emails, submitted from localhost on each domain's own server — a shared toolkit signature, not unique to any one sender (task 1, 9).	MEDIUM	Monitor (useful as a detection rule input — e.g. alert on inbound X-Mailer: PHPMailer combined with failed DMARC on an external domain claiming internal identity — not a blocklist entry by itself, since PHPMailer is also used by countless legitimate senders)
24	Infrastructure note	Hosting pattern: budget VPS providers named by HC3 (Hostinger, DigitalOcean pricing tiers)	E8 (HC3 alert)	HC3's own description of the campaign's hosting; not independently confirmed against this batch's fabricated IPs (task 4, 9).	LOW	Context only — do not block a hosting provider; broadly shared infrastructure used by legitimate customers too
25	Behavioral/pattern indicator	Domain-keyword pattern: portal, benefits, supplies, login in hostname	E2, E5, E7 (matched); E8 (HC3-reported keyword list)	All three of the trio's domains land on a keyword HC3 independently lists as observed in the regional campaign (task 9).	MEDIUM	Monitor — useful as a detection/hunting rule (e.g. newly-registered domain alert containing these keywords plus the organization's own brand), not a blocklist entry since these are common English words
26	Behavioral/pattern indicator	X-Priority: 1 (Highest) forced on all three (E2 additionally sets X-MSMail-Priority: High / Importance: High)	E2, E5, E7	Deliberate, shared technical choice to force apparent urgency regardless of body wording (task 9).	LOW	Context only — priority headers are trivially spoofable and common in legitimate mail too; useful only as a secondary scoring signal
27	Context-only comparator	HC3 advisory patterns: newly-registered lookalike domains (<30 days), PHPMailer/budget-VPS sending, 24–48h urgency windows, role-specific targeting of clinical/billing/HR staff	E8	Regional sector alert used to corroborate (not establish) the campaign link across E2/E5/E7; registration age and hosting provider could not be independently confirmed in this batch (task 4, 9).	N/A (reference intel, not an actionable IOC)	Context only — retain for situational awareness and to validate future indicators, not for blocking
2. Categorized by Attack Phase

Delivery (infrastructure that got the message into the inbox)

Domains: meddefense-portal[.]com (#1), outlook-protection[.]com (#5), medequip-supplies[.]net (#10), meddefense-benefits[.]org (#17)
IPs: 91.234.99.107 (#2), 51.38.42.17 (#6), 185.176.43.22 (#11), 164.90.218.73 (#18)
Sender/Reply-To addresses: #4, #8, #14, #15, #20, #21
Tool fingerprint: PHPMailer 6.6.0 (#23)

Credential harvesting (the destination the victim was pushed toward)

URLs: #3 (E2), #7 (E3), #12 and #13 (E5), #19 (E7)

Attachment or lure artifact

INV-2026-04891.pdf and its embedded payment URI (#16)

Infrastructure (hosting/build patterns linking otherwise-separate lures)

wp-admin.outlook-protection.com / wp-portal.meddefense-benefits.org naming convention (#9, #22)
Budget VPS hosting pattern per HC3 (#24)
Domain-keyword pattern (#25)

Context-only indicators (explain the campaign, not individually actionable)

Forced X-Priority headers (#26)
HC3 advisory comparator patterns (#27)
PHPMailer fingerprint (#23) and the domain-keyword pattern (#25) are listed twice above deliberately: they're real, evidence-backed links between the four emails, but they are pattern indicators, not unique-value IOCs, so they belong in a detection rule rather than a blocklist.
3. IOC Quality Assessment

High-confidence, safe to block directly — the 12 domain/IP pairs plus their associated URLs and sender/reply-to addresses (#1–8, #10–15, #17–21). Each is tied to a specific email with failed or self-serving authentication (SPF/DKIM/DMARC either fails outright, or "passes" only for a domain the organization does not own), a credential-harvesting or payment-fraud destination, and no legitimate business relationship to MedDefense. These are narrow, unique values — blocking them carries essentially no false-positive risk, because no legitimate MedDefense traffic would ever touch meddefense-portal.com, outlook-protection.com, medequip-supplies.net, or meddefense-benefits.org.

Should only be monitored, not blocked outright:

PHPMailer 6.6.0 / the PHP-<hex>@<domain> Message-ID pattern (#23) — PHPMailer is one of the most widely deployed open-source mail libraries on the internet; a huge volume of legitimate transactional mail uses it. Blocking on this signature alone would generate significant false positives. It is valuable only as one input into a composite detection rule (e.g., PHPMailer fingerprint + failed DMARC + a From: domain resembling the organization's own).
The portal / benefits / supplies / login keyword pattern (#25) — these are common English words that appear in countless legitimate domains. Useful for a newly-registered-domain hunting rule scoped to lookalikes of MedDefense's own brand, not as a standalone block list.
The wp- hostname naming convention (#9, #22) — WordPress is extremely common infrastructure; the convention is only meaningful in combination with the lookalike domain and failed authentication it appears alongside.

Should not be used alone, because they would create false positives:

X-Priority: 1 (Highest) and related urgency headers (#26) — many legitimate senders (including internal IT and executive mail) mark messages high-priority. On its own this header proves nothing.
HC3's budget-VPS hosting observation (#24) — Hostinger and DigitalOcean host millions of legitimate customers; blocking or even heavily weighting on hosting provider alone would be indiscriminate and is explicitly a "cannot independently confirm" item in this batch (task 4, 9).
Domain "registration age under 30 days" as described by HC3 — not independently verifiable in this batch at all (the fabricated domains returned no WHOIS record), so it is not listed as a standalone IOC row above; it is folded into the context-only HC3 comparator (#27) and should never be the sole trigger for a block, since many legitimate domains are also newly registered.

Not an IOC at all, retained for reference only:

The HC3 advisory itself (#27) and its described patterns. It corroborates the campaign link across E2/E5/E7 (three of the four domains match HC3's own listed keywords almost exactly) but should not be cited to a downstream defender as a technical indicator to block — it's threat intelligence context that helps interpret the other rows, not something to feed a blocklist.
4. HC3-Ready Summary

For distribution to regional healthcare-sector peers via HC3, or for immediate ingestion into MedDefense's own email/web gateway blocklists:

Domains to block:

meddefense-portal[.]com
outlook-protection[.]com
medequip-supplies[.]net
meddefense-benefits[.]org

IPs to block:

91.234.99.107
51.38.42.17
185.176.43.22
164.90.218.73

Sender addresses to block/alert on:

noreply@meddefense-portal[.]com
security@outlook-protection[.]com
invoices@medequip-supplies[.]net / billing@medequip-supplies[.]net (Reply-To)
hr-notifications@meddefense-benefits[.]org / no-reply@meddefense-benefits[.]org (Reply-To)

URLs to block:

hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1
hxxps://outlook-protection[.]com/verify
hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891
hxxps://medequip-supplies[.]net/portal/login
hxxps://meddefense-benefits[.]org/enroll

Composite detection rule for peers to consider (not a standalone block): inbound mail bearing X-Mailer: PHPMailer and failing DMARC while the From: domain lexically resembles the recipient organization's own brand or a well-known vendor/brand name, especially where the hostname contains portal, benefits, supplies, or login — matching HC3's independently reported regional pattern.

Caveat for anyone reusing this list: all values above are drawn from a single organization's four-email sample; none have been independently re-confirmed via live WHOIS/DNS/VirusTotal lookups (this batch's infrastructure is lab-fabricated and does not resolve). Recipients of this summary should treat the domain/IP/URL/address values as high-confidence within this incident, and re-validate registration/hosting details against their own live OSINT tooling before wider distribution.
