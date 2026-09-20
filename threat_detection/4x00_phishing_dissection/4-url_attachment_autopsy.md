MedDefense Health Systems: The URL and Attachment Autopsy
Prepared by: Aïda Sylla, Security Analyst
Prepared for: James Chen, SOC Lead
Source material: `meddefense-email-evidence-batch.txt` — raw HTML/text bodies and MIME attachment section of E2, E3, E5 and E7, plus the E6 link required as a mandatory indicator
Purpose: Safely document every suspicious URL and attachment indicator without navigating to any link or opening any attachment on a workstation. Every URL below is defanged before being written down, and every attachment is analyzed only through metadata and content visible in the raw evidence — never opened or executed.

Method: For each indicator, the safe investigation method described is the standard analyst workflow (WHOIS for domain registration age, `dig`/`nslookup` for current DNS resolution and hosting, `curl -I` run only from an isolated sandbox or scanning service rather than a production workstation, urlscan.io for an isolated visual/content scan, VirusTotal for domain/URL/file-hash reputation). Because this batch's domains and IPs are lab-fabricated evidence rather than live infrastructure, findings below are drawn from the evidence file itself, as the task instructions direct when a live lookup would not resolve.

---

## Indicator 1

- Source email: E2
- Original value: `https://meddefense-portal.com/verify/staff?id=dmarsh&token=a8f3e2d1`
- Defanged value: `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`
- Domain or IP: `meddefense-portal.com`
- Indicator type: Credential-harvesting link
- Evidence from email: Embedded in a "VERIFY MY ACCESS NOW" button under a 24-hour lockout threat; the query string carries the recipient's username (`id=dmarsh`) and a token, consistent with a link designed to pre-fill or track a fake login form per victim.
- Safe investigation method: WHOIS lookup on `meddefense-portal.com` to check registration age; `dig`/`nslookup` to identify current hosting; urlscan.io isolated scan of the full URL (never visited directly); VirusTotal URL and domain reputation check.
- Finding: The domain is a hyphenated lookalike of `meddefense.com`, already confirmed in task 1 to fail SPF/DKIM/DMARC and to be sent from external IP `91.234.99.107`, not from any MedDefense-owned or -delegated infrastructure. Per the batch's own collection notes, this domain and IP appear only in E2 — no reuse against the other three suspicious emails.
- Risk rating: HIGH

## Indicator 2

- Source email: E3
- Original value: `https://outlook-protection.com/verify`
- Defanged value: `hxxps://outlook-protection[.]com/verify`
- Domain or IP: `outlook-protection.com`
- Indicator type: Credential-harvesting link (brand impersonation)
- Evidence from email: Embedded in a "Verify account" button styled to match Microsoft's visual identity, under a 48-hour lockout threat following a fabricated "unusual sign-in" alert.
- Safe investigation method: WHOIS lookup on `outlook-protection.com` to confirm it is independently registered and unrelated to `microsoft.com`; `dig`/`nslookup` for current DNS resolution and hosting provider; urlscan.io isolated scan; VirusTotal domain/URL reputation check.
- Finding: The domain is entirely unrelated to Microsoft despite the branding — it is a separate registration that only resembles the real brand in name. Task 1 already established that its originating hostname (`wp-admin.outlook-protection.com`) is consistent with a WordPress installation, not Microsoft's mail platform. No IP reuse with the other three suspicious emails.
- Risk rating: HIGH

## Indicator 3

- Source email: E5
- Original value: `https://medequip-supplies.net/invoices/pay?id=INV-2026-04891` (also duplicated as `https://medequip-supplies.net/portal/login`)
- Defanged value: `hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891` (also `hxxps://medequip-supplies[.]net/portal/login`)
- Domain or IP: `medequip-supplies.net`
- Indicator type: Payment/credential-harvesting link (invoice fraud)
- Evidence from email: Two separate links pushing toward the same payment outcome — a direct "pay now" link and an alternate "portal login" link — inside an invoice email demanding USD 24,716.38 within 7 days with a late-fee threat.
- Safe investigation method: WHOIS lookup on `medequip-supplies.net` to check registration age against the claimed "established supplier" relationship; `dig`/`nslookup` for hosting; urlscan.io isolated scan of both link paths; VirusTotal domain/URL reputation check.
- Finding: The domain fails SPF (softfail) and DMARC and carries no DKIM signature (task 2), and its `Reply-To` mailbox diverges from its `From` address (task 1) — both consistent with a supplier identity that is not what it claims. No IP reuse with E2, E3, or E7.
- Risk rating: HIGH

## Indicator 4

- Source email: E5
- Original value: attachment `INV-2026-04891.pdf`, `Content-Type: application/pdf`, delivered as a base64-encoded MIME part
- Defanged value: Not applicable — this is a file attachment, not a URL, and is not opened
- Domain or IP: Not applicable (attachment indicator)
- Indicator type: Malicious/fraudulent attachment (suspected)
- Evidence from email: The PDF's declared filename mirrors the invoice number in the email body (`INV-2026-04891`), reinforcing the invoice pretext. Decoding the base64 stream at the metadata level (without rendering or opening the file) shows an embedded link object (`/S/URI`) pointing to the same `medequip-supplies.net/invoices/pay?id=INV-2026-04891` payment URL found in Indicator 3 — meaning the PDF itself, not just the email body, carries the phishing link. The stream also contains a trailing text marker resembling a SHA-256 hash outside the normal PDF object structure, which is not how a hash would legitimately appear inside a PDF generated by standard invoicing software.
- Safe investigation method: Extract metadata only with `pdfinfo` and `exiftool` (creation date, producer, embedded URI objects) — never open or render the file. Compute the file's SHA-256 hash and check it against VirusTotal's hash-reputation lookup, which does not require uploading the file. Never execute, preview, or print the attachment on an analyst workstation.
- Finding: A PDF invoice that embeds a clickable payment link duplicating the email body's link is a known technique to give a phishing lure a second route to the same destination if the primary email link is stripped or distrusted, and is not standard behavior for a routine vendor invoice.
- Risk rating: HIGH

## Indicator 5

- Source email: E7
- Original value: `https://meddefense-benefits.org/enroll`
- Defanged value: `hxxps://meddefense-benefits[.]org/enroll`
- Domain or IP: `meddefense-benefits.org`
- Indicator type: Credential-harvesting link
- Evidence from email: Embedded in a "COMPLETE ENROLLMENT" button under a same-day ("closes tomorrow") deadline, paired with a coverage-lapse threat.
- Safe investigation method: WHOIS lookup on `meddefense-benefits.org` to check registration age; `dig`/`nslookup` for hosting; urlscan.io isolated scan; VirusTotal domain/URL reputation check.
- Finding: The domain is a lookalike of `meddefense.com`, fails SPF/DKIM/DMARC (tasks 1–2), and its originating hostname (`wp-portal.meddefense-benefits.org`) follows the same WordPress-style naming convention already observed on the `outlook-protection.com` infrastructure in E3 — a shared pattern across two otherwise unrelated-looking lures. No IP reuse with E2, E3, or E5.
- Risk rating: HIGH

## Indicator 6

- Source email: E6 (included as a required indicator; E6 was classified `SPAM`, not `SUSPICIOUS`, during triage)
- Original value: `http://203.0.113.228/shop?ref=pwhite`
- Defanged value: `hxxp://203[.]0[.]113[.]228/shop?ref=pwhite`
- Domain or IP: `203.0.113.228`
- Indicator type: Bare-IP link (unsolicited bulk advertising)
- Evidence from email: The link uses a raw IP address with no accompanying domain name at all, embedded in a "CLICK HERE TO BUY NOW" call to action inside an unsolicited pharmaceutical advertisement already carrying a gateway spam score of 9.8 (threshold 5.0).
- Safe investigation method: `dig -x`/`nslookup` reverse lookup on the IP to check for any registered PTR record; VirusTotal IP reputation check; urlscan.io isolated scan if the link were ever pursued further. A WHOIS lookup on the IP block is the first step before any DNS query.
- Finding: `203.0.113.228` falls inside `203.0.113.0/24`, the block reserved by RFC 5737 for documentation and examples — it is not a real, routable internet address, so a live WHOIS or DNS lookup against it would not resolve to any actual hosting entity. A bare-IP link is itself a red flag independent of that: legitimate senders link to a named, DNS-registered domain, not a numeric address, which is a pattern more associated with low-effort scam infrastructure than with a targeted campaign.
- Risk rating: MEDIUM

---

## Cross-Indicator Findings

- No sending IP is reused across E2 (`91.234.99.107`), E3 (`51.38.42.17`), E5 (`185.176.43.22`), or E7 (`164.90.218.73`) — each suspicious email's link infrastructure sits on separate address space, so IP reuse cannot be used here to prove a single actor, even though the shared PHPMailer fingerprint and `wp-`-prefixed hostnames documented in task 1 point toward shared tooling.
- Every credential-harvesting link in E2, E3, and E7 follows the same shape: a display button, a lookalike domain matching the impersonated identity, and a short deadline in the surrounding body text — a consistent kit-level pattern rather than one-off, independently authored lures.
- E5 is the only indicator set where the malicious link appears in two channels at once (email body and embedded PDF object), which raises its practical risk even though its authentication posture (softfail rather than outright fail) is technically the weakest failure of the four suspicious emails.
