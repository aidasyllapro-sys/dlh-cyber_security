MedDefense Health Systems: The Email Authentication Analysis
Prepared by: Aïda Sylla, Security Analyst
Prepared for: James Chen, SOC Lead
Source material: `meddefense-email-evidence-batch.txt` — `Authentication-Results` header of each of the 8 emails, read as given, not recomputed
Purpose: Validate SPF, DKIM and DMARC for all 8 emails and state what each result actually proves and does not prove. SPF confirms whether the sending IP is authorized for the envelope-from domain. DKIM confirms whether the message was cryptographically signed by the domain named in the signature. DMARC checks whether SPF or DKIM aligns with the visible `From:` domain and reports the policy the sending domain has published. None of the three confirms that an email is safe to act on — they only confirm that a domain authorized its own infrastructure to send, which a malicious actor can do just as validly for a domain they themselves registered.

---

## Email 1 — healthcare-education-weekly.com

- SPF: pass — sender IP 198.51.100.42 is authorized in `healthcare-education-weekly.com`'s SPF record for `smtp.mailfrom=healthcare-education-weekly.com`.
- DKIM: pass — signed by `header.d=healthcare-education-weekly.com`, selector `mail01`. The signing domain matches the sending domain.
- DMARC: pass, `action=none` (policy `p=none` observed, no enforcement requested) — SPF/DKIM both align to `header.from=healthcare-education-weekly.com`, the same domain as the visible `From:` address.
- Authentication verdict: Supports legitimacy. All three mechanisms pass on a self-consistent domain that matches the `From:` header, with no lookalike substitution anywhere in the chain.
- Investigation meaning: No authentication-based reason to treat this message as a threat. Combined with the bulk-mailer signature and genuine unsubscribe mechanism already noted in triage, this is consistent with a legitimate opt-in newsletter.

## Email 2 — meddefense-portal.com

- SPF: fail — sender IP 91.234.99.107 is not authorized for `smtp.mailfrom=meddefense-portal.com`. The domain's own SPF record rejects this sending IP.
- DKIM: none — the message carries no DKIM signature at all (`header.d=none`), so there is no cryptographic proof of origin or integrity.
- DMARC: fail, `action=none` (policy is not set to enforce, so the message was not blocked or quarantined despite failing) — `header.from=meddefense-portal.com` fails alignment because neither SPF nor DKIM passed for that domain.
- Authentication verdict: Contradicts legitimacy. Every mechanism fails, and the domain itself — `meddefense-portal.com` — is not `meddefense.com` in the first place, so even a full pass would not have made this MedDefense-authorized mail.
- Investigation meaning: Authentication failure corroborates the header analysis conclusion that this message did not originate from MedDefense IT. The weak `action=none` DMARC policy on this lookalike domain is itself notable: it allowed the message through instead of being rejected or quarantined at the gateway.

## Email 3 — outlook-protection.com

- SPF: pass — sender IP 51.38.42.17 is authorized in `outlook-protection.com`'s own SPF record for `smtp.mailfrom=outlook-protection.com`.
- DKIM: pass — signed by `header.d=outlook-protection.com`, selector `default`. The signature validates against that domain's published key.
- DMARC: pass, `action=none` — SPF and DKIM both align to `header.from=outlook-protection.com`.
- Authentication verdict: Does not support legitimacy, despite passing every check. `outlook-protection.com` is a domain the sender registered and configured themselves; it is not `microsoft.com` and not `outlook.com`, and it has no relationship to either. SPF, DKIM and DMARC only ever validate that a domain's owner authorized the infrastructure that sent the message — they say nothing about who owns the domain or whether the domain is entitled to use the Microsoft name. A malicious actor who controls their own domain can configure all three correctly, exactly as has happened here, which produces a fully "passing" result for mail that is not from Microsoft in any sense.
- Investigation meaning: This is the case in the batch where authentication results must not be used as a legitimacy signal on their own. The right question is not "did it pass?" but "which domain passed, and does that domain have any real relationship to the brand it claims?" Here the answer is no, so the passing result should be read as a well-configured phishing domain, not as a safe sender.

## Email 4 — meddefense.com (internal)

- SPF: pass — sender IP 10.10.1.15 is MedDefense's own internal Exchange hub, authorized for `smtp.mailfrom=meddefense.com`.
- DKIM: pass — signed by `header.d=meddefense.com`, selector `selector1`, MedDefense's own signing key.
- DMARC: pass, `action=none` — SPF and DKIM both align to `header.from=meddefense.com`, the organization's real domain.
- Authentication verdict: Supports legitimacy. This is the one internal baseline in the batch: real domain, real internal sending IP, real signature, full alignment.
- Investigation meaning: Establishes what a genuine MedDefense-originated message looks like at the authentication layer, useful as the reference point against which E2's and E7's MedDefense-impersonating lookalike domains can be directly contrasted.

## Email 5 — medequip-supplies.net

- SPF: softfail — the sending IP 185.176.43.22 is not a full authorization match against `medequip-supplies.net`'s SPF record; the domain's policy marks this as suspicious rather than outright rejecting it.
- DKIM: none — no signature present (`header.d=none`), so there is no cryptographic proof this message came from an authorized `medequip-supplies.net` system.
- DMARC: fail, `action=none` — `header.from=medequip-supplies.net` fails alignment since neither SPF passed cleanly nor DKIM was present, and the domain's policy does not enforce rejection or quarantine.
- Authentication verdict: Contradicts legitimacy. A softfail plus an absent signature plus a failed, unenforced DMARC policy is a weak authentication posture for a domain claiming an active, several-thousand-dollar billing relationship.
- Investigation meaning: Authentication alone does not prove this is fraudulent, but it removes any technical basis for trusting the sender identity, and it aligns with the `Reply-To` mismatch and infrastructure findings already documented in the header analysis.

## Email 6 — canadian-pharma-discount.org

- SPF: softfail — the sending infrastructure does not cleanly match `canadian-pharma-discount.org`'s SPF authorization.
- DKIM: none — the message is unsigned.
- DMARC: fail, `action=quarantine` — this is the only email in the batch where the domain's own DMARC policy requests quarantine on failure, and the gateway's spam filter independently scored the message 9.8 out of a 5.0 threshold.
- Authentication verdict: Contradicts legitimacy, consistent with the domain's own stated intent for failing mail (quarantine).
- Investigation meaning: Authentication failure here supports the triage classification of unsolicited bulk spam rather than a targeted phishing attempt — the sending domain expects and plans for its own mail to fail these checks.

## Email 7 — meddefense-benefits.org

- SPF: fail — sender IP 164.90.218.73 is not authorized for `smtp.mailfrom=meddefense-benefits.org`.
- DKIM: none — no signature present (`header.d=none`).
- DMARC: fail, `action=none` — `header.from=meddefense-benefits.org` fails alignment, and the lookalike domain's policy does not enforce rejection despite the failure.
- Authentication verdict: Contradicts legitimacy. Same full-failure pattern as E2: no valid SPF, no DKIM, failed DMARC, on a domain that is not `meddefense.com`.
- Investigation meaning: Authentication failure corroborates that this is not a genuine MedDefense HR communication, consistent with the header analysis and with the recipient's own account of never having signed up for this service.

## Email 8 — hhs.gov

- SPF: pass — sender IP 134.174.47.82 is authorized for `smtp.mailfrom=hhs.gov` via HHS's own secure mail gateway.
- DKIM: pass — signed by `header.d=hhs.gov`, selector `hhs2026`.
- DMARC: pass, `action=none` — SPF and DKIM both align to `header.from=hhs.gov`, the genuine HHS domain.
- Authentication verdict: Supports legitimacy. Full pass on the real, verifiable government domain that owns this advisory function, addressed to a distribution list rather than an individual target.
- Investigation meaning: No authentication-based reason for concern. This message can be treated as a genuine sector alert rather than a lure, and read on its own technical merits.

## Summary Table

| Email | SPF | DKIM | DMARC (action) | Authentication verdict |
|---|---|---|---|---|
| E1 | pass | pass | pass (none) | Supports legitimacy |
| E2 | fail | none | fail (none) | Contradicts legitimacy |
| E3 | pass | pass | pass (none) | Passes, but does not support legitimacy — wrong domain entirely |
| E4 | pass | pass | pass (none) | Supports legitimacy |
| E5 | softfail | none | fail (none) | Contradicts legitimacy |
| E6 | softfail | none | fail (quarantine) | Contradicts legitimacy |
| E7 | fail | none | fail (none) | Contradicts legitimacy |
| E8 | pass | pass | pass (none) | Supports legitimacy |
