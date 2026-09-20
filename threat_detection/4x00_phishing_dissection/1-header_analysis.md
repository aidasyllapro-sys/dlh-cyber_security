MedDefense Health Systems: The Header Analysis
Prepared by: Aïda Sylla, Security Analyst
Prepared for: James Chen, SOC Lead
Source material: `meddefense-email-evidence-batch.txt` — full raw SMTP source, headers intact, no redaction
Purpose: Parse the SMTP header chain of the four emails flagged `SUSPICIOUS` during triage (E2, E3, E5, E7) to establish their true origin and routing, independent of the `From:` display name. Every fact and conclusion below is derived exclusively from header fields present in the batch (`From:`, `Return-Path:`, `Received:`, `Authentication-Results:`, `DKIM-Signature:`, `Message-ID:`, `X-Mailer:`, `Reply-To:`) — no live Wazuh, Sysmon, Suricata, or endpoint telemetry, and no external OSINT lookups (WHOIS, VirusTotal, urlscan.io) are used to reach any conclusion in this file.

Method: For each email, the `Received:` chain is read bottom-to-top (oldest hop first) to reconstruct the true path from originating server to MedDefense's edge relay. The external hop — the first `Received:` line naming a public IP outside MedDefense's own infrastructure — is treated as the sending IP; internal MedDefense hops (`10.10.1.x`) are excluded from that determination. The `From:`, `Return-Path:`, and `Reply-To:` addresses are then compared against that infrastructure to surface identity/infrastructure mismatches.

---

## Email 2 — meddefense-portal.com

### Header Evidence

- From: `"MedDefense IT Security" (noreply@meddefense-portal.com)`
- Return-Path: `(noreply@meddefense-portal.com)`
- Sending IP: `91.234.99.107` (external hop: `mail.meddefense-portal.com`)
- X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- Message-ID: `(PHP-5D7E2F4A@meddefense-portal.com)`

### Received Chain Summary

1. Message submitted on `localhost` (127.0.0.1) via `mail.meddefense-portal.com` using PHPMailer 6.6.0 — Mon, 14 Apr 2026 19:47:48 +0000.
2. Relayed from `mail.meddefense-portal.com` (`91.234.99.107`) into MedDefense's edge (`mx01.meddefense.com`) over plain ESMTP — no TLS cipher negotiated or logged — Mon, 14 Apr 2026 14:47:51 -0500.
3. Internal handoff from `mx01.meddefense.com` (`10.10.1.20`) to `inbound-relay.meddefense.com` for delivery to `dmarsh@meddefense.com` — Mon, 14 Apr 2026 14:47:52 -0500.

### Anomalies

- [HIGH] Sending domain `meddefense-portal[.]com` is a hyphenated lookalike of the real `meddefense.com` — not owned or delegated by MedDefense.
- [HIGH] `spf=fail`, `dkim=none`, `dmarc=fail` — the message has zero authorization to represent any MedDefense-affiliated identity.
- [HIGH] External hop uses unencrypted plain ESMTP, unlike every genuinely legitimate sender in this batch (E1, E4, E8 all negotiate ESMTPS with a named TLS cipher suite).
- [MEDIUM] Sent through PHPMailer 6.6.0, a generic open-source scripting library — MedDefense's real internal system (E4) sends through Microsoft Exchange Server 2019.
- [MEDIUM] `Message-ID` follows PHPMailer's default auto-generated pattern (`PHP-` followed by a hex string, `@`, and the sending domain), consistent with a quickly stood-up phishing kit rather than a corporate IT/ticketing platform.

### Conclusion

Every technical indicator contradicts the claimed sender. The domain is an unauthorized lookalike, the message fails SPF, DKIM, and DMARC outright, delivery occurred over unencrypted plain ESMTP, and the sending infrastructure is a generic PHPMailer script rather than MedDefense's actual Exchange-based mail platform. Based on header evidence alone, this message did not originate from MedDefense IT.

---

## Email 3 — outlook-protection.com

### Header Evidence

- From: `"Microsoft Account Protection" (security@outlook-protection.com)`
- Return-Path: `(security@outlook-protection.com)`
- Sending IP: `51.38.42.17` (external hop: `mail.outlook-protection.com`)
- X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- Message-ID: `(PHP-9F2D7E1B@outlook-protection.com)`

### Received Chain Summary

1. Message submitted on `wp-admin.outlook-protection.com` (127.0.0.1 localhost) via PHPMailer 6.6.0 — Tue, 15 Apr 2026 14:13:40 +0000.
2. Relayed from `mail.outlook-protection.com` (`51.38.42.17`) into MedDefense's edge over ESMTPS (TLS1.2) — Tue, 15 Apr 2026 09:13:43 -0500.
3. Internal handoff from `mx01.meddefense.com` to `inbound-relay.meddefense.com` for delivery to `rmendez@meddefense.com` — Tue, 15 Apr 2026 09:13:44 -0500.

### Anomalies

- [HIGH] The display name impersonates Microsoft ("Microsoft Account Protection"), but the actual domain — `outlook-protection[.]com` — is not `microsoft.com`, `outlook.com`, or any Microsoft-owned property; it never appears anywhere in the header chain.
- [HIGH] The originating hostname is `wp-admin.outlook-protection.com` — `wp-admin` is WordPress's standard administration path, meaning this "Microsoft security" alert was submitted from a WordPress installation, not a Microsoft-operated mail platform.
- [HIGH] The `DKIM-Signature` `b=` value reads `TrustMeIHaveAValidSignatureFromOutlookProtectionDotCom7A2D4F1E...` — this is not a valid base64-encoded cryptographic signature, it is placeholder/joke text sitting where a real signature blob belongs.
- [MEDIUM] `spf=pass`, `dkim=pass`, `dmarc=pass` all validate cleanly — but only against the attacker-controlled `outlook-protection.com` DNS records. A clean authentication result here proves the domain is internally self-consistent, not that the sender is Microsoft; it must never be read as "safe" on its own.
- [MEDIUM] Sent via PHPMailer 6.6.0 rather than Microsoft's actual outbound infrastructure.

### Conclusion

The header evidence shows brand impersonation on infrastructure never associated with Microsoft: a WordPress-path hostname, a PHPMailer signature, and a `DKIM-Signature` field whose `b=` value is literally not a valid signature. The fully "passing" SPF/DKIM/DMARC result is the most dangerous element here, since it authenticates the attacker's own domain, not Microsoft — a header-reading analyst must check which domain passed, not only whether it passed.

---

## Email 5 — medequip-supplies.net

### Header Evidence

- From: `"MedEquip Supplies Billing" (invoices@medequip-supplies.net)`
- Return-Path: `(invoices@medequip-supplies.net)`
- Sending IP: `185.176.43.22` (external hop: `mail.medequip-supplies.net`)
- X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- Message-ID: `(PHP-7C2D4E1A@medequip-supplies.net)`

### Received Chain Summary

1. Message submitted on `billing-svc.medequip-supplies.net` (127.0.0.1 localhost) via PHPMailer 6.6.0 — Wed, 16 Apr 2026 16:28:35 +0000.
2. Relayed from `mail.medequip-supplies.net` (`185.176.43.22`) into MedDefense's edge over plain ESMTP — Wed, 16 Apr 2026 11:28:37 -0500.
3. Internal handoff from `mx01.meddefense.com` to `inbound-relay.meddefense.com` for delivery to `arivera@meddefense.com` — Wed, 16 Apr 2026 11:28:39 -0500.

### Anomalies

- [HIGH] `spf=softfail`, `dkim=none`, `dmarc=fail` — no cryptographic proof this message came from any system authorized by `medequip-supplies.net`.
- [MEDIUM] `Reply-To: (billing@medequip-supplies.net)` differs from the `From:` address (`invoices@medequip-supplies.net`) — replies are silently redirected to a different mailbox than the one that appears to have sent the message, a common invoice-fraud technique.
- [MEDIUM] Sent through PHPMailer 6.6.0 over unencrypted ESMTP, inconsistent with the polished, ongoing-vendor-relationship tone of the message body.

### Conclusion

Header evidence alone does not support an established supplier relationship: weak-to-failing authentication, a `Reply-To` mailbox that diverges from the sending address, and generic scripted-mailer infrastructure are all consistent with invoice fraud rather than a genuine MedEquip billing communication.

---

## Email 7 — meddefense-benefits.org

### Header Evidence

- From: `"MedDefense HR Benefits" (hr-notifications@meddefense-benefits.org)`
- Return-Path: `(hr-notifications@meddefense-benefits.org)`
- Sending IP: `164.90.218.73` (external hop: `mail.meddefense-benefits.org`)
- X-Mailer: `PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)`
- Message-ID: `(PHP-2E4A7B1C@meddefense-benefits.org)`

### Received Chain Summary

1. Message submitted on `wp-portal.meddefense-benefits.org` (127.0.0.1 localhost) via PHPMailer 6.6.0 — Thu, 16 Apr 2026 20:22:02 +0000.
2. Relayed from `mail.meddefense-benefits.org` (`164.90.218.73`) into MedDefense's edge over plain ESMTP — Thu, 16 Apr 2026 15:22:05 -0500.
3. Internal handoff from `mx01.meddefense.com` to `inbound-relay.meddefense.com` for delivery to `lpatterson@meddefense.com` — Thu, 16 Apr 2026 15:22:07 -0500.

### Anomalies

- [HIGH] The display name impersonates an internal department ("MedDefense HR Benefits"), but the domain — `meddefense-benefits[.]org` — is a lookalike, not `meddefense.com`, and is not delegated by it.
- [HIGH] `spf=fail`, `dkim=none`, `dmarc=fail` — identical authentication-failure pattern to E2, both claiming a MedDefense-affiliated identity from an unauthorized external domain.
- [MEDIUM] Originating hostname `wp-portal.meddefense-benefits.org` follows the same WordPress-based naming convention seen in E3 (`wp-admin.outlook-protection.com`), suggesting a shared phishing-kit template across otherwise unrelated-looking lures.
- [MEDIUM] `Reply-To: (no-reply@meddefense-benefits.org)` differs from the `From:` address (`hr-notifications@meddefense-benefits.org`).

### Conclusion

Like E2, this message fails every authentication check on a domain built to impersonate an internal MedDefense function. The header evidence — failed authentication, a mismatched `Reply-To`, and a domain never delegated by MedDefense — is sufficient on its own to conclude this is not a legitimate HR communication.

---

## Cross-Email Observations (header evidence only)

- **E2 and E7** share an identical authentication-failure signature (`spf=fail`, `dkim=none`, `dmarc=fail`) and both target a MedDefense-lookalike domain impersonating an internal function (IT / HR).
- **E3 and E7** share the same `wp-` prefixed hostname convention (`wp-admin.outlook-protection.com`, `wp-portal.meddefense-benefits.org`) despite impersonating unrelated brands.
- All four suspicious emails (E2, E3, E5, E7) are sent via **PHPMailer 6.6.0** from a `localhost`-submitted, single-hop external relay — a consistent sending-infrastructure fingerprint across every suspicious message in this batch, none of which matches MedDefense's own Microsoft Exchange-based internal mail seen in E4's headers.
