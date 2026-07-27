# MedDefense Health Systems: The TLS Audit

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** Live SSL Labs (Qualys) scan results, verified directly for this document, cross-referenced against Finding 005 and Finding 013 (1x02) and the Certificate Anatomy and Chain of Trust work (Tasks 8 and 9) **Purpose:** Finding 005 has sat on the remediation list for three weeks. This document builds the understanding needed to close it correctly, using real data from real production sites, not assumptions about what a good configuration looks like.

---

## Part 1: SSL Labs Analysis

**A genuinely useful pairing found in real, current SSL Labs results: the same organization, two different grades, for exactly the reason MedDefense's own portal is at risk.**

### Site 1: [www.cloudflare.com](http://www.cloudflare.com), Grade A+

Verified against a live SSL Labs report dated May 18, 2026:

```
Overall Grade: A+
Protocol Support: TLS 1.3 confirmed supported. No legacy protocol
  warning present, meaning TLS 1.0 and TLS 1.1 are not offered.
Key Exchange: PQC (Post-Quantum Cryptography) key exchange supported,
  placing this configuration ahead of standard current practice, not
  merely meeting it.
Certificate: EC 256 bits (SHA256withECDSA), confirming an ECDSA P-256
  certificate in production use at a major, high-traffic commercial
  site, the same key algorithm this project already recommended for
  MedDefense's own portal (Task 8, Task 10).
Additional Findings: HSTS with long duration deployed. DNS CAA policy
  found, restricting which Certificate Authorities may legitimately
  issue for this domain.
Warnings: None reported in this scan.
```

### Site 2: cloudflare.com (the bare apex domain), Grade B

Verified against a separately cached SSL Labs report for the same organization's apex domain:

```
Overall Grade: B, explicitly grade-capped rather than earned through a
  point deduction.
Protocol Support: "This server supports TLS 1.0 and TLS 1.1. Grade
  capped to B," stated directly in SSL Labs' own summary for this scan.
  TLS 1.3 is also supported on this same host, confirming the server is
  capable of strong protocol negotiation but is still permitted to fall
  back to two protocol versions considered obsolete.
Certificate and other findings: The same organization, same underlying
  infrastructure family, PQC key exchange and long-duration HSTS also
  present on this host.
Warnings: SSL Labs' own documented grading policy, verified directly:
  since January 2020, any server that still supports TLS 1.0 or TLS 1.1
  is automatically capped at a B grade, regardless of how strong every
  other part of its configuration is.
```

**Why this pairing matters more than two unrelated sites would.** This is not two different companies with two different security cultures; it is the exact same organization, and the entire difference between an A+ and a B grade here comes down to one specific configuration decision: whether legacy TLS versions remain enabled on a given host. This is the single clearest, most directly applicable real-world evidence available for MedDefense's own situation, since Finding 005 describes precisely this same condition.

---

## Part 2: MedDefense Portal Assessment

**Predicted grade: B, capped, for the identical reason just demonstrated on cloudflare.com's own apex domain.** SSL Labs' grading policy is explicit and directly confirmed above: any server supporting TLS 1.0 is automatically capped at B regardless of every other configuration strength. Finding 005 already confirms the portal supports TLS 1.0 alongside TLS 1.2, meaning this cap applies before any other factor is even considered.

**Every issue that would reduce the grade, drawn directly from this program's own prior findings:**

- **TLS 1.0 support (Finding 005):** applies the automatic B-grade cap discussed above, independent of any other strength in the configuration.
- **No TLS 1.3 support (Finding 005):** further reduces the protocol support sub-score even within the B-capped range, since Finding 005 confirms only TLS 1.0 and TLS 1.2 are offered, with no TLS 1.3 at all, unlike both cloudflare.com hosts examined in Part 1.
- **HSTS not configured (Finding 005):** SSL Labs' own scoring rewards HSTS deployment directly, confirmed present on both cloudflare.com hosts above; its absence on MedDefense's portal removes a positive scoring factor entirely, independent of the protocol cap.
- **OCSP Stapling not configured (Finding 005):** undocumented cipher suite configuration was flagged directly in Finding 005 ("likely includes weak cipher suites alongside strong ones"), and if any legacy or export-grade cipher suites remain enabled alongside the modern ones, SSL Labs' rating methodology can reduce the grade further still, independent of the protocol-version cap already applied.
- **Certificate near expiration (Finding 013):** a certificate within its final days of validity does not by itself change the letter grade, but SSL Labs displays an explicit, prominent expiration warning alongside the grade, and a certificate that expires between the scan and a patient's actual visit produces total connection failure, a materially worse outcome than a lowered letter grade.

**Bottom line for James Chen:** even if every other part of the patient portal's TLS configuration were flawless, Finding 005 alone caps this portal at a B grade under the exact same rule that governs cloudflare.com's own apex domain, and the missing TLS 1.3 support, missing HSTS, and undocumented cipher suites mean the realistic predicted outcome sits at the lower end of the B range or below, not merely a technical B.

---

## Part 3: The Hardened Configuration

Apache configuration, chosen since Finding 005's own scan output already confirms the portal runs on Apache:

apache

```apache
# MedDefense Patient Portal - Hardened TLS Configuration
# Closes Finding 005 (1x02) directly

# --- Protocol versions ---
# TLS 1.2 and TLS 1.3 only. TLS 1.0 and 1.1 are explicitly disabled,
# closing Finding 005 and removing the automatic SSL Labs B-grade cap
# demonstrated directly against cloudflare.com's own apex domain in
# Part 1 of this document.
SSLProtocol -all +TLSv1.2 +TLSv1.3

# --- Cipher suite selection, ordered by preference ---
# Server chooses the cipher, not the client, so a weaker client
# request cannot silently downgrade the negotiated cipher.
SSLHonorCipherOrder on

# TLS 1.3 ciphers (configured separately from the legacy directive
# below, since TLS 1.3 uses its own cipher suite negotiation):
# TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
# TLS_AES_128_GCM_SHA256 -- all three are AEAD (authenticated
# encryption) ciphers with no legacy CBC-mode option offered at all,
# since TLS 1.3 removed CBC support from the protocol itself.
SSLCipherSuite TLSv1.3 TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256

# TLS 1.2 ciphers, ordered by preference:
SSLCipherSuite TLSv1.2 ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256
# ECDHE-ECDSA-AES256-GCM-SHA384 first: matches this project's own
#   ECDSA P-256 certificate recommendation (Task 8, Task 10) and
#   provides forward secrecy via ECDHE, directly closing the plain-DH
#   MITM exposure this project's own Task 4 demonstrated.
# ECDHE-RSA-AES256-GCM-SHA384 second: an RSA-certificate fallback with
#   the same forward-secrecy and AEAD properties, in case an
#   RSA-issued certificate is ever used instead.
# ECDHE-ECDSA-CHACHA20-POLY1305 third: a strong alternative AEAD
#   cipher, valuable specifically because it performs well on clients
#   without AES hardware acceleration (Task 6 of this project already
#   recommended ChaCha20-Poly1305 for exactly this reason).
# ECDHE-RSA-AES128-GCM-SHA256 last: the minimum acceptable strength
#   still offered, retained only for broader compatibility, positioned
#   last so it is never chosen when a stronger option is available.
# Every cipher listed uses AEAD (GCM or Poly1305); no CBC-mode cipher
#   is offered at all under TLS 1.2, closing the same class of weakness
#   (padding-oracle attacks against CBC) independent of the TLS 1.0
#   removal above.

# --- HSTS header ---
# max-age set to 1 year (31536000 seconds), matching the "long
# duration" HSTS configuration directly confirmed on both cloudflare.com
# hosts in Part 1. includeSubDomains ensures no subdomain of the portal
# can be used to bypass this protection; preload signals eligibility
# for browser HSTS preload lists, closing the very first, unencrypted
# HTTP request a returning patient's browser might otherwise still make.
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

# --- Other hardening parameters ---

# Disable TLS session tickets. Session tickets, if the server's ticket
# key is ever compromised, can retroactively decrypt previously
# captured sessions; disabling them trades a small performance cost
# for removing this specific forward-secrecy exposure.
SSLSessionTickets off

# Disable client-initiated renegotiation entirely. Client-initiated
# renegotiation was the root cause of a well-documented TLS
# vulnerability (CVE-2009-3555) allowing session-splicing attacks; this
# server does not need to support it at all for normal portal operation.
SSLInsecureRenegotiation off

# OCSP Stapling. The server pre-fetches its own revocation status and
# includes it in the handshake, closing the OCSP-related gap this
# project's own Task 9 documented directly, and avoiding a client-to-CA
# round trip that both slows the connection and leaks which patients
# are visiting the portal to the CA operating the OCSP responder.
SSLUseStapling on
SSLStaplingCache "shmcb:logs/ssl_stapling(32768)"
```

**One-sentence reasoning for each choice is included inline above, directly beside the directive it explains**, rather than separated into a disconnected list, so the configuration file itself remains the reference document, not merely an example needing separate translation.

---

## Part 4: The Downgrade Attack

A TLS downgrade attack exploits the fact that, during the initial handshake, a client and server negotiate which protocol version to use, and if the server is willing to accept a weaker version at all, an attacker positioned on the network path can interfere with that negotiation to force the weaker choice even when both parties would otherwise have agreed on something stronger. Because MedDefense's portal currently supports both TLS 1.0 and TLS 1.2 (Finding 005), an attacker performing a man-in-the-middle position on the connection, the same positioning this project's Task 4 already demonstrated defeats an unauthenticated Diffie-Hellman exchange, can strip or interfere with the client's initial TLS 1.2 handshake attempt (a technique historically executed by manipulating the ClientHello message or exploiting fallback behavior many older TLS stacks implemented for compatibility), causing the connection to fall back to TLS 1.0, a protocol already broken by the BEAST attack since 2011 and directly flagged as such in this project's own Task 6 algorithm table. Once downgraded, the attacker can then attack the weaker protocol directly, exactly the exposure Finding 005 already documents as present today. **The simplest way to prevent this attack is exactly what Part 3's configuration already implements: disable TLS 1.0 and TLS 1.1 on the server entirely.** A protocol version that the server will never accept under any circumstance cannot be the target of a downgrade, since there is no negotiation outcome, however manipulated, that results in a connection the server is even willing to complete.
