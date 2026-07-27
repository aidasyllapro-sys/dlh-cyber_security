# MedDefense Health Systems: The Certificate Anatomy

**Prepared by:** Aïda Sylla, Security Analyst **Source material:** Live `openssl s_client` connections captured directly on a Kali Linux workstation against letsencrypt.org, github.com, and expired.badssl.com, cross-referenced against Finding 005 and Finding 013 (1x02, the patient portal's weak TLS and expiring certificate) **Purpose:** Understand precisely what a browser checks in the milliseconds after a patient opens the MedDefense portal, before replacing the certificate that expires in 18 days.

---

## Part 1: Inspecting Three Certificates

### 1. Let's Encrypt (Domain Validated)

Real command and full output, captured directly:

```
$ echo | openssl s_client -connect letsencrypt.org:443 -servername letsencrypt.org 2>/dev/null | openssl x509 -text -noout
```

```
Serial Number: 05:05:bb:29:ef:e3:ee:15:2b:a3:e9:e6:87:28:10:b5:fe:b9
Signature Algorithm: ecdsa-with-SHA384
Issuer: C=US, O=Let's Encrypt, CN=YE2
Validity:
  Not Before: Jul  6 15:24:34 2026 GMT
  Not After : Oct  4 15:24:33 2026 GMT
Subject: CN=letsencrypt.org
Public Key Algorithm: id-ecPublicKey, 256 bit, ASN1 OID: prime256v1, NIST CURVE: P-256
Key Usage: critical, Digital Signature
Extended Key Usage: TLS Web Server Authentication
Subject Alternative Name: DNS:cp.letsencrypt.org, DNS:cp.root-x1.letsencrypt.org,
  DNS:cps.letsencrypt.org, DNS:cps.root-x1.letsencrypt.org, DNS:lencr.org,
  DNS:letsencrypt.com, DNS:letsencrypt.org, DNS:www.lencr.org,
  DNS:www.letsencrypt.com, DNS:www.letsencrypt.org
Authority Information Access: CA Issuers - URI:http://ye2.i.lencr.org/
CRL Distribution Points: URI:http://ye2.c.lencr.org/58.crl
```

**A directly observed confirmation of a fact this project's own Task 9 could only establish through research:** the Authority Information Access section above lists a CA Issuers URI only. **No OCSP URI appears anywhere in this real, live certificate.** This confirms directly, from an actual Let's Encrypt certificate issued in July 2026, that Let's Encrypt's OCSP shutdown (announced for August 2025) is a present, live fact, not a historical footnote; CRL Distribution Points, by contrast, is present, consistent with CRLs becoming the primary revocation mechanism industry-wide.

Validity period: 90 days exactly (July 6 to October 4, 2026), matching Let's Encrypt's standard lifetime precisely.

### 2. A commercial CA certificate: github.com (Domain Validated)

Real command and full output, captured directly:

```
$ echo | openssl s_client -connect github.com:443 -servername github.com 2>/dev/null | openssl x509 -text -noout
```

```
Serial Number: 72:01:0e:03:f4:a0:67:fe:4e:79:62:66:43:07:18:f6
Signature Algorithm: ecdsa-with-SHA256
Issuer: C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36
Validity:
  Not Before: Jul  3 00:00:00 2026 GMT
  Not After : Sep 30 23:59:59 2026 GMT
Subject: CN=github.com
Public Key Algorithm: id-ecPublicKey, 256 bit, ASN1 OID: prime256v1, NIST CURVE: P-256
Key Usage: critical, Digital Signature
Extended Key Usage: TLS Web Server Authentication
Authority Information Access:
  CA Issuers - URI:http://crt.sectigo.com/SectigoPublicServerAuthenticationCADVE36.crt
  OCSP - URI:http://ocsp.sectigo.com
Subject Alternative Name: DNS:github.com, DNS:www.github.com
```

**What this comparison already shows, before even reaching the broken example.** Both a free CA (Let's Encrypt) and a paid commercial CA (Sectigo, via GitHub) issue the same validation tier, Domain Validated, at nearly identical lifetimes (90 days versus 89 days), confirming the meaningful difference between them is not security strength. One concrete difference is directly visible in these two real captures, however: **Sectigo's certificate still publishes a live OCSP URI, while Let's Encrypt's does not.** This is a real, present-day illustration of the divided industry state this project's Task 9 already documented, different CAs are making different choices about OCSP now that it is optional rather than required.

### 3. A broken certificate: expired.badssl.com

Real commands and output, captured directly:

```
$ echo | openssl s_client -connect expired.badssl.com:443 -servername expired.badssl.com 2>/dev/null | openssl x509 -noout -subject -issuer
subject=OU=Domain Control Validated, OU=PositiveSSL Wildcard, CN=*.badssl.com
issuer=C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Domain Validation Secure Server CA

$ echo | openssl s_client -connect expired.badssl.com:443 -servername expired.badssl.com 2>/dev/null | openssl x509 -noout -dates
notBefore=Apr  9 00:00:00 2015 GMT
notAfter=Apr 12 23:59:59 2015 GMT
```

**What is wrong:** the certificate's validity window closed in April 2015, over a decade before this inspection; the subject confirms it is a wildcard certificate (`*.badssl.com`) issued through Domain Control Validation, otherwise structurally ordinary. A small, worth-noting detail: this certificate's issuer, **COMODO CA Limited**, is the same certificate authority that later rebranded as **Sectigo**, the exact CA that issued GitHub's certificate examined above; the two certificates in this document trace back to the same organizational lineage, over a decade apart, one current and one long expired.

---

## Part 2: The Broken Certificate

**What is precisely wrong.** For `expired.badssl.com`, exactly one property fails: the certificate's validity window closed in 2015. Everything else about the certificate, matching the correct hostname pattern, chaining to a real certificate authority (COMODO, now Sectigo), correctly signed throughout the chain, remains structurally valid; only the Not After date has passed, over ten years ago. This isolation is deliberate and is what makes badssl.com useful as a testing tool: it lets a developer confirm their software correctly rejects an expired certificate without that test being confused by a second, unrelated problem.

**What error a browser would display.** A modern browser presented with this certificate shows a full-page interstitial warning, in Chrome, "Your connection is not private," with the specific sub-message identifying the certificate as expired (`NET::ERR_CERT_DATE_INVALID`), not a passive notice; the browser actively blocks navigation to the page behind an additional "Advanced" click required to proceed.

**What risk this misconfiguration creates.** An expired certificate provides no evidence about whether the current connection is genuinely still going to the legitimate server; the mathematical encryption itself may still function, but the entire trust model TLS depends on, that a currently-valid, currently-trusted authority recently vouched for this specific key, is broken the moment the validity window closes, meaning a user clicking through the warning has no remaining basis to distinguish the real site from an attacker who has, for instance, compromised DNS and presented their own certificate instead.

**Would I advise a patient to proceed?** No, without qualification. For a healthcare patient portal specifically, handling protected health information under a legal, not merely technical, obligation to secure it, the correct guidance is to close the browser and contact MedDefense directly through a known phone number, not to click through a security interstitial that exists precisely to stop this action. This is not a hypothetical scenario for MedDefense: Finding 013 (1x02) already confirmed the patient portal's own certificate is on a 90-day Let's Encrypt lifecycle with no auto-renewal configured, expiring in a matter of days at the time of that assessment, meaning this exact browser warning, for this exact reason, is a real, near-term possibility for MedDefense's own patients if this project's remediation work does not complete first.

---

## Part 3: MedDefense Certificate Profile

**Certificate type: Domain Validated (DV), not Organization Validated (OV) or Extended Validation (EV).** This recommendation may be counterintuitive for a healthcare portal handling sensitive data, so the reasoning is stated directly: modern browsers no longer display the distinct visual indicators (the green address bar, the organization name) that once made EV certificates meaningfully different to an end user, meaning the primary historical benefit of OV or EV, visible trust signaling, no longer exists in current browser UI. Both real certificates examined in Part 1, Let's Encrypt (a free CA) and Sectigo (a commercial CA), are DV certificates protecting a major open-source infrastructure site and one of the world's largest software platforms respectively; DV is not a lesser choice, it is the current baseline for legitimate, high-traffic production sites.

**Certificate Authority: Let's Encrypt**, specifically because its 90-day validity period paired with the ACME protocol enables full automation (certbot or an equivalent ACME client renewing automatically well before expiration), directly closing the root cause behind Finding 013 in the first place: a manually-managed certificate with no auto-renewal configured. One tradeoff worth noting directly, now confirmed from a real, live certificate in Part 1 rather than documentation alone: Let's Encrypt no longer offers OCSP, so any MedDefense revocation-checking design should plan around CRL-based revocation rather than assuming OCSP stapling will be available for this specific CA going forward.

**SAN entries.** At minimum, the primary patient portal domain and its `www` variant should both be listed as Subject Alternative Names on a single certificate, since modern certificate validation relies entirely on the SAN extension, not the deprecated Common Name field. Both real certificates examined in Part 1 confirm this pattern directly: GitHub's own certificate lists exactly `github.com` and `www.github.com` as its two SAN entries, the same minimal, purpose-scoped pattern recommended here for MedDefense's portal.

**Key algorithm and size: ECDSA P-256.** Directly connecting back to this project's own Task 2 findings: ECC P-256 provides security equivalent to a much larger RSA key at a fraction of the computational cost, and both real certificates captured in Part 1 of this document, Let's Encrypt's own domain certificate and GitHub's production certificate, use exactly this key type in live production today, not merely a theoretical recommendation.

**Validity period: 90 days, matching Let's Encrypt's standard lifetime, with automated renewal configured to trigger at 30 days remaining.** A short lifetime is a deliberate security choice, not merely Let's Encrypt's default: it bounds how long a compromised private key remains usable and forces the renewal automation this project recommends to actually be exercised regularly, rather than configured once and never verified until it silently fails, precisely the gap already responsible for Finding 013.

**Wildcard or single-domain: single-domain (or a small, explicit SAN list), not a wildcard.** A wildcard certificate (`*.meddefense.example`) would also validate for any subdomain an attacker could stand up if any single subdomain's DNS or hosting were ever compromised. This is not a purely theoretical concern: the broken certificate examined directly in Part 1 of this document, `*.badssl.com`, is itself a wildcard certificate, and while its failure here is expiration rather than scope abuse, a wildcard's broader validation scope is a real, additional risk surface MedDefense does not need to accept when a small, explicit list of the specific hostnames actually in use covers every legitimate need.
