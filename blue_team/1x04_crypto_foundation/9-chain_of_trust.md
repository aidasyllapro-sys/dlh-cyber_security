# MedDefense Health Systems: The Chain of Trust

**Prepared by:** Aïda Sylla, Security Analyst **Source material:** A real GitHub.com certificate chain captured directly with OpenSSL on a Kali Linux workstation, and this same system's live root trust store, cross-referenced against the Certificate Anatomy work (Task 8) **Purpose:** Understand exactly how trust propagates from a root certificate a browser has never seen a human verify, down to the specific leaf certificate protecting a patient's connection, and what happens to that trust the moment one link is missing.

---

## Part 1: Capturing the Full Chain

**Command used:**

```
$ openssl s_client -connect github.com:443 -servername github.com -showcerts
```

**Real result: 3 certificates in the chain**, confirmed directly with `grep -c "BEGIN CERTIFICATE"` against the captured output, each extracted to its own file.

```
Certificate 0 (leaf):
  Role: The end-entity certificate, the one actually presented for the
    connection being made.
  Subject: CN=github.com
  Issuer:  C=GB, O=Sectigo Limited,
           CN=Sectigo Public Server Authentication CA DV E36

Certificate 1 (intermediate):
  Role: The certificate authority that signed the leaf, itself signed
    by a higher authority rather than being self-signed.
  Subject: C=GB, O=Sectigo Limited,
           CN=Sectigo Public Server Authentication CA DV E36
  Issuer:  C=GB, O=Sectigo Limited,
           CN=Sectigo Public Server Authentication Root E46

Certificate 2 (a second intermediate, not a true self-signed root,
  a distinction worth explaining directly since it is a real-world
  nuance a simpler example would miss):
  Subject: C=GB, O=Sectigo Limited,
           CN=Sectigo Public Server Authentication Root E46
  Issuer:  C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network,
           CN=USERTrust ECC Certification Authority
```

**How the Issuer of one matches the Subject of the next, confirmed exactly, character for character:** the leaf's Issuer field is identical to Certificate 1's Subject field. Certificate 1's Issuer field is identical to Certificate 2's Subject field. This exact-match chaining, verified here directly rather than assumed, is the entire mechanical basis of chain validation: a client walks this chain by matching Issuer to Subject one link at a time until it reaches a certificate already present in its own trust store.

**A genuinely important real-world detail this specific chain surfaces, that a simpler textbook example would not:** despite its name including "Root," Certificate 2 is **not self-signed**. Its Subject (`Sectigo Public Server Authentication Root E46`) is not identical to its Issuer (`USERTrust ECC Certification Authority`), meaning it is itself a cross-signed intermediate, not the actual trust anchor. The true self-signed root, USERTrust ECC Certification Authority, is not part of the chain GitHub's server sent at all; it is assumed to already exist in every client's trust store. This is common, legitimate practice: it lets a certificate authority transition or cross-sign under an older, more widely-trusted root while a newer root gradually gains distribution, and it means "the last certificate the server sends" is not always the actual trust anchor a client relies on.

---

## Part 2: Manual Chain Verification

**Verification with the full chain:**

```
$ openssl verify -CAfile 2_cert.pem -untrusted 1_cert.pem 0_cert.pem
0_cert.pem: OK
```

Note precisely what this command does, given Part 1's finding above: `-CAfile 2_cert.pem` tells `openssl verify` to trust Certificate 2 directly as a root for the purpose of this test, regardless of whether it is genuinely self-signed. This is a reasonable and standard way to test a chain, but it is worth distinguishing from what a real browser does, which would instead need to walk one additional step, from Certificate 2 up to USERTrust ECC Certification Authority, using its own trust store, since Certificate 2 is not actually a root a browser trusts on its own.

**Verification with the intermediate removed, leaf and (non-root) anchor only:**

```
$ openssl verify -CAfile 2_cert.pem 0_cert.pem
CN=github.com
error 20 at 0 depth lookup: unable to get local issuer certificate
error 0_cert.pem: verification failed
```

**What this demonstrates.** A client validating a certificate does not simply trust any certificate signed, however many steps removed, by something in its trust store; it must be able to walk the specific, unbroken chain of Issuer-to-Subject links from the leaf all the way to a root it already trusts, and the intermediate is not optional scaffolding, it is a required link in that walk. This is precisely why a server must send the full chain (the leaf plus every intermediate) during the TLS handshake rather than only its own leaf certificate: the client generally does not have a copy of every CA's intermediate certificates sitting locally, only root certificates, so if the server omits an intermediate, most clients cannot complete the walk themselves and will fail closed, exactly as demonstrated above, even though the leaf certificate itself is entirely valid and correctly issued.

---

## Part 3: Revocation Mechanisms

**CRL (Certificate Revocation List).** A CRL is a signed file, published directly by a Certificate Authority, listing the serial numbers of every certificate that CA has revoked before its scheduled expiration. A client downloads this list and checks an incoming certificate's serial number against it locally; if the serial number appears, the certificate is rejected regardless of whether it is still within its stated validity period. The main limitation is exactly what the task's own hint points to: size and update frequency. A CRL for a large CA can grow to list many thousands of revoked certificates, meaning the full list must be downloaded and re-checked periodically rather than queried per-certificate, and a revocation only takes effect for a given client once that client's next scheduled CRL download occurs, not the moment the CA actually revokes the certificate.

**OCSP (Online Certificate Status Protocol).** OCSP improves on this by replacing the bulk-list model with a real-time, per-certificate query: a client asks a CA-operated responder directly, "is this one specific certificate still valid," and receives a "good," "revoked," or "unknown" answer immediately, without needing to download or store any list at all. **OCSP Stapling** improves this further by having the web server itself periodically fetch its own OCSP response from the CA and attach ("staple") that response directly to the TLS handshake, so the client receives fresh revocation status without making a separate network call to the CA at all, removing both the extra round-trip latency and a genuine privacy problem OCSP otherwise creates, since a direct client-to-CA OCSP query tells the CA exactly which site a specific user is visiting and when.

**A significant, current correction to the textbook narrative, and one this project's own Task 8 already confirmed directly on real, live certificates:** the OCSP-is-simply-better-than-CRL direction actually reversed during 2025 and 2026. Let's Encrypt, the world's largest certificate authority by volume, shut down its OCSP responder entirely on August 6, 2025. A real letsencrypt.org certificate captured directly in Task 8 confirms this precisely: its Authority Information Access section lists a CA Issuers URI only, no OCSP URI at all. GitHub's certificate, issued by Sectigo, was also captured directly in that same task and shows the opposite: a live OCSP URI is still present. The two real certificates examined in this program sit on opposite sides of the same industry transition, not a hypothetical one.

**MedDefense's specific scenario: the portal's private key exposed in a Git repository (per 1x03's own MCQ scenario).** The exact sequence of actions required:

```
1. Immediately request revocation from the issuing CA (Let's Encrypt,
   per this project's Task 8 recommendation), specifying the reason as
   key compromise, which CAs treat as the highest-priority revocation
   category, processed faster than a routine revocation request.
2. In parallel, not sequentially, generate a brand new key pair. The
   compromised private key must never be reused under a replacement
   certificate; a new certificate issued for the same, now-untrusted
   key would not close the exposure at all.
3. Issue a new certificate against the new key pair and deploy it to
   the patient portal (web-srv-01) immediately, minimizing the window
   between revocation and replacement, during which the portal may be
   unreachable or displaying a broken-certificate error to patients.
4. Confirm the revoked certificate's serial number actually appears in
   the CA's published CRL. Given Let's Encrypt no longer offers OCSP
   (confirmed directly in Task 8), this CRL check is the only
   verification path available for a Let's Encrypt-issued certificate,
   not merely one option among several.
5. Immediately remove the exposed private key from the Git repository's
   current state and, critically, from its full history, not just the
   latest commit, since a key still recoverable from an earlier commit
   remains exposed regardless of what the current file tree shows.
6. Treat this as a documented security incident under the Incident
   Response Plan already drafted in this program's own Quick Wins
   (1x03, Task 13), including an assessment of whether any traffic
   during the exposure window shows signs of actual exploitation, not
   only the possibility of it.
```

---

## Part 4: Trust Store Exploration

**Location, confirmed directly on this system:** `/etc/ssl/certs/`, with the consolidated bundle at `/etc/ssl/certs/ca-certificates.crt`.

**Number of trusted root CAs, counted directly, not estimated:**

```
$ grep -c "BEGIN CERTIFICATE" /etc/ssl/certs/ca-certificates.crt
144
```

**This system trusts 144 root certificate authorities by default.**

**Inspecting one root directly: DigiCert Global Root CA.**

```
$ openssl x509 -in /etc/ssl/certs/DigiCert_Global_Root_CA.pem -text -noout | grep -A2 "Validity"
        Validity
            Not Before: Nov 10 00:00:00 2006 GMT
            Not After : Nov 10 00:00:00 2031 GMT
```

**Validity period: a 25-year lifetime (2006 to 2031).** This is genuinely worth pausing on, and the task's own question, "does this surprise you," deserves a direct, honest answer: yes, on first glance, especially set against this project's own Task 8 recommendation of a 90-day certificate lifetime for MedDefense's patient portal, confirmed as the real-world standard by both Let's Encrypt's and Sectigo's actual certificates in that same task. But this is not a contradiction once the reason is worked through rather than assumed: a root certificate is trusted because it is physically present in a client's trust store, installed there through the operating system or browser vendor's own out-of-band vetting process, not because a chain-of-signature check is performed against it the way a leaf or intermediate certificate is checked against its issuer, exactly the same distinction Part 1 of this document just demonstrated directly with Certificate 2's own non-self-signed status. A long root lifetime avoids the operational nightmare of needing to re-distribute a new root to every device on Earth on any short cycle, a fundamentally different problem than renewing one organization's own leaf certificate.

**A second detail worth flagging, since it is a fixed property of this specific, universally-distributed certificate file rather than something that would vary by machine: this actively-trusted root's own self-signature uses `sha1WithRSAEncryption`,** the same SHA-1 algorithm this project's own Task 6 documented as Broken. This is not the contradiction it first appears to be, and the precise reason matters: SHA-1's practical break is a collision attack, the ability to construct two different documents that hash to the same value, which is a real threat when a certificate's signature is what establishes trust in the certificate's contents (an intermediate or leaf certificate, where forging a colliding certificate could let an attacker impersonate a real site). A root certificate's own self-signature does not serve that same function; nothing relies on that signature to establish the root's trustworthiness, since the root is trusted simply because it is present in the store, not because a client cryptographically verifies its self-signature against any external authority. The signature exists structurally, as part of the X.509 format, without doing the trust-establishing work it does everywhere else in the chain, which is why a 2006-era SHA-1 self-signature can sit, unremarked, inside a root store actively protecting connections in 2026.
