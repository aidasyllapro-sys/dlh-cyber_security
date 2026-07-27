# MedDefense Health Systems: The CSR Workshop

**Prepared by:** Aïda Sylla, Security Analyst **Source material:** A real CSR generated directly with OpenSSL on a Kali Linux workstation, cross-referenced against the Algorithm Reference Table (Task 6), the Certificate Profile recommendation (Task 8), and Finding 013 (1x02, the portal's expiring certificate) **Purpose:** Every field in this CSR becomes a field in the certificate that protects a patient's connection. Eighteen days remain before the current certificate expires; this document generates its replacement and documents every decision behind it.

---

## Part 1: Key Generation Decision

**Decision: ECC P-256.**

This is a direct, deliberate continuation of the recommendation already made in this project's own Certificate Profile (Task 8) and Algorithm Reference Table (Task 6), and it is worth explaining why the "compatibility with older browsers" consideration this task specifically raises does not overturn that earlier conclusion. ECC P-256 provides security equivalent to RSA-2048 (roughly 128-bit equivalent strength) at a fraction of the computational cost per handshake, though for a portal handling roughly 800 patient connections per day, averaging under one connection per minute, this performance advantage is a genuine bonus rather than a load-driven necessity, since either algorithm would handle this volume without strain. The compatibility concern is real but does not favor RSA in practice: ECC P-256 has been supported by essentially every browser and operating system capable of a modern TLS 1.2 or 1.3 handshake since roughly 2014, and this project's own Task 8 already confirmed real, live production certificates (both Let's Encrypt's and GitHub's, via Sectigo) use exactly this key type today, not merely a theoretical recommendation.

**Command used:**

```
$ openssl ecparam -genkey -name prime256v1 -out portal_key.pem
```

---

## Part 2: CSR Generation

**A field decision that needed resolving before generation, disclosed directly rather than passed over silently:** the instructed Common Name, `portal.meddefense.local`, uses the `.local` top-level domain, which is reserved for local/mDNS resolution and cannot receive a publicly-trusted certificate from any public CA, including Let's Encrypt, this project's own recommended CA (Task 8), under the CA/Browser Forum's baseline requirements. This CSR is generated exactly as instructed for this exercise, but this mismatch is flagged explicitly here because it is exactly the kind of detail that would otherwise cause a real CA submission to fail after this entire workshop's worth of preparation; Part 4 of this document addresses the resolution directly at the CA submission step.

**A second issue encountered during this exercise, disclosed directly because it is a genuinely useful, real-world lesson, not just an incidental mistake:** while building the `openssl.cnf` file, a copy-paste step silently corrupted the second SAN entry, transforming `www.portal.meddefense.local` into a markdown-formatted link, `[www.portal.meddefense.local](https://www.portal.meddefense.local)`, an artifact introduced by the application used to transfer the text, not by any OpenSSL command. This was not caught by re-reading the same copy-pasted text, since the same corruption reproduced identically every time the file's contents were viewed through that same path; it was only caught by inspecting the file directly on disk with `cat` in the terminal itself (confirmed clean) and counting literal bracket characters with `grep -c "\["` (returning 0, matching the file's 4 genuine INI section headers exactly, not the corrupted value). **The lesson generalizes directly to this task's own stated risk**: "a missing SAN entry breaks mobile access." A corrupted SAN entry, silently different from what a human reviewer believes they are looking at, is arguably a worse failure mode than a missing one, since it can pass a casual visual review while still being rejected by a CA's automated CSR parser or, if somehow accepted, issued as a certificate with an unusable SAN value. The concrete practice this incident confirms directly: verify configuration file contents on disk, in the terminal, immediately before using them to generate anything security-relevant, rather than trusting a copy-pasted or externally-rendered view of the same content.

**openssl.cnf used, verified clean directly in the terminal after the incident above:**

```
[ req ]
default_bits       = 256
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
CN = portal.meddefense.local
O  = MedDefense Health Systems
OU = Information Technology
L  = Springfield
ST = Illinois
C  = US

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = portal.meddefense.local
DNS.2 = www.portal.meddefense.local
DNS.3 = meddefense.local
```

**Field decisions explained:** the `www` variant is included as a second SAN entry because patients commonly type or are redirected through the `www` prefix, and any hostname not explicitly listed produces the same hostname-mismatch failure documented directly in this project's Task 8 (the `wrong.host.badssl.com` failure class); the bare `meddefense.local` domain is included as a third entry in case any internal or redirect traffic reaches the portal without the `portal.` subdomain prefix. Locality and State (Springfield, Illinois) are placeholder values representative of MedDefense's stated regional hospital profile from this program's earliest work; the actual values should be confirmed against MedDefense's real registered business address before submission.

**Command used:**

```
$ openssl req -new -key portal_key.pem -out portal.csr -config openssl.cnf
```

---

## Part 3: CSR Inspection

**Real command and full output, captured directly on a Kali Linux workstation:**

```
$ openssl req -text -noout -in portal.csr

Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: CN=portal.meddefense.local, O=MedDefense Health Systems,
                 OU=Information Technology, L=Springfield, ST=Illinois, C=US
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:85:63:10:41:44:67:a4:71:95:99:a7:04:b9:46:
                    02:41:73:50:d1:a8:b8:2f:2c:eb:78:9e:5f:c8:f5:
                    36:ff:02:b1:b1:3d:42:1b:33:8e:da:b4:16:b8:9e:
                    bc:c9:a9:a7:37:a1:c9:c1:6c:98:da:00:a6:ea:ad:
                    8c:07:ad:f5:61
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name:
                    DNS:portal.meddefense.local, DNS:www.portal.meddefense.local, DNS:meddefense.local
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:3b:7e:65:fa:38:e8:80:b5:c4:b1:d6:29:0c:cf:
        b4:52:4d:9f:15:7f:4d:53:9a:32:66:5e:70:12:2f:b3:e1:78:
        02:21:00:82:62:94:25:4b:52:05:e2:14:4a:be:a6:16:08:1c:
        98:0b:1a:c8:d1:a6:ae:3d:a7:44:47:92:ff:e5:d0:46:a8
```

**Field-by-field confirmation:**

- Common Name: `portal.meddefense.local`, correct.
- Organization: `MedDefense Health Systems`, correct.
- Organizational Unit: `Information Technology`, correct.
- Locality/State/Country: `Springfield`, `Illinois`, `US`, present as instructed.
- **SAN entries confirmed present and, after the correction above, clean**: `portal.meddefense.local`, `www.portal.meddefense.local`, `meddefense.local`, independently re-verified with `grep -c "\[" portal.csr` returning `0`, confirming no residual corruption reached the actual CSR file.
- Public Key Algorithm: `id-ecPublicKey`, P-256, matching Part 1's decision exactly.
- Signature Algorithm: `ecdsa-with-SHA256`, the correct, matching signature type for an EC key (an RSA key would instead show `sha256WithRSAEncryption`).

**Signature verification, confirming the CSR was genuinely signed by the corresponding private key:**

```
$ openssl req -in portal.csr -noout -verify
Certificate request self-signature verify OK
```

---

## Part 4: The Full Certificate Lifecycle

```
1. CSR generated (done). portal_key.pem and portal.csr exist, verified
   in Part 3 above, with the private key never leaving the server that
   generated it, consistent with correct CSR practice: a CSR proves
   possession of a private key without that key ever being transmitted
   anywhere.

2. Submission to CA: Let's Encrypt, via the ACME protocol. This project's
   own Task 8 recommendation is followed directly, specifically because
   ACME enables full renewal automation, closing Finding 013's root
   cause (no auto-renewal configured) rather than reproducing it with a
   new certificate on the same manual process. Before this step can
   actually proceed, the Common Name mismatch flagged in Part 2 must be
   resolved: either MedDefense registers and uses a real, public,
   ICANN-recognized domain for the patient-facing portal (for example,
   portal.meddefense.org), or, if portal.meddefense.local is genuinely
   intended as an internal-only address, an internal/private CA is used
   instead of Let's Encrypt, since no public CA can issue for a .local
   name under current CA/Browser Forum rules.

3. Validation process: for a Domain Validated certificate from Let's
   Encrypt, the CA verifies control of the domain, not MedDefense's
   organizational identity, typically via the HTTP-01 challenge
   (placing a CA-specified file at a specific path on the web server)
   or the DNS-01 challenge (publishing a specific TXT record), either
   of which an ACME client automates without manual intervention.

4. Certificate issuance: upon successful validation, Let's Encrypt
   issues a certificate valid for 90 days, chaining to one of its
   active intermediates and ultimately to ISRG Root X1 or X2, matching
   the certificate model already confirmed directly on a real, live
   Let's Encrypt certificate in this project's Task 8.

5. Installation on the web server: the new certificate and the private
   key generated in Step 1 are configured in web-srv-01's Apache TLS
   configuration, replacing the certificate Finding 013 flagged as
   expiring; this step should occur in a maintenance window with the
   old certificate still valid and in place as a fallback until the new
   one is confirmed working, not as a same-moment swap with no rollback
   path.

6. Verification that the new certificate is serving correctly: an
   independent connection test (either a fresh openssl s_client
   connection or a third-party checker, following the same verification
   discipline this project's own Task 8 and Task 9 applied throughout,
   including the specific lesson from this task's own SAN-corruption
   incident, verify the deployed file directly rather than trusting an
   intermediate view of it) confirms the served certificate matches the
   newly issued one, presents the correct SAN entries, and chains
   correctly to a trusted root.

7. Decommission of the old certificate: once the new certificate is
   confirmed serving correctly and stable, the old private key should be
   securely deleted, not merely left unused, since a private key with no
   further legitimate purpose is a liability with no offsetting benefit;
   if the old certificate's key is suspected to have ever been exposed,
   this is also the point to request its revocation from its original
   issuing CA, following the same revocation sequence documented directly
   in this project's Task 9.

8. Monitoring for the next renewal: an ACME client (certbot or
   equivalent) is configured to run automatically well before the new
   90-day certificate's expiration, with the SIEM already funded in this
   program's own budget (1x03, Task 8) configured to alert if a renewal
   attempt fails or if the portal's certificate expiration date ever
   drops within a defined threshold (for example, 14 days), so a failed
   automated renewal is caught by monitoring rather than discovered the
   way Finding 013 originally was, by a scan noting the certificate was
   already down to 18 days remaining.
