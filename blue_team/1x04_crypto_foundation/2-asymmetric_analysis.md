# MedDefense Health Systems: The Asymmetric Engine

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** Hands-on OpenSSL operations performed directly for this document, using the same patient record test file from Task 1, cross-referenced against the Vulnerability Assessment (1x02, Finding 005) and the Crypto Inventory (Task 0) **Purpose:** Measure, empirically, why asymmetric encryption cannot replace symmetric encryption for bulk data, and why the hybrid model exists as a direct consequence of that limitation, not an arbitrary design choice.

---

## Part 1: RSA Key Generation and Encryption

**Key generation, exact commands used:**

```
$ openssl genrsa -out rsa_private.pem 2048
$ openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
```

Real output confirmed: `rsa_private.pem` (1,704 bytes), `rsa_public.pem` (451 bytes).

**Encrypting the patient record (85 bytes) with the public key:**

```
$ openssl pkeyutl -encrypt -pubin -inkey rsa_public.pem \
    -in patient_record.txt -out patient_record_rsa.enc
```

Result: `patient_record_rsa.enc`, exactly 256 bytes, confirmed with `ls -la`. This is not a coincidence: RSA-2048 always produces output equal to its key size (2048 bits = 256 bytes) regardless of how small the input is, since the entire input is treated as a single number smaller than the modulus.

**Decrypting with the private key:**

```
$ openssl pkeyutl -decrypt -inkey rsa_private.pem \
    -in patient_record_rsa.enc -out patient_record_rsa_decrypted.txt
```

`diff patient_record.txt patient_record_rsa_decrypted.txt` confirmed byte-for-byte identical output.

**Attempting the 100MB test file from Task 1:**

```
$ openssl pkeyutl -encrypt -pubin -inkey rsa_public.pem \
    -in testfile -out testfile_rsa.enc
```

Real error captured, not paraphrased:

```
Public Key operation error
40A73DD5097F0000:error:0200006E:rsa routines:ossl_rsa_padding_add_PKCS1_type_2_ex:
data too large for key size:../crypto/rsa/rsa_pk1.c:133:
```

**Confirming the exact limit empirically, not just citing it:** rather than trust the textbook figure, this was tested directly. A 245-byte file encrypted successfully; a 246-byte file, one byte larger, failed with the identical padding error above. **RSA-2048 with default PKCS1v1.5 padding can encrypt at most 245 bytes, confirmed by direct experiment, matching the theoretical maximum exactly (256-byte modulus minus 11 bytes of mandatory PKCS1v1.5 padding overhead).**

**Why RSA cannot encrypt large files directly, and what this means in practice:** RSA encryption is a mathematical operation on a single number that must be smaller than the key's modulus; it was never designed to process a data stream the way a symmetric block or stream cipher does, so the maximum plaintext size is hard-capped by the key size itself, with a small, fixed amount of that capacity consumed by padding regardless of key length. This is not a bug or an implementation gap to work around; it is why every real-world system that uses RSA, including the DICOM PS3.15 TLS profile already referenced in this project's Crypto Inventory (Task 0), never uses RSA to encrypt the actual payload, only to encrypt a much smaller symmetric key that then encrypts the real data, exactly the hybrid model this document builds toward in Part 3.

---

## Part 2: ECC Key Generation

**Key generation, exact commands used:**

```
$ openssl ecparam -genkey -name prime256v1 -out ecc_private.pem
$ openssl ec -in ecc_private.pem -pubout -out ecc_public.pem
```

Real output confirmed: `ecc_private.pem` (302 bytes), `ecc_public.pem` (178 bytes).

**File size comparison, measured directly:**

|Key|File size|
|---|---|
|rsa_private.pem (RSA-2048)|1,704 bytes|
|ecc_private.pem (ECC P-256)|302 bytes|
|**Ratio**|**5.64x**|

This PEM-file ratio includes ASN.1 structural encoding overhead on both sides, not just raw key material; the underlying raw key difference is even more dramatic, an RSA-2048 private key's core numbers total roughly 2048 bits of modulus plus supporting values, while a P-256 private key is a single 256-bit (32-byte) integer, confirmed directly in the `openssl ec -text` output produced during this exercise.

**Why ECC achieves equivalent security with much smaller keys, and why it matters for constrained devices:** ECC's security rests on the elliptic curve discrete logarithm problem, which is dramatically harder to solve per bit of key size than the integer factorization problem RSA depends on, meaning a 256-bit ECC key provides security roughly equivalent to a 3072-bit RSA key, not a 256-bit one. For MedDefense specifically, this is not an academic distinction: the BD Alaris infusion pumps and Philips patient monitors documented throughout this program's prior work run on limited embedded processors with real constraints on computation, memory, and battery or thermal budget, exactly the class of device where RSA's larger keys and heavier modular exponentiation operations impose a meaningfully higher cost than ECC's smaller keys and lighter elliptic curve arithmetic for the same security level.

---

## Part 3: The Hybrid Model

In practice, no widely-deployed system encrypts bulk data with asymmetric cryptography directly, for exactly the reason demonstrated empirically in Part 1: it cannot. Instead, TLS and nearly every other encrypted communication protocol uses asymmetric cryptography for a single, narrow purpose, securely establishing a shared symmetric key between two parties who have never met, and then hands the actual data off to symmetric encryption, which has no size limitation and is orders of magnitude faster for bulk throughput. This combination is superior to using either approach alone because it takes exactly what each is good at: asymmetric cryptography solves the key distribution problem (how do two strangers agree on a secret without ever having exchanged one in advance) without ever being asked to do something it is mathematically unsuited for, encrypting large amounts of data; symmetric cryptography, in turn, never has to solve the key distribution problem itself, since the asymmetric handshake already delivered it a fresh secret to use. Using RSA alone for an entire HTTPS session would be computationally prohibitive and, per Part 1's direct demonstration, would not even be possible past 245 bytes without a completely different chunking scheme; using a symmetric cipher alone would require MedDefense and every patient's browser to have somehow already agreed on a shared secret before their first connection ever occurred, which is not realistic for a public-facing patient portal.

**Connecting this directly to MedDefense's patient portal (web-srv-01):** when a patient connects over HTTPS, the TLS handshake, using either RSA key exchange or, in a modern configuration, elliptic-curve Diffie-Hellman (ECDHE), handles the asymmetric portion, authenticating the server and establishing a shared session key without that key ever being transmitted in a form an eavesdropper could directly recover. Once that handshake completes, every subsequent byte of the actual session, the patient's appointment data, portal navigation, and any messages exchanged, is encrypted with a symmetric cipher (in a modern TLS 1.2 or 1.3 configuration, typically AES-GCM or ChaCha20-Poly1305) using the key that handshake just established. This program's own Vulnerability Assessment (1x02, Finding 005) already confirmed the portal currently supports TLS 1.0 alongside TLS 1.2 with no TLS 1.3 support at all, meaning the asymmetric handshake securing that key exchange is, for any connection still permitted to negotiate TLS 1.0, running on a protocol version broken by BEAST and POODLE since 2011, a direct, already-documented illustration of why the hybrid model's asymmetric half needs to be current, not just present.

---

## Part 4: The Key Length Table

|Algorithm|Type|Key Length(s)|Equivalent Security|Status|MedDefense Usage|
|---|---|---|---|---|---|
|AES-128|Symmetric (block)|128 bits|128-bit|Approved|Not currently used; recommended minimum for new deployments per this project's own remediation work|
|AES-192|Symmetric (block)|192 bits|192-bit|Approved|Not currently used anywhere in MedDefense's environment|
|AES-256|Symmetric (block)|256 bits|256-bit|Approved, preferred|Recommended standard for this project's own encryption-at-rest work (patient database, backups), matching HIPAA's expectation of strong encryption for regulated data|
|RSA-2048|Asymmetric|2048 bits|Roughly 112-bit|Approved, minimum acceptable|Confirmed in use on the patient portal's current certificate infrastructure; acceptable but not the stronger option available|
|RSA-4096|Asymmetric|4096 bits|Roughly 150-bit|Approved, stronger|Not currently deployed; recommended for any newly-issued MedDefense certificate authority or long-lived key material given the small performance cost of the larger key for infrequent operations|
|ECC P-256|Asymmetric (elliptic curve)|256 bits|Roughly 128-bit|Approved|Not currently deployed; recommended specifically for the medical device fleet given Part 2's demonstrated efficiency advantage|
|ECC P-384|Asymmetric (elliptic curve)|384 bits|Roughly 192-bit|Approved, stronger|Not currently deployed; appropriate for any system requiring higher assurance than P-256, such as the domain controller's own certificate infrastructure|
|ChaCha20-Poly1305|Symmetric (stream, authenticated)|256 bits|256-bit|Approved|Not currently deployed; a strong alternative to AES-GCM specifically valuable on devices without AES hardware acceleration, directly relevant to MedDefense's embedded medical device fleet|
|3DES (Triple DES)|Symmetric (block)|168 bits (effective ~112-bit)|Roughly 112-bit, degraded further by known attacks (Sweet32)|Deprecated, not approved for new use|Not confirmed in use anywhere in MedDefense's environment; if found during implementation, must be treated as a finding requiring remediation, not a legacy exception|
|DES|Symmetric (block)|56 bits|Broken, trivially brute-forceable|Prohibited|Confirmed still enabled as a supported Kerberos encryption type on both domain controllers (1x02, Finding 018; 1x03, Task 0 Crypto Inventory), a direct, already-documented violation of this standard requiring immediate remediation|
|RC4|Symmetric (stream)|40 to 2048 bits (commonly 128)|Broken, multiple practical key-recovery and plaintext-recovery attacks published|Prohibited|Confirmed still enabled as a supported Kerberos encryption type on both domain controllers, alongside DES (same findings as above), a second, equally direct violation requiring the same immediate remediation|

**Two rows in this table are not academic entries: they are confirmed, present findings in MedDefense's own environment today.** DES and RC4 are both still enabled on MedDefense's domain controllers, not as a theoretical risk this table warns against in the abstract, but as a specific, already-documented condition (1x02, Finding 018) this project's own remediation work must close directly.
