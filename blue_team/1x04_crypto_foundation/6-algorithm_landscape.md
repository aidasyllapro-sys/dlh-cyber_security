# MedDefense Health Systems: The Algorithm Landscape

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** Cross-referenced against every hands-on finding of this project (Tasks 0 through 5) and the Vulnerability Assessment (1x02, Findings 005 and 018) **Purpose:** The definitive reference table carried into both the Security+ exam and this project's remaining implementation work. Every algorithm below connects to something already confirmed present, or confirmed missing, at MedDefense.

---

## Symmetric Algorithms

|Algorithm|Key Size|Primary Use Case|Status|Why Deprecated/Broken|MedDefense Usage|
|---|---|---|---|---|---|
|AES-128|128 bits|General-purpose bulk encryption|Current|N/A|Not currently used; a viable option for constrained medical devices where the smaller key offers a modest performance advantage over AES-256|
|AES-192|192 bits|General-purpose bulk encryption|Current|N/A|Not currently used anywhere in MedDefense's environment; rarely chosen over AES-128 or AES-256 in practice|
|AES-256|256 bits|Bulk encryption of high-sensitivity data|Current, preferred|N/A|Recommended standard for this project's own remediation work: patient database encryption at rest and NAS-01 backup encryption, both confirmed absent in the Crypto Inventory (Task 0)|
|DES|56 bits effective|Legacy block cipher|Broken|A 56-bit keyspace has been brute-forceable since 1998 (the EFF's Deep Crack machine); trivial with modern hardware|**Confirmed still enabled** as a supported Kerberos encryption type on both MedDefense domain controllers (1x02, Finding 018)|
|3DES|168 bits nominal, ~112 bits effective|Legacy block cipher, transitional replacement for DES|Deprecated|Vulnerable to the Sweet32 birthday attack due to its 64-bit block size; formally disallowed by NIST for new use after 2023|Not confirmed in use anywhere in MedDefense's environment|
|ChaCha20-Poly1305|256 bits|Authenticated stream encryption, especially on hardware without AES acceleration|Current|N/A|Not currently used; recommended specifically for MedDefense's medical device fleet (Task 2), where embedded processors often lack AES-NI hardware acceleration|
|RC4|40 to 2048 bits (commonly 128)|Legacy stream cipher|Broken|Multiple practical statistical bias and plaintext-recovery attacks published; formally prohibited in TLS by RFC 7465 (2015)|**Confirmed still enabled** as a supported Kerberos encryption type on both MedDefense domain controllers (1x02, Finding 018), the same finding as DES above|
|Blowfish|32 to 448 bits (variable)|Legacy block cipher|Deprecated|Its 64-bit block size carries the same Sweet32-class birthday-attack exposure as 3DES, superseded by AES for general use|Not confirmed in use anywhere in MedDefense's environment|

---

## Asymmetric Algorithms

|Algorithm|Key Size|Primary Use Case|Status|Why Deprecated/Broken|MedDefense Usage|
|---|---|---|---|---|---|
|RSA-2048|2048 bits (~112-bit equivalent security)|Key exchange, digital signatures, certificates|Current, minimum acceptable|N/A|**Confirmed in use** on the patient portal's current certificate infrastructure (Task 2)|
|RSA-4096|4096 bits (~150-bit equivalent security)|Key exchange, digital signatures, long-lived keys|Current, stronger|N/A|Not currently deployed; recommended for any newly-issued MedDefense certificate authority or root key material, where the larger key's small performance cost is easily justified by its long operational lifetime|
|ECC P-256|256 bits (~128-bit equivalent security)|Key exchange, digital signatures|Current|N/A|Not currently deployed; recommended specifically for the medical device fleet (Task 2), given its efficiency advantage on constrained processors|
|ECC P-384|384 bits (~192-bit equivalent security)|Key exchange, digital signatures, higher-assurance systems|Current, stronger|N/A|Not currently deployed; recommended for the domain controller's own certificate infrastructure, where a higher assurance level than P-256 is appropriate|
|Diffie-Hellman (finite-field)|Typically 2048 bits or larger|Key exchange|Current, though generally superseded by ECDHE for new deployments|N/A (not broken, simply less efficient than its elliptic-curve equivalent)|**Confirmed in use** for the Central-to-Westside and Central-to-HQ VPN tunnels, using IKEv2 with DH Group 14 (Task 0 Crypto Inventory, Sarah Park's own notes)|
|ECDHE|Typically 256 to 384 bits|Key exchange with forward secrecy, the standard for modern TLS|Current, preferred|N/A|Not confirmed in use anywhere; recommended for the patient portal once TLS 1.3 support is enabled (closing Finding 005), since ECDHE is what provides forward secrecy in a modern TLS handshake|

---

## Hash Algorithms

|Algorithm|Output Size|Primary Use Case|Status|Why Deprecated/Broken|MedDefense Usage|
|---|---|---|---|---|---|
|MD5|128 bits|Legacy checksum, legacy password hashing|Broken|Practical collisions demonstrated since 2004; chosen-prefix collisions practical since 2008|Directly related to a **confirmed** finding: NTLMv2 authentication derives its HMAC key using HMAC-MD5 over the NT hash (verified directly in this project's Task 3 research), meaning MD5 sits inside MedDefense's own authentication protocol today, not as a hypothetical risk|
|SHA-1|160 bits|Legacy checksum, legacy digital signatures|Broken|A practical, published collision (the "SHAttered" attack, Google and CWI, 2017) proved exploitable collisions are achievable|Not directly confirmed in use, though Finding 005 (1x02) notes the patient portal's TLS cipher suites are undocumented and "likely include weak cipher suites alongside strong ones," meaning SHA-1-based cipher suites cannot be ruled out without direct inspection|
|SHA-256|256 bits|General-purpose hashing, digital signatures, integrity verification|Current|N/A|Recommended and already used throughout this project's own hands-on work (Tasks 1, 3, and 5): file integrity verification and digital signature hashing|
|SHA-512|512 bits|High-assurance hashing|Current|N/A|Not currently used; a reasonable option for particularly high-assurance audit log integrity, though SHA-256 is sufficient for most of MedDefense's needs|
|SHA-3|224/256/384/512 bits (variable)|General-purpose hashing, structurally distinct backup standard|Current|N/A|Not currently used; no urgent need, but a reasonable long-term diversification choice given its different internal structure (Keccak, a sponge construction) from SHA-2|

---

## Key Derivation Functions

|Algorithm|Output Size|Primary Use Case|Status|Why Deprecated/Broken|MedDefense Usage|
|---|---|---|---|---|---|
|PBKDF2|Configurable (commonly 256 bits)|Password-based key derivation|Current, weaker than memory-hard alternatives|N/A (not broken, but its low memory-hardness makes it more efficiently parallelizable on GPUs/ASICs than bcrypt or Argon2)|**Used directly in this project's own CBC encryption work** (Task 1) for password-based key derivation; not confirmed in use anywhere in MedDefense's actual application password storage|
|bcrypt|192 bits (fixed)|Password hashing|Current|N/A|Not currently used; a viable, strong alternative to PBKDF2|
|Argon2|Configurable|Password hashing|Current, preferred|N/A|Not currently used; **recommended directly in this project's own analysis (Task 3)** as MedDefense's application password storage standard, given its memory-hardness against GPU-accelerated cracking|
|scrypt|Configurable|Password hashing, key derivation|Current|N/A|Not currently used; not specifically recommended over Argon2, since Argon2 is already this project's chosen standard and introducing a second KDF would add operational complexity without a corresponding security benefit|

---

## MedDefense Crypto Gap Analysis

Comparing what this project's own hands-on work (Task 0's Crypto Inventory) and the underlying vulnerability findings (1x02) confirm MedDefense currently uses against what it should use surfaces at least four specific cases of a deprecated or broken algorithm in active production use, not a hypothetical risk:

**1. DES enabled as a Kerberos encryption type on both domain controllers.** Confirmed directly in Finding 018 (1x02) and restated in this project's own Crypto Inventory (Task 0). DES has been broken since 1998; there is no legitimate reason for it to remain enabled. **Recommended replacement: disable DES as a supported Kerberos encryption type domain-wide, enforcing AES-256 (AES256-CTS-HMAC-SHA1-96 or the newer AES256-CTS-HMAC-SHA384-192 where supported) as the minimum accepted type**, exactly the remediation already scheduled in this program's own control selection work (1x03, Task 11, mapped to CIS Control 4).

**2. RC4 enabled as a Kerberos encryption type on both domain controllers, alongside DES.** Also confirmed in Finding 018. RC4 is formally prohibited in modern TLS and carries well-documented statistical weaknesses; its presence in Kerberos specifically enables the Kerberoasting attack path this project's own Task 3 analysis already walked through in detail. **Recommended replacement: identical to DES above, disable RC4 as a supported encryption type in the same change, enforcing AES-256 exclusively.**

**3. MD4-based, unsalted NT hashes as Active Directory's foundational password storage, with MD5 appearing inside the NTLMv2 authentication protocol itself.** Confirmed directly against Microsoft's own documentation in this project's Task 3. This is a structurally different case from the two above: it cannot simply be disabled, since the NT hash format is fundamental to how Windows domain authentication works at all. **Recommended replacement: not a direct algorithm swap, but closing Findings 018 and 007 together (disabling weak Kerberos encryption types and enforcing LDAP signing) removes the practical mechanism that lets an attacker obtain this weak hash material for offline cracking in the first place**, while any password storage MedDefense controls directly at the application layer (outside AD itself) should use Argon2, not any hash-based scheme resembling AD's own legacy design.

**4. TLS 1.0 still supported on the patient portal, alongside TLS 1.2, with no TLS 1.3 available.** Confirmed directly in Finding 005 (1x02). TLS 1.0 has been considered broken since the BEAST attack in 2011 and was formally deprecated by the IETF in RFC 8996 (2021). Every connection permitted to negotiate TLS 1.0 is also permitted to negotiate whatever key exchange and cipher suite that protocol version allows, potentially including the same weak algorithms flagged elsewhere in this table. **Recommended replacement: disable TLS 1.0 entirely, enable TLS 1.3 as the preferred protocol with TLS 1.2 retained only as a fallback, and explicitly configure ECDHE for key exchange with AES-GCM or ChaCha20-Poly1305 for bulk encryption**, closing the gap this project's Task 4 already identified between Diffie-Hellman's mathematical guarantee and the certificate-based authentication a modern TLS configuration provides on top of it.

**The pattern across all four cases is the same one this entire program has identified repeatedly since Project 0x00: these are not unknown risks awaiting discovery.** Every algorithm-level gap in this analysis traces to a finding already confirmed, documented, and in three of the four cases already carrying a specific remediation assignment in this project's own prior work. This table's contribution is not new discovery; it is showing, in one place, exactly which entries in a Security+ study guide are also, right now, a live condition in MedDefense's own environment.
