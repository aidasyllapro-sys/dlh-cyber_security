# MedDefense Health Systems: The Obfuscation Toolkit

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** Cross-referenced against the Crypto Inventory (Task 0), the Data Handling section of the Acceptable Use Policy (1x03, Task 12), and the medical imaging findings already documented (1x02, Finding 024) **Purpose:** Not every data protection mechanism is encryption, and confusing them is both a common exam mistake and a real design error. This document distinguishes five distinct techniques, then applies them directly to MedDefense's own billing, clinical, and imaging data.

---

## Part 1: Technique Comparison

```
Encryption
What it does: Transforms data into ciphertext using a reversible
  mathematical algorithm and a key.
Recoverable: Yes, by anyone holding the correct decryption key. This is
  the defining property that separates encryption from every other
  technique in this comparison.
Healthcare use case: Encrypting the EHR patient database at rest
  (currently absent, per this project's own Task 0 Crypto Inventory),
  so a stolen disk or database dump remains unreadable without the key.
```

```
Hashing
What it does: Transforms data into a fixed-length digest using a
  one-way mathematical function.
Recoverable: No, not by anyone, not even the party that computed it,
  by design. A hash can only be verified by re-computing it and
  comparing, never reversed back to the original input.
Healthcare use case: Storing password verification data (or, more
  precisely, a properly salted and stretched hash, per this project's
  Task 3) so that even a full database compromise does not directly
  expose usable passwords.
```

```
Tokenization
What it does: Replaces sensitive data with a non-sensitive substitute
  value (a token) that has no mathematical relationship to the original,
  unlike encryption's ciphertext, which is mathematically derived from
  the plaintext and key.
Recoverable: Yes, but only by looking up the token in a separate,
  tightly controlled vault that maps tokens back to real values; the
  token itself carries no information that could reveal the original
  even if the underlying algorithm were fully known.
Healthcare use case: The exact scenario Part 2 of this document designs
  directly: replacing stored credit card numbers in MedDefense's billing
  system with tokens, so the billing database itself never holds a
  usable card number at all.
```

```
Data Masking
What it does: Hides part of a value while preserving its format and
  displaying the rest, or replaces a value entirely with placeholder
  text, depending on the masking level applied.
Recoverable: Depends entirely on role and system design; masking is a
  presentation-layer or access-layer control, not a mathematical
  transformation, so "recovery" here means whether a more privileged
  view of the same underlying value exists elsewhere in the system, not
  whether a cryptographic operation can be reversed.
Healthcare use case: The exact scenario Part 3 of this document designs
  directly: showing a billing clerk only the last four digits of a
  patient's SSN, sufficient to verify identity for a claim, without
  displaying the full number that role has no legitimate need to see.
```

```
Steganography
What it does: Hides the existence of data entirely, embedding a
  secret payload within an innocuous-looking carrier file (commonly an
  image, audio file, or, as Part 4 of this document examines directly,
  a DICOM medical image) such that the carrier appears completely
  ordinary to anyone not specifically looking for hidden content.
Recoverable: Yes, but only by someone who knows a hidden payload exists
  at all and has the specific extraction method or key used to embed
  it; unlike encryption, where an observer knows a message exists but
  not its content, steganography's core property is that an observer
  does not even know there is a message to begin with.
Healthcare use case: A legitimate, defensive use exists (embedding a
  digital watermark within a medical image to verify its authenticity
  and detect tampering), though Part 4 of this document examines the
  more urgent case for MedDefense: steganography as an exfiltration
  technique, not a protection one.
```

---

## Part 2: MedDefense Tokenization Design

**What data is tokenized, and the token format.** The full 16-digit credit card number (Primary Account Number) is tokenized in its entirety. The token itself is designed to preserve the original's format exactly, a 16-digit numeric string, so existing billing application code that validates card-number-shaped input continues to function without modification, but with the first six and last four digits retained in cleartext (matching the card's issuer identification number and a display-friendly trailing group) while the middle six digits are replaced with a randomly generated, non-derivable value, producing a token such as `424242XXXXXX4242` in the exact shape of a real card number, with no mathematical relationship to the digits it replaces.

**Where the vault is stored, and how it is protected.** The token-to-real-data vault is a dedicated, physically and logically separate database, not co-located with billing-srv-01 or any system this program's own Vulnerability Assessment (1x02) already found compromised twice. The vault itself is encrypted at rest with AES-256, consistent with this project's own recommended standard (Task 6), with the encryption key held in a separate key management system, not on the vault server itself, directly applying the lesson Sarah Park's own crypto audit notes already stated plainly for backup data: "If we encrypt the backups on the NAS and the key is stored on the NAS... we lose both the backups AND the key. This needs to be designed properly." Access to the vault is restricted to a single, narrowly-scoped service account used only by the tokenization/detokenization API itself, never by a human user or the billing application's general database credentials, with every detokenization request logged and requiring MFA-authenticated administrative approval for any bulk export, mapping directly to the network segmentation Management VLAN already designed in this program's prior work (1x03, Task 14).

**What happens if the token vault is compromised.** An attacker who breaches the vault gains the ability to map tokens back to real card numbers, a serious incident, but a contained one: it requires compromising this one specific, minimally-connected system, not the billing database, the EHR, or any other system storing tokens rather than card numbers, meaning the blast radius of a vault compromise is limited to exactly the credit card data itself, not the broader financial or clinical environment those tokens might otherwise appear in. This is a materially different, and better, outcome than a compromise of billing-srv-01 itself under the current, non-tokenized design, where this project's own Task 6 quantitative work already calculated the billing server ransomware risk at an ALE of $137,170 partly driven by exactly this kind of stored financial data exposure.

**Tokenization versus simply encrypting the card numbers, advantages and disadvantages.** Encryption keeps the sensitive data physically present everywhere it is used, meaning every system touching an encrypted card number needs the decryption key or a call to a decryption service at the point of use, expanding the number of places a key compromise or a misconfiguration could expose the underlying value, exactly the kind of inconsistent enforcement this project's own Crypto Inventory (Task 0) already found in MedDefense's PostgreSQL configuration, where SSL was enabled but not consistently enforced. Tokenization, by contrast, means the real card number exists in exactly one place, the vault, and every other system, including billing-srv-01 itself, only ever handles a token that is useless to an attacker without separately breaching that one vault, a smaller, more defensible attack surface than encryption's approach of protecting the data everywhere it travels. The tradeoff is operational complexity: tokenization requires building and maintaining a new, dedicated service and vault rather than simply applying an encryption library to an existing column, and any system that legitimately needs the real card number (processing an actual charge with a payment processor, for example) still needs a detokenization call, adding a dependency encryption's simpler model does not require. For MedDefense's specific case, storing card numbers used for billing rather than needing to reverse them for display or analysis in most system, tokenization's smaller attack surface is the stronger fit despite its added complexity.

---

## Part 3: Data Masking Examples

|Data Field|Full Value|Nurse (clinical)|Billing Clerk|Reception|
|---|---|---|---|---|
|SSN|987-65-4321|Not displayed at all|***-**-4321 (last 4 digits only)|Not displayed at all|
|Patient Name|Maria Gonzalez|Maria Gonzalez (full)|Maria Gonzalez (full)|Maria Gonzalez (full)|
|Diagnosis|Type 2 Diabetes|Type 2 Diabetes (full)|ICD-10 code only (E11.9), not the narrative text|Not displayed at all|

**Justifications, one sentence per cell:**

- **SSN, Nurse:** Clinical care does not require a Social Security Number at any point, so the field is not displayed at all rather than partially masked, since there is no legitimate clinical need to justify showing even a fragment.
- **SSN, Billing Clerk:** Insurance claim verification legitimately requires confirming identity against a partial SSN in most real-world workflows, so the last four digits are shown, with the full number available only through a separate, logged, elevated action for the specific claim-submission steps that genuinely require it.
- **SSN, Reception:** Front-desk check-in and scheduling rely on name and date of birth for identity verification, not SSN, so the field is not displayed at all.
- **Patient Name, Nurse:** Correct patient identification is a direct patient-safety requirement for any clinical interaction, so the full name is always shown.
- **Patient Name, Billing Clerk:** Billing records must match insurance documentation exactly, which requires the full legal name, so no masking applies.
- **Patient Name, Reception:** Scheduling and check-in are built entirely around identifying the correct patient by name, so the full name is always shown.
- **Diagnosis, Nurse:** Full, unmasked clinical detail is required to deliver safe and appropriate care, so the complete diagnosis is always shown.
- **Diagnosis, Billing Clerk:** Accurate insurance coding requires knowing the diagnosis category, but not the full clinical narrative a nurse would need, so only the standardized ICD-10 code is shown, satisfying HIPAA's minimum-necessary standard for a payment-operations function.
- **Diagnosis, Reception:** Scheduling and front-desk administrative tasks have no legitimate need for diagnosis information at all, so the field is not displayed.

---

## Part 4: Steganography as Threat Vector

DICOM medical images are large, routinely-transferred binary files by design, MRI and CT studies frequently run into the tens or hundreds of megabytes, and MedDefense's own environment already confirms this exact traffic moves between the MRI workstation, radiology workstations, and the PACS server in cleartext today (1x02, Finding 024), meaning both the technical opportunity and the transport path already exist without a malicious insider needing to build anything new. A malicious insider with legitimate DICOM access, exactly the kind of "Curious Employee" or "Ghost Account" scenario this program's own Insider File (1x01, Task 3) already modeled, could embed exfiltrated patient records, SSNs, billing data, or credentials as steganographic payload within the unused bit-depth or pixel data of a legitimate-looking medical image, then transmit that image through routine, expected DICOM traffic that raises no alarm because sending large binary imaging files between facilities is exactly what this system is supposed to do all day. This is materially harder to detect than traditional exfiltration specifically because it defeats content-based data loss prevention entirely: a DLP tool scanning for patterns that look like an SSN or a credit card number in transit finds nothing, since the sensitive payload is not present as recognizable text or structured data at all, it is hidden inside pixel values that inspect as an entirely ordinary, valid medical image, and the file's size and destination are both already expected and authorized. **The control from this project's own 1x03 strategy most directly relevant here is the SIEM deployment (Task 7, Task 8), specifically its capacity for behavioral and volumetric anomaly detection rather than content inspection**: a SIEM tuned to flag unusual patterns, an unusual volume of DICOM transfers from a single account, transfers to an unexpected destination, or transfers occurring outside that user's normal working pattern, can catch this exact exfiltration method precisely because it does not depend on recognizing the hidden content at all, only on recognizing that the behavior around otherwise-legitimate files has changed.
