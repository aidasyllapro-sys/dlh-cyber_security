# MedDefense Health Systems: Hardware Security and Key Management

**Prepared by:** Aïda Sylla, Security Analyst **Source material:** Current 2026 cloud HSM and KMS pricing, researched directly for this document, cross-referenced against the Risk Register and Governance Architecture (1x03), and the encryption work already built in Tasks 10, 12, and 13 **Purpose:** Every encryption scheme in this project has the same fatal weakness if left unaddressed: the key. This document designs where MedDefense's keys actually live, not just which algorithm protects the data they unlock.

---

## Part 1: Technology Comparison

```
Technology: TPM (Trusted Platform Module)
What It Is: A dedicated cryptographic chip, either soldered to the
  motherboard or integrated into the CPU itself, providing hardware-
  based key storage, random number generation, and platform integrity
  measurement (measured boot).
What It Protects: The system's own boot and disk-encryption keys, most
  commonly a BitLocker or LUKS master key sealed to the specific
  hardware and boot state, so the key only unseals if the system has
  not been tampered with since last boot.
Typical Cost: Effectively free on modern hardware. TPM 2.0 is now a
  standard, often mandatory component of current CPU platforms (a
  requirement for Windows 11, for example), not a separate purchase.
Typical Deployment: Universal on modern laptops and desktops, including
  every device this project's own Task 13 recommends full-disk
  encryption for (MedDefense's employee laptops).
```

```
Technology: HSM (Hardware Security Module)
What It Is: A dedicated, tamper-resistant hardware device, either a
  physical appliance or a cloud-hosted equivalent, purpose-built for
  high-volume, high-assurance cryptographic operations, commonly
  certified to FIPS 140-2 or 140-3 Level 3.
What It Protects: Server-side and application-level keys operating at
  scale, database encryption keys, certificate authority signing keys,
  and payment processing keys, where a key must never leave the
  hardware boundary even in memory.
Typical Cost: Verified directly for this document: a genuine dedicated
  cloud HSM cluster (AWS CloudHSM, Azure Dedicated HSM) runs
  approximately $1,000 to $1,200 per HSM instance per month, with at
  least two instances typically recommended for high availability,
  putting a dedicated cluster in the $10,000 to $100,000 per year
  range for moderate usage. A materially cheaper alternative exists and
  is directly relevant to this project: cloud KMS offerings with HSM-
  backed key storage (not a dedicated single-tenant cluster) cost
  approximately $1 per key per month, confirmed directly against AWS
  KMS's own published pricing.
Typical Deployment: Regulated industries and enterprises needing
  certified, dedicated hardware isolation; the far more common and
  affordable deployment for an organization MedDefense's size is HSM-
  backed software KMS, not a dedicated cluster.
```

```
Technology: Secure Enclave
What It Is: An isolated, hardware-based trusted execution environment
  built directly into a CPU (Apple's Secure Enclave, Intel SGX, ARM
  TrustZone), creating a protected execution area whose contents remain
  protected even if the operating system itself is fully compromised.
What It Protects: Biometric data (fingerprint or facial recognition
  templates), mobile payment tokenization, and application code that
  must run correctly even in the presence of a compromised host OS.
Typical Cost: Built into the cost of the CPU or device itself; not an
  independently priced line item, though it requires specific CPU or
  device support to exist at all.
Typical Deployment: Consumer mobile devices primarily, with growing
  presence in some laptops and specific cloud virtual machine offerings
  (AWS Nitro Enclaves); not a natural fit for MedDefense's own server-
  side data stores, which are the primary encryption targets in this
  project.
```

```
Technology: KMS (Software, cloud or self-hosted)
What It Is: A centralized key management service, either cloud-provided
  (AWS KMS, Azure Key Vault, Google Cloud KMS) or self-hosted
  (HashiCorp Vault), managing key lifecycle, access policy, and
  auditing through software controls rather than requiring dedicated
  hardware MedDefense would own and operate itself.
What It Protects: Application and database-level encryption keys,
  exactly the keys this project's Task 13 recommendation (database-
  level TDE for the patient and billing databases) and Task 12 (the
  NAS-01 LUKS key) both depend on having somewhere secure to live,
  outside the systems they protect.
Typical Cost: Approximately $1 per key per month for a cloud KMS key,
  confirmed directly against AWS KMS's current published pricing,
  optionally backed by HSM-grade hardware at the provider's
  infrastructure level for a modest additional cost per operation,
  without MedDefense needing to provision or manage that hardware
  itself.
Typical Deployment: The standard, affordable choice for an organization
  MedDefense's size needing centralized, auditable key management
  without the capital and operational cost of dedicated HSM hardware.
```

---

## Part 2: MedDefense Key Management Design

**The keys this plan covers, drawn directly from this project's own prior work:** the patient database encryption key (Task 13), the billing database encryption key (Task 13), the NAS-01 backup LUKS key and a separate offsite replica key (Task 12), the patient portal TLS private key (Task 10), and the site-to-site VPN tunnel keys (Central-Westside, Central-HQ).

**Where each key is stored.** No key is stored on the same system it protects, directly applying the principle Sarah Park's own crypto audit notes already established (1x03, Task 0) and this project's own Task 12 design already committed to for NAS-01 specifically. All application and database-level keys (the patient database, billing database, and both backup keys) are stored in a cloud KMS with HSM-backed key storage, not a dedicated HSM cluster, a decision justified directly in Part 3 below. The TLS private key for the patient portal remains on web-srv-01 itself, consistent with standard TLS practice where the server must hold its own private key to complete a handshake, but is generated fresh and rotated automatically every 90 days (Task 10), limiting how long any single exposure of that specific key remains dangerous. VPN tunnel keys are managed directly on the FortiGate appliance terminating both tunnels, the standard architecture for site-to-site IPSec.

**Who has access to each key, mapped directly to the governance roles this project's own Task 4 (1x03) already defined.** Access to the KMS holding the database and backup keys is restricted to a single, narrowly-scoped service account used only by the application or backup process itself, never a human user directly, consistent with the tokenization vault design this project's own Task 7 already built on the same principle. Administrative access to the KMS (the ability to create, rotate, or revoke keys, not merely use them for encryption operations) is restricted to Sarah Park's IT team, with any action logged and requiring James Chen's review for anything outside routine rotation, mapping directly to the RACI structure already defined in 1x03: Sarah is Responsible for technical execution, James holds Accountability for the program as a whole. The TLS private key on web-srv-01 is accessible only to the service account running Apache and to IT administrators with direct server access, the same population already responsible for that server today.

**How keys are rotated.** Database and backup keys rotate automatically every 90 days, matching the same cadence this project already established for the patient portal's own TLS certificate (Task 10), chosen specifically so MedDefense's security team only needs to reason about one rotation rhythm across its entire key inventory rather than tracking several different schedules. VPN tunnel keys, by contrast, rotate on a longer, 12-month cycle, consistent with standard site-to-site IPSec practice, since more frequent rotation of a site-to-site tunnel risks operational disruption to both locations without a corresponding security benefit proportional to a database key's much higher-value target. Every rotation is automated through the KMS's own scheduling capability, not a manual calendar reminder, directly closing the same class of gap this project's Task 10 already identified behind Finding 013 (a manually-managed certificate with no automated renewal).

**What happens if a key is compromised.** The affected key is revoked in the KMS immediately, which does not delete the data it protected but does prevent any further use of that specific key version; a new key is generated and the affected data is re-encrypted under the new key as the immediate next step, not a delayed one. This mirrors directly the certificate revocation-and-replacement sequence this project's own Task 9 already documented for a compromised TLS private key, generate the replacement first, then formally revoke the compromised one, minimizing the window where MedDefense has neither a working key nor a revoked one. The incident is treated as a Critical security event under the Incident Response Plan already drafted in this program's Quick Wins (1x03, Task 13), including a specific review of KMS access logs to determine how long the compromised key may have been usable by an unauthorized party before detection.

**What happens if a key is lost, and whether key escrow is appropriate.** This must be stated with the same honesty this project's own Task 12 already applied to a lost LUKS passphrase: for the backup and database keys specifically, losing the key with no recovery path means the data it protects is permanently unrecoverable, indistinguishable from the underlying storage having been destroyed. Key escrow, a securely stored secondary copy of the key held independently from the primary KMS, is recommended specifically for the two highest-criticality keys, the patient database key and the NAS-01 backup key, given both protect data this program's own Risk Register (1x03) already rates among MedDefense's highest-ALE risks. Escrow is deliberately not recommended for every key in this inventory; the VPN tunnel keys and the TLS private key are both operationally simple to regenerate and reissue from scratch if lost, since neither protects data at rest the way the database and backup keys do, meaning escrow there would add complexity without a corresponding reduction in real risk.

---

## Part 3: The HSM Decision

**Cost of the two realistic options, using real, current pricing rather than an estimate.** A genuine dedicated cloud HSM cluster costs approximately $1,000 to $1,200 per instance per month, with at least two instances recommended for availability, putting MedDefense at roughly $24,000 to $28,800 per year for a dedicated cluster alone, before any operational overhead of managing it. The alternative this document recommends in Part 2, cloud KMS with HSM-backed key storage rather than a dedicated cluster, costs approximately $1 to $2 per key per month, matching the task's own stated pricing range directly. MedDefense's actual key inventory from Part 2 totals 6 keys (patient database, billing database, NAS-01 backup, offsite replica, TLS, VPN), giving an annual cost of **$72 to $144 per year** for the KMS-with-HSM-backing approach, a difference of roughly two orders of magnitude from a dedicated cluster.

**The relevant risk from the Risk Register.** RISK-002 (EHR database, residual exposure after mitigation) is the most directly applicable entry: this project's own Task 6 (1x03) calculated the ALE for unauthorized access to the patient database at $816,750 per year even after the network-level mitigation already funded. A compromised or poorly-managed encryption key protecting that same database produces functionally the same outcome this risk already prices, an attacker with usable read access to 50,000 patient records, whether the path there is a network misconfiguration or a mismanaged key sitting in a plaintext configuration file, exactly the failure mode this task's own context paragraph describes directly.

**Is the investment justified, and which investment specifically.** A dedicated HSM cluster, at $24,000 to $28,800 per year, is difficult to justify against this specific risk on cost-benefit grounds alone: it would consume a meaningful fraction of MedDefense's entire $120,000 annual security budget (1x03) to protect against a risk that proper key management, achievable through KMS-with-HSM-backing, already closes for under $150 per year. **The KMS-with-HSM-backing investment is justified overwhelmingly**, returning protection against a $816,750 annual risk for a cost small enough to be a rounding error against that figure, using the same return-on-investment logic this project's own Task 7 (1x03) already applied to its highest-value security recommendations. The dedicated HSM cluster should be revisited only if a future, specific regulatory or contractual requirement demands FIPS 140-3 Level 3 certified, single-tenant hardware directly, not because the underlying data-protection need itself requires it; on the evidence available today, it does not.
