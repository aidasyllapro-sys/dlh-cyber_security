# MedDefense Health Systems: The Cryptographic Attack Surface

**Prepared by:** Aïda Sylla, Security Analyst **Source material:** Cross-referenced directly against the TLS Audit (Task 11), the Hash Laboratory (Task 3), the Key Exchange work (Task 4), the Crypto Inventory (Task 0), and Finding 018, Finding 024, and Finding 003 (1x02) **Purpose:** Downgrade attacks, collision attacks, birthday attacks, and Kerberoasting are not abstract exam concepts here. Each one maps to a specific, already-identified weakness in MedDefense's own environment, not a hypothetical one.

---

## Attack 1: TLS Downgrade

```
Attack: TLS Downgrade
Mechanism: A TLS downgrade attack exploits the fact that a client and
  server negotiate a protocol version during the initial handshake, and
  if the server is willing to accept a weaker version at all, an
  attacker positioned on the network path can interfere with that
  negotiation to force the weaker choice, even when both parties would
  otherwise agree on something stronger.
MedDefense Vulnerability: The patient portal (web-srv-01) supports TLS
  1.0 alongside TLS 1.2, with no TLS 1.3 available at all.
Evidence: Finding 005 (1x02); confirmed directly in this project's own
  Task 11 SSL Labs research, where a live certificate authority's own
  documented grading policy (in effect since January 2020) automatically
  caps any server still supporting TLS 1.0 at a B grade, regardless of
  every other configuration strength.
Viable Today: Yes. The portal's own configuration permits the exact
  downgrade path this attack requires; nothing currently prevents a
  client from being forced onto TLS 1.0, a protocol broken by the
  BEAST attack since 2011.
Mitigation: Disable TLS 1.0 and TLS 1.1 entirely on web-srv-01, exactly
  the hardened Apache configuration this project's own Task 11 already
  built and documented in full.
```

---

## Attack 2: Collision Attack

```
Attack: Collision Attack (MD5/MD4 in Windows authentication)
Mechanism: A collision attack finds two different inputs that produce
  the identical hash output, undermining any security property that
  depends on a hash uniquely representing its input, such as a
  signature or an integrity check. For MD5 specifically, practical
  collisions have been demonstrated since 2004, with chosen-prefix
  collisions (letting an attacker choose the colliding content in
  advance rather than accept whatever the collision search happens to
  produce) practical since 2008.
MedDefense Vulnerability: A precise correction to the task's own
  framing is worth stating directly, consistent with this project's own
  practice of not letting an imprecise premise pass uncorrected: Active
  Directory's NT hash is MD4-based, not MD5, though MD5 does appear
  directly in this environment, in NTLMv2's own HMAC-MD5 key derivation
  step, confirmed against Microsoft's official documentation in this
  project's Task 3. Both MD4 and MD5 come from the same broken hash
  family and share the same practical exposure to collision-based
  attack.
Evidence: This project's own Task 0 (Crypto Inventory) and Task 3 (Hash
  Laboratory) research, verified directly against Microsoft's own
  documentation
Viable Today: Yes, in the sense that the underlying hash algorithms are
  confirmed broken and in active use in MedDefense's authentication
  stack; a full Kerberoasting-style offline attack against this exact
  weakness is detailed separately in Attack 4 below, since that is the
  more direct, practical exploitation path available today.
Mitigation: No direct algorithm replacement is possible, since the NT
  hash format is structurally fundamental to Windows domain
  authentication; the actionable mitigation targets the exploitation
  path instead, closing Finding 018 (1x02) by disabling RC4 and DES as
  supported Kerberos encryption types.
```

---

## Attack 3: Birthday Attack

```
Attack: Birthday Attack (theoretical, worked through directly)
Mechanism: The birthday attack exploits the mathematical fact that
  finding any two inputs that collide requires far fewer attempts than
  finding a collision with one specific, chosen input. For an n-bit
  hash, a targeted collision requires roughly 2^n attempts, but finding
  any collision at all requires only about 2^(n/2), the same math
  behind why a room of just 23 people has a 50% chance two people share
  a birthday, despite there being 365 possible birthdays.
MedDefense Vulnerability: This directly determines which of
  MedDefense's own hash algorithms are within reach of a real attacker
  and which are not. For MD5 (128-bit), the birthday bound is roughly
  2^64 operations, a number confirmed practical with modern hardware,
  which is exactly why real MD5 collisions have been publicly
  demonstrated since 2004. For SHA-256 (256-bit), the equivalent figure
  is roughly 2^128, a number that remains computationally infeasible
  with any hardware that exists or is plausibly foreseeable.
Evidence: This project's own Task 3 direct calculation: 2^128 possible
  outputs for MD5 versus 2^256 for SHA-256, and the same task's real,
  hands-on confirmation of the avalanche effect using actual computed
  hashes, not assumed values.
Viable Today: Yes for MD5/MD4, confirmed practical and already relevant
  to MedDefense's own authentication stack (Attack 2 above); no for
  SHA-256, which this project has used throughout its own hands-on
  cryptographic work (Tasks 1, 3, 5) specifically because its 128-bit
  birthday bound remains out of reach.
Mitigation: Continue using SHA-256 or stronger for all new hashing work,
  exactly as this project's own prior tasks already do; the birthday
  attack is not something MedDefense can configure away for MD5/MD4
  specifically, since that exposure is fixed once the output size is
  fixed, reinforcing why closing Finding 018 (removing RC4/DES
  Kerberos encryption types) is the only real lever available.
```

---

## Attack 4: Kerberoasting

```
Attack: Kerberoasting
Mechanism: An authenticated domain user requests a Kerberos service
  ticket for any service account, which the domain controller encrypts
  using a key derived from that service account's own password hash.
  If RC4 encryption is permitted for this ticket, the attacker can take
  the ticket entirely offline and attempt to crack the password at
  whatever speed modern GPU hardware can compute RC4/MD4-based
  operations, with no further contact with the domain controller and no
  way for MedDefense to detect the cracking attempt in progress.
MedDefense Vulnerability: Both domain controllers (ad-dc-01, ad-dc-02)
  support RC4 as a Kerberos encryption type, alongside DES.
Evidence: Finding 018 (1x02), confirmed and analyzed in full detail in
  this project's own Task 3, including the direct, verified fact that
  the underlying NT hash is unsalted, confirmed against Microsoft's own
  official documentation.
Viable Today: Yes. Both weak encryption types remain enabled, and this
  project's own Task 15 (Crypto Posture Audit) already rated this
  finding at the highest urgency tier, Immediate, consistent with its
  original priority in 1x02's own triage.
Mitigation: Disable RC4 and DES as supported Kerberos encryption types
  domain-wide, enforcing AES-256 exclusively, exactly the remediation
  this project has already recommended consistently since Task 3 and
  reaffirmed directly in Task 15.
```

---

## Attack 5: On-Path/MITM on Unencrypted Channels

```
Attack: On-Path/Man-in-the-Middle on Unencrypted Channels
Mechanism: An attacker positioned on the network path between two
  legitimate parties can passively read, or actively modify, any
  traffic that is not both encrypted and authenticated; this project's
  own Task 4 already demonstrated directly why authentication matters
  as much as encryption, since an attacker performing a separate key
  exchange with each victim can decrypt, alter, and re-encrypt traffic
  passing through them without either party detecting a problem.
MedDefense Vulnerability: Two specific, confirmed channels: DICOM
  imaging traffic between the MRI workstation, radiology workstations,
  and pacs-srv-01 travels entirely in cleartext, including patient
  identifiers embedded in DICOM headers; and PostgreSQL connections to
  ehr-db-01 permit unencrypted "hostnossl" connections alongside
  encrypted ones, with no way to confirm which path any given
  connection actually used.
Evidence: Finding 024 (1x02) for DICOM traffic; Finding 003 (1x02) for
  the PostgreSQL configuration; both independently confirmed again in
  this project's own Crypto Inventory (Task 0) and formally scored in
  the Crypto Posture Audit (Task 15) as CRYPTO-002 and CRYPTO-008.
Viable Today: Yes for both. Neither channel currently enforces
  encryption in a way that would prevent an on-path attacker positioned
  anywhere on MedDefense's own internal network, the same flat network
  this program's own kill chain work (1x01) already showed provides
  exactly this kind of unrestricted internal positioning.
Mitigation: Enable DICOM TLS (PS3.15) between all three imaging systems;
  remove every "hostnossl" entry from pg_hba.conf, enforcing "hostssl"
  exclusively, both already recommended directly in this project's own
  Task 15 findings (CRYPTO-002 and CRYPTO-008).
```

---

## Attack 6: Key Recovery from Memory

```
Attack: Key Recovery from Memory
Mechanism: A symmetric encryption key must exist in plaintext in RAM at
  the exact moment a CPU performs an encryption or decryption operation
  with it, since the processor cannot execute AES rounds on a key that
  is itself still encrypted. An attacker with root or administrator
  access to a running system can dump process memory directly and
  search it for key material; AES key schedules have a distinctive,
  identifiable structure in raw memory that makes this search
  practical even without knowing the target key's value in advance.
MedDefense Vulnerability: billing-srv-01 specifically. This is not a
  hypothetical precondition: this exact server was already compromised
  at the root level once before, during the cryptominer incident this
  program's earliest work (0x00) documented directly. If the database-
  level encryption this project's own Task 13 and Task 14 recommend for
  this server's MySQL data is implemented, the encryption key will, by
  necessity, exist in that MySQL process's memory whenever it services
  a query against encrypted data.
Evidence: The 0x00 cryptominer incident (root-level compromise already
  proven achievable on this exact host); this project's own Task 13 and
  Task 14 recommendations, which establish the precondition (a key that
  will exist in memory) this attack requires.
Viable Today: Conditionally yes, and this condition should be stated
  precisely rather than glossed over: the precondition, root-level
  compromise of billing-srv-01, is already proven achievable, confirmed
  by the 0x00 incident; the specific key this attack would target does
  not yet exist in production, since this project's own Task 13/14
  database encryption recommendation for this server has not yet been
  deployed. The moment it is deployed without the mitigation below, this
  attack becomes immediately viable, not a future concern to revisit
  later.
Mitigation: Layered, since no single control fully closes this attack
  once a key must exist somewhere in an active process's memory: first,
  close the root-access vector itself, the EDR already funded in this
  program's own budget (1x03, Task 8) specifically to detect exactly
  the kind of unauthorized access the 0x00 incident achieved; second,
  where the key management design (Task 14) uses a cloud KMS with
  genuine HSM-backed operations rather than simply fetching the raw key
  into application memory, perform the decryption operation inside the
  HSM boundary itself so the raw key is never exposed to billing-srv-01
  at all; third, configure the SIEM (1x03, Task 8) to alert on memory-
  dumping tool signatures and anomalous process access to the MySQL
  process specifically, since this attack cannot be prevented by
  encryption algorithm choice alone, only detected and contained.
