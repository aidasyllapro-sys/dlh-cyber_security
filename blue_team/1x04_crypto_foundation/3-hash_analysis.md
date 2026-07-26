# MedDefense Health Systems: The Hash Laboratory

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** Hands-on hash computations performed directly for this document, crackstation.net's own published methodology (fetched directly), Microsoft's official Active Directory password storage documentation, cross-referenced against Finding 018 (1x02) and the Crypto Inventory (Task 0) **Purpose:** Understand, through direct experiment rather than assertion, why a hashed password is not automatically a protected one, and what separates "attacker has hashes but cannot use them" from "attacker has every password in 30 minutes."

---

## Part 1: The Avalanche Effect

**Real commands and output:**

```
$ echo -n "MedDefense" | sha256sum
39e026e107a44b2268e43e16e61033fdcc5d2bd62b23e03aca51db35c8671098

$ echo -n "MedDefense1" | sha256sum
97a4141d69cc726a7f6ef577df588d4010c3fe4f235a8bdb616732ba9bf17b92

$ echo -n "MedDefense" | md5sum
75d47fd4b4d183456d0f98fd9ba6ae4d

$ echo -n "MedDefense1" | md5sum
0d2aed72043f78c2935e61ba8520306d
```

**A precise measurement, not an estimate.** Counting differing hex characters directly gives 62 of 64 for SHA-256 (96.9%) and 30 of 32 for MD5 (93.8%), figures that look nothing like the textbook "50%" claim. This is worth explaining rather than reporting misleadingly: a hex character encodes 4 bits, and a single differing bit anywhere within that nibble marks the entire character as "different," so counting characters systematically overstates the true effect. The avalanche effect is properly measured in bits, not hex digits. Computing the actual bitwise Hamming distance (XOR the two hash values as integers, count the set bits) gives the real answer: **SHA-256: 131 of 256 bits differ (51.2%). MD5: 71 of 128 bits differ (55.5%).** Both land almost exactly on the theoretical ideal of 50%, confirming the avalanche effect precisely once measured the correct way, and directly illustrating why a one-character change to a password produces a completely unrelated hash rather than a "close" one an attacker could use as a starting point.

---

## Part 2: Hash Collisions and the Birthday Problem

**Possible unique outputs:**

- MD5 (128-bit): 2^128 possible outputs
- SHA-256 (256-bit): 2^256 possible outputs

**Why a shorter hash is more susceptible to collision attacks, and what the birthday attack exploits.** The birthday attack exploits the mathematical fact that finding any two inputs that collide requires far fewer attempts than finding a collision with one specific, chosen input: for an n-bit hash, a targeted collision requires roughly 2^n attempts, but finding any collision at all requires only about 2^(n/2), the same math behind why a room of just 23 people has a 50% chance two people share a birthday, despite there being 365 possible birthdays. For MD5, that means a practical collision search needs roughly 2^64 operations, a number well within reach of modern hardware (real MD5 collisions have been publicly demonstrated since 2004); for SHA-256, the equivalent figure is roughly 2^128, a number that remains computationally infeasible with any hardware that exists or is plausibly foreseeable. A shorter hash simply has a smaller space of possible outputs to begin with, so the birthday bound's already-reduced exponent lands on a number small enough to actually compute.

**Connecting this directly to Finding 018 (1x02).** Finding 018 confirmed that MedDefense's domain controllers still support RC4 as a Kerberos encryption type. A precise technical clarification matters here, since the premise conflates two related but distinct algorithms: RC4-HMAC Kerberos tickets are keyed from the Windows NT hash, which is MD4, not MD5, though the two are closely related, weak, fast, legacy algorithms from the same design era, and this distinction does not change the practical conclusion. Microsoft's own documentation, verified directly for this document, confirms plainly: "Neither the NT hash nor the LM hash is salted." The practical implication for MedDefense is direct: any attacker capable of requesting an RC4-encrypted service ticket (a Kerberoasting attack, already flagged as enabled by this exact finding) receives ciphertext keyed from an unsalted MD4 hash of a password, which can then be cracked entirely offline, at whatever speed modern GPU hardware can compute MD4, with no further contact with MedDefense's network and no way for MedDefense to detect the cracking attempt in progress.

---

## Part 3: Rainbow Table Demonstration

**Real commands and output, verified on a Kali Linux workstation:**

```
$ echo -n "password123" | md5sum
482c811da5d5b4bc6d497ffa98491e38

$ echo -n "s4lt9xQ2:password123" | md5sum
6d537fa53f1db2c22b0451ef4ef9fbe8
```

**Both hashes were submitted directly to crackstation.net, and the results were observed firsthand, not inferred from the site's own published methodology as an earlier draft of this document had to rely on.**

**Result for the unsalted hash, `482c811da5d5b4bc6d497ffa98491e38`:**

```
Hash                              | Type | Result
482c811da5d5b4bc6d497ffa98491e38  | md5  | password123
```

Marked in green, "Exact match." CrackStation correctly identified the hash type automatically and returned the plaintext password instantly, confirming directly what this document's earlier draft had only reasoned would happen based on the site's documented 15-billion-entry lookup table: "password123" is common enough that it is present in that table.

**Result for the salted hash, `6d537fa53f1db2c22b0451ef4ef9fbe8`:**

```
Hash                              | Type    | Result
6d537fa53f1db2c22b0451ef4ef9fbe8  | Unknown | Not found.
```

Marked in red, "Not found." One detail here is worth noting directly rather than glossed over: CrackStation lists the type as "Unknown," not "md5," even though the hash is, in fact, an MD5 digest. This is consistent with how the tool actually works: it identifies a hash's algorithm by successfully matching it against a known plaintext in its lookup table, not by inspecting the hash's format alone. With no match found, it has no basis to confirm the algorithm either, which is itself a small, concrete illustration of the same principle this section demonstrates: without a precomputed table entry, the hash offers no shortcut at all, not even confirmation of which algorithm produced it.

**Why salting defeats rainbow tables, and why every user needs a unique salt.** A rainbow table (or any pre-computed lookup table) works by pre-computing hashes for a large set of candidate passwords once, then reusing that same table against any hash it encounters; a salt appended or prepended before hashing changes the actual input to the hash function, meaning the pre-computed table for the plain password no longer matches at all, forcing an attacker back to computing hashes fresh for every single guess. This defense only holds if every user's salt is unique: a single shared salt across all users would let an attacker pre-compute exactly one new table for that specific salt and then crack every user's password against it at once, recreating the same economy of scale a rainbow table exploits in the first place, just shifted one step later; a unique salt per user forces a completely separate, from-scratch computation for every single account, exactly the cost multiplication that makes large-scale offline cracking impractical.

---

## Part 4: Key Stretching

**bcrypt.** Built specifically as a password hashing function around the Blowfish cipher, bcrypt repeats its internal key-setup process a configurable number of times before producing a final hash, deliberately making each individual guess computationally expensive rather than nearly instantaneous like a raw hash function. This resistance comes directly from that repeated internal work: an attacker attempting billions of guesses per second against a raw MD5 or SHA-256 hash can only attempt a small fraction of that rate against bcrypt, since each single guess now costs meaningfully more CPU time. The "cost factor" (commonly a power-of-two work factor, such as 12) controls exactly how many internal rounds are performed, and increasing it by 1 doubles the computational cost of every single guess, letting the parameter scale forward as hardware gets faster.

**PBKDF2.** Rather than a dedicated password-hashing design, PBKDF2 takes an existing cryptographic hash function (commonly SHA-256) and applies it repeatedly, feeding each round's output back into the next, for a configured iteration count. Its resistance comes from the same principle as bcrypt, multiplying the cost of a single guess by the iteration count, though PBKDF2 is generally considered weaker against specialized hardware than bcrypt or Argon2, since it uses relatively little memory and is therefore easier to parallelize efficiently on GPUs and ASICs built for exactly this kind of repeated-hash workload. The "iteration count" parameter (commonly 600,000 or higher under current OWASP guidance for SHA-256-based PBKDF2) directly controls how many rounds each single guess requires.

**Argon2.** The winner of the 2015 Password Hashing Competition and the current best-practice recommendation from OWASP, Argon2 is deliberately memory-hard, requiring not just repeated computation but a configurable, substantial amount of RAM per guess, specifically to blunt the advantage GPUs and custom ASICs have over general-purpose CPUs, since specialized cracking hardware is optimized for raw computation, not large memory allocation per parallel thread. Its resistance comes from this dual cost, both CPU time and memory footprint scale together, meaning an attacker cannot simply add more parallel compute without also needing proportionally more memory per attempt, a resource that is far more expensive to scale at massive parallelism than raw computation alone. Argon2's cost parameters explicitly separate memory cost, time cost (iterations), and parallelism, giving finer control than bcrypt's single work factor.

**Recommendation for MedDefense's application password storage: Argon2id** (the hybrid variant OWASP currently recommends), specifically because it provides the strongest resistance against the GPU-accelerated offline cracking this same document's Part 2 already demonstrated is realistic against MedDefense's own weakest hashing (the unsalted, unstretched NT hash), and because MedDefense's application-level authentication (distinct from Active Directory itself) is new enough infrastructure that there is no legacy compatibility reason to choose a weaker, older option like PBKDF2 instead.

**What Active Directory uses by default, and whether it is adequate.** Researched directly against Microsoft's own official documentation: Active Directory stores the NT hash, a single, unsalted MD4 computation of the password, with no iteration or stretching applied at all. This is confirmed adequate for its original, narrow purpose (backward-compatible NTLM authentication) but is not adequate by any modern password-storage standard, and this is not a theoretical concern for MedDefense specifically: it is the exact mechanism Finding 018 (1x02) already confirmed is exposed to offline attack via enabled RC4 Kerberos tickets. This is also not a setting MedDefense can simply reconfigure away, since the NT hash's format is fundamental to how Windows domain authentication itself works; the actionable mitigation available to MedDefense is not "stretch the NT hash," but closing Finding 018 directly (disabling RC4 and DES as supported Kerberos encryption types, already recommended in this program's prior remediation work) to remove the specific mechanism that lets an attacker obtain that unsalted, unstretched hash material for offline cracking in the first place.

---

## Part 5: The Integrity Verification Script

Built, tested, and verified directly, including both success and failure paths:

```
$ ./3-hash_verify.sh patient_record.txt 4e835bed9f9b9300bbffa442fd620ebdb0c2a807739fafe2d2eeec813aa9d48d
INTEGRITY OK
(exit code: 0)

$ ./3-hash_verify.sh patient_record.txt 0000000000000000000000000000000000000000000000000000000000000000
INTEGRITY FAILED - expected 0000...0000 got 4e835bed9f9b9300bbffa442fd620ebdb0c2a807739fafe2d2eeec813aa9d48d
(exit code: 1)

$ ./3-hash_verify.sh fichier_inexistant.txt <any hash>
Error: file 'fichier_inexistant.txt' not found.
(exit code: 1)
```

A fourth test confirmed the script correctly matches an expected hash supplied in uppercase against the lowercase output `sha256sum` produces natively, since a human operator typing or pasting an expected hash value should not have a failed comparison purely over letter case.
