# MedDefense Health Systems: The Key Exchange

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** A Diffie-Hellman key exchange performed directly with OpenSSL for this document, cross-referenced against Finding 014 and RISK-010 (1x02/1x03, the Westside site-to-site VPN) **Purpose:** Reproduce, hands-on, the 1976 solution to the key distribution problem, then demonstrate precisely where that solution stops protecting MedDefense and certificates have to take over.

---

## Part 1: The DH Simulation

**Step 1: Shared DH parameters (2048-bit).**

```
$ openssl dhparam -out dhparams.pem 2048
```

Real output confirmed on a Kali Linux workstation: `dhparams.pem` generated successfully, using the visible `+` and `*` progress indicators OpenSSL prints during the underlying prime-search computation. This is worth noting directly rather than assumed away: DH parameter generation is genuinely computationally expensive, which is exactly why these parameters are generated once and reused, never regenerated per-connection.

**Step 2 and 3: Alice's key pair, derived from the shared parameters.**

```
$ openssl genpkey -paramfile dhparams.pem -out alice_private.pem
$ openssl pkey -in alice_private.pem -pubout -out alice_public.pem
```

Output confirmed: `alice_private.pem` and `alice_public.pem` both generated successfully with no errors.

**Step 4: Bob's key pair, derived from the identical shared parameters.**

```
$ openssl genpkey -paramfile dhparams.pem -out bob_private.pem
$ openssl pkey -in bob_private.pem -pubout -out bob_public.pem
```

Output confirmed: `bob_private.pem` and `bob_public.pem` both generated successfully with no errors. Both key pairs were generated from the exact same `dhparams.pem`, the mathematical precondition that makes the next step work at all.

**Step 5: Alice derives the shared secret from her own private key and Bob's public key.**

```
$ openssl pkeyutl -derive -inkey alice_private.pem -peerkey bob_public.pem -out alice_secret.bin
```

Output: `alice_secret.bin`, 256 bytes (2048 bits, matching the DH parameter size exactly).

**Step 6: Bob derives the shared secret from his own private key and Alice's public key.**

```
$ openssl pkeyutl -derive -inkey bob_private.pem -peerkey alice_public.pem -out bob_secret.bin
```

Output: `bob_secret.bin`, 256 bytes.

**Step 7: Comparing the two secrets.**

```
$ diff alice_secret.bin bob_secret.bin
$ echo $?
0
```

Real result: **no output from `diff`, exit code 0.** Confirmed definitively with a second, independent check:

```
$ sha256sum alice_secret.bin bob_secret.bin
066711d8d9e17d2c9d7e10c1b3c9eade8f674a8edd44b8ad7c1ea3c06dcd64fa  alice_secret.bin
066711d8d9e17d2c9d7e10c1b3c9eade8f674a8edd44b8ad7c1ea3c06dcd64fa  bob_secret.bin
```

Identical hashes. Alice and Bob, working entirely independently, each with only their own private key and the other party's public key, arrived at exactly the same 256-byte value, confirmed here by the matching SHA-256 digest above rather than by displaying the raw secret's full hex content, since the value itself is randomly generated fresh on every run of this exercise and has no meaning as a fixed reference number; what matters, and what is verified conclusively here, is that both independently-computed values are identical to each other.

---

## Part 2: The Explanation, for Robert Kim

Think of it like mixing paint. Alice and Bob agree publicly, out loud, where anyone can hear, on a starting can of yellow paint (the shared DH parameters). Each of them then privately adds their own secret color at home, where nobody is watching: Alice mixes in a private shade only she knows, and so does Bob. They each mail the other their resulting mixed color, still in the open, where anyone can see the color itself. Here is the trick: mixing paint is easy to do, but essentially impossible to undo. Nobody watching the exchange can look at either mixed color and work backward to figure out the original private shade each person added. When Alice takes the color Bob mailed her and mixes in her own private shade again, and Bob does the same with Alice's color and his own private shade, they both end up with the exact same final color, confirmed here byte for byte in the OpenSSL output above, without either of them ever having mailed that final color to the other. Eve, watching every single message on the wire, sees the starting paint and both parties' mixed colors in full, everything this document just showed in Part 1's public key files, but she cannot reconstruct either private shade from what she observed, and without one of those two private shades, she cannot mix the final, matching color herself.

---

## Part 3: The MITM Attack

Plain Diffie-Hellman authenticates nothing about who is on the other end of the exchange; it only guarantees that whoever holds the matching private key can compute the same shared secret, and Eve can simply become that person. If Eve sits on the network path between Alice and Bob, she does not need to break the mathematics at all: she intercepts Alice's public key before it reaches Bob and substitutes her own, then intercepts Bob's public key headed back to Alice and substitutes her own there too, meaning Alice unknowingly completes a DH exchange with Eve while believing she is talking to Bob, and Bob unknowingly completes a separate DH exchange with Eve while believing he is talking to Alice. Eve now holds two different shared secrets, one with each victim, and can decrypt every message from Alice, read or alter it, then re-encrypt it under the other secret before forwarding it to Bob, with neither party ever noticing the traffic passed through a third party at all. **Mapped directly to MedDefense: the Central-to-Westside VPN tunnel is confirmed in this program's own prior work (1x02, Finding 014; 1x03, RISK-010) to terminate on a consumer-grade router with an unknown firmware and patching history**, meaning if that tunnel's key exchange relied on DH alone with no independent way to verify the other endpoint's identity, an attacker positioned on that path could execute exactly this attack, intercepting the exchange and reading or modifying every byte of clinical and financial traffic between the two sites without either endpoint detecting a problem. **Certificates prevent this specifically by binding a public key to a verified identity through a trusted third party's signature**, so that when Alice receives a public key claiming to be Bob's, she can check it against a certificate signed by an authority she already trusts, rather than accepting whatever public key arrives on the wire at face value; an attacker substituting their own key cannot also forge that certificate's signature, and the substitution is detected before the exchange ever completes, which is exactly why MedDefense's site-to-site VPN configuration must be verified to be authenticating both endpoints with certificates, not relying on Diffie-Hellman's key agreement alone.
