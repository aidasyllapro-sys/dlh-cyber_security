# MedDefense Health Systems: The Disk Encryption Lab

**Prepared by:** Aïda Sylla, Security Analyst **Source material:** A real, complete LUKS2 workflow performed directly with `cryptsetup` on a Kali Linux workstation, cross-referenced against Finding 015 (1x02, NAS-01 unencrypted storage), the Crypto Inventory (Task 0), and the AES performance measurements from Task 1 **Purpose:** NAS-01 stores every MedDefense backup in plaintext today. This document practices the encryption-at-rest workflow on a safe target before that changes on production, and designs the actual strategy for NAS-01 itself.

---

## Part 1: LUKS Setup

**Step 1: the 500MB backing file.**

```
$ dd if=/dev/zero of=encrypted_volume.img bs=1M count=500
500+0 records in
500+0 records out
524288000 bytes (524 MB, 500 MiB) copied, 2.87104 s, 183 MB/s
```

**Step 2: format with LUKS.**

```
$ sudo cryptsetup luksFormat encrypted_volume.img

WARNING!
========
This will overwrite data on encrypted_volume.img irrevocably.
Are you sure? (Type 'yes' in capital letters): YES
Enter passphrase for encrypted_volume.img:
Verify passphrase:
```

**Step 3: open the encrypted volume.**

```
$ sudo cryptsetup luksOpen encrypted_volume.img secure_vol
Enter passphrase for encrypted_volume.img:
```

**Step 4: create a filesystem and write test data.**

```
$ sudo mkfs.ext4 /dev/mapper/secure_vol
mke2fs 1.47.4 (6-Mar-2025)
Creating filesystem with 123904 4k blocks and 123904 inodes
Filesystem UUID: d4c37141-3f6e-4d9d-9a6a-224941e65e72
Superblock backups stored on blocks:
        32768, 98304

Allocating group tables: done
Writing inode tables: done
Creating journal (4096 blocks): done
Writing superblocks and filesystem accounting information: done

$ sudo mkdir -p /mnt/secure_vol
$ sudo mount /dev/mapper/secure_vol /mnt/secure_vol
$ echo "MedDefense test data - patient backup sample" | sudo tee /mnt/secure_vol/test.txt
MedDefense test data - patient backup sample
$ cat /mnt/secure_vol/test.txt
MedDefense test data - patient backup sample
```

**Step 5: unmount and close.**

```
$ sudo umount /mnt/secure_vol
$ sudo cryptsetup luksClose secure_vol
```

Every step completed without error, `cryptsetup 2.8.6` confirmed available and working natively.

---

## Part 2: Verification

**Attempting to read the raw, closed volume file for any trace of plaintext:**

```
$ strings encrypted_volume.img | head -50
```

**A genuinely important, precise result, worth explaining carefully rather than reported as a flat "nothing was found."** The command's real output is not empty; it shows readable text, but that text is the **LUKS2 header's own JSON metadata**, not the patient backup data written inside the volume:

```
LUKS
sha256
7ceed2bd-0ffe-46a7-ae15-087fd00a5e9d
{"keyslots":{"0":{"type":"luks2","key_size":64,"af":{"type":"luks1",
"stripes":4000,"hash":"sha256"},"area":{"type":"raw","offset":"32768",
"size":"258048","encryption":"aes-xts-plain64","key_size":64},
"kdf":{"type":"argon2id","time":4,"memory":680783,"cpus":2,
"salt":"Y7Vg011NIughOuL7c7C/D0OU12M9utXsLaGBncaprsQ="}}},"tokens":{},
"segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic",
"iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":4096}},
"digests":{"0":{"type":"pbkdf2","keyslots":["0"],"segments":["0"],
"hash":"sha256","iterations":414129, ...
```

This is the correct, expected LUKS2 design, not a flaw: the header describing _how_ to decrypt the volume (which algorithm, which key derivation function, where the encrypted data segment begins) is stored in cleartext by design, because a client needs to read this metadata before it can even attempt to unlock anything. **This is a genuinely useful, real confirmation of two specific choices this project has already discussed on its own merits**: the header shows `"encryption":"aes-xts-plain64"`, confirming LUKS2's default cipher is AES in XTS mode, a third distinct mode from the CBC and GCM already worked with in Task 1, specifically designed for disk encryption rather than network or file transport. It also shows `"kdf":{"type":"argon2id",...}`, confirming LUKS2 uses Argon2id, the exact key-derivation function this project's own Task 3 independently recommended as the strongest available choice for password-based key stretching, here validated as the real, current default for Linux's own disk encryption standard, not merely this project's own theoretical preference.

**The actual data, in contrast, produced no match anywhere in the file:**

```
$ grep -a "MedDefense test data" encrypted_volume.img
$ echo "Code de sortie: $?"
Code de sortie: 1
```

No output from `grep`, exit code 1, confirming the specific sentence written inside the encrypted volume does not appear anywhere in the raw file, distinguishing clearly between "the header is intentionally readable" and "the payload is not," the precise distinction this task's own question is really asking about.

**The full reopen-mount-read-unmount-close cycle, confirming data integrity:**

```
$ sudo cryptsetup luksOpen encrypted_volume.img secure_vol
Enter passphrase for encrypted_volume.img:
$ sudo mount /dev/mapper/secure_vol /mnt/secure_vol
$ cat /mnt/secure_vol/test.txt
MedDefense test data - patient backup sample
$ sudo umount /mnt/secure_vol
$ sudo cryptsetup luksClose secure_vol
```

The data returned exactly as written, confirming the volume's contents survive a full close-and-reopen cycle intact, exactly as production backup storage requires.

---

## Part 3: The LUKS Automation Script

`12-luks_manager.sh` implements `create`, `open`, and `close` modes using the genuine `cryptsetup` command sequence (`luksFormat`, `luksOpen`, `mkfs.ext4`, `luksClose`), matching exactly what MedDefense's actual production deployment on NAS-01 will run. **All three modes were tested directly and confirmed working end to end on a real Kali Linux system:**

```
$ sudo ./12-luks_manager.sh create test_volume.img 100 test_secure_vol
Creating a 100MB backing file at test_volume.img...
100+0 records in
100+0 records out
104857600 bytes (105 MB, 100 MiB) copied, 0.0372922 s, 2.8 GB/s
Formatting test_volume.img with LUKS...
[... luksFormat, luksOpen, mkfs.ext4 all succeed ...]
Volume created and closed. Use 'open' mode to mount it for use.

$ sudo ./12-luks_manager.sh open test_volume.img test_secure_vol /mnt/test_secure_vol
Volume open and mounted at /mnt/test_secure_vol.

$ echo "MedDefense test via script" | sudo tee /mnt/test_secure_vol/proof.txt
MedDefense test via script
$ cat /mnt/test_secure_vol/proof.txt
MedDefense test via script

$ sudo ./12-luks_manager.sh close test_secure_vol /mnt/test_secure_vol
Volume unmounted and closed.
```

All three modes completed without error on the first attempt, confirming the script's command sequence is correct against a real cryptsetup installation, not only syntactically valid.

---

## Part 4: MedDefense Backup Encryption Design for NAS-01

**Encryption level: volume-level (full-disk/full-volume), not file-level.** NAS-01 hosts backup archives from multiple source systems (PostgreSQL dumps, MySQL dumps, general file backups) with no ongoing need for granular, per-file access control the way a shared document repository might have; a single LUKS-encrypted volume covering the entire backup storage area protects everything written to it uniformly, without requiring every backup job across every source system to separately implement its own file-level encryption logic, a design that would multiply the chances of one job being misconfigured to skip encryption entirely.

**Performance overhead.** This project's own hands-on work now confirms directly, from the real LUKS2 header captured in Part 2, that the default cipher is AES-XTS, not the AES-CBC measured in Task 1's own performance benchmarking. XTS is itself a block-cipher mode built on the same underlying AES round function CBC and GCM both use, and benefits from the same AES-NI hardware acceleration Task 1 already confirmed present on this hardware; while this project has not directly benchmarked AES-XTS throughput, the reasonable, evidence-adjacent estimate is that its per-byte cost sits in a similar range to the CBC figures already measured (roughly 135 MB/s wall-clock in Task 1), meaning encryption overhead for NAS-01's backup jobs should remain a modest, low single-digit percentage of total job time, not a multiple, since network transfer and disk write speed are far more likely to dominate total backup duration than the cost of encrypting each block as it is written.

**Where the encryption key is stored: not on the NAS.** This is not a preference, it is the exact lesson Sarah Park's own crypto audit notes already stated directly (1x03, Task 0): "If we encrypt the backups on the NAS and the key is stored on the NAS, and ransomware encrypts the NAS, we lose both the backups AND the key. This needs to be designed properly." The LUKS passphrase (or, more precisely, a key file protecting the actual LUKS master key, allowing rotation without re-encrypting the full volume) should be stored in a dedicated key management system, physically and logically separate from NAS-01, consistent with the tokenization vault design this project's own Task 7 already built on this exact principle: the data and the key to that data should never share a single point of failure.

**What happens if the key is lost.** This must be stated with full honesty rather than softened: **a lost LUKS passphrase (with no other enrolled key slot) means the backup data is permanently, cryptographically unrecoverable**, indistinguishable in practice from the disk having been destroyed. This is precisely why LUKS2's design of supporting multiple independent key slots matters operationally, not just academically: a second, independently-held recovery passphrase or key file can be enrolled in a separate key slot specifically to avoid a single lost credential becoming a total data-loss event, though that second credential must itself be stored with the same rigor and separation as the primary key, or it simply becomes a second single point of failure rather than a genuine safeguard.

**Integration with the offsite cloud replication control (1x03, Task 7, Control 4).** Yes, the cloud replica must also be encrypted, and it should use a **separate key from NAS-01's own local LUKS passphrase**, not the same one. Using an identical key for both would mean a single key compromise exposes both the local and offsite copies simultaneously, defeating much of the purpose of maintaining a geographically and logically separate backup in the first place. The cloud replica's own encryption (for example, AWS S3 with server-side encryption using a customer-managed key, distinct from any key AWS itself could access unilaterally) should be managed independently, with its own key stored in its own separate location, so that a compromise of NAS-01's on-premises key management system does not also grant access to the offsite copy, and vice versa, preserving the actual redundancy this control was funded to provide.
