# MedDefense Health Systems: Root cause analysis -billing-srv-01

**Prepared by:** Aïda Sylla, Security Analyst  **Prepared for:** James Chen, Deputy CISO **Source material:** `billing-srv-01_diagnostics.txt` (excerpt provided: `top` snapshot, `netstat` excerpt), prior sysadmin ticket, Incident A (January ransomware, see `1-incident_classification.md`) **Purpose:** Determine the actual cause of recurring "performance degradation" on billing-srv-01 and evaluate whether the sysadmin's proposed hardware upgrade addresses the real problem.

---

## 1. Process identification

**What `kworker` is doing:** The process listed as `./kworker -o stratum+tcp://pool.monero.org:4443` is **not** a legitimate Linux kernel worker thread. Genuine kernel `kworker` threads:

- Run as part of the kernel itself (they do not appear as a standalone executable at a filesystem path like `./kworker`).
- Never take command-line arguments such as `-o` (an "output pool" flag) or a `stratum+tcp://` URL.
- Are owned/scheduled by the kernel, not spawned as a `www-data`-owned userspace process.

This is a classic naming-disguise technique: malware is renamed to `kworker` (or similar kernel-sounding names) specifically so that a quick glance at `top` or `ps` by an administrator looks unremarkable. The "kernel is busy" reads as normal, while "an unknown mining binary is using 94% CPU" would trigger immediate investigation.

**What the `stratum+tcp://pool.monero.org:4443` connection tells us:** `stratum` is the standard TCP-based protocol used by cryptocurrency miners to communicate with a mining pool. It is how a mining client submits computed hashes and receives new work. `pool.monero.org` is a mining pool for **Monero (XMR)**, a privacy-focused cryptocurrency frequently favored by attackers precisely because its transactions are difficult to trace, unlike Bitcoin.

**Purpose of the process:** This is **cryptojacking**. The process is an unauthorized cryptocurrency miner that has been silently installed on billing-srv-01 to consume the server's CPU resources and generate Monero for whoever planted it. It is not related to billing operations, EHR functions, or any legitimate MedDefense service.

**Supporting observation (worth flagging, not asserting as fact):** The mining process runs under the `www-data` user. The account normally used by the Apache web service (`apache2`, also visible in the `top` output). This strongly suggests the miner was dropped through the web application layer (e.g., a web application vulnerability or web shell), rather than through a direct server-level compromise such as a stolen root/administrator credential. This should be **verified**, not assumed, during follow-up log analysis of the Apache service on this host.

**A second unresolved detail:** The `netstat` output also shows an established connection to `91.121.87.10:8080`, in addition to the mining pool connection. Its purpose is not established by the diagnostics provided. It could be a secondary/backup mining pool, a proxy, or a separate command-and-control channel. I don't have a confirmed source or explanation for this connection; it should be treated as an open investigative item rather than classified.

---

## 2. Classifying the real compromise (CIA Triad)

The sysadmin's ticket frames this purely as an **Availability** problem ("CPU saturation... probably undersized... recommend hardware upgrade"). That is a description of the visible **symptom**, not the incident. Before Availability is affected at all, two other pillars are already compromised:

**Integrity: Compromised first.** An unauthorized, disguised executable is running on billing-srv-01. Regardless of what it does, its mere presence means the server's expected, trusted state has been altered without authorization. Someone (or something) placed and executed a foreign binary on this system outside of any change-management or deployment process. This is, by definition, an integrity violation: the system is no longer running only what it is supposed to be running.

**Confidentiality: Compromised second (and this is the more serious concern).** For a mining process to be installed and executed on the server in the first place, whoever placed it needed a level of unauthorized access to the system, most plausibly through the web application (`www-data` context) hosted on this box. Billing-srv-01 handles billing and claims processing, which per the environment summary involves both financial data and PHI-adjacent information. An actor capable of writing and executing a file on this server has, at minimum, the technical capability to read, copy, or exfiltrate whatever data the `www-data` account (and potentially further-escalated access) can reach. There is no direct evidence in the diagnostics that data was actually exfiltrated. That should not be assumed but the access required to install the miner is the same class of access that would allow data theft, which is why confidentiality must be treated as at-risk, not merely availability.

**Availability: The visible, downstream symptom.** The 94.2% CPU consumption by the miner is what causes the "performance degradation" the sysadmin has been reacting to. It is real, but it is the last and least significant of the 3 impacts — a resource-exhaustion side effect of an intrusion that already violated integrity and put confidentiality at risk.

---

## 3. Why the Sysadmin's solution fails

Upgrading billing-srv-01's hardware, or migrating it to a more powerful VM, **does not remove the compromise**. It only changes how the compromise is experienced:

- The miner will simply have more CPU capacity to consume. Mining software typically scales its resource usage to whatever is available; on a larger server, the same malicious process may run less conspicuously (a lower CPU _percentage_ even as it consumes more absolute compute), potentially delaying detection further rather than resolving anything.
- The root cause, how the attacker gained the access needed to place the miner on this server in the first place, remains completely unaddressed. Whatever vulnerability, misconfiguration, or credential weakness enabled the initial compromise is carried over to the new hardware or VM.
- Any data-exposure risk created by the underlying access (see Confidentiality, above) is untouched by a hardware change.
- The recurring pattern would likely continue: IT would eventually see "performance issues" again (or the attacker could pivot to something more damaging than mining, such as data exfiltration or another ransomware deployment) on the new infrastructure, and the cycle of misdiagnosis-and-restart would repeat.

In short: a hardware upgrade treats a capacity symptom that does not actually exist as a capacity problem, while leaving the actual security incident (an unauthorized actor with code-execution capability on a financially/clinically sensitive server) completely unresolved.

---

## 4. Connection to the January ransomware incident (Incident A)

Billing-srv-01 has now been compromised twice within the same fiscal period, by two different types of malware (ransomware in January; a cryptominer discovered after the rebuild), and the sysadmin's own ticket confirms this is the **third** "performance degradation" flag on this specific server in two months.

This pattern suggests one of two possibilities, both of which point away from "coincidence" and toward an **unresolved entry vector**:

1. **The rebuild after the January ransomware incident restored the server's data/services but did not identify and close the original access vector.** If the same vulnerability, exposed service, or credential weakness that let the ransomware in in January was never found and fixed, it remains available for any subsequent attacker (the same one, or an unrelated opportunistic one) to walk back through, which is consistent with a cryptominer appearing on the rebuilt system.
2. **The rebuild itself may not have started from a verified-clean state.** If the restore process used backups, images, or configuration captured at or after the point of initial compromise, a backdoor or vulnerable configuration could have been unintentionally carried over into the "rebuilt" server.

**The question this should raise for the assessment is not "why does this server keep having problems," but:**

> _"What is the actual initial access vector into billing-srv-01, was it identified and formally remediated as part of the January incident response, and was the rebuild verified as clean before returning the server to production?"_

This question matters because, per the environment summary, billing-srv-01 sits on Central's flat, unsegmented network (10.10.0.0/16, no VLANs) alongside the EHR database, domain controllers, and medical devices, and Linux servers organization-wide still permit SSH password authentication (migration to key-only auth was only completed on `ehr-srv-01` before Marcus's departure). If the access vector is something systemic — a weak or reused credential, an exposed service, or a web application flaw — rather than something unique to this one server, then billing-srv-01 should be treated as an indicator of a broader exposure across Central's server estate, not an isolated "problem server." This should be escalated as a priority item for the gap analysis: a proper root-cause investigation (log review, timeline reconstruction, and vulnerability identification) is needed before billing-srv-01 can be considered trustworthy again — a hardware upgrade should not proceed until that investigation is complete.
