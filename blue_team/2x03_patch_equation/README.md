MedDefense Health Systems: The Patch Equation

Three critical CVEs landed overnight across the entire MedDefense Linux fleet: a kernel privilege escalation in linux-image (CISA KEV, active exploitation), an openssh-server pre-authentication RCE, and a TLS parsing bug in libssl3. Every hardened server is on the affected list. Hardening decays — sysctl values, AppArmor profiles, and PAM policies do not change by themselves, but the software they protect does, and in 4 of 5 hospital breaches the CISA advisory reviewed, the compromised software had a patch sitting in the repository the whole time.

This project treats patching as engineering, not housekeeping. Every deliverable is a script: idempotent, measuring state before any change, applying patches only after a plan and a maintenance-window check, validating that a fix actually closed the vulnerability it targeted, and always leaving a rollback path open. Every operation is recorded as structured JSON, not free-text notes — when Dr. Morales asks "are we vulnerable to this CVE right now?", the answer is a file produced by a script, not an opinion.

See 0-vuln_inventory.sh onward for the full deliverable set.
