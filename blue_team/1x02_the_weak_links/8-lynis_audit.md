# MedDefense Health Systems: The Self-Audit: Lynis Security Audit

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** Lynis 3.1.6 audit (`lynis audit system`), run directly on the analyst's own Kali Linux machine (275 tests performed, 1 plugin enabled) **Purpose:** Run a real security auditing tool on a real machine to build the practical skill of reading raw audit output, then project that understanding onto billing-srv-01 in the MedDefense environment.

---

## Part 1: Hardening Index

**Hardening index: 61 / 100** `[############ ]`

This score reflects a Kali Linux rolling-release install used for security tooling and coursework, not a hardened production server, and not intended to be one. It should be read as a baseline, not a target: 275 individual tests were run, and the majority returned `[ OK ]`, with the score primarily reduced by hardening features (kernel sysctls, mandatory access control, file integrity monitoring) that are reasonable to leave disabled on a personal pentesting workstation but would be genuinely dangerous to leave disabled on a production server holding patient or financial data.

---

## Part 2: Analysis of Results

### Top Warnings

Lynis's own "Warnings" summary section lists exactly **one** formal Warning-tier finding, and a full read of the raw scan output surfaces exactly **two more** items independently marked `[ WARNING ]` inline during individual checks (as opposed to Lynis's own internal "this test took a long time to run" performance notices, which are not security findings and are excluded here). That is **3 total genuine security Warnings**, not 5, reported honestly rather than padded, with the reason this matters explained after the third entry.

```
1. [NETW-2705] Couldn't find 2 responsive nameservers
   What Lynis checks: Whether /etc/resolv.conf lists at least two
     working DNS resolvers, tested by actually querying each one.
   Why it matters: A single DNS resolver is a single point of failure —
     if it becomes unreachable, the system loses the ability to resolve
     any hostname, which can silently break package updates, security
     tool downloads, and any service with a hostname-based dependency.
     This is an availability/resilience gap rather than a directly
     attacker-exploitable flaw.
   Remediation: Add a second nameserver entry to /etc/resolv.conf (or
     the relevant NetworkManager/systemd-resolved configuration) — for
     example a secondary internal DNS server or a redundant resolver.
```

```
2. [AUTH] Permissions for directory: /etc/sudoers.d — WARNING
   What Lynis checks: File and directory permissions on sudo-related
     configuration paths, verifying they are not writable by
     unauthorized (non-root) users.
   Why it matters: /etc/sudoers.d contains files that directly grant
     privilege-escalation rights — who is allowed to run what as root.
     If this directory's permissions are looser than they should be, a
     lower-privileged local user or a compromised low-privilege process
     could potentially add or modify a rule and grant itself root
     access — a direct local privilege escalation path.
   Remediation: Verify actual current permissions (`ls -la
     /etc/sudoers.d`) and correct them if looser than the expected
     baseline (typically 750, owned by root:root); audit individual
     files inside the directory as well, not just the directory itself.
```

```
3. [HOME] Permissions of home directories — WARNING
   What Lynis checks: Whether user home directories are more permissive
     than they should be (e.g., world-readable or world-writable),
     which would let other local accounts browse another user's files.
   Why it matters: On a multi-user system, loosely permissioned home
     directories allow any local account to read another user's files —
     SSH private keys, shell history, credentials accidentally stored in
     dotfiles — enabling local information disclosure and lateral
     movement between accounts on the same machine.
   Remediation: Audit and tighten home directory permissions (e.g.,
     `chmod 750 /home/<user>` for each account) so only the owner (and
     root) can access the contents by default.
```

**Why only 3, not 5:** this is itself worth stating plainly rather than treated as a shortfall in the audit. Lynis reserves its Warning tier for its most serious, high-confidence findings. The vast majority of hardening opportunities on this particular machine (57 of them) fall into the lower-severity Suggestions tier instead, covered next. A low Warning count on a single-user development workstation with a small attack surface is not evidence of strong hardening; it is partly a reflection of how little is exposed on this machine to begin with. This distinction matters directly for Part 3 below, where the same tool run against a real production server with far more exposed services would very plausibly surface a longer Warnings list, not just a longer Suggestions list.

### Top 5 Suggestions

Selected from the 57 total Suggestions, prioritized for direct relevance to this project's already-documented MedDefense findings:

```
1. [AUTH-9262] Install a PAM module for password strength testing
   (pam_cracklib, pam_passwdqc, or libpam-passwdqc)
   Security improvement: Enforces minimum password complexity at the
     authentication layer itself, rather than relying on policy alone —
     directly relevant given this entire project has repeatedly
     identified weak/absent authentication hardening (no MFA anywhere
     at MedDefense) as a top-priority, recurring gap.
```

```
2. [DEB-0880] Install fail2ban to automatically ban hosts that commit
   multiple authentication errors
   Security improvement: Provides automated brute-force protection by
     temporarily blocking source IPs after repeated failed login
     attempts — a compensating control that directly reduces the risk
     created by any system (like billing-srv-01) that still permits
     password-based authentication.
```

```
3. [SSH-7408] Harden SSH configuration (multiple sub-findings:
   AllowTcpForwarding, X11Forwarding, AllowAgentForwarding set to YES
   where NO is recommended; MaxAuthTries at 6 instead of 3; LogLevel at
   INFO instead of VERBOSE; among others)
   Security improvement: Each of these settings reduces SSH's usable
     attack surface — disabling unused forwarding features removes
     potential tunneling/pivoting paths, lowering MaxAuthTries reduces
     the brute-force attempt budget per connection, and raising
     LogLevel to VERBOSE improves the audit trail for any authentication
     attempt. This directly parallels the SSH hardening gap already
     documented for MedDefense's own Linux servers (only ehr-srv-01 has
     been migrated to key-only authentication).
```

```
4. [HRDN-7230] Harden the system by installing at least one malware
   scanner for periodic file system scans (e.g., rkhunter, chkrootkit,
   OSSEC, Wazuh)
   Security improvement: Provides a detection capability for malicious
     files, rootkits, or unauthorized binaries already present on disk —
     directly relevant given this exact category of gap (no server-
     class malware detection) is the confirmed root cause that let a
     cryptominer run undetected on billing-srv-01 for an extended
     period in this project's own incident history.
```

```
5. [ACCT-9628] Enable auditd to collect audit information
   Security improvement: Provides detailed, kernel-level logging of
     security-relevant system events (file access, command execution,
     privilege use) — directly relevant given the absence of
     centralized detection and audit capability has been the single
     most frequently repeated finding across this entire two-project
     body of work.
```

### Category Breakdown

Lynis organizes its 275 tests into roughly 30 categories. Reading across all of them, a clear pattern emerges:

**Categories that scored well** (predominantly `[ OK ]`): Users, Groups and Authentication (account consistency, password file integrity); Memory and Processes (no zombie processes, no I/O-waiting processes); most of Networking (no promiscuous interfaces, no waiting connections); and most of File Permissions (core system files like `/etc/passwd`, `/etc/group`, and `/boot/grub/grub.cfg` all correctly permissioned).

**Categories that scored poorly, and the pattern among them is not random:**

- **Kernel Hardening**: 17 of roughly 34 checked sysctl values were flagged `[ DIFFERENT ]` from the hardened baseline (kernel.kptr_restrict, kernel.dmesg_restrict, kernel.yama.ptrace_scope, net.ipv4.conf.all.rp_filter, among many others) — roughly half of all kernel-level hardening controls checked are at their permissive defaults.
- **Security frameworks**: Both AppArmor and SELinux are present on the system but explicitly **disabled**; no Mandatory Access Control framework is active at all.
- **Software: file integrity**: dm-integrity disabled, dm-verity disabled, no file integrity tool installed. Zero for three.
- **Software: Malware**: No malware scanning components found at all.
- **Software: System tooling**: No automation tooling, and explicitly "Checking for IDS/IPS tooling - NONE."
- **Accounting**: Process accounting not found, sysstat disabled, auditd not found. Zero for three, matching the pattern above exactly.
- **Banners and identification**: Both `/etc/issue` and `/etc/issue.net` flagged `[ WEAK ]` (no legal warning banner configured).

**What this tells us about this system's security posture (and it is a genuinely useful pattern, not just a list of gaps):** every category that scored poorly is, in one way or another, a **detective or hardening-in-depth** control (kernel introspection restrictions, mandatory access control, file integrity monitoring, malware scanning, audit logging), while the categories that scored well are largely **baseline hygiene** controls (correct file ownership, consistent account records, no obviously broken configuration). This is not a coincidence specific to this one machine. It is the exact same "prevention-and-hygiene-present, detection-and-defense-in-depth-absent" pattern this entire project has independently identified as MedDefense's core organizational weakness, from Gap G-001/GAP-004 in Project 0x00 through the recurring "no centralized detection" finding threaded across nearly every kill chain in Project 1x01. Seeing the identical shape of gap reproduce itself on a single personal machine, audited by an entirely different tool, is a small but genuine confirmation that this pattern is common industry-wide, not an artifact of how MedDefense specifically was assessed.

---

## Part 3: MedDefense Projection - billing-srv-01

Without direct access to MedDefense's servers, the following 5 findings are projected for billing-srv-01 (Ubuntu 18.04, Apache 2.4.29, MySQL, a documented cryptominer compromise history, and SSH password authentication confirmed enabled), reasoning from what this Lynis run found on a comparable but far less exposed Ubuntu-family system, combined with facts already established about billing-srv-01 elsewhere in this project.

```
Prediction 1: SSH password authentication itself flagged prominently
  (SSH-7408 family, likely escalated beyond a Suggestion)
Reasoning: This Lynis run flagged multiple SSH hardening Suggestions
  even on a machine where password authentication was not itself the
  headline issue. billing-srv-01 is already confirmed (Project 0x00,
  Task 2) to have PasswordAuthentication enabled with no account
  lockout policy — a materially more severe, actively brute-forceable
  configuration than anything observed in this self-audit. Lynis would
  very plausibly flag this at Warning tier rather than Suggestion tier
  given the demonstrably higher real-world risk.
```

```
Prediction 2: No malware scanner installed (HRDN-7230)
Reasoning: This exact finding appeared on the self-audited machine
  despite it never having been compromised. On billing-srv-01, the same
  absence would be flagged identically — but it would carry
  categorically more weight, since this server has already been
  compromised by an undetected cryptominer in this project's own
  documented incident history (Project 0x00, Task 2). The Lynis finding
  here would not be a theoretical suggestion; it would be a direct
  explanation for why that compromise went unnoticed for as long as it
  did.
```

```
Prediction 3: Outdated or unassessable package vulnerability status
  (PKGS-family checks)
Reasoning: Ubuntu 18.04's standard security support ended in June 2023,
  and Extended Security Maintenance was never activated on billing-
  srv-01 (confirmed directly in the vulnerability scan, Finding 011).
  Lynis's package vulnerability check depends on active, current
  repository data — without ESM enrollment, this check would either
  surface a large number of genuinely vulnerable packages or be unable
  to properly assess currency at all, both of which are red flags in
  their own right.
```

```
Prediction 4: Apache hardening modules absent (HTTP-6640 / HTTP-6643 —
  no mod_evasive, no ModSecurity)
Reasoning: Both were flagged as absent on the self-audited machine's
  own Apache installation. On billing-srv-01, this same absence is far
  more consequential: Apache 2.4.29 on this exact host carries a
  confirmed, unpatched Critical vulnerability (CVE-2021-44790, CVSS
  9.8, Finding 001 of the vulnerability scan). The absence of a web
  application firewall (ModSecurity) or anti-DoS/brute-force module
  (mod_evasive) means no compensating control exists for that specific,
  already-identified unpatched flaw.
```

```
Prediction 5: No audit daemon / accounting active (ACCT-9628 and
  related)
Reasoning: This self-audit found process accounting, sysstat, and
  auditd all absent or disabled. Given that GAP-004 (no centralized
  detection or logging correlation) is the single most repeated finding
  across both this project and Project 0x00's posture assessment, and
  given billing-srv-01 specifically is the server where a real
  compromise already went undetected for an extended period, it would
  be surprising if this server had auditd enabled when a general-
  purpose development machine in this self-audit did not. This
  prediction is less about auditd's absence in isolation and more about
  confirming, from an entirely independent tool, the same detection gap
  already established through direct evidence elsewhere in this project.
```

**Overall framing for this projection:** none of these 5 predictions require new information. Each one takes a finding this self-audit already surfaced on a low-stakes personal machine and reasons about how the same underlying gap would manifest with substantially higher consequence on a server that is a documented, repeat compromise target holding financial and PHI-adjacent data. That gap between "low-stakes finding" and "high-consequence finding" is precisely the translation this entire project exists to make.
