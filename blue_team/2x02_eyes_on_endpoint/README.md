MedDefense Health Systems: Eyes on the Endpoint

billing-srv-01 scores 84 on Lynis. DC01 has Sysmon deployed, locked passwords, AES-only Kerberos, SMBv1 disabled, AppLocker in audit mode. Hardening reduced what an attacker can do — but walls do not tell you when someone is climbing them. The Crimson Tide advisory confirmed that hospitals with firewalls and antivirus still missed an attacker living inside their network for 4-7 days, because nobody was watching. Deploying Sysmon, auditd rules, and PowerShell logging is not the same as proving they actually capture what matters.

This project produces no report. Every deliverable is a script that triggers a specific, controlled action and verifies the corresponding telemetry event was actually captured, with the expected level of detail. Every script carries a header (name, purpose, author) and follows the language-specific error-handling standard: Set-StrictMode -Version Latest for PowerShell, #!/bin/bash plus a clean shellcheck pass for Bash.

See 0-sysmon_validation.ps1 onward for the full deliverable set.
