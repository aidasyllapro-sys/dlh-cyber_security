MedDefense Health Systems: The Windows Fortress

DC01, the Windows Server 2022 domain controller for meddefense.local, has never had a structured security reconnaissance performed against it. The Crimson Tide campaign profiled in 1x01 targets exactly this kind of environment: privileged accounts, service accounts, and Kerberos delegation paths that go unreviewed. Until the current state of the domain — accounts, groups, service accounts, GPOs, password and lockout policy, Kerberos encryption support, and privileged group membership — is documented, no targeted hardening decision can be justified.

This project produces no report. Every deliverable is a PowerShell script: read-only where reconnaissance is the goal, idempotent where configuration changes are made, and producing structured JSON output as audit evidence. Every script carries a header (name, purpose, author, date) and uses Set-StrictMode -Version Latest and $ErrorActionPreference = "Stop" for robust error handling.

See 0-domain_baseline.ps1 onward for the full deliverable set.
