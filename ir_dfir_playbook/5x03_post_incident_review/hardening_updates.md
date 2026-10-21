# Hardening Updates: IR-2026-0414-01

Each control below is justified by a specific finding in `forensic_findings_summary.md` and
closes a specific Gap ID from `gap_analysis.md` (Task 2). Where I am not fully certain a
documented configuration detail is still Microsoft's current, supported guidance, I flag it
explicitly rather than presenting it as confirmed — verify against current Microsoft Learn
documentation before deployment in all four cases below.

---

## HRD-001: PowerShell Constrained Language Mode

**Closes:** GAP-004, GAP-005

**Configuration:**
- Documented, supported path: enforce a Windows Defender Application Control (WDAC) policy in
  Enforce mode. When WDAC is enforced, PowerShell automatically restricts any session running
  under an identity not covered by an allowed signer/path rule to Constrained Language Mode —
  this is the same WDAC infrastructure as HRD-002 below, applied policy-wide rather than only
  to `MSBuild.exe`.
- Legacy/test-only mechanism commonly cited for this purpose (not a supported security boundary
  on its own — I am not fully certain this is still Microsoft's current recommended production
  path, and it can reportedly be altered by an account with write access to the environment
  variable, so verify current guidance before relying on it as the only control):
  - GPO: Computer Configuration > Preferences > Windows Settings > Environment
  - Variable name: `__PSLockdownPolicy`
  - Value: `4` (Constrained Language)

**Effect:** Blocks `[System.Management.Automation.ScriptBlock]::Create` and arbitrary .NET type
instantiation from a non-administrative PowerShell session. This is the layer the incident's
actual technique depended on: `powershell.exe` (PID 7812, `-ep bypass -w hidden -enc ...`)
launched `MSBuild.exe` (PID 8104), which executed an inline-task XML (`update.xml`) that
compiles and runs embedded C# at runtime — a .NET-type-loading operation Constrained Language
Mode is designed to block before MSBuild itself ever needs to be reached. It directly
complements GAP-005 (which blocks `MSBuild.exe` execution itself) and, by preventing the
technique at an earlier layer, reduces how often the detection gap in GAP-004 (alert fired with
no automated containment) would ever need to matter again.

**Applies to:** Non-administrative accounts on all clinical and administrative workstations,
including the `WST-WS-031`/`WST-WS-017` host class (`asset_class=clinical_workstation`).

**Validation:** As a standard (non-administrative) user, run:
```powershell
$ExecutionContext.SessionState.LanguageMode
```
Expected output: `ConstrainedLanguage`.

---

## HRD-002: WDAC / AppLocker rule restricting MSBuild.exe

**Closes:** GAP-005

**Configuration:** An AppLocker Executable rule collection, in Enforce mode, denying
`MSBuild.exe` by default and allowing it only for `BUILTIN\Administrators` and named CI/CD
service accounts (for example `MEDDEFENSE\svc-cicd-build`). Recommended: run in Audit mode for
at least one full build cycle before switching to Enforce, to confirm no legitimate developer
workflow outside the allow-listed accounts is broken (the clean baseline in `clean_sysmon.jsonl`
shows MSBuild.exe launched via `devenv.exe` under a developer's own session, not a service
account — confirm with the engineering team whether that workflow needs its own exception before
enforcing). General AppLocker Publisher rule structure (verify the exact current schema against
Microsoft Learn before import — I am giving the general shape, not a byte-exact export):
```xml
<RuleCollection Type="Exe" EnforcementMode="Enabled">
  <FilePublisherRule Id="<GUID>" Name="Deny MSBuild.exe except CI/CD and Admins"
                      Description="Closes GAP-005 (IR-2026-0414-01)" UserOrGroupSid="S-1-1-0"
                      Action="Deny">
    <Conditions>
      <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
                               ProductName="MICROSOFT(R) BUILD TOOLS"
                               BinaryName="MSBUILD.EXE">
        <BinaryVersionRange LowSection="*" HighSection="*" />
      </FilePublisherCondition>
    </Conditions>
  </FilePublisherRule>
  <FilePublisherRule Id="<GUID>" Name="Allow MSBuild.exe for CI/CD service account"
                      UserOrGroupSid="<SID of MEDDEFENSE\svc-cicd-build>" Action="Allow">
    <Conditions>
      <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
                               ProductName="MICROSOFT(R) BUILD TOOLS"
                               BinaryName="MSBUILD.EXE">
        <BinaryVersionRange LowSection="*" HighSection="*" />
      </FilePublisherCondition>
    </Conditions>
  </FilePublisherRule>
</RuleCollection>
```

**Effect:** Stops `MSBuild.exe` from executing an attacker-supplied inline-task file at all,
for any account other than `BUILTIN\Administrators` or the named CI/CD service account —
directly closing the gap that let the incident's `update.xml` run on a clinical workstation
(`ART-001-F01`/`ART-001-F02`, `forensic_findings_summary.md`).

**Applies to:** All clinical and administrative workstations; build/CI infrastructure is
explicitly excluded via the allow rule rather than left unmanaged.

**Validation:** As a standard user, attempt `msbuild.exe C:\Windows\Temp\test.xml` and confirm
it is blocked; check for AppLocker event ID 8004 ("was prevented from running") in
`Applications and Services Logs > Microsoft > Windows > AppLocker > EXE and DLL`.

---

## HRD-003: Conditional access policy for VPN logons from a new geography

**Closes:** GAP-002, GAP-003

**Configuration:** This closes an existing gap rather than a missing capability — Entra ID
(Azure AD) Identity Protection already scored the account's 18:14:41Z sign-in as
`risk=medium, risk_detail=impossibleTravel` (`ad_auth_log.jsonl`); the actual failure was that
the `ca_policy=compliant_device` exception let it through unchallenged.
- Primary fix: edit the existing Conditional Access policy so the "trusted/compliant device"
  exception no longer bypasses a medium-or-higher Identity Protection risk score. Policy logic:
  `IF user_risk >= Medium OR sign_in_risk >= Medium THEN require MFA (phishing-resistant,
  e.g. FIDO2/Windows Hello for Business), regardless of device compliance state.`
- Secondary, narrower control specifically for "new country in the prior 30 days": native
  Conditional Access location conditions work against a maintained named-locations list, not an
  automatic rolling per-user history — I am not confident Entra ID ships a built-in "country not
  seen for this account in 30 days" condition out of the box; verify current Identity Protection
  capabilities before committing to this exact mechanism. A defensible way to build it today is a
  Microsoft Sentinel analytics rule (or Logic App) that maintains each account's prior-30-day
  country list from sign-in logs and calls the Graph API to mark the user "at risk" (triggering
  the existing Conditional Access risk-based policy above) the first time a new country appears —
  this reuses the same policy from the primary fix rather than requiring a second, separate
  Conditional Access rule type.

**Effect:** Removes the single point of failure identified in GAP-002 — the exception that let
stolen credentials be used from `45.63.9.88` (RU) despite a flagged risk score — and extends the
same enforcement to the VPN re-authentication from the same IP eight hours later (GAP-003),
which currently receives no additional scrutiny on reuse.

**Applies to:** All `MEDDEFENSE` user accounts authenticating to Office 365 and VPN.

**Validation:** Use the Conditional Access "What If" tool in the Entra admin center with a
simulated sign-in matching `risk=medium` and `compliant_device=true`; expected result: the
policy now shows as applied (MFA required), not excluded.

---

## HRD-004: Windows Credential Guard

**Closes:** GAP-008

**Configuration:** Enable Virtualization-Based Security (VBS) and Credential Guard via Group
Policy: Computer Configuration > Administrative Templates > System > Device Guard > "Turn On
Virtualization Based Security" = Enabled, with "Credential Guard Configuration" set to "Enabled
with UEFI lock." Equivalent registry path (set by the same GPO):
`HKLM\SYSTEM\CurrentControlSet\Control\LSA`, value `LsaCfgFlags` (REG_DWORD) `= 1`.
Hardware/firmware prerequisites: 64-bit CPU with virtualization extensions (Intel VT-x or AMD-V)
and SLAT, UEFI firmware with Secure Boot enabled, and Hyper-V's hypervisor component available.
I am not fully certain of the exact current Windows 10/11 edition and licensing requirements
(this has changed across Windows releases) — confirm against current Microsoft Learn
documentation which editions in use at MedDefense actually support Credential Guard before
mass deployment.

**Effect:** Isolates NTLM hashes and Kerberos ticket-granting-ticket material in a
hypervisor-protected memory region inaccessible to the LSASS process space that was read in this
incident — directly addressing the finding that NTLM hash material for `dmarsh` was resident and
accessible in `lsass.exe` memory (`ART-002-M04`, `forensic_findings_summary.md`) with zero
detection at the time.

**Applies to:** All clinical workstations, including the `WST-WS-031`/`WST-WS-017` host class,
subject to the hardware/firmware prerequisites above being met fleet-wide.

**Validation:**
```powershell
(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
```
Expected output includes `1` (Credential Guard running). Note this closes the credential-theft
pathway itself; it does not, on its own, add the real-time ticket-reuse alerting that GAP-009
still requires — the two remain separate fixes for separate stages of the attack.
