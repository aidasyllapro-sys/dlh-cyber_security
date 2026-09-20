MedDefense Health Systems: The Click Investigation
Prepared by: Aïda Sylla, Security Analyst
Prepared for: James Chen, SOC Lead
Source material: `meddefense-email-evidence-batch.txt` — collection summary block (user, workstation, email, click timestamp) and the E2 header/content findings already documented in tasks 1, 3 and 4
Purpose: Assess the reported click by Diane Marsh on the Email 2 phishing link and define what evidence would be needed to determine whether compromise occurred. This project provides no endpoint, identity, or SIEM logs, so this report documents confirmed facts, key unknowns, and recommended follow-up checks — it does not claim any endpoint or account log was reviewed.

---

## Click Investigation — Diane Marsh / WS-NURSE-04

### Confirmed Facts

- User: Diane Marsh (`dmarsh@meddefense.com`), workstation `WS-NURSE-04`.
- Workstation IP: `10.10.2.15` (internal, per the collection summary).
- Email: E2, "ACTION REQUIRED: Portal re-verification needed within 24 hours," delivered internally on Mon, 14 Apr 2026 at 14:47:52 CDT.
- URL clicked: `meddefense-portal.com/verify/staff?id=dmarsh&token=a8f3e2d1` (a credential-harvesting link, per task 4's autopsy — defanged form: `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`).
- Domain: `meddefense-portal.com`, a lookalike domain unaffiliated with `meddefense.com`, confirmed in task 1 to be sent from external IP `91.234.99.107` and to fail SPF/DKIM/DMARC in task 2.
- Click timestamp: 2026-04-14 15:02:33 CDT, per the workstation's own NTP-synced clock, as recorded in the collector's summary notes.
- Time-to-click: approximately 14 minutes 41 seconds between email delivery (14:47:52 CDT) and the recorded click (15:02:33 CDT).

### Key Unknowns

- Whether Diane entered any credentials, partial credentials, or other information on the landing page before recognizing it as suspicious, or before leaving the page.
- Whether the phishing page prompted for and captured a multi-factor authentication (MFA) code in addition to a password.
- Whether any file was offered, downloaded, or executed from the landing page.
- Whether the `dmarsh` account has shown any sign-in activity, from any location, since the click timestamp.
- Whether the workstation `WS-NURSE-04` has exhibited any new process, network connection, or file activity since the click.
- Whether the attacker's infrastructure (IP `91.234.99.107`, domain `meddefense-portal.com`) has been observed contacting any other MedDefense system or account since 2026-04-14.

None of these can be answered from the email evidence batch alone. They require endpoint and identity telemetry that this project does not provide.

### Endpoint Checks To Perform

The following are recommended follow-up checks against `WS-NURSE-04`, to be carried out if and when endpoint logging (EDR, Sysmon, local event logs) is available. None of these have been performed as part of this report.

- Review browser history and cache for navigation to `meddefense-portal.com` around 2026-04-14 15:02 CDT, and check whether the browser recorded a form submission (a `POST` request) to that domain rather than only a page load (`GET`).
- Check the browser's download history and the user's Downloads/Temp/AppData folders for any file created around or after the click timestamp.
- Review process-creation logs (e.g., Sysmon Event ID 1) for any process spawned by the browser around the click time, especially command interpreters (`powershell.exe`, `cmd.exe`) launched as a child of the browser process — a common sign of a drive-by payload.
- Review PowerShell script-block or console logging (e.g., Event ID 4104) for any command activity on the workstation following the click.
- Check for newly created scheduled tasks, registry Run/RunOnce keys, or startup items on `WS-NURSE-04` created after 2026-04-14 15:02 CDT.
- Review outbound network connections from `WS-NURSE-04` after the click timestamp for traffic to unfamiliar external IPs or domains.
- Check any installed antivirus/EDR product for alerts on this workstation around the click window.

### Account Checks To Perform

The following are recommended follow-up checks against the `dmarsh` account (e.g., in Active Directory / Microsoft Entra sign-in logs), to be carried out if and when identity logging is available. None of these have been performed as part of this report.

- Review failed logon attempts for `dmarsh@meddefense.com` around and after the click timestamp.
- Review successful logons for unusual source IPs, geographic locations, or device fingerprints inconsistent with Diane's normal sign-in pattern.
- Review MFA prompt history for any approval or denial Diane did not personally initiate ("MFA fatigue" pattern), and for any newly registered MFA method.
- Review password change history on the account since the click timestamp.
- Review the mailbox for newly created inbox rules (especially auto-forwarding, auto-delete, or rules hiding replies) — a common indicator left behind after a mailbox takeover.
- Review group membership and any privilege or role changes applied to the account.
- Review OAuth application consents granted under the account, since a captured session can sometimes be used to authorize a malicious app rather than sign in directly.

### Decision Matrix

| Outcome | Criteria |
|---|---|
| No compromise found | Endpoint logs confirm only a page load (`GET`, no form submission) with no downloaded file and no anomalous process activity; account logs show no sign-in from an unfamiliar source, no new MFA registration, and no new inbox rule since the click. |
| Possible credential exposure | Endpoint logs confirm a form submission to the phishing page, or endpoint/account logs are incomplete or unavailable and therefore cannot rule out submission; no confirmed unauthorized account activity has yet been observed. |
| Confirmed compromise | Any one of: a successful sign-in to `dmarsh`'s account from an unfamiliar location or device after the click, a new inbox rule the user did not create, an MFA approval the user did not initiate, or evidence of process execution/lateral movement tied to the workstation or account following the click. |

### Recommended Containment

These are safe, reversible actions that can be taken immediately, without waiting for the endpoint and account checks above to complete:

- Force an immediate password reset on `dmarsh@meddefense.com`.
- Revoke all active sessions and tokens for the account (force sign-out on all devices), so that any session cookie potentially captured by the phishing page is invalidated even if the password alone would not stop it.
- Review and, if warranted, reset MFA registration on the account, and check recent MFA approval history for anything Diane does not recognize.
- Conduct a brief, non-punitive interview with Diane Marsh: what she recalls seeing on the page, whether she entered anything before leaving it, and whether anything looked or behaved unusually — this is often the fastest way to narrow the decision matrix above.
- Add `meddefense-portal.com` and its associated sending IP (`91.234.99.107`) to the email and web gateway blocklists to prevent further delivery or access.
- Apply heightened monitoring on the `dmarsh` account for an elevated period following the incident (sign-in alerts, new inbox rule alerts, mailbox forwarding alerts).
- Preserve `WS-NURSE-04` in its current state for forensic imaging rather than reimaging it immediately, in case any later finding upgrades this from "possible" to "confirmed" compromise.
- Loop in Diane's manager and the security awareness program for supportive follow-up, since reported clicks from users who then self-report (as happened here) should be reinforced as good behavior, not penalized.

### Conclusion

The evidence batch confirms only that Diane Marsh's workstation loaded a credential-harvesting URL roughly 15 minutes after the phishing email was delivered — nothing in this project's evidence confirms or rules out whether credentials were actually entered or whether the account has since been misused. Given the credential-harvesting design of the landing page and the operational risk profile of a clinical user with EHR access, this should be treated as a **possible credential exposure** by default until the endpoint and account checks above are actually performed, and the containment steps listed should be applied now rather than held pending that confirmation.
