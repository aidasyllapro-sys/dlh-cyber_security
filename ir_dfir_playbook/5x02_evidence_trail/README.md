# MedDefense Health Systems: The Evidence Trail

"Every contact leaves a trace." - Edmond Locard

WST-WS-031 is contained. The active threat on the host is remediated, the C2 channel is severed, the
scheduled task and Run key are gone. That answered one question: has the threat been stopped. This module
answers a harder one: what actually happened, how far did it go, and can it be proven.

Helena Reyes, General Counsel, has placed a formal litigation hold (`LH-2026-0414-01`) on every artifact from
the incident. Dr. Patricia Morales needs a report she can present to the board inside 72 hours. The findings
will drive the HIPAA breach notification assessment, and the report itself may end up cited in a regulatory
proceeding. From here forward, nothing is written down as "probably happened" - every claim is tied to a
specific, verifiable piece of evidence, and the chain of custody is a continuous discipline, not a form filled
out once.

Three artifacts are waiting in the evidence store, unanalyzed: a disk image from WST-WS-031, and memory dumps
from WST-WS-031 and WST-WS-017. The acquisition itself was imperfect - no hashes were taken at capture time,
no chain-of-custody log existed before this module, and the disk image was briefly mounted read-write. That
imperfection is not hidden; it is the first thing documented, because an honest account of a gap is worth more
than a clean record that silently isn't true.

Grounding materials:

* `acquisition_notes.md` - Mike Torres's own account of how the three artifacts were pulled, with what tools,
  at what timestamps, and which steps did not follow best practice. The starting point for the chain of
  custody, not a file to analyze for attacker activity.
* `ad_auth_log.jsonl` - Active Directory and Azure AD authentication events across the incident window,
  including the account's logons, the impossible-travel sign-in, and the Kerberos activity behind the
  lateral movement to WST-WS-017 and LIS-WSIDE-01.
* `proxy_log.jsonl` - web traffic for the account across the incident window, including the phishing-page
  visit, the dropper download, and the outbound connections to both C2 IPs.
* `siem_alert_export.json` - the original detection alert that opened the incident, exported with its own
  chain-of-custody reference, kept exactly as the SOC first saw it.

No live EDR console, SIEM, or ticketing system is used here. Every deliverable is a document a forensic
analyst would actually produce under a litigation hold: a chain-of-custody log that never stops growing, a
filesystem and memory analysis built on artifacts whose integrity is proven before they are touched, a
timeline that only accepts a finding once more than one source agrees on it, and a final report written for
two different readers at once - the board, and anyone who might later need to verify every line of it.

See `chain_of_custody.md` onward for the full deliverable set.
