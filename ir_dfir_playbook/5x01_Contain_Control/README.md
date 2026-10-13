# MedDefense Health Systems: Contain and Control

02:47 Z, Tuesday. Rule wz-edr-100041 fires on WST-WS-031, a clinical workstation at the West Campus: a
PowerShell process, launched hidden with an encoded command, spawns MSBuild.exe against a file sitting in
a temp folder. Fifteen seconds later MSBuild opens an outbound TLS connection to a known Tor exit relay. The
account behind it, dmarsh, visited a fake Microsoft login page the evening before. Nobody else is online. James
Chen's instruction is one line: "You own this. Contain it. Document everything."

This module runs that incident end to end, not as a story told afterward but as the paper trail built while it
happens: the authoritative timeline opened the moment the incident is declared, the evidence that would vanish
the instant you touch the host captured before you touch it, a containment option chosen and justified on the
page, the scope reassessed the moment it grows, eradication checked surface by surface instead of assumed, and
a handoff package complete enough that the next analyst never has to ask a question.

Grounding materials:

* `alert_A-20260414-9841.json` - the full EDR alert behind the abridged version seen in Task 0: process tree,
  network connection, Tor exit-relay enrichment, and the MITRE ATT&CK techniques already tagged against it.
* `auth_24h_dmarsh.json` / `auth_expansion_0334Z.log` - authentication activity for the account, including the
  moment the scope expands beyond the original host.
* `edr_wst_ws_031_24h.jsonl` / `proxy_24h_dmarsh.log` - the 24-hour endpoint and web activity that places the
  alert in context, including the phishing-style login page visited the night before.
* `evidence_store_init.sh` - sets up the evidence store used to capture and timestamp everything preserved
  during the response.
* `mock_validation_api/` - a local stand-in for MedDefense's real endpoint, SIEM, and service APIs, used later
  to prove recovery with a query instead of an assumption.

No live EDR console or SIEM is used here - every deliverable is written as a document a real on-call analyst
would produce under pressure, from the first triage note through the final handoff package. Evidence is always
preserved before it is acted on, every containment choice is written down with what it costs as well as what it
protects, and nothing in this module is treated as confirmed until it is backed by the evidence files provided.

See `0-triage.md` onward for the full deliverable set.
