MedDefense Health Systems: When the Alarm Sounds

Day 0, 19:42. Three help desk tickets, twenty minutes apart: shared drives unreachable. By 20:15 a SOC analyst has confirmed file-share encryption and done the one thing that matters most in the first minutes of a real incident — called James Chen instead of trying to fix it alone. Twenty-four hours later the entry vector is traced back to a phishing email and a compromised admin account. Two weeks after that, a post-incident review finds three gaps in the playbooks and ships two new detection rules. None of it happened in a straight line: detection work was still running hours after containment had already started.

This module builds the capability to run that kind of response — not from memory, but against a shared, written standard the whole organization agrees on before the next incident starts. MedDefense Health Systems (see 5x00_shared/meddefense_profile.md for sites, systems, staffing, and regulatory posture) is the organization; Cascadia Regional Medical Center, 2024, is the reference incident every task maps back to.

Grounding materials:

5x00_shared/meddefense_profile.md — the organization's canonical profile. Technology footprint, security team, regulatory obligations (HIPAA, state privacy law), and incident readiness baseline. Treated as authoritative across every task in this module.
The Cascadia incident timeline — a real-shaped ransomware response, Day 0 through Day 14, used to test whether a lifecycle phase, a severity level, or a decision-authority rule actually holds up against a live sequence of events rather than a textbook description of one.

No live SOC platform, ticketing system, or communication tool is used here — every deliverable is written as a document a real incident commander could put in front of a CISO, a SOC analyst, or legal counsel and expect it to mean the same thing to all three. Severity, phase, and authority are always tied to patient safety and operational impact, never to technical complexity alone.

See 0-map_lifecycle.md onward for the full deliverable set.
