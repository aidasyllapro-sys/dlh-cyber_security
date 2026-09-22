MedDefense Health Systems: Wireshark Territory

The phishing investigation closed with a click nobody could take back: Diane Marsh (WS-NURSE-04) opened the link in E2, and the header/OSINT trail could only prove what left her mailbox, not what happened on the wire afterward. Days later, Sarah Park in the SOC flagged something she couldn't quite name — a workstation reaching out to the same external address every few minutes, too regular to be a person. Around the same time, James Chen pulled the team into an emergency meeting over a DNS TXT anomaly traced to billing-srv-01: short, unremarkable-looking subdomains, queried far more often than billing has any reason to touch DNS.

Six PCAP files carry this investigation forward:

normal_baseline_clinical.pcap — 30 minutes of clean clinical VLAN traffic from the morning of April 14, before the click. The reference point for everything else.
phishing_click.pcap — the moment Diane's click left the mail client and became network traffic.
c2_beaconing.pcap — the regular outbound heartbeat Sarah noticed.
dns_exfil.pcap — the TXT anomaly James raised, examined at the packet level.
lateral_movement.pcap — whatever happened next, machine to machine.
full_timeline.pcap — the full incident window, used to cross-check that every timestamp pulled from the other five files lines up.

This module produces no automated detection tooling either. Every deliverable is a tshark-driven script or a Markdown/Word write-up: traffic measured and compared against a documented baseline rather than judged on sight, every anomaly tied to a specific packet, timestamp, and protocol field, and every conclusion kept separate from hypothesis until the evidence says otherwise.

See 0-baseline_analysis.sh onward for the full deliverable set.
