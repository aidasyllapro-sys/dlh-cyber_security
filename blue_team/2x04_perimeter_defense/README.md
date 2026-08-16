MedDefense Health Systems: Perimeter and Network Defense

Every endpoint at MedDefense is hardened - auditd on every Linux host, Sysmon and Script Block Logging on every Windows host, PAM, AppArmor, sysctl and audit policy all in place. Then Mike Torres drops a printed arp -a dump and a manual traceroute on the desk: between the hardened endpoints, the network is flat. Anything that reaches one machine can reach every other machine. Guest Wi-Fi can reach the billing database. A forgotten Telnet listener sits in radiology. There is nothing on the wire enforcing what should and shouldn't talk to what.

This project builds the control plane that lives between hosts. Every deliverable maps to a footprint with no live monitoring stack, no SIEM daemon and no collector: nftables on every Linux host, Windows Firewall on every Windows host, and Suricata run offline against captured PCAPs when something needs investigating. No daemons that expect a collector, no rules that expect a manager - local enforcement, local evidence, local validation. Every deliverable is a script, a rule file or a structured JSON artifact, packaged in the exact format Module 3's analysts will read next week.

See 0-network_baseline.sh onward for the full deliverable set.
