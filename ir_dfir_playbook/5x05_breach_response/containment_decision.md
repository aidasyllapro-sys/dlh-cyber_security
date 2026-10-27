# Containment Decision: IR-2026-0420-01

## Strategy options

| Strategy | Action | Effect on attacker | Effect on patient care | Evidence preserved / destroyed | Time to execute | Reversibility |
|---|---|---|---|---|---|---|
| A. Full power-off | Immediately shut down all 6 confirmed-compromised hosts | Fastest, total cutoff | Severe: ED workstation, scheduling, and file server go dark simultaneously with no fallback staged | Destroys volatile memory on every host not yet captured (5 of 6 at this point) - directly contradicts the Task 1 preservation plan | Seconds | Power-on reversible; evidence loss is not |
| B. Egress-only firewall block | Block the C2 domain/IP (`staging.office365-cdn.net`, `45.152.66.114`) at the perimeter firewall; hosts stay on the network and operational | Cuts outbound C2 communication but leaves the implant resident; does not stop internal lateral movement or an undetonated ransomware script from triggering | None - no disruption to clinical operations | Maximal - no host state is frozen | Minutes (single firewall rule) | Fully reversible (remove rule) |
| C. Staged network isolation + egress block (chosen) | Apply the egress block immediately network-wide, then isolate each of the 6 hosts individually once its volatile evidence is captured, in the Task 1 priority order | Cuts both outbound C2 and any further lateral movement from isolated hosts; strongest option that does not destroy evidence | Moderate and sequenced: each host goes offline only after coordination, not all at once; FILE-SVR-01 isolation requires On-Call Clinical Lead acknowledgment per PB-003 | None destroyed - memory capture precedes isolation on every host; disk imaging can proceed after isolation since it is non-volatile | ~30 minutes for full sequence across 6 hosts | Fully reversible once each host is confirmed clean |

## Chosen strategy and rationale

Strategy C is adopted. Strategy A is rejected outright: it would destroy exactly the volatile
evidence Task 1 spent its priority order protecting, on five of the six hosts that have not yet
had memory captured. Strategy B alone is rejected because it leaves four undetonated ransomware
staging scripts resident on network-connected, credentialed hosts with no removal - egress blocking
stops the C2 channel but does nothing about a script that could still trigger locally. Strategy C
sequences the two: the egress block is applied first and network-wide, cutting C2 communication
within minutes for every host including ones not yet isolated, while individual host isolation
proceeds only after each host's volatile evidence is secured - preserving both the clinical
operation of hosts still pending coordination and the forensic record, at the cost of a slower full
containment than a blanket shutdown would achieve.

**Authorizing role:** James Chen, IR_Commander (`authority_ceiling: SEV2`, matching this incident's
declared severity; Technical_Lead's ceiling of SEV3 is insufficient to authorize this action alone).

**Rollback trigger:** Isolation is reversed for a given host only once eradication is validated
against that host's own recovery_validation criteria (no active implant, process, or outbound
connection; baseline restored) and, for FILE-SVR-01 and SCHED-SVR-01 specifically, on-call clinical
leadership confirms no outstanding emergency need for reconnection.
