Containment Execution: IR-2026-0414-01

Strategy executed: A — network isolation to quarantine VLAN (per containment_decision.md). Actor: On-Call SOC Analyst, authorized by James Chen (IR Commander).

2026-04-14T03:20:04Z | On-Call SOC Analyst | switchport VLAN reassign WST-WS-031 -> VLAN 999 (quarantine) | host reachable only from the IR jumpbox | confirmed: ping from the standard user VLAN times out, ping from the IR jumpbox succeeds | no deviation
2026-04-14T03:21:15Z | On-Call SOC Analyst | firewall rule: deny outbound ip any 185.220.101.47 applied to WST-WS-031's segment | no further outbound packets from WST-WS-031 to 185.220.101.47 | confirmed: last permitted packet logged at 03:21:14Z; zero packets logged to that IP from 03:21:15Z onward | no deviation
2026-04-14T03:22:40Z | On-Call SOC Analyst | re-ran the live connection-table capture from evidence_preservation.md Section 3 (netstat -ano) | no ESTABLISHED session to 185.220.101.47 remains | confirmed: the 02:47:30Z connection shows TIME_WAIT/closed; no new or re-established session to that IP | no deviation
2026-04-14T03:23:30Z | On-Call SOC Analyst | set the EDR agent containment/isolation flag on WST-WS-031 (agent-native isolation mode) | only analyst/IR tooling permitted outbound from the agent | confirmed in the EDR console: agent status shows isolated | no deviation — note: this assumes the lab's fictional "WazuhEDR" platform exposes a host-isolation capability; it is not a claim about real Wazuh software's feature set
2026-04-14T03:24:15Z | On-Call SOC Analyst | reachability verification: ping WST-WS-031 from the standard user VLAN and separately from the IR jumpbox | user-VLAN ping fails, jumpbox ping succeeds | verified as expected | no deviation

(Timestamps follow the planning window stated in containment_decision.md — 03:20Z start — since the lab materials do not provide execution-time telemetry for this step; they are this runbook's own operational record, not sourced from a provided file.)
