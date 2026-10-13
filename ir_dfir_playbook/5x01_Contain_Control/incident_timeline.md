Incident Timeline: IR-2026-0414-01
Header
incident_id: IR-2026-0414-01
declared_at: 2026-04-14T02:52:00Z
declared_by: On-Call SOC Analyst
initial_severity: SEV2
current_severity: SEV2
ir_commander: James Chen, SOC Lead
scribe: On-Call SOC Analyst
Legend
OBSERVATION: raw fact from an alert, log, or artifact
DECISION: a choice made by an authorized actor, with rationale
ACTION: an operation executed against an asset, with owner
COMMUNICATION: a message sent or received, with audience
EVIDENCE: a preserved artifact with hash and storage path
Entries
2026-04-14T02:47:11Z | OBSERVATION | SIEM rule wz-edr-100041 | powershell.exe (PID 7812) spawns msbuild.exe (PID 8104) on WST-WS-031; msbuild.exe opens outbound TCP to 185.220.101.47:443 (Tor exit relay) | source=alert A-20260414-9841 | certainty=confirmed
2026-04-14T02:52:00Z | DECISION | On-Call SOC Analyst | Incident declared as IR-2026-0414-01; host WST-WS-031 and account MEDDEFENSE\dmarsh placed in scope | source=alert A-20260414-9841 | certainty=confirmed
2026-04-14T02:52:30Z | DECISION | On-Call SOC Analyst | Initial severity set to SEV2: confirmed code execution with an active C2-style channel from a high-criticality clinical workstation; data exposure and credential compromise not yet confirmed | source=alert A-20260414-9841 + severity_matrix.md (Module 5x00) | certainty=confirmed
2026-04-13T18:14:02Z | OBSERVATION | On-Call SOC Analyst (log review) | User dmarsh visited ms0365-support[.]login-verification[.]click/auth (HTTP 200), a login-page-style URL, approximately 8.5 hours before the alert fired | source=proxy_24h_dmarsh.log | certainty=confirmed
2026-04-14T02:58:00Z | OBSERVATION | On-Call SOC Analyst (log review) | The base64 -enc payload in the parent powershell.exe command line decodes (UTF-16LE) to the same domain recorded in the 2026-04-13T18:14:02Z entry above, confirming a direct link between that phishing-site visit and this execution chain | source=alert A-20260414-9841 (process_tree.parent.cmdline) + proxy_24h_dmarsh.log | certainty=confirmed
