Containment Decision: IR-2026-0414-01

Host: WST-WS-031 (clinical workstation, West Campus Laboratory). Confirmed running Hyperspace.exe (Epic EHR client) during normal use on 2026-04-13T10:02:15Z, per edr_wst_ws_031_24h.jsonl — this is the concrete basis for the patient-care effects below, not an assumption about the host's role.

Candidate strategies
A. Network isolation (quarantine VLAN)
action: move WST-WS-031 to an isolation VLAN, block all outbound, allow access from the IR jumpbox only
attacker effect: C2 to 185.220.101.47:443 severed immediately; local persistence (Run key, scheduled task) remains until eradication, so the attacker's foothold is paused, not removed
evidence effect: host stays powered on; nothing beyond what Task 2 already captured is at risk, and the host remains available for further live inspection if a Section 9 hash mismatch needs re-checking
patient care effect: dmarsh's access to Epic Hyperspace and the lab system is cut from this one workstation. Whether other workstations or staff can cover immediately is not established by the lab materials — flagged here rather than assumed either way
time to execute: minutes (VLAN/EDR-based network isolation)
reversibility: fully reversible — VLAN reassignment reversed in minutes
B. Host power-off
action: immediate hard power-off
attacker effect: all connections and processes terminated instantly
evidence effect: Task 2's memory/process/network captures are unaffected since they were already taken live, but power-off forecloses any further live investigation or re-capture — for example if Section 9 verification finds a hash mismatch, there is no live host left to re-check
patient care effect: same loss of Epic/lab access as Option A, but abrupt — any in-progress clinical documentation session on this host is lost, not just paused
time to execute: immediate (seconds)
reversibility: the shutdown itself cannot be undone; any unsaved session state is permanently lost
C. Selective process kill + egress block
action: terminate MSBuild.exe (PID 8104) and powershell.exe (PID 7812) individually, then apply an EDR/firewall rule blocking egress to 185.220.101.47
attacker effect: the observed execution chain is killed, but update.exe (the dropper that launched it) and both persistence mechanisms (Run key, scheduled task) remain untouched and could relaunch the same chain at the next user_logon trigger
evidence effect: no additional loss beyond the two killed PIDs' memory, already captured in Task 2 Section 1
patient care effect: none — the host stays fully usable for Epic/Hyperspace and lab work throughout
time to execute: minutes (requires exact PID targeting via the EDR console)
reversibility: fully reversible, but does not address persistence on its own
Chosen: A — Network isolation to quarantine VLAN

Rationale: Option A severs the one actively time-sensitive fact (the live C2 channel) immediately, loses no evidence beyond what Task 2 already preserved, and keeps the host available for any follow-up live inspection that Section 9's verification step might require — all while remaining fully reversible within minutes. Option B is ruled out because it forecloses that follow-up access and risks losing in-progress clinical session data for no clear evidentiary gain now that volatile state is already captured. Option C is ruled out on its own because it leaves both persistence mechanisms live, meaning the same chain could simply relaunch at the next logon — it remains a reasonable fallback (see rollback plan) but not the primary choice while persistence is still unaddressed.

Execution window

(Not provided by the lab materials; the times below are this runbook's own planning estimate, stated as such, not a confirmed record.)

Evidence preservation (Task 2) estimated complete: 2026-04-14T03:18:00Z
Containment execution (Task 4) planned start: 2026-04-14T03:20:00Z
Approval
Action authorized by James Chen, IR Commander (per incident_timeline.md header, ir_commander field)
Rollback plan
If VLAN isolation is found to block legitimate lab operations with no acceptable alternative access path, revert the VLAN assignment within five minutes and fall back to Option C (selective process kill + egress block) while eradication of the Run key and scheduled task (Section 8 of evidence_preservation.md) is executed in parallel to prevent relaunch.
