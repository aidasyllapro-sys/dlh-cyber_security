Persistence Artifact Analysis: ART-001 (wst-ws-031.dd)
Status of this analysis

Same constraint as filesystem_analysis.md (Task 3): the raw disk image wst-ws-031.dd is not present in this analysis environment, per the same mentor guidance. This document records the exact registry and execution-artifact methodology, which hives and keys to extract, and how to parse each one — but no registry value, timestamp, run count, or Amcache/ShimCache entry is invented. Where a fact is already established from a different evidence type for this same incident (EDR telemetry, 5x01), it is included as labeled corroborating context, with its own evidentiary tier (confirmed/probable/possible) stated explicitly, never silently upgraded to a disk-forensic finding.

Artifact verification
Hash at analysis start: NOT AVAILABLE — wst-ws-031.dd (ART-001) is not accessible in this environment.
CoC entry updated: NO — no access event logged in chain_of_custody.md; none has occurred.
Hive extraction procedure

Once the artifact is available and the NTFS offset is known (from mmls, Task 3):

icat -o <offset> wst-ws-031.dd <inode_of_SYSTEM>   > SYSTEM
icat -o <offset> wst-ws-031.dd <inode_of_SOFTWARE> > SOFTWARE
icat -o <offset> wst-ws-031.dd <inode_of_NTUSER>   > dmarsh_NTUSER.DAT
icat -o <offset> wst-ws-031.dd <inode_of_Amcache>  > Amcache.hve

The inode for each hive is found via fls -r output (Task 3) at its standard path: C:\Windows\System32\config\SYSTEM, ...\SOFTWARE, C:\Users\dmarsh\NTUSER.DAT, and C:\Windows\AppCompat\Programs\Amcache.hve. Extracted hives are then parsed with a registry-reading tool (e.g. regipy or reglookup) against a local copy, never against the mounted image directly.

Status: NOT PERFORMED — no hive has been extracted.

Registry persistence
ART-001-R01: Run key (pending direct verification)
Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value name: WindowsUpdateSvc
Value data: NOT AVAILABLE from this analysis — not yet read from dmarsh_NTUSER.DAT
Last write: NOT AVAILABLE from this analysis
Evidentiary tier: probable, not confirmed — sourced from EDR telemetry (edr_wst_ws_031_24h.jsonl, 5x01, not part of 5x02 lab materials): a registry-write event at 2026-04-13T18:15:12Z reported this exact key and value name, targeting update.exe. This is EDR's own report of a registry write, not a direct read of the hive on disk. It becomes confirmed only once the same key/value/timestamp is independently read from the extracted NTUSER.DAT.
Significance: if confirmed, this is the primary startup-persistence mechanism — it already drove ERAD-003 in eradication_checklist.yaml (5x01, Task 6).
ART-001-R02: Scheduled task (pending direct verification)
Path: C:\Windows\System32\Tasks\{7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A}
Trigger: NOT AVAILABLE from this analysis — not yet read from the extracted task XML
Action: NOT AVAILABLE from this analysis
Principal: NOT AVAILABLE from this analysis
Last write: NOT AVAILABLE from this analysis
Evidentiary tier: probable, not confirmed — sourced from EDR telemetry (same source as above): a scheduled-task-create event at 2026-04-13T18:15:14Z reported this exact GUID, trigger user_logon, and action update.exe. This is EDR's report of the creation event, not a direct read of the task's XML definition file on disk. It becomes confirmed only once the XML itself is parsed from the image.
Significance: if confirmed, this is the mechanism that relaunched the attack chain at next logon — it already drove ERAD-002 in eradication_checklist.yaml (5x01, Task 6).

No other registry persistence location (RunOnce, services, Winlogon, etc.) has any corroborating evidence from any source in this incident's record. None is asserted here.

Execution evidence
ART-001-E01: UserAssist

Status: NOT AVAILABLE — no UserAssist data has been read from dmarsh_NTUSER.DAT; no other evidence source in this incident's record reports UserAssist-equivalent data (run count, last-executed timestamp). Nothing is asserted.

ART-001-E02: AppCompatCache / ShimCache

Status: NOT AVAILABLE — no ShimCache data has been read from the SYSTEM hive. ShimCache records file metadata and last-modified time, not execution confirmation by itself, and nothing here corroborates or contradicts it. Nothing is asserted.

ART-001-E03: Amcache

Status: NOT AVAILABLE — no Amcache data has been read from Amcache.hve. Note for later cross-referencing: Amcache keys execution records by SHA-1, while the hashes already on record for this incident (EDR-reported, see filesystem_analysis.md) are SHA-256 — the two cannot be compared directly; a SHA-1 of the same binaries will need to be computed independently once the files are extracted from disk, or Amcache's own SHA-1 field read directly.

ART-001-E04: MSBuild.exe process execution (EDR-corroborated, not a registry/Amcache artifact)
Evidentiary tier: confirmed — this is not a disk-forensic finding, it is restated here only for cross-reference. MSBuild.exe (PID 8104) was observed by the EDR agent executing at 2026-04-14T02:46:57Z, already confirmed in the original alert (siem_alert_export.json, alert.process_tree.child). Any UserAssist or ShimCache entry found later for MSBuild.exe should be checked against this timestamp for consistency, not treated as a new, independent confirmation of execution — EDR process-create telemetry already establishes that fact.
Recent (LNK files)

Status: NOT AVAILABLE — C:\Users\dmarsh\AppData\Roaming\Microsoft\Windows\Recent\ has not been examined (see filesystem_analysis.md, Task 3, same path). No LNK target is asserted.

Outstanding work

This document is incomplete by design and must be revised, not replaced, once wst-ws-031.dd is available:

Extract SYSTEM, SOFTWARE, dmarsh's NTUSER.DAT, and Amcache.hve per the procedure above.
Read the real Run/RunOnce key values and last-write timestamps; upgrade ART-001-R01 from probable to confirmed only if the EDR-reported value and timestamp match, or document the discrepancy as a DEVIATION if they do not.
Parse the scheduled task XML directly; upgrade ART-001-R02 the same way.
Decode UserAssist, ShimCache, and Amcache; record real run counts, timestamps, and SHA-1 values as ART-001-E01 through E03.
Examine the Recent folder for real LNK targets.
Log the access in chain_of_custody.md the moment any of the above actually runs against the real artifact, per the append-only rule.
