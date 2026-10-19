Filesystem Analysis: ART-001 (wst-ws-031.dd)
Status of this analysis

The raw disk image wst-ws-031.dd is not present in this analysis environment. Per guidance received from the course mentor, this document proceeds without the binary artifact: it records the exact TSK methodology, command syntax, and expected interpretation for each step, and documents every piece of command output as NOT AVAILABLE rather than inventing a plausible-looking result. Any fact in the "Key findings" section that is stated as established is sourced from a different, already-verified evidence type for this same incident (EDR telemetry read during the Contain and Control phase, module 5x01) and is labeled as such — it is corroborating context, not a substitute for the disk-level finding that TSK would produce. No MAC timestamp, inode number, partition offset, or file hash in this document is presented as derived from wst-ws-031.dd unless it was actually computed from that file.

Artifact verification
Hash at analysis start: NOT AVAILABLE — wst-ws-031.dd (ART-001) is not accessible in this environment; no baseline exists yet in hashes.txt to compare against (see verify_artifacts.sh, Task 2).
Mounted read-only: NOT PERFORMED. The required procedure, once the artifact is available, is to mount the partition read-only after the offset is known from mmls (see below), e.g.:
  sudo mount -o ro,loop,noexec,offset=$((<sector_offset> * 512)) wst-ws-031.dd /mnt/art-001

TSK's own command-line tools (mmls, fsstat, fls, icat) do not require the image to be mounted at all — they read the raw image directly — so the safer practice is to run every TSK command below directly against wst-ws-031.dd and reserve a read-only mount only for a tool that has no TSK equivalent. No mount of any kind has occurred, so there is no filesystem-metadata risk from this analysis session itself.

CoC entry updated: NO — no access event has been logged in chain_of_custody.md for ART-001 by this analysis, because no access to the actual artifact has taken place. Per the append-only rule, the correct entry will be added at the moment real analysis begins, not before.
Partition layout

Command to run:

mmls wst-ws-031.dd

Purpose: identify the partition table and the sector offset of the main NTFS volume, which every subsequent TSK command needs via its -o flag.

Output: NOT AVAILABLE — wst-ws-031.dd is not present in this environment.

Filesystem metadata

Command to run (once the NTFS offset is known from mmls, substituted for <offset>):

fsstat -o <offset> wst-ws-031.dd

Purpose: confirm the filesystem type, volume serial number, and last mount time, and establish cluster size for later inode-level work.

Output: NOT AVAILABLE — wst-ws-031.dd is not present in this environment.

Recursive file listing and MAC timeline

Commands to run:

fls -r -o <offset> wst-ws-031.dd > fls_output.txt
mactime -b fls_output.txt -d > mac_timeline.csv

Purpose: list every file and deleted-but-unallocated entry with its inode number, then convert that listing into a chronologically sorted CSV of Modified/Accessed/Changed/Born (MACB) times across the whole volume — the basis for correlating filesystem activity against the EDR and network timeline already built in the 5x01 phase of this incident.

Output: NOT AVAILABLE — wst-ws-031.dd is not present in this environment. fls_output.txt and mac_timeline.csv have not been generated.

File extraction

Command pattern to run once a specific inode of interest is identified in mac_timeline.csv:

icat -o <offset> wst-ws-031.dd <inode> > extracted_file
sha256sum extracted_file

Purpose: pull the raw content of one file by inode number without touching the rest of the image, then hash the extracted copy for the evidence record.

No inode numbers are known (they can only come from a real fls/mactime run), so no extraction has been performed.

Paths examined
C:\Users\dmarsh\AppData\Local\Temp\

TSK finding: NOT AVAILABLE — not examined on the disk image.

EDR-corroborated context (per edr_wst_ws_031_24h.jsonl, 5x01 telemetry for this same incident, IR-2026-0414-01 — not part of the 5x02 lab materials, included here only as corroborating evidence, not as a disk-forensic finding):

update.zip downloaded by chrome.exe at 2026-04-13T18:14:43Z; EDR-reported SHA-256: 3c2a1b9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a.
update.xml created by explorer.exe at 2026-04-13T18:15:02Z; EDR-reported SHA-256: a4f1e9b4fe7aa6d5d3f3e2b8c9a7d4e8f5b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3.
update.exe created by explorer.exe at 2026-04-13T18:15:05Z; EDR-reported SHA-256: 5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b.

These EDR-reported hashes were computed by the EDR agent at telemetry time, not independently verified by this analyst against the disk image via icat + sha256sum. Until that independent verification happens, they are probable, not confirmed, under the three-tier evidentiary standard used in this investigation.

C:\Windows\System32\Tasks\

TSK finding: NOT AVAILABLE — not examined on the disk image.

EDR-corroborated context (same source as above): a scheduled task with GUID {7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A} was created at 2026-04-13T18:15:14Z, configured with trigger user_logon, targeting update.exe. This task definition was removed under eradication_checklist.yaml item ERAD-002 (5x01, Task 6), which is consistent with — but not a substitute for — a direct disk-level examination of the task's XML definition file under this path.

C:\Users\dmarsh\AppData\Roaming\Microsoft\Windows\Recent\

TSK finding: NOT AVAILABLE — not examined on the disk image.

No corroborating evidence from any other artifact in this incident's record names a specific LNK file or its target. This path remains entirely open pending real disk access. No finding is asserted here.

C:\Users\dmarsh\AppData\Local\Microsoft\Windows\History\

TSK finding: NOT AVAILABLE — not examined on the disk image.

Note on scope: proxy_log.jsonl (provided in this module's materials) records the same account's web activity at the network-proxy level — including the phishing-page visit at 2026-04-13T18:14:02Z and the update.zip download at 18:14:43Z — but a proxy log is a different evidence type from the local browser History database under this path. It corroborates that browsing occurred; it cannot stand in for what the local History artifact itself would show (e.g., locally cached entries for sites visited outside the proxied network, or entries surviving after a proxy log's retention window). No finding about the local History artifact itself is asserted here.

Key findings

No ART-001-F## finding is recorded in this document. Per the investigation's own evidentiary standard — "supported by documented evidence," not "probably happened" — no finding may be numbered and presented as established without the disk-level TSK output (MAC times, inode, SHA-256 via icat) that the task requires. The EDR-corroborated context above is preserved as background, not converted into ART-001-F## entries, until it can be independently confirmed against wst-ws-031.dd itself.

Outstanding work

This document is incomplete by design and must be revised, not replaced, once wst-ws-031.dd is available:

Run mmls, record the real partition table and NTFS offset.
Run fsstat -o <offset>, record the real filesystem metadata.
Run fls -r -o <offset> and mactime -b, record the real MAC timeline.
Examine the four listed paths directly via fls/icat, and only then record ART-001-F01 onward with real path, MAC times, size, SHA-256, and significance.
Log the access in chain_of_custody.md the moment any of the above actually runs against the real artifact, per the append-only rule.
