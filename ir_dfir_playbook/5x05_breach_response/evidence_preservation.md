# Evidence Preservation: IR-2026-0420-01

## Scope note

The five hosts below are those named in this task. Sysmon data (`sysmon_multihost.sample.jsonl`,
line 18) additionally shows the same malicious binary (`C:\ProgramData\Microsoft\svchost32.exe`)
executed on **SCHED-SVR-01** at 2026-04-20T18:02:18Z - this is not the stuck batch job Torres
suspected, but the same compromise. SCHED-SVR-01 is not in this task's host list and is therefore
not acquired here; this is flagged as an immediate scope-expansion item for containment/evidence
preservation outside this task. All artifact samples provided are explicitly marked as condensed
samples (`fileserver_access.sample.json`), not full exports; conclusions here are bounded by what
the samples show and may not capture activity outside the sampled window.

## Priority order rationale

1. **CS-WS-101 (memory already captured; disk is next, priority 1).** This host shows the most
   recent confirmed beacon activity of any host in the artifact set (proxy log, 19:32:04Z, six
   minutes before Torres's 19:38Z memory capture, pattern `sleep_60s_jitter_10pct`), and was the
   source of the LSASS credential-access event (Sysmon, 2026-04-17T14:25:02Z) that enabled the
   lateral Kerberos logon to FILE-SVR-01. It has not yet been isolated. Disk imaging is the single
   highest-priority remaining acquisition.
2. **FILE-SVR-01 (memory + disk, priority 2, effectively tied with CS-WS-101).** Not yet touched by
   Torres ("I did not touch the file server," per the call transcript). It holds the actual record
   of the 1,847 PHI object-access events (`fileserver_access.sample.json`) and the single largest
   confirmed egress payload in the entire artifact set: 2,400,412 bytes transferred 18 seconds after
   the attacker's lateral logon (proxy log, 2026-04-19T02:14:22Z). If a live process or session
   related to that transfer is still resident in memory, it is lost the moment this host is isolated
   or rebooted - this is the strongest concrete evidence of possible exfiltration available, and
   justifies acquisition before any containment action touches this host.
3. **CS-WS-104, CS-WS-107, CS-WS-112 (memory + disk, priority 3, equal ranking).** Each shows one
   confirmed beacon-in on 2026-04-19 (00:04:17Z, 00:12:44Z, and 00:18:02Z respectively) and an
   identical ransomware-staging file drop on 2026-04-20 (14:25:02Z, 14:25:42Z, 14:26:14Z
   respectively), with no further confirmed beacon activity in the sampled window since initial
   compromise. The available data does not meaningfully differentiate their urgency from one
   another - unlike the illustrative example in this task's instructions, nothing in the real
   Sysmon/proxy samples shows WS-104 or WS-107 as more "actively beaconing" than WS-112; all three
   are treated as equal priority and acquired in parallel, in host-ID order, rather than an
   unsupported ranking. All three carry an undetonated ransomware staging script, which still makes
   memory capture necessary before any eradication action removes or triggers it.

## ART-001: cs-ws-101.mem (Torres acquisition)

- **host:** CS-WS-101
- **acquired_by:** Mike Torres, Network Engineer
- **acquired_at:** 2026-04-20T19:38Z
- **tool:** WinPmem
- **sha256_at_acquisition:** NOT RECORDED - Torres did not compute a hash at acquisition time; he
  flagged this himself during handoff as a repeat of the same gap documented in IR-2026-0414-01.
- **sha256_verified_by_analyst:** to be computed at first opportunity (2026-04-20T19:58Z) using
  `sha256sum cs-ws-101.mem`. Because no acquisition-time hash exists, this value can only prove the
  file is unchanged from 19:58Z onward - it cannot prove integrity for the 20-minute window between
  acquisition (19:38Z) and this first hash. This is a material chain-of-custody weakness, not a
  formality; documented as a finding for the eventual improvement phase.
- **gap_note:** 5 min 18 sec between acquisition (19:38Z) and Torres's call start (19:43:18Z); 14
  minutes between acquisition and formal incident declaration (19:52Z). The captured state reflects
  conditions at 19:38Z, before the call and before declaration - relevant for correlating this
  memory snapshot against later timeline entries, which describe conditions reported slightly after
  the capture.

## ART-002: cs-ws-101.dd

- **host:** CS-WS-101
- **priority:** 1
- **acquired_before:** network isolation of CS-WS-101
- **tool:** forensic disk-imaging tool (e.g. FTK Imager) run over the IR jumpbox against the live
  host, producing a raw `.dd` image
- **command (acquisition host, via jumpbox):** `ftkimager \\.\PhysicalDrive0 cs-ws-101.dd --e01` (or
  equivalent raw-image mode; verify exact current flags against the installed FTK Imager version
  before running for real)
- **sha256:** `sha256sum cs-ws-101.dd` computed immediately after the image completes, before any
  copy or transfer
- **chain_of_custody_note:** acquired by the analyst/Technical_Lead team after Torres's handoff;
  logged with acquiring analyst name, timestamp, and hash in the chain of custody table below

## ART-003: cs-file-svr-01.mem

- **host:** FILE-SVR-01
- **priority:** 2
- **acquired_before:** any containment action on FILE-SVR-01 (network segmentation, account
  restriction, service termination)
- **tool:** WinPmem
- **command:** `winpmem.exe -o cs-file-svr-01.mem` (run locally on FILE-SVR-01 or via remote
  forensic agent per your organization's acquisition procedure; confirm exact current WinPmem syntax
  against its own `--help` before running for real)
- **sha256:** `sha256sum cs-file-svr-01.mem` computed immediately after acquisition completes

## ART-004: cs-file-svr-01.dd

- **host:** FILE-SVR-01
- **priority:** 2
- **tool:** forensic disk-imaging tool over the IR jumpbox, same method as ART-002
- **sha256:** `sha256sum cs-file-svr-01.dd` computed immediately after the image completes
- **note:** the Windows Security Event Log covering the 1,847 object-access events
  (`fileserver_access.evtx`) is captured as part of this disk image; no separate live export is
  needed once the image is secured

## ART-005: cs-ws-104.mem

- **host:** CS-WS-104
- **priority:** 3
- **tool:** WinPmem
- **sha256:** `sha256sum cs-ws-104.mem` computed immediately after acquisition

## ART-006: cs-ws-104.dd

- **host:** CS-WS-104
- **priority:** 3
- **tool:** forensic disk-imaging tool over the IR jumpbox
- **sha256:** `sha256sum cs-ws-104.dd` computed immediately after the image completes

## ART-007: cs-ws-107.mem

- **host:** CS-WS-107
- **priority:** 3
- **tool:** WinPmem
- **sha256:** `sha256sum cs-ws-107.mem` computed immediately after acquisition

## ART-008: cs-ws-107.dd

- **host:** CS-WS-107
- **priority:** 3
- **tool:** forensic disk-imaging tool over the IR jumpbox
- **sha256:** `sha256sum cs-ws-107.dd` computed immediately after the image completes

## ART-009: cs-ws-112.mem

- **host:** CS-WS-112
- **priority:** 3
- **tool:** WinPmem
- **sha256:** `sha256sum cs-ws-112.mem` computed immediately after acquisition

## ART-010: cs-ws-112.dd

- **host:** CS-WS-112
- **priority:** 3
- **tool:** forensic disk-imaging tool over the IR jumpbox
- **sha256:** `sha256sum cs-ws-112.dd` computed immediately after the image completes

## Chain of custody

| Artifact | Host | Type | Acquired By | Acquired At | Tool | SHA-256 at Acquisition | Verified By / At |
|---|---|---|---|---|---|---|---|
| ART-001 | CS-WS-101 | Memory | Mike Torres | 2026-04-20T19:38Z | WinPmem | Not recorded (documented gap) | Analyst, 2026-04-20T19:58Z |
| ART-002 | CS-WS-101 | Disk | Analyst / Technical_Lead team | After declaration, priority 1 | Forensic disk imager (jumpbox) | Computed at acquisition | Same analyst, at acquisition |
| ART-003 | FILE-SVR-01 | Memory | Analyst / Technical_Lead team | After declaration, priority 2 | WinPmem | Computed at acquisition | Same analyst, at acquisition |
| ART-004 | FILE-SVR-01 | Disk | Analyst / Technical_Lead team | After declaration, priority 2 | Forensic disk imager (jumpbox) | Computed at acquisition | Same analyst, at acquisition |
| ART-005 | CS-WS-104 | Memory | Analyst / Technical_Lead team | After declaration, priority 3 | WinPmem | Computed at acquisition | Same analyst, at acquisition |
| ART-006 | CS-WS-104 | Disk | Analyst / Technical_Lead team | After declaration, priority 3 | Forensic disk imager (jumpbox) | Computed at acquisition | Same analyst, at acquisition |
| ART-007 | CS-WS-107 | Memory | Analyst / Technical_Lead team | After declaration, priority 3 | WinPmem | Computed at acquisition | Same analyst, at acquisition |
| ART-008 | CS-WS-107 | Disk | Analyst / Technical_Lead team | After declaration, priority 3 | Forensic disk imager (jumpbox) | Computed at acquisition | Same analyst, at acquisition |
| ART-009 | CS-WS-112 | Memory | Analyst / Technical_Lead team | After declaration, priority 3 | WinPmem | Computed at acquisition | Same analyst, at acquisition |
| ART-010 | CS-WS-112 | Disk | Analyst / Technical_Lead team | After declaration, priority 3 | Forensic disk imager (jumpbox) | Computed at acquisition | Same analyst, at acquisition |
