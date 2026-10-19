# Chain of Custody: `LH-2026-0414-01`

## Case Header

- **Case number:** `LH-2026-0414-01`
- **Incident ID:** `IR-2026-0414-01`
- **Lead investigator:** Aïda Sylla
- **Date opened:** `2026-04-14`
- **Litigation hold reference:** Memo from Helena Reyes, 2026-04-14T07:30Z

## Artifact Registry

| Artifact ID | Name | Format | Acquired By | Acquired At (UTC) | Tool | SHA-256 at Acquisition | Storage Path | Access Controls |
|---|---|---|---|---|---|---|---|---|
| ART-001 | wst-ws-031.dd | RAW (dd) | Mike Torres | 2026-04-14T06:14Z (started 04:51Z) | FTK Imager | NOT COMPUTED — see DEVIATION-001 | `\\evidence\share\IR-2026-0414-01\wst-ws-031.dd` | read-only, IR team only |
| ART-002 | wst-ws-031.mem | RAW | Mike Torres | 2026-04-14T03:02Z | WinPmem v3.3-rc3 | NOT COMPUTED — see DEVIATION-001 | `\\evidence\share\IR-2026-0414-01\wst-ws-031.mem` | read-only, IR team only |
| ART-003 | wst-ws-017.mem | RAW | Mike Torres | 2026-04-14T03:38Z | WinPmem v3.3-rc3 | NOT COMPUTED — see DEVIATION-001 | `\\evidence\share\IR-2026-0414-01\wst-ws-017.mem` | read-only, IR team only |

## DEVIATION Notes

**DEVIATION-001 — No SHA-256 computed at acquisition (all three artifacts).**
Per `acquisition_notes.md`, Mike Torres did not compute a SHA-256 hash at the time of capture for ART-001, ART-002, or ART-003. No baseline hash exists from the moment of acquisition for any of the three artifacts. Consequence: integrity relative to the original acquired state cannot be cryptographically proven — only integrity from the point a baseline is first established going forward (see "Baseline hash establishment," pending below). This gap is documented, not concealed, and is itself now part of the evidentiary record under litigation hold `LH-2026-0414-01`.

**DEVIATION-002 — ART-001 mounted read-write before imaging, not remounted read-only.**
Per `acquisition_notes.md`, Torres mounted the live filesystem of WST-WS-031 read-write to verify the presence of `update.xml` prior to imaging, and did not unmount or remount read-only before running FTK Imager. The resulting disk image (ART-001) may reflect filesystem metadata changes introduced by this access (e.g., access timestamps), not solely the state of the system at the moment isolation to VLAN 999 occurred. Any filesystem-timeline finding involving ART-001 must account for this possibility before being treated as a confirmed finding.

**DEVIATION-003 — No chain-of-custody log existed between acquisition and hand-off.**
Per `acquisition_notes.md`, no chain-of-custody form was completed by Torres at acquisition time, and he did not record who had physical or network access to the three artifacts between acquisition and hand-off to the SOC evidence share at 2026-04-14T07:42Z. This document (`chain_of_custody.md`) is the first continuous custody record for these artifacts; everything before its creation is reconstructed from `acquisition_notes.md` as a retrospective, best-available account, not a contemporaneous log.

## Access Log

| Timestamp (UTC) | Actor | Artifact ID | Action | Tool | Hash Verified | Notes |
|---|---|---|---|---|---|---|
| 2026-04-14T03:02Z | Mike Torres | ART-002 | acquire | WinPmem v3.3-rc3 | no | Acquired from live host (still beaconing) via USB3 to external NVMe enclosure, then copied to evidence share. No SHA-256 computed — see DEVIATION-001. |
| 2026-04-14T03:38Z | Mike Torres | ART-003 | acquire | WinPmem v3.3-rc3 | no | Acquired from console at West Campus after James Chen extended scope. Same workflow as ART-002. No SHA-256 computed — see DEVIATION-001. |
| 2026-04-14T04:51Z | Mike Torres | ART-001 | read_write_mount | Windows Explorer (live host) | no | Live filesystem mounted read-write to verify presence of `update.xml` at the path named in the alert. File confirmed present. Not unmounted/remounted read-only before imaging — see DEVIATION-002. |
| 2026-04-14T06:14Z | Mike Torres | ART-001 | acquire | FTK Imager | no | Full raw image acquired after VLAN 999 isolation (isolation occurred before this timestamp). No SHA-256 computed — see DEVIATION-001. |
| 2026-04-14T07:42Z | Mike Torres | ART-001 | custody_transfer | — | no | Handed off to SOC evidence share and forensic analyst. No chain-of-custody form completed prior to this transfer — see DEVIATION-003. |
| 2026-04-14T07:42Z | Mike Torres | ART-002 | custody_transfer | — | no | Handed off to SOC evidence share and forensic analyst. No chain-of-custody form completed prior to this transfer — see DEVIATION-003. |
| 2026-04-14T07:42Z | Mike Torres | ART-003 | custody_transfer | — | no | Handed off to SOC evidence share and forensic analyst. No chain-of-custody form completed prior to this transfer — see DEVIATION-003. |
| PENDING | Aida Sylla | ART-001 | hash_verify (baseline establishment) | sha256sum | PENDING | Not yet performed. `wst-ws-031.dd` is not present on the analysis workstation at the time this log was created. Baseline SHA-256 to be computed and recorded as the first action taken on this artifact, per acquisition_notes.md's own recommendation. |
| PENDING | Aida Sylla | ART-002 | hash_verify (baseline establishment) | sha256sum | PENDING | Not yet performed. `wst-ws-031.mem` is not present on the analysis workstation at the time this log was created. Baseline SHA-256 to be computed and recorded as the first action taken on this artifact. |
| PENDING | Aida Sylla | ART-003 | hash_verify (baseline establishment) | sha256sum | PENDING | Not yet performed. `wst-ws-017.mem` is not present on the analysis workstation at the time this log was created. Baseline SHA-256 to be computed and recorded as the first action taken on this artifact. |

> **Note on the three PENDING rows:** per module principle "no artifact is analyzed before its baseline integrity is established," no TSK or Volatility 3 command may be run against ART-001, ART-002, or ART-003 until each PENDING row above is replaced with a real timestamp, a real SHA-256 value from `sha256sum`, and `Hash Verified: yes`. This document remains append-only: these rows are not deleted when completed, they are followed by new rows recording the completed action.
