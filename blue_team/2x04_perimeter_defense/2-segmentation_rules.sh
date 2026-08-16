#!/bin/bash
#
# script name : 2-segmentation_rules.sh
# purpose     : translate the MedDefense four-zone model (DMZ, INTERNAL,
#               MGMT, MEDDEV) into the structured rule set every
#               downstream firewall implementation task (nftables,
#               Windows Firewall) reads as its single source of truth.
#               Defines each zone's CIDR, purpose and default policies,
#               every explicitly required cross-zone allow flow, and
#               programmatically derives an explicit deny_all entry for
#               every ordered zone pair that has no allow flow, so no
#               pair is ever silently forgotten. This task implements
#               nothing itself - it only emits the contract.
# author      : Aïda Sylla
# date        : 2026-08-16
 
set -uo pipefail
 
# ---------------------------------------------------------------------------
# The minimum required flows this script encodes, quoted verbatim from the
# task's own instructions, for direct traceability between this contract
# and the requirement it satisfies:
#   - MGMT to INTERNAL on tcp/22 for administration
#   - MGMT to DMZ on tcp/22 for administration
#   - INTERNAL clinical workstations to INTERNAL server hosts on tcp/443 and tcp/3306
#   - DMZ to INTERNAL databases on tcp/3306 only from named DMZ application hosts
#   - MEDDEV to INTERNAL hosts on tcp/4242 (DICOM) and tcp/443 (EHR web)
#     only
#   - ALL to MGMT resolver on udp/53 and tcp/53
#   - No flows from MEDDEV to DMZ or the public Internet
#   - No flows from any zone into MEDDEV except MGMT on tcp/22 and
#     tcp/4242
# ---------------------------------------------------------------------------
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to assemble segmentation_rules.json. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_PATH="${SCRIPT_DIR}/segmentation_rules.json"
 
# ---------------------------------------------------------------------------
# 1. Zones. CIDR ranges are this project's own assignment (not supplied by
#    the task) - one /24 per zone, chosen to be unambiguous and
#    non-overlapping; adjust if MedDefense's real addressing plan differs.
#    default_outbound restrictions encode this task's own explicit "no
#    flows from MEDDEV to DMZ or the public Internet" requirement directly
#    on the zone definition, not just as an absence of an allow flow.
# ---------------------------------------------------------------------------
ZONES_JSON='[
  {
    "name": "DMZ",
    "cidr": "10.10.1.0/24",
    "purpose": "Public-facing services (web front ends, DMZ application hosts)",
    "default_inbound": "drop",
    "default_outbound": {"policy": "accept", "restrictions": ["no unsolicited inbound from DMZ into MEDDEV"]}
  },
  {
    "name": "INTERNAL",
    "cidr": "10.10.2.0/24",
    "purpose": "Clinical applications, clinical workstations and internal databases",
    "default_inbound": "drop",
    "default_outbound": {"policy": "accept", "restrictions": ["no unsolicited inbound from INTERNAL into MEDDEV"]}
  },
  {
    "name": "MGMT",
    "cidr": "10.10.3.0/24",
    "purpose": "Administration workstations and the internal DNS resolver",
    "default_inbound": "drop",
    "default_outbound": {"policy": "accept", "restrictions": []}
  },
  {
    "name": "MEDDEV",
    "cidr": "10.10.4.0/24",
    "purpose": "Medical device VLAN (imaging, monitoring and other clinical devices)",
    "default_inbound": "drop",
    "default_outbound": {"policy": "accept", "restrictions": ["no MEDDEV to DMZ", "no MEDDEV to the public Internet", "No flows from MEDDEV to DMZ or the public Internet"]}
  }
]'
 
# ---------------------------------------------------------------------------
# 2/3. Explicit cross-zone allow flows (the minimum set the task requires).
#    exception_for is null for every flow here since none of these are
#    granted as a temporary exception - the field exists in the schema for
#    downstream tasks (e.g. the change log) to populate later if a
#    time-boxed exception is ever added on top of this baseline.
# ---------------------------------------------------------------------------
FLOWS_JSON='[
  {"src_zone":"MGMT","dst_zone":"INTERNAL","proto":"tcp","dport":22,"justification":"administration","exception_for":null},
  {"src_zone":"MGMT","dst_zone":"DMZ","proto":"tcp","dport":22,"justification":"administration","exception_for":null},
  {"src_zone":"INTERNAL","dst_zone":"INTERNAL","proto":"tcp","dport":443,"justification":"clinical workstations to server hosts (HTTPS application access)","exception_for":null,"src_subnet_note":"clinical workstations","dst_subnet_note":"server hosts"},
  {"src_zone":"INTERNAL","dst_zone":"INTERNAL","proto":"tcp","dport":3306,"justification":"clinical workstations to server hosts (database access)","exception_for":null,"src_subnet_note":"clinical workstations","dst_subnet_note":"server hosts"},
  {"src_zone":"DMZ","dst_zone":"INTERNAL","proto":"tcp","dport":3306,"justification":"DMZ application hosts to internal databases","exception_for":null,"src_hosts":["dmz-app-01","dmz-app-02"]},
  {"src_zone":"MEDDEV","dst_zone":"INTERNAL","proto":"tcp","dport":4242,"justification":"DICOM imaging to PACS","exception_for":null},
  {"src_zone":"MEDDEV","dst_zone":"INTERNAL","proto":"tcp","dport":443,"justification":"EHR web integration for device display","exception_for":null},
  {"src_zone":"ALL","dst_zone":"MGMT","proto":"udp","dport":53,"justification":"internal DNS resolution","exception_for":null},
  {"src_zone":"ALL","dst_zone":"MGMT","proto":"tcp","dport":53,"justification":"internal DNS resolution (large responses / zone transfer fallback)","exception_for":null},
  {"src_zone":"MGMT","dst_zone":"MEDDEV","proto":"tcp","dport":22,"justification":"administration of medical devices","exception_for":null},
  {"src_zone":"MGMT","dst_zone":"MEDDEV","proto":"tcp","dport":4242,"justification":"MGMT-initiated DICOM diagnostics on medical devices","exception_for":null}
]'
 
# ---------------------------------------------------------------------------
# 4. Explicit deny_all for every ordered real-zone pair with no allow flow.
#    Computed programmatically (not hand-listed) precisely so no pair can
#    ever be silently forgotten as the zone/flow lists evolve. "ALL" is a
#    DNS-only wildcard source in this schema, not a real zone, so it is
#    excluded from this ordered-pair enumeration.
# ---------------------------------------------------------------------------
echo "[*] Computing explicit deny_all for every zone pair with no allow flow..."
 
ZONE_NAMES=("DMZ" "INTERNAL" "MGMT" "MEDDEV")
DENY_ENTRIES=()
 
for src in "${ZONE_NAMES[@]}"; do
    for dst in "${ZONE_NAMES[@]}"; do
        [[ "${src}" == "${dst}" ]] && continue
        # NOTE: found the hard way on billing-srv-01 - `jq -e` both PRINTS
        # its boolean result to stdout AND sets the exit code from it;
        # capturing that printed output via `$(jq -e ... && echo true ||
        # echo false)` doubled up the value into a two-line string
        # ("true\ntrue") that could never equal the plain string "true",
        # so every single pair was wrongly treated as "no flow found".
        # The fix: redirect jq's own stdout away and rely solely on its
        # exit status via a plain if-statement.
        if jq -e --arg s "${src}" --arg d "${dst}" \
            '[.[] | select(.src_zone == $s and .dst_zone == $d)] | length > 0' \
            >/dev/null 2>&1 <<< "${FLOWS_JSON}"; then
            has_flow="true"
        else
            has_flow="false"
        fi
        if [[ "${has_flow}" != "true" ]]; then
            DENY_ENTRIES+=("$(jq -n --arg s "${src}" --arg d "${dst}" '{src_zone: $s, dst_zone: $d, action: "deny_all"}')")
        fi
    done
done
 
DENY_JSON="[$(IFS=,; echo "${DENY_ENTRIES[*]:-}")]"
deny_count="${#DENY_ENTRIES[@]}"
flow_count="$(jq 'length' <<< "${FLOWS_JSON}")"
cross_zone_pairs=$(( ${#ZONE_NAMES[@]} * (${#ZONE_NAMES[@]} - 1) ))
 
# With 4 zones (DMZ, INTERNAL, MGMT, MEDDEV), the number of ordered
# cross-zone pairs is 4 * 3 = 12 total ordered zone pairs - confirmed on
# billing-srv-01: 11 allow flows, 7 explicit deny_all pairs, 12 total
# ordered zone pairs.
echo "    ${flow_count} allow flows, ${deny_count} explicit deny_all pairs, ${cross_zone_pairs} total ordered zone pairs."
 
# ---------------------------------------------------------------------------
# 5. Emit segmentation_rules.json
# ---------------------------------------------------------------------------
jq -n \
    --argjson zones "${ZONES_JSON}" \
    --argjson flows "${FLOWS_JSON}" \
    --argjson deny_all "${DENY_JSON}" \
    --argjson flow_count "${flow_count}" \
    --argjson deny_count "${deny_count}" \
    --argjson cross_zone_pairs "${cross_zone_pairs}" \
    '{
        zones: $zones,
        flows: $flows,
        deny_all: $deny_all,
        summary: {
            flow_count: $flow_count,
            allow_count: $flow_count,
            deny_count: $deny_count,
            cross_zone_pairs: $cross_zone_pairs
        }
    }' > "${OUTPUT_PATH}"
 
echo "Report saved to: $(basename "${OUTPUT_PATH}")"
exit 0
