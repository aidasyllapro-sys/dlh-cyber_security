#!/bin/bash
#
# 11-yara_testing.sh
#
# MedDefense Health Systems -- Intelligence-Driven Defense (4x02)
# Task 11: Testing the Arsenal
#
# Systematically tests the YARA rules from Tasks 9 and 10 against the
# full sample corpus, measuring true positive rate, false positive
# rate, false negative rate, detection rate and precision per rule,
# and issuing a DEPLOY / TUNE / MONITOR recommendation for each.
#
# KNOWN DATA GAP (must not be silently worked around):
#   Task 10's deliverable, 10-yara_arsenal.yar, was never produced in
#   this project -- it does not exist in this directory. That file is
#   expected to define HEALTHBANE_Email_Headers (targeting the .eml
#   samples) and HEALTHBANE_Campaign_Composite (a combined rule). This
#   script does NOT invent stand-in rules to fill that gap: it detects
#   the file's absence, prints an explicit, visible warning, and skips
#   only the sections that depend on it -- HEALTHBANE_Phishing_PDF from
#   Task 9 is tested in full, for real, against every sample file.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLES_DIR="${SCRIPT_DIR}/samples"
RULE_9="${SCRIPT_DIR}/9-yara_phishing_pdf.yar"
RULE_10="${SCRIPT_DIR}/10-yara_arsenal.yar"

if ! command -v yara >/dev/null 2>&1; then
    echo "ERROR: the 'yara' command-line tool is not installed or not on PATH." >&2
    echo "Install it (e.g. 'sudo apt-get install yara') and re-run this script." >&2
    exit 1
fi

if [ ! -d "${SAMPLES_DIR}" ]; then
    echo "ERROR: samples directory not found at ${SAMPLES_DIR}" >&2
    exit 1
fi

if [ ! -f "${RULE_9}" ]; then
    echo "ERROR: ${RULE_9} not found -- Task 9's rule is required for this script." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Expected classification ground truth, per samples_manifest.txt's own
# "MATCH expectations for YARA grader" table. Format:
# "filename:expected_verdict" where expected_verdict is POS or NEG.
#
# The manifest defines expectations for HEALTHBANE_Phishing_PDF ONLY
# against the 4 PDF samples -- it makes no claim about how this rule
# should behave on the 4 .eml samples (those are scoped to the
# Task-10 email rules instead). Scoring is therefore computed against
# exactly the manifest's 4-file table for this rule, matching this
# task's own worked example (TP:2 | TN:2 | FP:0 | FN:0). Instruction 1
# ("run against every file in the samples directory") is still honored
# literally -- see the separate, unscored robustness check below, which
# runs this rule against the .eml files too and reports any unexpected
# match without folding it into the core TP/TN/FP/FN counts.
# ---------------------------------------------------------------------------
# shellcheck disable=SC2034  # consumed via run_rule_test's `local -n` nameref
PDF_RULE_EXPECTATIONS=(
    "phishing_sample.pdf:POS"
    "healthbane_lure_02.pdf:POS"
    "clean_invoice.pdf:NEG"
    "benign_invoice.pdf:NEG"
)

# Files outside a rule's own manifest-defined scope, scanned only as an
# informational robustness check (instruction 1's "every file"), never
# scored into TP/TN/FP/FN.
# shellcheck disable=SC2034  # consumed via run_scope_check's `local -n` nameref
PDF_RULE_OUT_OF_SCOPE=(
    "healthbane_email_01.eml"
    "healthbane_email_02.eml"
    "healthbane_email_03.eml"
    "benign_newsletter.eml"
)

# ---------------------------------------------------------------------------
# Ground truth from samples_manifest.txt for HEALTHBANE_Email_Headers,
# reproduced here ONLY so that -- once 10-yara_arsenal.yar exists -- this
# table is ready to use. It is not used to fabricate results while the
# rule file is absent.
# ---------------------------------------------------------------------------
# healthbane_email_01.eml   -> TRUE POSITIVE
# healthbane_email_02.eml   -> TRUE POSITIVE
# healthbane_email_03.eml   -> FALSE NEGATIVE (manifest states this is
#                              intentional; Task 11 must identify why and
#                              propose a fix once the rule exists)
# benign_newsletter.eml     -> TRUE NEGATIVE

# --- Run a rule against a fixed list of "filename:expected" pairs, and
#     print TP/TN/FP/FN plus the derived metrics and a recommendation.
#     Args: rule_name  rule_file  expectations_array_name
run_rule_test() {
    local rule_name="$1"
    local rule_file="$2"
    local -n expectations="$3"

    local tp=0 tn=0 fp=0 fn=0
    declare -a fn_files=()
    declare -a fp_files=()

    for entry in "${expectations[@]}"; do
        local fname="${entry%%:*}"
        local expected="${entry##*:}"
        local fpath="${SAMPLES_DIR}/${fname}"

        if [ ! -f "${fpath}" ]; then
            echo "WARNING: sample ${fname} not found in ${SAMPLES_DIR}, skipping." >&2
            continue
        fi

        # yara exits 0 whether or not a rule matches; a match prints a
        # line naming the rule and file, no match prints nothing.
        local match_output
        match_output="$(yara "${rule_file}" "${fpath}" 2>/dev/null || true)"

        local matched="NEG"
        if [ -n "${match_output}" ]; then
            matched="POS"
        fi

        if [ "${expected}" = "POS" ] && [ "${matched}" = "POS" ]; then
            tp=$((tp + 1))
        elif [ "${expected}" = "NEG" ] && [ "${matched}" = "NEG" ]; then
            tn=$((tn + 1))
        elif [ "${expected}" = "NEG" ] && [ "${matched}" = "POS" ]; then
            fp=$((fp + 1))
            fp_files+=("${fname}")
        elif [ "${expected}" = "POS" ] && [ "${matched}" = "NEG" ]; then
            fn=$((fn + 1))
            fn_files+=("${fname}")
        fi
    done

    # Detection rate = TP / (TP + FN); false positive rate = FP / (FP + TN);
    # precision = TP / (TP + FP). Guard every division against a zero
    # denominator rather than letting the shell divide by zero.
    local detection_rate="N/A" fp_rate="N/A" precision="N/A"
    if [ $((tp + fn)) -gt 0 ]; then
        detection_rate="$(awk -v tp="${tp}" -v fn="${fn}" 'BEGIN{printf "%.1f", (tp/(tp+fn))*100}')%"
    fi
    if [ $((fp + tn)) -gt 0 ]; then
        fp_rate="$(awk -v fp="${fp}" -v tn="${tn}" 'BEGIN{printf "%.1f", (fp/(fp+tn))*100}')%"
    fi
    if [ $((tp + fp)) -gt 0 ]; then
        precision="$(awk -v tp="${tp}" -v fp="${fp}" 'BEGIN{printf "%.1f", (tp/(tp+fp))*100}')%"
    fi

    echo "Rule: ${rule_name}"
    echo "TP: ${tp} | TN: ${tn} | FP: ${fp} | FN: ${fn}"
    echo "Detection rate: ${detection_rate}"
    echo "False positive rate: ${fp_rate}"
    echo "Precision: ${precision}"

    # Deployment recommendation logic:
    #   DEPLOY  - zero false positives AND zero false negatives
    #   TUNE    - false positives present (would flood analysts), or a
    #             mix of both FP and FN -- the rule needs adjustment
    #             before it is safe to run unattended
    #   MONITOR - false negatives present but zero false positives --
    #             the rule is safe to run (won't generate noise) but is
    #             missing real detections, so it should feed a watch
    #             process while a fix is developed, not be relied on
    #             alone
    local recommendation
    if [ "${fp}" -eq 0 ] && [ "${fn}" -eq 0 ]; then
        recommendation="DEPLOY"
    elif [ "${fp}" -gt 0 ]; then
        recommendation="TUNE"
    else
        recommendation="MONITOR"
    fi
    echo "Recommendation: ${recommendation}"
    echo ""

    if [ "${#fn_files[@]}" -gt 0 ]; then
        echo "  False negatives for ${rule_name}:"
        for f in "${fn_files[@]}"; do
            echo "    - ${f}"
        done
        echo ""
    fi
    if [ "${#fp_files[@]}" -gt 0 ]; then
        echo "  False positives for ${rule_name}:"
        for f in "${fp_files[@]}"; do
            echo "    - ${f}"
        done
        echo ""
    fi
}

# --- Informational-only robustness check: run a rule against files
#     outside its manifest-defined scope (instruction 1's "every file
#     in the samples directory") and flag any unexpected match. Not
#     folded into the scored TP/TN/FP/FN counts, since the manifest
#     makes no expectation claim for these file/rule pairs.
#     Args: rule_name  rule_file  out_of_scope_array_name
run_scope_check() {
    local rule_name="$1"
    local rule_file="$2"
    local -n out_of_scope="$3"

    local unexpected=()
    for fname in "${out_of_scope[@]}"; do
        local fpath="${SAMPLES_DIR}/${fname}"
        [ -f "${fpath}" ] || continue
        local match_output
        match_output="$(yara "${rule_file}" "${fpath}" 2>/dev/null || true)"
        if [ -n "${match_output}" ]; then
            unexpected+=("${fname}")
        fi
    done

    if [ "${#unexpected[@]}" -eq 0 ]; then
        echo "  Robustness check: ${rule_name} did not fire on any of the"
        echo "  ${#out_of_scope[@]} out-of-scope samples (${out_of_scope[*]})."
    else
        echo "  Robustness check WARNING: ${rule_name} unexpectedly matched"
        echo "  ${#unexpected[@]} out-of-scope sample(s): ${unexpected[*]}"
        echo "  This is not counted in the scored metrics above (the"
        echo "  manifest defines no expectation for this rule/file pair),"
        echo "  but it is worth investigating before deployment."
    fi
    echo ""
}

echo "=== YARA TESTING SUMMARY ==="
echo ""

run_rule_test "HEALTHBANE_Phishing_PDF" "${RULE_9}" PDF_RULE_EXPECTATIONS
run_scope_check "HEALTHBANE_Phishing_PDF" "${RULE_9}" PDF_RULE_OUT_OF_SCOPE

echo "-----------------------------------------------------------------"
echo ""

if [ ! -f "${RULE_10}" ]; then
    cat <<'EOF'
Rule: HEALTHBANE_Email_Headers
STATUS: NOT TESTED -- 10-yara_arsenal.yar was not found in this
  directory. Task 10 ("The Arsenal Expands" or equivalent) has not
  been completed/delivered in this project, so no rule named
  HEALTHBANE_Email_Headers exists to test. Fabricating pass/fail
  numbers for a rule that was never written would misrepresent this
  project's actual state. Once 10-yara_arsenal.yar is produced, this
  script's PDF-rule test pattern (see run_rule_test/EMAIL_RULE_
  EXPECTATIONS) can be reused unchanged for this rule and for
  HEALTHBANE_Campaign_Composite -- the ground-truth table for the
  4 .eml samples is already commented in this script's source, ready
  to activate.

Rule: HEALTHBANE_Campaign_Composite
STATUS: NOT TESTED -- same reason as above; this rule also depends on
  10-yara_arsenal.yar, which does not exist yet.

Recommendation for both rules: N/A (cannot recommend DEPLOY / TUNE /
  MONITOR for a rule that has not been written or tested).
EOF
    echo ""
    echo "-----------------------------------------------------------------"
    echo ""
    echo "OVERALL NOTE: this run covers only Task 9's rule (1 of the 3"
    echo "rules this task is meant to evaluate). Re-run this script once"
    echo "10-yara_arsenal.yar exists to get complete Task 11 results."
else
    echo "NOTE: 10-yara_arsenal.yar was found, but this script's"
    echo "expectation tables for HEALTHBANE_Email_Headers and"
    echo "HEALTHBANE_Campaign_Composite have not been filled in against"
    echo "its actual rule names/logic. Update this script to add those"
    echo "expectation arrays and run_rule_test calls before relying on"
    echo "its output for those two rules."
fi
