MedDefense Health Systems: Intelligence-Driven Defense
===============================================

Week twelve. Three weeks since the phishing click, and the IOCs MedDefense
submitted to HC3 came back changed. HC3 published a TLP:CLEAR advisory
Friday, designating the campaign HEALTHBANE — confirming the phishing
emails MedDefense caught were only Stage 1. Two other healthcare
organizations weren't as fast: they saw Stage 2 malware delivery and Stage
3 data exfiltration. James Chen doesn't want yesterday's blocklist; he
wants to understand the adversary. Dr. Morales has a board meeting in ten
days and needs to know what MedDefense trusts, what it can detect, what it
can't, and what's being done about the gap — not a pile of indicators.

Four sources describe HEALTHBANE, and they don't fully agree:

- `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt` — the sector advisory. 23
  indicators, attribution explicitly UNCONFIRMED, direct visibility on 6
  of at least 14 targeted organizations.
- `commercial_feed_extract.json` — a commercial CTI feed tracking the same
  activity under its own label, VITALSCORE. 41 auto-tagged indicators,
  confidence ranging from 15 to 96, several self-flagged by the vendor as
  noise not to be blocked.
- `researcher_blog_analysis.txt` — an independent researcher who pulled
  the live phishing kit from a misconfigured server and privately tracks
  the operator as APT-MEDAGENT, medium confidence, based on tooling and
  infrastructure fingerprint alone.
- `meddefense_4x00_findings.txt` — MedDefense's own internal report from
  the original phishing investigation, carried forward as one more source
  to reconcile rather than ground truth.
- `samples/` — a benign/malicious corpus (PDFs and `.eml` files) with a
  manifest of expected results, used later to test YARA rules against
  real true/false positive and negative cases before deployment.

This module produces no live SIEM, Wazuh server, or Suricata sensor —
detection rules and logic are written and tested locally as scripts and
documentation. Every deliverable keeps confirmed fact, analytical
assessment, and unsupported assumption in visibly separate categories;
every source is graded on reliability and credibility independently
(Admiralty Code); every indicator is traced back to the source(s) that
actually published it rather than merged into one anonymous list; and
disagreement between sources — on attribution, on confidence, on which
indicators are even worth acting on — is documented, not silently
resolved in whichever direction looks cleanest.

See `0-intel_intake.py` / `0-intel_intake.md` onward for the full
deliverable set.
