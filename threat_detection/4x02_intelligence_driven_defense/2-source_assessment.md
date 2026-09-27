2 - Source Credibility Matrix
==============================

MedDefense Health Systems -- Intelligence-Driven Defense (4x02)
Task 2: assessing the reliability of each HEALTHBANE source and the
credibility of its content using the Admiralty Code (NATO system), so
that later tasks (indicator triage, ATT&CK mapping, YARA development)
weight each source's claims appropriately instead of treating four very
different documents as equally authoritative.

---

## 1. Methodology

This assessment uses the **Admiralty Code**, adapted from its military
intelligence origin for a cyber-threat-intelligence context. It rates two
things independently, because a source can be reliable in general while
being wrong about one specific claim, and a source can publish credible
detail while being, as an institution, hard to independently verify.

**Source reliability (A-F)** -- a property of the *source itself*, based
on its track record, position to observe the facts, and institutional
accountability:

| Grade | Meaning |
|---|---|
| A | Completely reliable -- no doubt of authenticity, trustworthiness, competence; history of accuracy. |
| B | Usually reliable -- minor doubts; history of mostly valid reporting. |
| C | Fairly reliable -- doubts exist; has provided valid information in the past, but not consistently. |
| D | Not usually reliable -- significant doubts; has provided valid information in the past, but is inconsistent. |
| E | Unreliable -- lacks a track record, or history of invalid reporting. |
| F | Reliability cannot be judged -- no basis exists for evaluation. |

**Information credibility (1-6)** -- a property of the *specific claim
or content*, based on how it was obtained and whether it is corroborated:

| Grade | Meaning |
|---|---|
| 1 | Confirmed by other independent sources; logical; consistent with other information on the subject. |
| 2 | Probably true -- logical, consistent with other information, not confirmed. |
| 3 | Possibly true -- reasonably logical, agrees with some other information, not confirmed. |
| 4 | Doubtful -- not logical, but no other information to contradict it. |
| 5 | Improbable -- not logical, contradicted by other information. |
| 6 | Cannot be judged -- validity cannot be determined. |

A rating of, for example, **B2** means "usually reliable source,
probably-true content." The two axes are graded independently:
this assessment does not average reliability and credibility into a
single score, because a highly reliable source (A) can still publish an
individual claim that is only possibly true (3) if that specific claim
sits outside what the source directly observed.

**Confidence levels (HIGH / MEDIUM / LOW)** are used throughout this
document, and throughout this project, as the plain-language translation
of an Admiralty pairing for a given claim, mapped as follows:

| Admiralty pairing | Confidence level used in this project |
|---|---|
| A1, A2, B1 | HIGH |
| B2, B3, C1, C2 | MEDIUM |
| C3, D-x, E-x, F-x, or any pairing involving grade 4-6 credibility | LOW |

This mapping is a simplification made explicit here so it is applied
consistently: a MEDIUM confidence label anywhere else in this project
(Task 0's per-source notes, Task 1's triage table) should trace back to
a B2/B3/C-range pairing under this table, not to an unstated gut feeling.

---

## 2. Per-Source Assessment

### 2.1 HC3 Sector Advisory (HC3-2026-HEALTHBANE-001)

| Attribute | Assessment |
|---|---|
| **Source reliability** | **A** -- a US federal sector coordination center (HHS HC3) publishing under its own document ID, with a named originating branch and a POC mailbox. Reliability is institutional: HC3 has legal/regulatory standing, a review process (the advisory states "Prepared by: HC3 Threat Intelligence Branch"), and its factual claims are grounded in named contributing organizations rather than automated collection alone. |
| **Information credibility** | **1** for Stage 1-3 activity claims -- HC3 states these are based on "6 HC3 partner organizations providing full telemetry," "HC3 sensor deployment at 2 regional healthcare ISAOs," and independent corroboration from abuse.ch URLhaus. **3** for the attribution/actor-type claim ("financially motivated mid-tier cybercrime actor") -- HC3 itself rates this MODERATE confidence, and attribution specifically is stated as LOW confidence with no named actor. |
| **Timeliness** | Published 2026-04-25, one day after the researcher's blog (2026-04-24) and roughly nine days after the original MedDefense incident (2026-04-14). This is fast for a federal sector advisory and reflects direct coordination with the researcher (see conflict note below), but it means HC3's IOC set was frozen at publication -- it will not reflect anything the commercial feed or researcher observed afterward. |
| **Relevance to MedDefense** | High. HC3 explicitly states direct or partner visibility on 6 of at least 14 targeted organizations, in the same Midwest ISAC region and sector as MedDefense, and MedDefense's own indicators (contributed via the 4x00 investigation) appear to be reflected in HC3's Stage 1/2/3 confidence ratings. |
| **Limitations** | Direct visibility limited to 6 of at least 14 known targets -- the true scope is stated as "at least 14," meaning HC3's own picture is partial. Two additional techniques (T1078, T1021) are explicitly held back from the OBSERVED table pending confirmation, i.e. HC3 is being conservative rather than complete. Next update is not guaranteed before 2026-05-09 except "on significant new development." |
| **Bias / visibility constraints** | Institutional caution is a structural bias here: HC3 explicitly declines to endorse any commercial attribution label ("commercial tracking names circulating in industry channels are noted but not endorsed"), which is defensible epistemically but means HC3's advisory will systematically lag behind more speculative sources on attribution, by design. HC3's visibility is also mediated through partner organizations' own reporting quality -- HC3 did not independently observe most of what it reports; it aggregates. |

### 2.2 Acme CTI Commercial Feed (extract ACME-HEALTH-2026-0426-117)

| Attribute | Assessment |
|---|---|
| **Source reliability** | **C** -- a commercial vendor feed, automated and only "sampled, not exhaustive" per its own disclaimer. It has a real collection pipeline (it independently corroborates several HC3/MedDefense indicators with matching confidence), but its own metadata openly documents an inconsistent process: some entries carry `acme_confidence` as low as 15 and are self-flagged as noise, in the same feed as entries at 96. A single feed producing both is graded C, not B, because reliability describes the whole source's track record, and a track record that includes acknowledged false-positive-prone auto-tagging is "fairly reliable" at best, not "usually reliable." |
| **Information credibility** | Highly variable by indicator, which is itself the finding: **2** for the 16 highest-confidence, VITALSCORE-tagged, cross-corroborated indicators (confidence 85-96, matching HC3/MedDefense/researcher entries); **5-6** for the entries the feed itself annotates as shared/CDN infrastructure (`DO NOT BLOCK`, `LIKELY NOISE`) or as ML-clustered on keyword/name similarity with "human review not performed." This feed cannot be assigned one credibility grade -- see Task 1's triage, where the same 41-indicator feed splits roughly evenly between indicators worth acting on and indicators the vendor itself warns against blocking. |
| **Timeliness** | Extract dated 2026-04-26T08:14:00Z, the most recent of the four sources by one to two days -- consistent with an automated feed that continues collecting after human-authored reports are published. |
| **Relevance to MedDefense** | Moderate-to-high for the corroborated subset (its highest-confidence indicators substantially overlap MedDefense's own IOCs and HC3's advisory); low for the self-flagged noise subset, which is healthcare-keyword-triggered but not actually tied to this campaign. |
| **Limitations** | The feed's own stated limitation: "indicators are auto-tagged, and analyst review was SAMPLED, not exhaustive." 16 of 41 indicators carry confidence below 60. Several entries are pre-campaign-window (`rx-benefits-portal.com`, "predates HEALTHBANE window by 16 days") and may reflect a related but distinct earlier campaign rather than HEALTHBANE itself. |
| **Bias / visibility constraints** | Commercial incentive bias: a vendor feed has a structural incentive toward broader indicator counts and a proprietary label (VITALSCORE) that increases the feed's apparent value and distinctiveness, independent of whether every included indicator is operationally sound. The feed's own notes partially self-correct for this (it flags its own noise), which is a point in its favor, but the underlying incentive remains. |

### 2.3 Marcus Weller Research Blog ("The Phishing Kit Behind The HEALTHBANE Campaign")

| Attribute | Assessment |
|---|---|
| **Source reliability** | **B** -- an individual, unaffiliated researcher, but with a documented track record referenced in his own post (three prior campaigns tracked since 2024: RXBRIDGE, CLAIMBRIDGE, MEDNEXUS) and a disclosed, verifiable disclosure process: he notified HC3 on 2026-04-22, agreed to a 72-hour publication delay at HC3's request, and published only after HC3 confirmed the delay had been useful. That is meaningfully more accountable than an anonymous blog, which is why this is graded B rather than C, but it remains a single, unaffiliated individual with no institutional review, which is why it is not graded A. |
| **Information credibility** | **1** for the technical kit analysis (PHPMailer 6.6.0, config.php structure, hosting/registrar pattern) -- this was obtained by direct extraction from a misconfigured live endpoint, i.e. primary evidence, not inference, and it is corroborated by HC3's own Stage 1/2 findings. **4** for the APT-MEDAGENT attribution -- the researcher himself states this is "based entirely on infrastructure and tooling fingerprint... NOT based on telemetry, signals intelligence, or insider reporting," which is a real analytic method but a narrow evidentiary basis for naming an actor. |
| **Timeliness** | Published 2026-04-24 14:22 UTC -- the earliest of the four sources, one day ahead of HC3's advisory (by the researcher's own account, deliberately delayed 72 hours from when he could have published, at HC3's request). |
| **Relevance to MedDefense** | High for defensive guidance -- the post's Section 7 gives operational-pattern detections (PHPMailer 6.6.0 header string, Namecheap+compound-keyword domain registration pattern) that are explicitly designed to "survive rotation," directly useful input for later YARA/behavioral-rule tasks in this project. Lower for indicator-level blocking, which the researcher himself says will "work for about one week" before rotation. |
| **Limitations** | Solo researcher with, by his own account, "no visibility into victim telemetry" -- everything is inferred from the attacker-side artifact (the kit) and infrastructure, never from what happened inside a victim's network. Explicitly does not know whether Acme's VITALSCORE corresponds 1:1 to his own APT-MEDAGENT tracking. |
| **Bias / visibility constraints** | A solo researcher publishing under his own name has a professional incentive toward being first and toward naming a distinct tracked actor (APT-MEDAGENT is his own label, from his own prior tracking) -- this doesn't make the analysis wrong, but it is a structural pull toward attribution confidence that the stated MEDIUM rating and explicit caveats appropriately temper. His visibility is also inherently one-sided: he sees the kit and its infrastructure, never the defender's environment. |

### 2.4 MedDefense Internal Investigation (MD-2026-IR-0414-001)

| Attribute | Assessment |
|---|---|
| **Source reliability** | **A** for MedDefense's own direct observations -- this is MedDefense's own SOC/CISO-reviewed internal report (reviewed by James Chen, approved by Dr. Patricia Morales), describing MedDefense's own mailbox, EDR and header data. There is no third party between the observation and the report; reliability here is about direct institutional visibility into one's own environment, which is as high as this project's sourcing gets. |
| **Information credibility** | **1** -- every indicator in this report was extracted from MedDefense's own confirmed phishing emails and the confirmed click (Diane Marsh / WS-NURSE-04) from the 4x00 investigation. This is not inference or fingerprint-matching; it is primary evidence from MedDefense's own systems, including the one genuinely non-templated captured artifact in the whole indicator set (the real `token=a8f3e2d1` value in the verify-staff URL, as opposed to every other source's placeholder). |
| **Timeliness** | Dated 2026-04-16 -- the oldest of the four sources by over a week, because it documents the originating incident rather than the sector-wide campaign that was only recognized afterward. Its own Q3 answer ("Is the campaign broader than the three emails we caught? -> Likely. HC3 submission pending.") shows MedDefense knew at the time that its own picture was necessarily incomplete. |
| **Relevance to MedDefense** | Maximal by definition -- this is MedDefense's own incident. It is also the anchor that lets every other source's claims be checked against a ground-truth internal event (e.g., confirming that HC3's "Stage 1 HIGH confidence" domains match what actually hit MedDefense's own mailboxes). |
| **Limitations** | Narrow scope by design -- 8 emails, 3 confirmed as this campaign, 1 confirmed click, at one organization. Its own Q4 answer states a mass EDR scan on 2026-04-16 found no matching Stage 2 hash, meaning MedDefense has no direct evidence of malware execution on its own endpoints, only of Stage 1 (credential harvesting) and the click. Its own handoff section explicitly defers Stage 2/3 network confirmation to the 4x01 project and sector correlation to 4x02 -- i.e., the report itself documents that it should not be read as covering more than it does. |
| **Bias / visibility constraints** | Distribution marked INTERNAL, not for external share (except the "indicator-only extract" sent to HC3) -- this is not a bias in the analytic sense, but it does mean the full narrative context (who was targeted, exact phrasing, internal response timeline) is not available to HC3, the researcher, or Acme; only the indicators are. This asymmetry is itself a source-conflict driver: MedDefense knows things about its own incident that no other source can corroborate or contradict. |

---

## 3. Source Comparison Matrix

| | HC3 Advisory | Acme Commercial Feed | Researcher Blog | MedDefense 4x00 |
|---|---|---|---|---|
| **Source type** | Government advisory | Commercial feed | Open-source research | Internal investigation |
| **Reliability grade** | A | C | B | A |
| **Credibility (core claims)** | 1 | 2 (high-confidence subset) / 5-6 (self-flagged noise subset) | 1 (technical) / 4 (attribution) | 1 |
| **Confidence level (this project's mapping)** | HIGH | Split: HIGH for corroborated subset, LOW for noise subset | HIGH (technical) / MEDIUM (attribution) | HIGH |
| **Published / dated** | 2026-04-25 | 2026-04-26T08:14Z | 2026-04-24 14:22 UTC | 2026-04-16 |
| **TLP / distribution** | TLP:CLEAR | AMBER | None (public) | INTERNAL |
| **Indicators provided** | 23 | 41 | 14 | 11 |
| **Attribution stance** | UNCONFIRMED; does not endorse VITALSCORE | Uses proprietary label VITALSCORE | Uses APT-MEDAGENT, MEDIUM confidence | No attribution offered |
| **Basis of visibility** | 6 partner orgs' telemetry + 2 ISAO sensors + OSINT | Automated collection + ML clustering, sampled human review | Direct extraction of live phishing kit; no victim telemetry | MedDefense's own mailboxes, EDR, and one confirmed click |
| **Primary strength** | Broadest confirmed sector-level visibility | Broadest raw indicator volume; useful cross-check | Deepest technical/tooling detail; actor-tracking history | Only source with direct ground-truth on the originating incident |
| **Primary weakness** | Conservative; excludes techniques pending confirmation; partial visibility (6 of 14+ orgs) | Inconsistent per-indicator quality within the same feed | Single individual; no victim-side telemetry | Narrow scope (one org, 3 emails); no EDR-confirmed Stage 2 |

---

## 4. Analytical Note: The Attribution Conflict

Four sources, four different attribution stances, on the same underlying
activity:

- **HC3**: uses the campaign designation **HEALTHBANE** (a descriptive
  campaign name, not an actor name) and explicitly states attribution
  confidence is LOW, with no named actor. HC3 additionally states it is
  aware of "commercial tracking names circulating in industry channels"
  and declines to endorse them.
- **Acme (commercial feed)**: uses **VITALSCORE** as its actor/cluster
  label, applied automatically via its clustering engine, with
  `acme_confidence` scores per indicator rather than one confidence
  level for the label itself.
- **Researcher (Marcus Weller)**: uses **APT-MEDAGENT**, his own private
  tracking label carried over from three prior campaigns (RXBRIDGE 2024,
  CLAIMBRIDGE 2024, MEDNEXUS 2025), at MEDIUM confidence, based entirely
  on tooling and infrastructure fingerprint overlap -- explicitly not on
  telemetry or insider reporting.
- **MedDefense (4x00)**: offers no attribution at all. Its scope was the
  originating incident, not actor identification, and it correctly
  treats that question as out of scope for an internal report.

**Are these four labels the same actor?** Probably referring to the same
underlying operational activity, but this is not confirmed, and the
sources themselves say so:

- The researcher explicitly states: "I have seen one commercial feed
  (Acme) use the label 'VITALSCORE' for overlapping activity... I have
  no visibility into whether Acme's VITALSCORE corresponds 1:1 with my
  APT-MEDAGENT." This is the strongest direct statement on the
  relationship between any two of the three actor labels, and it is a
  statement of *uncertainty*, not equivalence.
- HC3's silence on both labels is not evidence against either; it
  reflects HC3's own institutional confidence threshold, not an
  independent assessment that the labels are wrong.
- No source claims VITALSCORE and APT-MEDAGENT are *different* actors --
  the disagreement is entirely about naming and evidentiary threshold,
  not about a documented actor-identity conflict.

**Why this matters operationally:** treating "HEALTHBANE," "VITALSCORE"
and "APT-MEDAGENT" as three confirmed distinct campaigns would fragment
detection and response unnecessarily; treating them as one confirmed
actor would overstate what any source has actually established.  The
defensible position, and the one used throughout this project, is:

> **One operational campaign (HEALTHBANE), with LOW-to-MEDIUM confidence
> that it maps to a single actor tracked under two different private
> labels (VITALSCORE, APT-MEDAGENT) by two different parties who have
> not cross-validated their labels against each other.** Attribution to
> a specific named threat-actor group remains UNCONFIRMED per the most
> reliable source (HC3), and no task in this project should present
> VITALSCORE or APT-MEDAGENT as a confirmed actor identity.

The researcher's own recommendation is adopted here: treat VITALSCORE as
a probable alias for the same activity, but do not import Acme's
additional, uncorroborated indicators on the strength of that label
alone -- the label's credibility does not transfer to every indicator
tagged with it (see Task 1's triage, where several VITALSCORE-tagged
Acme indicators were still rated NOISE independent of the label).

---

## 5. Weighting Recommendation

**For confirmed healthcare-sector facts (campaign existence, stage
progression, sector-wide scope):** prioritize **HC3**. It is the only
source with cross-organizational visibility (6+ confirmed orgs, 14+
suspected) and the only one whose reliability grade (A) and credibility
grade (1, for Stage 1-3 claims) are both at the top of the scale
simultaneously. Where HC3 is silent or explicitly conservative (e.g. the
two techniques held back from the OBSERVED table), treat that silence as
"not yet confirmed," not as "does not exist."

**For confirmed facts about the originating incident specifically (what
actually happened to MedDefense):** prioritize **MedDefense's own 4x00
report**. It is the only source with direct, primary evidence of what
occurred inside MedDefense's own environment, including the one real
(non-templated) captured artifact in the entire indicator set.

**For technical/tooling detail (kit internals, infrastructure choices,
detection patterns that survive rotation):** prioritize the **researcher
blog**. Its Stage 1/2 technical claims are credibility-1 (direct
extraction from a live artifact) and it is the only source that offers
behavioral, rotation-resistant detection guidance (the PHPMailer
6.6.0 header string; the compound-keyword domain registration pattern) --
directly useful for this project's later YARA and behavioral-rule tasks.
Its attribution claim (APT-MEDAGENT) should be carried forward labeled
MEDIUM confidence, never silently upgraded to HIGH.

**Source to treat carefully because of noise or weak clustering: the
Acme commercial feed.** Not because it is worthless -- its
highest-confidence, cross-corroborated indicators (16 of 41) are as
usable as HC3's or MedDefense's -- but because a single feed mixes that
tier with a second tier the vendor itself flags as shared
infrastructure ("DO NOT BLOCK"), unreviewed ML clustering ("human review
not performed"), and pre-campaign-window activity of uncertain relevance.
Every Acme indicator must be evaluated on its own `acme_confidence` and
`acme_note`, never on the feed's aggregate reputation or the VITALSCORE
label alone (this is exactly what Task 1's per-indicator triage already
implements).

**How conflicting claims should be handled, as a general rule for the
rest of this project:**

1. **Corroboration outranks confidence labels.** An indicator or claim
   independently reported by two or more sources should be weighted
   above a single source's high-confidence claim, because a confidence
   label is the source's own self-assessment, while corroboration is
   external validation.
2. **Direct observation outranks inference.** MedDefense's own telemetry
   and HC3's partner telemetry (both credibility-1, primary evidence)
   outrank the researcher's fingerprint-based inference and Acme's
   similarity-clustering (both explicitly inferential for their weaker
   claims), even where the inferential source is more specific or
   detailed.
3. **A source's explicit self-flagged uncertainty should never be
   silently dropped when the claim is reused downstream.** Where HC3
   says LOW confidence on attribution, the researcher says MEDIUM
   confidence and explicitly evidentiary-limited, or Acme flags an
   indicator as noise, every later task in this project (Task 1's
   triage, the ATT&CK mapping, the YARA rules) must carry that same
   qualifier forward rather than presenting the claim as settled fact.
4. **When two sources conflict outright** (not observed here for any
   factual claim -- the actual conflicts in this dataset are about
   naming/labeling and about confidence level, not about contradictory
   facts) **the higher reliability-grade source's version is provisionally
   preferred, but the conflict itself is documented rather than
   silently resolved**, consistent with this project's general
   fact/assessment/assumption separation.
