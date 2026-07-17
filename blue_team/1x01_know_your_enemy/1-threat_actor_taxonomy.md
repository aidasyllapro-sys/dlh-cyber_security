# MedDefense Health Systems: Threat Actor Taxonomy - 8-Report Classification Exercise

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** `threat-actor-reports.txt`, 8 anonymized intelligence reports **Purpose:** Practice inferring threat actor type, attributes, and motivation from observed behavior alone; the core analytical skill of threat intelligence, since actor identity is rarely known at the time of investigation.

**Framework applied:** 6 actor categories (nation-state, organized crime, hacktivist, insider threat, unskilled attacker, shadow IT), each assessed on Internal/External, Resources, Sophistication, and Primary Motivation (from the standard motivation list: data exfiltration, espionage, service disruption, blackmail, financial gain, philosophical/political belief, ethical motivation, revenge, chaos, war).

---

```
Report A:
  Actor Type: Nation-state
  Internal/External: External — justified by the use of a remote access
    tool deployed via a VPN zero-day, with no indication of any internal
    account or employee involvement.
  Resources: High — a zero-day VPN exploit and a stolen code-signing
    certificate are both expensive, hard-to-obtain capabilities; these
    are not freely available to a typical criminal actor.
  Sophistication: High — custom-built malware, DNS-based covert
    communication (a technique specifically chosen to evade standard
    network detection), a stolen signing certificate to bypass
    trust-based defenses, and a 14-month dwell time before discovery are
    all hallmarks of a well-resourced, patient operator rather than an
    opportunistic one.
  Primary Motivation: Espionage — the target (proprietary Phase III
    clinical trial data valued at an estimated $2 billion) and the
    method (systematic, sustained copying rather than a single bulk
    exfiltration) both point to long-term intelligence collection rather
    than a smash-and-grab financial crime.
  Confidence Level: Medium — the technical profile matches nation-state
    tradecraft closely, but attribution based on behavior alone is
    inherently uncertain; a well-funded corporate espionage group
    working on behalf of a competitor could theoretically produce a
    similar profile. This is a case where the *category* (a
    highly-resourced, patient, espionage-motivated actor) is more
    defensible than a confident claim of nation-state affiliation
    specifically.
```

```
Report B:
  Actor Type: Organized crime
  Internal/External: External — initiated via a phishing email to the
    billing department, with no internal account compromise implied
    before the initial email.
  Resources: Medium — the tools used (a commercially available RAT, a
    known/patched Adobe Reader vulnerability) were purchased or obtained
    rather than custom-built, consistent with the Ransomware-as-a-Service
    supply-chain model rather than a top-tier custom-tooling operation.
  Sophistication: Medium — no novel exploitation technique was used, but
    the multi-stage operation (phishing → RAT foothold → 3-week dwell →
    data exfiltration → ransomware deployment → timed extortion demand)
    reflects organized, procedural execution well beyond an opportunistic
    single-step attack.
  Primary Motivation: Financial gain — a specific ransom amount (40 BTC,
    ~$1.6M) with a payment deadline and a double-extortion threat is a
    direct, unambiguous financial motive.
  Confidence Level: High — this sequence (phishing → RAT → dwell →
    double-extortion ransomware with a payment deadline) is the
    well-documented, canonical Ransomware-as-a-Service playbook,
    directly matching the pattern described in the CISA and HC3 sources
    reviewed in this project's threat landscape summary.
```

```
Report C:
  Actor Type: Hacktivist
  Internal/External: External — exploitation of a public-facing web
    vulnerability (SQL injection) with no internal access involved.
  Resources: Low — SQL injection against a content management system is
    a common, well-documented technique requiring no special funding or
    custom tooling.
  Sophistication: Low to Medium — some technical skill is required to
    exploit SQL injection successfully, but the attacker made no attempt
    to escalate, move laterally, or access anything beyond the public
    website, suggesting either limited capability or — more likely,
    given the messaging — a deliberately narrow, symbolic objective
    rather than a technical ceiling.
  Primary Motivation: Philosophical/political belief — explicit protest
    messaging tied to a specific policy decision (the clinic closure),
    a named activist group's branding, and a public call to action are
    unambiguous ideological signals, not financial or espionage ones.
  Confidence Level: High — the combination of a political message, a
    named activist affiliation, no data theft, and no attempt to move
    beyond the defaced surface is a very low-ambiguity hacktivist
    signature.
```

```
Report D:
  Actor Type: Insider threat (malicious)
  Internal/External: Internal — the actor is a former employee acting on
    privileged knowledge and access created while still employed (the
    undocumented VPN account was created *before* termination); the
    technical connection occurring after termination does not change
    that the access and the intent originate from an insider.
  Resources: Low — no specialized tooling was used; the actor relied
    entirely on legitimate administrative knowledge and a
    self-created backdoor account.
  Sophistication: Low to Medium — the technical actions themselves
    (dropping database tables, disabling a backup job) are simple, but
    the premeditation is notable: creating an untracked VPN account and
    disabling the backup job three days *before* termination shows
    deliberate planning specifically intended to maximize damage and
    prevent recovery, which is a meaningfully more calculated profile
    than a purely impulsive act.
  Primary Motivation: Revenge — the timing (two days after a disciplinary
    termination), the target (the specific system the administrator
    managed), and the deliberate disabling of backups beforehand all
    point to retaliation rather than financial gain (no ransom or data
    sale was involved) or any other motive.
  Confidence Level: High — the circumstantial and technical evidence
    (an unlinked backdoor account created pre-termination, access from
    the administrator's home IP at 2:30 AM, and a backup deliberately
    disabled three days prior) converge on this specific individual with
    very little ambiguity.
```

```
Report E:
  Actor Type: Unskilled attacker
  Internal/External: External — automated exploitation of an
    internet-facing vulnerability with no internal involvement.
  Resources: Low — a publicly available cryptomining tool and a known,
    already-patchable CVE (published 6 months prior) require no
    meaningful investment to use.
  Sophistication: Low — no lateral movement, no persistence mechanism
    beyond the miner itself, and no attempt at data access; this is
    consistent with a mass, automated exploitation campaign rather than
    a deliberate operation against this specific clinic.
  Primary Motivation: Financial gain — cryptocurrency mining converts
    compromised compute resources directly into money for the attacker,
    though at a low, opportunistic scale rather than a high-value theft.
  Confidence Level: High — the attacker's wallet address being linked to
    300+ unrelated victim organizations worldwide is strong, near-
    definitive evidence of automated mass exploitation rather than any
    targeting of this clinic specifically.
```

```
Report F:
  Actor Type: Shadow IT (as the enabling/primary actor of interest), with
    a secondary Unskilled attacker (external) who exploited the
    resulting exposure
  Internal/External: Internal for the Shadow IT element — a biomedical
    engineering employee introduced an unauthorized personal device onto
    the medical device network. The subsequent compromise itself was
    carried out by an external party who found the device via an
    inadvertently exposed internet-facing port.
  Resources: Low — a consumer-grade Raspberry Pi and default,
    unchanged vendor credentials (pi/raspberry) involve no investment or
    special access on either the employee's or the external attacker's
    part.
  Sophistication: Low — the employee's action required no malicious
    technical skill at all (a personal monitoring project, not an
    attack), and the external compromise relied entirely on well-known
    default credentials rather than any custom exploitation.
  Primary Motivation: This report is the clearest illustration in this
    set of why Shadow IT is classified as its own actor category
    distinct from the other five: the internal party had **no malicious
    intent whatsoever** — the report explicitly states this — so no
    entry from the standard motivation list applies to them; their
    "motivation" was operational convenience for a personal project. The
    subsequent external attacker's motivation is less clear from the
    report (likely opportunistic access/reconnaissance rather than a
    stated financial or disruptive goal, given no further action beyond
    the pivot is described).
  Confidence Level: High — the report explicitly confirms the employee
    acted without malicious intent and traces the technical chain (Pi →
    default credentials → pivot to nurse call system) without ambiguity.
```

```
Report G: [DELIBERATELY AMBIGUOUS — the evidence in this report does
  not actually distinguish between the two leading hypotheses (see
  below); a single primary label is still given, with an explicit
  tiebreak criterion rather than a false claim of discriminating
  evidence]
  Actor Type: Insider Threat (Malicious) — primary classification, but
    on a narrow basis. The absence of malware, an exploited
    vulnerability, or a phishing lure does NOT, by itself, favor an
    insider over an external actor — a purchased or stolen credential
    would produce an identical absence of technical artifacts, since
    the access itself would still be genuine. The actual tiebreak used
    here is the documented sector base rate: insiders account for
    approximately 35% of healthcare breaches (this project's Task 0
    intelligence dossier, Verizon DBIR healthcare supplement), a
    quantifiable prior that marginally favors this label in the
    absence of any case-specific evidence pointing either way — not a
    claim that the report's details themselves discriminate between
    the two.
  Internal/External: Internal — follows directly from the Actor Type
    tiebreak above, on the same basis and with the same limitation:
    this is a probabilistic lean, not a conclusion the case evidence
    itself supports over the external alternative.
  Resources: Low to Medium — the operation required only a working set
    of valid credentials, not custom tooling or a zero-day; this
    attribute is identical under either hypothesis and does not help
    distinguish them.
  Sophistication: Medium — the consistent off-hours access pattern from
    a single IP address, sustained over 6 weeks, and the selective
    targeting of high-value-insurance patients rather than bulk/random
    records, both suggest deliberate, disciplined operational behavior
    rather than a low-skill or automated actor — true under either
    hypothesis.
  Primary Motivation: Financial gain — the concentration on
    high-value-insurance-plan patients (valuable for identity theft
    and insurance fraud, per this project's threat landscape summary)
    points toward financial motive over espionage, disruption, or
    ideology, even though no ransom demand was made and no dark-web
    listing has appeared yet.
  Confidence Level: Low — this is a forced single-choice classification
    made explicitly on a statistical tiebreak, not on case-specific
    discriminating evidence, and should be read accordingly. The full
    alternate hypothesis, and the specific evidence that would actually
    resolve this case one way or the other, follows immediately below.
```

### Why this classification is a tiebreak, not a conclusion, and what would actually resolve it

Report G is constructed so that 2 very different actor types produce **exactly the same observable evidence**, and no detail in the report itself breaks that symmetry. This is worth stating plainly rather than papering over with a confident-sounding label:

**Candidate 1: Insider threat (malicious), by someone other than the absent physician.** The access used a _legitimate_ physician account rather than any sign of external intrusion (no exploited vulnerability, no malware, no phishing lure is described). Someone with the ability to access or reuse that physician's credentials (a colleague, a member of IT/helpdesk staff, or anyone who knew or had access to that login) could be exploiting a legitimate account that nobody thought to monitor precisely because the credential itself is genuine and privileged. Healthcare's structurally broad clinical access (documented in this project's threat landscape summary as a core insider-threat enabler) makes this entirely plausible.

**Candidate 2: Organized crime (external), using stolen or purchased valid credentials.** The threat landscape summary produced earlier in this project notes that "valid credentials (purchased or harvested)" account for a meaningful share of healthcare initial access, and that Initial Access Brokers specifically sell working credentials as a commodity. An external actor who purchased or phished this physician's credentials, entirely unrelated to the physician's medical leave, would produce an identical access pattern: legitimate login, no malware, no exploited vulnerability, curated rather than bulk data selection (consistent with a buyer targeting specifically resalable, high-value records).

**What the report does _not_ tell us, and what would resolve the ambiguity:**

- **The source IP address's nature.** If the consistent IP resolves to a residential or business address plausibly linked to a specific individual known to the organization (a colleague, a contractor), that favors the insider explanation. If it resolves to a VPN exit node, a Tor node, or an address geolocated somewhere inconsistent with any known employee, that favors the external-credential-theft explanation.
- **How the physician's credentials could have been obtained.** Evidence of a prior phishing email sent to that physician, or of that physician's credentials appearing in a known breach dump or dark-web credential marketplace, would point strongly toward external compromise. Conversely, evidence that the physician's password was weak, reused, shared, or written down somewhere accessible internally would point toward an insider with direct or indirect access to it.
- **Whether MFA was enabled on this account.** If multi-factor authentication was active and not bypassed, that would argue against a purely remote credential-theft scenario (since the attacker would have needed the second factor too) and shift weight toward an insider with broader access to the physician's devices or accounts.
- **Correlation with other insider indicators.** A check of whether any other current employee has a documented connection to high-value-insurance patients (e.g., a relative, a prior interaction, a known financial motive) would support the insider hypothesis; the complete absence of any such connection would weaken it.

Without this additional evidence, both actor types remain consistent with everything stated in the report, which is precisely the point of using this scenario as a training exercise: **real intelligence analysis frequently reaches this exact point, a plausible, narrowed set of hypotheses rather than a single certain answer**, and knowing which specific piece of missing evidence would break the tie is as important a skill as the classification itself.

```
Report H:
  Actor Type: Organized crime (most likely an independent or small-scale
    criminal actor rather than a large RaaS syndicate — see note below)
  Internal/External: External — access via a Tor exit node against a
    public-facing API, with no internal involvement indicated.
  Resources: Medium — Tor usage reflects basic but deliberate operational
    security; more significantly, the actor identified and exploited a
    genuine broken-authentication logic flaw rather than relying on a
    known CVE or an automated scanner, which requires real vulnerability
    research capability.
  Sophistication: Medium — finding and exploiting an authentication logic
    flaw (rather than a published, patchable vulnerability) demonstrates
    a level of technical understanding above an opportunistic or
    automated actor, though the overall operation (a single extortion
    email with a proof sample) is far simpler than the multi-stage
    ransomware operation seen in Report B.
  Primary Motivation: Blackmail — the actor explicitly demands payment in
    exchange for not publishing both the vulnerability details and the
    extracted patient records, which is extortion by definition rather
    than a ransom-for-decryption or data-resale model.
  Confidence Level: Medium — the financial/extortion motive and the
    genuine technical capability are clear, but there is not enough
    evidence in the report to confidently distinguish a lone,
    unaffiliated cybercriminal from a small organized group; unlike
    Report B, there are no supply-chain indicators (no RAT purchased
    from a known toolkit, no ransomware payload, no evidence of an
    Initial Access Broker or affiliate structure) that would confirm
    this actor operates within a larger organized criminal ecosystem.
```

---

## Summary Table

| Report | Actor Type                                           | Internal/External                             | Resources  | Sophistication | Motivation                                  | Confidence |
| ------ | ---------------------------------------------------- | --------------------------------------------- | ---------- | -------------- | ------------------------------------------- | ---------- |
| A      | Nation-state                                         | External                                      | High       | High           | Espionage                                   | Medium     |
| B      | Organized crime                                      | External                                      | Medium     | Medium         | Financial gain                              | High       |
| C      | Hacktivist                                           | External                                      | Low        | Low–Medium     | Philosophical/political                     | High       |
| D      | Insider threat (malicious)                           | Internal                                      | Low        | Low–Medium     | Revenge                                     | High       |
| E      | Unskilled attacker                                   | External                                      | Low        | Low            | Financial gain                              | High       |
| F      | Shadow IT + Unskilled attacker                       | Internal (enabling) / External (exploitation) | Low        | Low            | None (Shadow IT) / opportunistic (external) | High       |
| G      | Insider threat **or** Organized crime - undetermined | Could be either                               | Low–Medium | Medium         | Financial gain                              | **Low**    |
| H      | Organized crime (independent actor)                  | External                                      | Medium     | Medium         | Blackmail                                   | Medium     |

**Observation across all 8 reports:** the 2 reports with the lowest confidence (A and H) are precisely the 2 where behavioral evidence is technically strong but attribution-specific evidence (named group affiliation, infrastructure overlap with known campaigns) is absent. A realistic reminder that sophistication and confidence are independent axes: knowing _how good_ an actor is does not automatically tell you _who_ they are.
