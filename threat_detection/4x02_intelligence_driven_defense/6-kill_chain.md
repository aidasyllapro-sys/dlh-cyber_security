6 - Kill Chain Reconstruction
===============================

MedDefense Health Systems -- Intelligence-Driven Defense (4x02)
Task 6: reconstructing the full HEALTHBANE campaign across its three
observed attack phases, using all four sources together, with every
claim traced back to the specific source and evidence that supports it.

No single source in this dataset describes the whole campaign end to
end. HC3 has the only cross-organizational view but summarizes technical
detail; the researcher has deep technical detail on Stage 1 and the
infrastructure bridge into Stage 2/3 but no victim telemetry; MedDefense
has ground-truth telemetry but only for Stage 1, at one organization; the
commercial feed has volume but does not label phases explicitly. This
document reconciles the four into one timeline and phase-by-phase
account, marking every claim as confirmed, corroborated, or inferred.

---

## 1. Campaign Timeline

| Date / window | Event | Source(s) | Evidence quality |
|---|---|---|---|
| 2026-04-05 to 2026-04-10 | Phishing-lookalike domains registered (Namecheap). HC3 states the broader range 04-05 to 04-10 across all 6 visible orgs; MedDefense's own three domains registered specifically on 04-08, 04-09 and 04-10. | HC3 (Sec. 2, Stage 1); MedDefense (F2) | Confirmed (WHOIS registration dates, corroborated by two independent sources) |
| 2026-04-14 | **Earliest known campaign activity**: first phishing email observed at an HC3 partner organization in the Midwest ISAC region; same date MedDefense's own 8-email cluster begins. | HC3 (Sec. 1.2); MedDefense (Scope) | Confirmed, corroborated by two independent sources on the same date |
| 2026-04-14 15:02:33 UTC | **MedDefense Stage 1 event**: Diane Marsh (WS-NURSE-04) clicks the link in Email 2; credential submission assessed at 15:02:58 UTC (47-second HTTPS session, no concurrent file-download event). | MedDefense (Scope; F5) | Confirmed click (SIEM connection log); credential submission LIKELY, not packet-confirmed as of the 4x00 report's close |
| 2026-04-14 to 2026-04-16 | **HC3 Stage 1 reporting window**: credential harvesting observed at all 6 HC3-visible organizations (100%). | HC3 (Sec. 2, Stage 1) | Confirmed at HC3's stated confidence (direct partner telemetry) |
| 2026-04-16 to 2026-04-22 | **Stage 2 malware-delivery window**: stolen Stage 1 credentials used to send follow-up emails carrying a macro document, observed at 2 of the 6 HC3-visible organizations (33%). | HC3 (Sec. 2, Stage 2) | Confirmed at HC3's stated confidence (sandbox analysis + 2 organizations) |
| 2026-04-18 | Researcher recovers the live phishing kit via a misconfigured directory listing at `meddefense-portal.com`; notes the kit "was still live... but was taken down around 2026-04-22." | Researcher (Sec. 1) | Confirmed by direct extraction (primary evidence), single source |
| 2026-04-22 | Researcher notifies HC3 of the kit contents and indicators; HC3 requests a 72-hour publication delay. Kit taken offline around this date. | Researcher (Sec. 8) | Confirmed (researcher's own disclosure account) |
| 2026-04-23 to 2026-04-26 | **Stage 3 data-exfiltration window**: DNS TXT-record tunneling observed at the same 2 of 6 organizations that reached Stage 2. | HC3 (Sec. 2, Stage 3) | Confirmed at HC3's stated confidence (packet captures from 2 compromised organizations) |
| 2026-04-24 14:22 UTC | Researcher publishes blog post (deliberately delayed from an earlier possible date, per the HC3 coordination above). | Researcher (header) | Confirmed |
| 2026-04-25 | HC3 publishes the sector advisory, TLP:CLEAR. | HC3 (header) | Confirmed |
| 2026-04-26 08:14 UTC | **Most recent reported event in this dataset**: Acme commercial feed extract date; `last_seen` timestamps on the feed's highest-confidence indicators also cluster on 04-26. | Commercial feed (`_metadata`) | Confirmed as the feed's own extract time; does not itself confirm campaign activity that late (see caveat below) |

**Caveat on the "most recent event":** one commercial-feed IP
(`13.107.42.14`) carries a `first_seen` of 2022-01-01 -- four years before
the campaign. This is the same IP Task 1 already rated NOISE (Acme's own
note: "This is a Microsoft Outlook.com cloud IP. Clustering model
noise."). It is excluded from this timeline because it reflects shared
Microsoft cloud infrastructure being present in Acme's dataset since
2022, not HEALTHBANE activity; including it would misrepresent the
campaign's actual start date.

---

## 2. Attack Phases

### Stage 1: Credential Harvesting

| Attribute | Reconstruction |
|---|---|
| **Phishing operation** | Spear-phishing emails impersonating healthcare-adjacent senders (staff portal, insurance, HR benefits) sent from newly registered lookalike domains. Landing pages were a PHPMailer-served HTML credential form. Confirmed at all 6 HC3-visible organizations (100%) and independently confirmed at MedDefense (3 of 8 flagged emails: E2, E5, E7). |
| **Targeting pattern** | Compound healthcare-themed domain names (`meddefense-*`, `medequip-*`, `*-benefits`, `*-portal`) targeting hospital systems, outpatient clinics, medical billing services and regional insurance administrators (HC3 Sec. 1.4); medical device manufacturers, pharmacies and public health departments were not observed as targets. At MedDefense specifically, three individuals across three different functions were targeted: a nurse (clinical), an accounts-payable employee, and a billing employee (MedDefense F4) -- consistent with the operator casting across departments rather than targeting one role. |
| **Infrastructure used** | Lookalike domains registered at Namecheap 4-10 days before first email use, hosted on a mix of Hostinger, DigitalOcean and OVH (researcher Sec. 3; HC3 Sec. 1.5). The researcher's direct kit extraction additionally identifies the mailer as PHPMailer 6.6.0 (config.php `MAILER_VERSION`), matching MedDefense's own header analysis (F1: "share a PHPMailer 6.6.0 X-Mailer header") -- this specific version string is corroborated by two independent methods (kit extraction vs. header forensics) and is the single highest-fidelity Stage 1 signature in the dataset. |
| **Known victims** | HC3: 6 organizations with confirmed Stage 1 activity, out of at least 14 targeted overall (Sec. 1, Sec. 2). MedDefense: 3 named individuals received phishing (dmarsh, arivera, lpatterson), 1 confirmed click (dmarsh). |
| **MedDefense evidence** | Direct: header analysis of all 8 flagged emails, authentication verification (SPF hard-fail/soft-fail, DKIM absent, DMARC fail on the three campaign emails), WHOIS/passive DNS on the domains, and a SIEM connection log showing the 47-second HTTPS session for the confirmed click. One variant technique was identified locally: Email E3 used a *fully-authenticated* lookalike domain (`outlook-protection.com`, correctly configured SPF/DKIM/DMARC for itself) -- MedDefense's own finding F3 calls this "a higher-sophistication variant," since authentication checks pass even though the domain is impersonating Microsoft visually. |
| **Success rate across reported victims** | At MedDefense: 1 of 3 targeted individuals clicked (33%), and that individual's credential submission is LIKELY but not packet-confirmed. Sector-wide, HC3 does not publish a click/submission rate, only that Stage 1 was *observed* (i.e., emails delivered and, implicitly, landing-page activity logged by the attacker's own infrastructure) at all 6 visible organizations -- this is not the same measurement as MedDefense's per-recipient click rate, so the two numbers should not be averaged together. No source publishes a sector-wide success rate. |

### Stage 2: Malware Delivery

| Attribute | Reconstruction |
|---|---|
| **Transition from stolen credentials to follow-up emails** | HC3 states Stage 1 credentials were used to authenticate to the victim's own cloud email account, from which the attacker sent follow-up emails to the victim's colleagues (Sec. 2, Stage 2) -- i.e., the follow-on email is sent *from a real, trusted internal address*, not from attacker infrastructure. This is a materially more dangerous delivery method than Stage 1's external lookalike-domain email, and it explains why Stage 2 was only observed at 2 of 6 organizations (33%): it requires the Stage 1 compromise to have actually succeeded, not merely been attempted. MedDefense's own 4x00 investigation closed before this transition was observed locally (its own EDR scan on 2026-04-16 found no matching Stage 2 hash, and F6 notes no post-compromise authentication event in the dmarsh account within the 4x00 window) -- MedDefense's own case had not reached Stage 2 as of that report's close. |
| **Document type** | A macro-enabled Word document, `HEALTHBANE_S2_invoice.docm` (HC3 Sec. 2, Stage 2) -- an invoice-themed lure, consistent with the `medequip-supplies.net` domain's invoice-payment URL pattern already documented in Task 0/1. |
| **Malware or script artifacts** | The macro downloads a Windows executable, `svchost_update.exe` (named to blend in with the legitimate Windows service host process), from a secondary C2 domain. The commercial feed independently lists the exact URL `https://healthbane-c2.net/update/svchost_update.exe` at `acme_confidence` 90, tagged `malware-download` -- corroborating HC3's narrative with a specific, matching artifact path. |
| **Download infrastructure** | `healthbane-c2.net`, tagged `c2` at `acme_confidence` 94 in the commercial feed, and independently identified by the researcher's kit extraction: `config.php` contains `OPS_CONTACT = "ops@healthbane-c2.net"` and `EXFIL_ENDPOINT = "https://healthbane-c2.net/api/ingest"` (researcher Sec. 2). This is the single most important corroborating detail in the whole dataset: the researcher found this domain *inside the Stage 1 kit's own configuration*, which is direct evidence that the Stage 1 harvesting infrastructure and the Stage 2/3 C2 infrastructure are operated by the same party -- not merely coincidentally reported together by different sources. |
| **Persistence mechanisms** | A scheduled task named "HealthSync Update Service" and a Registry Run key (HC3 Sec. 2, Stage 2). Both are named to sound like a legitimate healthcare-IT service, consistent with the operator's general pattern of healthcare-themed disguise seen at every other stage. |
| **Evidence source** | Primarily HC3 (sandbox analysis plus telemetry from the 2 affected organizations) for the malware behavior and persistence mechanism; the commercial feed corroborates the specific download URL and C2 domain independently; the researcher corroborates the C2 domain via a completely different method (static kit-config extraction, no victim telemetry involved). No source in this dataset provides a file hash for `svchost_update.exe` itself -- the commercial feed's hash-type indicators are tagged `trojan`/`persistence`/`dropper-variant`/`powershell` generically, and none of their values are stated to be this specific binary, so the executable's own hash remains an evidence gap (see Section 4). |

### Stage 3: Data Exfiltration

| Attribute | Reconstruction |
|---|---|
| **Data targeted** | Patient records and insurance claims data (HC3 Sec. 2, Stage 3). No source specifies record volume, specific data fields, or whether PHI/PII was confirmed present in what was exfiltrated versus merely accessible. |
| **Protocol or tool used** | DNS TXT-record tunneling: data encoded in base32 subdomain labels queried against `data-sync.healthbane-c2.net`, with C2 responses returned as base64-encoded command strings in TXT records (HC3 Sec. 2, Stage 3). Observed query interval 10-15 seconds; observed label length 44-60 characters -- these two figures are the most specific, directly-measured technical detail HC3 publishes for any stage, consistent with packet-capture-derived evidence rather than log inference. |
| **Exfiltration infrastructure** | `data-sync.healthbane-c2.net`, the subdomain of the same `healthbane-c2.net` root identified in Stage 2 -- corroborated in the commercial feed at `acme_confidence` 94, tagged `c2`/`dns-tunneling`. |
| **Evidence source** | HC3 exclusively, from "packet captures from 2 compromised orgs" (Sec. 6, Sourcing and Confidence). This is the one stage where no other source in this dataset offers independent corroboration: the researcher's kit access ended at the config-file / Stage 1-2 bridge and did not include DNS-tunneling behavior; MedDefense's own investigation never reached this stage locally; the commercial feed's `dns-tunneling`/`dns-tunnel` tags on `data-sync.healthbane-c2.net` and `51.38.42.191` describe the *domain/IP*, not independent observation of tunneling behavior, so they corroborate infrastructure identity but not the exfiltration mechanism itself. |
| **What is confirmed vs. unclear** | Confirmed (HC3, direct packet evidence, at 2 organizations only): the tunneling protocol, the domain, the query interval and label-length parameters. Unclear: whether the same mechanism was used at any of the other 4 HC3-visible organizations that reached Stage 1 but not Stage 2/3 (HC3 states Stage 3 was only *observed* at 2 of 6 -- this does not establish that the other 4 avoided exfiltration, only that HC3 lacks evidence either way); total volume or specific record types exfiltrated; whether exfiltration occurred at organizations outside HC3's direct or partner visibility (i.e., among the 8+ targeted organizations HC3 has no visibility on at all). |

---

## 3. Evidence Quality Assessment by Phase

Using this project's confirmed / corroborated / inferred distinction
(Task 2's Admiralty Code credibility scale underlies this): confirmed =
credibility 1, direct primary evidence; corroborated = credibility 1-2,
independently reported by two or more sources via different methods;
inferred = credibility 3-4, a reasonable conclusion drawn from indirect
or single-source evidence.

| Phase | Confirmed evidence | Corroborated evidence | Inferred evidence | Unknowns |
|---|---|---|---|---|
| **Stage 1** | MedDefense: the click, SPF/DKIM/DMARC results, domain registration dates (all direct telemetry/WHOIS). HC3: Stage 1 observed at 6/6 visible orgs (direct partner telemetry). | PHPMailer 6.6.0 signature (MedDefense header analysis + researcher's independent config.php extraction -- two different methods, same finding). Domain/IP infrastructure (MedDefense's 3 domains + 3 IPs match the researcher's independently-derived infrastructure list and the commercial feed's high-confidence entries). | Credential *submission* by dmarsh (LIKELY per MedDefense F5, based on session duration and self-report, but explicitly not packet-confirmed). Sector-wide click/submission rate (no source measures this; only per-organization "activity observed"). | Whether the other 5 named MedDefense recipients existed sector-wide (i.e. click/non-click outcomes at the other 5 HC3-visible organizations); true total number of individuals targeted across all 14+ organizations. |
| **Stage 2** | The macro-document mechanism and executable name, from HC3's sandbox analysis (direct analysis of a captured sample, at HC3's stated HIGH confidence). | The C2 domain `healthbane-c2.net` and download URL, corroborated across HC3 (sandbox+telemetry), the commercial feed (independent confidence-90 entry), and the researcher (independent static kit-config extraction) -- three different methods agreeing. | That the follow-up email is sent from the victim's own compromised account specifically because Stage 1 succeeded there (HC3's narrative logic; not separately evidenced by a captured example of one such email in this dataset). | The file hash of `svchost_update.exe` itself (not published by any source); whether the executable is unique per victim or reused identically across all Stage-2 organizations; why only 2 of 6 progressed from Stage 1 to Stage 2 (attacker selection criteria vs. Stage-1 failure at the other 4 is not established). |
| **Stage 3** | The DNS-tunneling mechanism, query interval and label-length parameters -- direct packet-capture evidence per HC3, at HC3's stated HIGH confidence, but from only 2 organizations. | Infrastructure identity only (`data-sync.healthbane-c2.net` tagged consistently across HC3 and the commercial feed) -- the mechanism itself is not independently corroborated by a second source. | That the same 2 organizations are the same 2 that reached Stage 2 (HC3's narrative presents them as the same set but does not name the organizations, so this is a reasonable but not independently verifiable inference from the text). | Actual data volume/type exfiltrated; whether Stage 3 occurred at any organization outside HC3's visibility; total campaign impact. |

---

## 4. What Is Not Known

**Attribution gaps.** As documented in Task 2: HC3 rates attribution LOW
confidence with no named actor; the researcher's APT-MEDAGENT label is
MEDIUM confidence and explicitly based only on tooling/infrastructure
fingerprint, not telemetry; the commercial feed's VITALSCORE label is
automated and the researcher himself states he has "no visibility into
whether Acme's VITALSCORE corresponds 1:1" with his own tracking. None of
the four sources can currently answer *who* is running this campaign with
more than MEDIUM confidence, and that MEDIUM-confidence claim rests on
infrastructure/tooling overlap with three prior campaigns (RXBRIDGE 2024,
CLAIMBRIDGE 2024, MEDNEXUS 2025) that this dataset does not itself
include for independent review.

**Missing victim telemetry.** Of at least 14 targeted organizations, HC3
has direct or partner visibility on only 6 -- meaning the majority of
targets have no telemetry represented anywhere in this dataset at all.
Within the 6 visible organizations, only 2 progressed to Stage 2/3 with
analyzed evidence; whether the remaining 4 were successfully contained
at Stage 1, quietly progressed further without being caught, or were
never actually vulnerable, is not established by any source. MedDefense's
own case is the only one with named-individual detail, and even there,
Stage 2/3 local telemetry was explicitly out of scope for the 4x00 report
(deferred to 4x01) and not available in the materials for this task.

**Incomplete Stage 3 visibility.** The DNS-tunneling mechanism is
evidenced at exactly 2 organizations, from HC3 alone. No source publishes
what was actually exfiltrated (record counts, specific fields, whether
regulated PHI was confirmed extracted versus only accessible), which
matters directly for MedDefense's own breach-notification obligations
even though MedDefense's own case had not been confirmed to reach this
stage as of the 4x00 report.

**Commercial-feed uncertainty.** As established in Tasks 1 and 2, 16 of
the Acme feed's 41 indicators carry confidence below 60, and several are
explicitly self-flagged as shared infrastructure or unreviewed
ML-clustering output. The feed also references two related Acme reports
by ID (`ACME-HEALTH-2026-0301`, `ACME-FINSECTOR-2026-0402`) that are not
included in the materials for this project -- meaning Acme's own claimed
context for this campaign (an earlier related report, and a cross-sector
report suggesting the operator may also target financial-sector
organizations) cannot be verified or incorporated here. Similarly, HC3
references a related advisory by ID (`HC3-2026-BROKER-003`, "partial
infrastructure overlap") that is likewise not available for review.

**What collection would fill the gaps:**

1. **Endpoint/EDR data from the 2 Stage-2/3 organizations** (or, failing
   direct access, a more detailed HC3 follow-up advisory) to obtain the
   `svchost_update.exe` hash and confirm whether it is identical across
   both organizations -- this would resolve the Stage 2 tooling-reuse
   question and give a directly actionable file-hash indicator, which
   this dataset currently lacks for the actual second-stage payload.
2. **Passive DNS / netflow on `data-sync.healthbane-c2.net`** across a
   longer window and a broader victim set than HC3's 2 confirmed
   organizations, to establish whether Stage 3 activity is present but
   undetected elsewhere among the 6 visible (or 14+ total) targeted
   organizations.
3. **The two referenced-but-unavailable reports** (`ACME-HEALTH-2026-0301`,
   `HC3-2026-BROKER-003`) and the Acme cross-sector reference
   (`ACME-FINSECTOR-2026-0402`), to determine whether this is a new
   campaign or a continuation, and whether targeting extends beyond the
   healthcare sector.
4. **A confirmed sample of a Stage-2 follow-up email** (sent from a
   compromised internal account) to verify HC3's stated delivery
   mechanism directly, rather than relying on HC3's narrative summary of
   sandbox/telemetry analysis MedDefense's own report was never able to
   observe.
5. **Coordinated victim outreach at the 8+ organizations HC3 has no
   visibility on**, through the HC3 reporting channel described in the
   advisory's own Section 7, to close the largest single visibility gap
   in this dataset -- the majority of known targets have no
   representation in any source reviewed here.
