# MedDefense Health Systems — Incident classification (CIA Triad)

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** Marcus Webb's "Incident Log, Last 6 Months" (MedDefense onboarding packet) **Purpose:** Classify each recorded incident against the CIA Triad (Confidentiality, Integrity, Availability) to establish a consistent analytical baseline before performing the full security posture assessment.

**Framework used:**

- **Confidentiality**: Information was accessed by someone who should not have seen it.
- **Integrity**: Information or a system was modified without authorization (or corrupted).
- **Availability**: A service, system or data became inaccessible when it was needed.

A pillar can be impacted regardless of whether the cause was malicious (attack) or accidental (misconfiguration, human error, untested procedure). The CIA Triad classifies the _effect_ of the incident, not the intent behind it.

---

## Incident-by-Incident Analysis

### Incident A: Ransomware on billing-srv-01 (January 15)

**Primary pillar: Availability** Justification: The ransomware payload encrypted billing-srv-01, and the finance team was unable to process insurance claims for 4 days. The defining effect was that a required service became inaccessible when needed.

**Secondary pillar: Integrity** Connection: Ransomware encryption is, by definition, an unauthorized modification of the data on the server. The billing data itself was altered (encrypted) without authorization, which is an integrity violation layered on top of the availability loss. The 3-week-old backup (caused by a misconfigured cron job) does not change the classification. It is an aggravating control failure that extended the availability impact, not a third pillar.

---

### Incident B: Patient portal IDOR (February 2)

**Primary pillar: Confidentiality** Justification: A broken access control allowed an authenticated patient to view another patient's lab results by modifying a URL parameter. This is unauthorized disclosure of Protected Health Information (PHI) to someone who should not have had access to it.

**Secondary pillar: None clearly established** Connection: The incident as reported only describes unauthorized _viewing_ of data (an IDOR, Insecure Direct Object Reference, vulnerability). There is no indication in the log that the same flaw allowed data modification or caused any service disruption. This should be flagged as a **Known Unknown**: the underlying vulnerability class (broken access control) is frequently capable of enabling modification as well as disclosure, and this should be verified during the technical assessment rather than assumed absent.

---

### Incident C: Pharmacy dosage data corruption (March 18)

**Primary pillar: Integrity** Justification: A database update script bug overwrote dosage values, causing the pharmacy management system to display incorrect medication dosages across all 3 sites for approximately 6 hours. The data itself was altered and became inaccurate, which is the core definition of an integrity failure.

**Secondary pillar: None clearly established** Connection: The system remained accessible throughout (Availability was not impacted. The system was up, just displaying wrong data), and no unauthorized party accessed information (Confidentiality was not impacted). This incident is a clean, single-pillar example. Note for the broader assessment: although this classifies as an integrity incident rather than a safety incident, the real-world consequence (a pharmacist nearly relying on incorrect dosage data) illustrates why integrity failures in clinical systems carry disproportionate business/patient-safety impact. This should be reflected in the impact rating, not the pillar classification.

---

### Incident D: Public website defacement (April 5)

**Primary pillar: Integrity** Justification: The homepage content was replaced with an unauthorized political message. This is unauthorized modification of a system's content, which is the defining characteristic of an integrity violation.

**Secondary pillar: Availability** Connection: For the roughly 2 hours before restoration from backup, the legitimate website content and its intended function (informing visitors, supporting the patient portal entry point) were effectively unavailable to users, even though the server itself remained technically online. This is a secondary, time-bound availability impact riding on top of the primary integrity breach. Note: because web-srv-01 also hosts the patient portal per the environment summary, this incident is a useful indicator of the DMZ server's exposure, even though this specific event did not touch patient data.

---

### Incident E: EHR outage during database migration (May 22)

**Primary pillar: Availability** Justification: The EHR system was inaccessible for 9 hours during a planned migration that ran over time and could not be rolled back (the rollback procedure had never been tested), forcing physicians to revert to paper records. A critical clinical service was unavailable when needed.

**Secondary pillar: None clearly established** Connection: There is no indication that data was altered improperly (Integrity) or that anyone gained unauthorized access to information (Confidentiality) during this event. This is a clean, single-pillar Availability incident. It is worth noting for the assessment that this was a **planned, internal change**, not an attack. The CIA Triad still applies, since it classifies impact, not cause. The untested rollback procedure is itself a control gap (absence of tested Business Continuity / change-management procedures) that should be tracked separately in the gap analysis.

---

### Incident F: Intern's personal laptop on internal network (June 10)

**Primary pillar: Confidentiality** Justification: An unmanaged, personal device ran on the internal corporate network (not the guest network) for 3 weeks, on the same network segment as the HR file share. This created sustained, unauthorized exposure risk to sensitive HR data (an unmanaged endpoint on a flat network segment containing sensitive data is functionally equivalent to an unauthorized party having potential access to it).

**Secondary pillar: Availability** Connection: The laptop was running a torrent client actively sharing files, which generates sustained upload/download traffic. On a corporate network, this kind of traffic can consume bandwidth and degrade network performance/availability for legitimate business systems sharing the same segment. Note for the assessment: this incident, more than the others, is really a story about a **missing detective control** (3 weeks elapsed before this was found) and the risk created by the lack of network segmentation described in the environment summary (flat network, no VLANs), the same underlying condition that made billing-srv-01 and the medical devices' impact possible in other findings.

---

## Formatted incident classification table

|ID|Date|Incident|Primary Pillar|Primary Justification|Secondary Pillar|Secondary Justification|
|---|---|---|---|---|---|---|
|A|Jan 15|Ransomware encrypted billing-srv-01; claims processing halted 4 days|**Availability**|Billing service was inaccessible for 4 days when finance needed it|**Integrity**|Ransomware encryption is an unauthorized modification of the underlying data|
|B|Feb 2|Patient portal IDOR exposed other patients' lab results|**Confidentiality**|PHI was disclosed to a patient who was not authorized to see it|None established|Only unauthorized viewing is documented; whether the flaw also permits modification is unverified|
|C|Mar 18|Database script bug corrupted displayed medication dosages (~6h, all 3 sites)|**Integrity**|Data was altered/corrupted, producing inaccurate dosage information|None established|System remained available; no unauthorized access occurred|
|D|Apr 5|Central's public website defaced with a political message|**Integrity**|Website content was modified without authorization|**Availability**|Legitimate site content/function was effectively unavailable for ~2 hours until restored|
|E|May 22|EHR system down 9 hours during a mismanaged planned migration|**Availability**|A critical clinical system was inaccessible for 9 hours, forcing a fallback to paper|None established|No data alteration or unauthorized access occurred; impact was purely on access|
|F|Jun 10|Intern's personal laptop ran undetected on internal network (HR segment) for 3 weeks|**Confidentiality**|An unmanaged device had sustained, unauthorized presence on a network segment holding sensitive HR data|**Availability**|Active torrenting traffic can consume bandwidth and degrade network performance for legitimate systems|

---

## Cross-Cutting Observation

4 of the 6 incidents (A, D, E, F) trace back, directly or indirectly, to control gaps already flagged in the Structured Environment Summary: the flat, unsegmented Central network (10.10.0.0/16, no VLANs), the co-located/non-offsite backup design, and the absence of tested continuity procedures. This incident log should not be read as six unrelated events; it is early evidence that a small number of structural weaknesses are producing repeated, varied impacts across the CIA Triad. This pattern should carry directly into the gap analysis and prioritization work later in this project.
