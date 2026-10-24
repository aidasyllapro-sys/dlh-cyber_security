# Tabletop Exercise: Nexus Supply Chain Compromise

**Date:** 2026-10-25
**Classification:** Internal - Exercise Use Only
**Facilitator:** Aida Sylla
**Scenario version:** 1.0

## Organization background

MedDefense Health Systems operates three clinical sites (West Campus, Main, North Site) and relies
on Nexus Patient Scheduling for outpatient scheduling, pre-registration, and insurance eligibility
checks across all three, representing approximately 3,500 patient-facing interactions per week.
As a HIPAA Covered Entity, MedDefense is directly responsible for the confidentiality, integrity,
and availability of the electronic Protected Health Information (ePHI) that flows through every
vendor integration it operates, including this one.

## Vendor background

Nexus Patient Scheduling is a cloud-hosted, multi-tenant SaaS platform operated by Nexus Health
Technologies, Inc., in use at MedDefense since August 2023. It accesses patient demographic data,
appointment data, and staff rostering information needed to schedule and confirm visits, but does
not handle clinical charting. The integration with MedDefense's Epic environment runs over HL7
FHIR R4 via HTTPS, authenticated through an OAuth2 client credentials flow with short-lived access
tokens bound to a dedicated service principal. Nexus pushes signed software updates automatically
to an on-premises agent installed on a dedicated scheduling server at each site.

MedDefense's Business Associate Agreement (BAA) with Nexus has been in force since August 2023
and was last amended in May 2025. Under its terms, Nexus must notify MedDefense within 24 hours of
discovering a breach, provide an annual SOC 2 Type II report, and return or destroy all PHI on
contract termination.

## Opening situation

Three days ago, Nexus Health Technologies' build infrastructure was compromised by an unknown
threat actor. A malicious software update, signed with Nexus's legitimate code-signing
certificate, was distributed automatically through the normal update channel. The resulting
backdoor has been running on MedDefense's Nexus agent hosts at all three sites since the update
was deployed.

Forty-five minutes ago, the MedDefense SOC flagged unusual outbound network traffic from the
Main campus scheduling server to an unknown external IP address.

## Known facts at exercise start

- An EDR/SOC alert for unusual outbound traffic from the Main campus scheduling server, flagged
  45 minutes ago.
- Nexus agent host names: `SCHED-SVR-01` (Main), `SCHED-SVR-02` (West Campus), `SCHED-SVR-03`
  (North Site).
- The EDR alert shows the outbound connection recurring at periodic, roughly four-hour intervals.
- Nothing else is confirmed at this point. The scope, duration, and content of any data access or
  modification are unknown at exercise start.

## Organizational ambiguities

- Nexus's update was validly signed with their legitimate certificate. Does a correctly signed
  update from a compromised vendor make future updates from that same vendor more trustworthy
  (because the signing process itself wasn't forged) or less trustworthy (because the compromise
  proves their build pipeline can produce malicious-but-valid updates)? There is no clean answer,
  and it directly affects whether MedDefense can safely continue accepting automatic updates from
  Nexus while the investigation is open.
- Should MedDefense immediately sever the integration with Nexus to contain the suspected
  compromise, even though doing so cuts off real-time scheduling, eligibility checks, and
  appointment confirmations for approximately 3,500 weekly patient interactions across all three
  sites? Containment favors cutting the link now; continuity of care favors keeping it until scope
  is better understood. Neither choice is without real cost.

## Patient safety dimension

Because the compromise window predates its detection by at least three days, appointment records
processed through Nexus during that window cannot yet be assumed accurate. Records may have been
silently modified, including appointment times, cancellations, or wait-list status, with a direct
risk of missed or duplicated patient visits if the records are trusted without verification.

## Regulatory tension

Nexus is a Business Associate under MedDefense's HIPAA obligations. If the compromise is confirmed
to have affected ePHI, Nexus's contractual duty is to notify MedDefense within 24 hours of its own
discovery, but MedDefense's own breach notification clock under HIPAA begins independently, based
on what MedDefense itself knows and when. Acting too early, before the scope of PHI exposure is
understood, risks an inaccurate or premature notification; waiting too long, until Nexus completes
its own investigation, risks missing MedDefense's own regulatory notification obligations.
