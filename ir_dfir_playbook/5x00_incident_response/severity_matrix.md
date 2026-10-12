MedDefense Severity Matrix
Purpose

Common severity language for all MedDefense incidents. Applied from first alert through closure.

Severity Matrix
Level	Patient Safety Impact	Data Exposure	Service Availability	Max Response Time	Decision Authority
SEV1	high	confirmed_broad	full_outage	15 min	CISO
SEV2	moderate	confirmed_limited	partial_outage	30 min	IR Commander
SEV3	low	suspected	degraded	60 min	SOC Lead
SEV4	none	none	none	240 min	SOC Analyst
Level Definitions
SEV1
Ransomware affecting clinical systems across multiple sites (e.g. Epic and the Main Hospital network segment simultaneously)
Confirmed exfiltration of patient records at scale (approaching or exceeding the ~180,000-record active patient population)
Patient monitoring system or ICU/OR clinical equipment offline during active care
SEV2
Confirmed compromise of a clinical-access account (e.g. an Epic or Active Directory account with access to patient records)
Malware confirmed on a single workstation at a clinical site (e.g. a West Campus workstation on the 10.42.118.0/24 segment)
Suspected exfiltration under investigation, not yet confirmed in scope or volume
SEV3
Phishing email reported and confirmed malicious, but no evidence of credential use or lateral movement
A single non-clinical endpoint flagged by Wazuh EDR or Microsoft Defender for Endpoint, contained before lateral spread
A degraded but still-functioning non-critical service (e.g. slow response from Nexus Patient Scheduling) with no confirmed security cause yet ruled out
SEV4
A failed login or brute-force attempt blocked automatically by existing controls, with no indication of further compromise
A low-risk vulnerability finding from routine scanning with no active exploitation observed
A policy violation (e.g. an unapproved USB device detected) with no data movement or malware indicators
Escalation Rule

Severity is reviewed at every status update. It increases when new evidence raises patient safety, data exposure, or service availability to the next tier. It decreases only after confirmed containment and IR Commander approval.
