# MedDefense Health Systems: Certificate Lifecycle Management

**Prepared by:** Aïda Sylla, Security Analyst **Source material:** Cross-referenced against the Certificate Anatomy and Chain of Trust work (Tasks 8, 9), the CSR Workshop (Task 10), the TLS Audit (Task 11), Finding 013 (1x02), and the Crypto Posture Audit (Task 15) **Purpose:** The patient portal certificate is a symptom, not the disease. The disease is that MedDefense has no certificate inventory, no expiration monitoring, no renewal process, and no policy on certificate types. This document builds the program that prevents this specific emergency from ever recurring.

---

## Part 1: Certificate Inventory

**A note on the expiration dates below, stated honestly:** MedDefense has no existing certificate inventory to query directly, which is the exact gap this task exists to close; every date below is an estimate reasoned from established facts in this program's prior work, not a live system check, and each entry notes its basis explicitly.

```
Certificate: Patient Portal (web-srv-01)
Current Issuer: Let's Encrypt
Expiration: Estimated based on Finding 013 (1x02), which recorded 18
  days remaining at that assessment's own point in this program's
  timeline; if the CSR built and verified in this project's own Task 10
  has since been submitted and issued, this certificate is now on a
  fresh 90-day cycle from that issuance date. Flagged as the single
  highest-priority entry in this inventory to verify first, given its
  documented history.
Responsible Owner: Sarah Park, IT Director (execution), per the RACI
  structure this program's own Task 4 (1x03) already established
```

```
Certificate: EHR internal TLS (ehr-srv-01 to ehr-db-01, and any
  internal client connections)
Current Issuer: Unconfirmed; likely self-signed or entirely absent,
  given this project's own Crypto Inventory (Task 0) found PostgreSQL's
  ssl=on setting present but inconsistently enforced, with no confirmed
  certificate management process behind it at all
Expiration: Unknown; this is itself a finding, not merely a missing
  data point, since a certificate MedDefense cannot date is a
  certificate MedDefense is not managing
Responsible Owner: Sarah Park, IT Director
```

```
Certificate: Active Directory / LDAPS (ad-dc-01, ad-dc-02)
Current Issuer: Unconfirmed; likely absent, directly consistent with
  this project's own Task 15 finding (CRYPTO-011) that LDAP is not
  encrypted by default and LDAP signing is not enforced
Expiration: N/A currently, since no certificate appears to be deployed
  for this purpose; this entry exists in the inventory specifically to
  track the certificate this program's own Task 15 recommendation
  requires provisioning, not one that already exists
Responsible Owner: Sarah Park, IT Director
```

```
Certificate: Site-to-Site VPN (FortiGate, Central-Westside and
  Central-HQ tunnels)
Current Issuer: Unconfirmed whether certificate-based authentication is
  in use at all; this project's own Task 4 demonstrated directly that
  plain Diffie-Hellman without certificate authentication is vulnerable
  to exactly the man-in-the-middle risk already flagged for the
  Westside tunnel specifically (Finding 014, 1x02; RISK-010, 1x03)
Expiration: N/A pending confirmation of whether certificates are
  currently used for tunnel authentication at all
Responsible Owner: Sarah Park, IT Director, coordinated with the
  Westside firewall replacement already funded in this program's own
  budget (1x03, Task 8, Control 6)
```

```
Certificate: Email signing / S/MIME (per-user certificates for
  physicians and staff handling patient data)
Current Issuer: None currently deployed, directly consistent with this
  project's own Task 0 and Task 15 findings that S/MIME and Office
  Message Encryption are not configured
Expiration: N/A, not yet provisioned; this entry tracks the certificate
  population this program's own Task 15 recommendation (CRYPTO-016)
  requires issuing, not an existing deployment
Responsible Owner: Sarah Park, IT Director, for provisioning; individual
  physicians and staff as end users once issued
```

```
Certificate: NAS-01 DSM Management Interface
Current Issuer: Unconfirmed; likely self-signed or the Synology default,
  given Finding 015 (1x02) already confirmed this interface is broadly
  reachable with no other hardening applied
Expiration: Unknown
Responsible Owner: Sarah Park, IT Director
```

```
Certificate: Code signing
Current Issuer: Not applicable
Expiration: Not applicable
Responsible Owner: Not applicable
Note: This entry is included specifically to confirm its absence is
  correct, not overlooked. This project's own prior work (1x03, Task 2,
  CIS Control 16) already established MedDefense has no internally
  developed software in its asset inventory; a code-signing certificate
  would have no legitimate use case until that changes.
```

---

## Part 2: Auto-Renewal Strategy

**Recommendation: ACME via Let's Encrypt for the patient portal specifically, not a commercial CA.** This is not a new decision invented for this task; it is the same recommendation this project already made and built directly in Task 8 and Task 10, restated here with the justification this task specifically asks for.

**Justification, considering 800 daily patients and clinical impact directly.** A commercial CA's 1-year certificate initially looks like the safer choice for a clinical system, fewer renewal events per year seems like fewer opportunities to fail. This reasoning is backwards for MedDefense's actual documented history: Finding 013 (1x02) shows the portal's certificate reached 18 days from expiration specifically because the previous, presumably longer-lived certificate was managed manually with no automated renewal at all. A 1-year commercial certificate does not fix a broken manual process, it only makes the next failure occur once a year instead of every 90 days, with no guarantee the same operational gap that caused Finding 013 has actually closed in the meantime. Let's Encrypt's 90-day cycle, by contrast, is only acceptable, and only becomes an advantage rather than a liability, because it is paired with ACME automation (certbot or an equivalent client) that renews without a human remembering to act at all; a short-lived, automated certificate that renews itself 4 times a year is safer for 800 daily patients than a long-lived, manually-managed one that requires a human to succeed exactly once, correctly, twelve months from now. The clinical impact of a portal outage, patients unable to view records, message physicians, or manage appointments, is not reduced by a longer certificate lifetime; it is reduced by removing the human failure point entirely, which only the automated path achieves.

**Where a commercial CA remains the correct choice, stated directly rather than presenting Let's Encrypt as universally superior:** the Active Directory/LDAPS certificate and any future code-signing certificate are better suited to an internal or commercial CA, since Let's Encrypt cannot issue certificates for internal, non-publicly-resolvable names at all, the exact `.local` domain problem this project's own Task 10 already identified and flagged directly for the patient portal's own Common Name.

---

## Part 3: Monitoring and Alerting

**System: the SIEM already funded in this program's own budget allocation (1x03, Task 8), extended to include certificate expiration monitoring as a specific, configured alert source, not a separate tool.** This directly follows the same recommendation this project's own Task 10 (Part 4, Step 8) already made for the patient portal specifically, generalized here to every certificate in Part 1's inventory.

```
Threshold: 90 days remaining
Alert Fires To: Sarah Park (IT Director), as a routine, informational
  notice confirming automated renewal is expected to trigger on
  schedule, not yet requiring action
Purpose: Establishes a baseline confirmation that the certificate is
  being tracked at all, closing the exact gap Finding 013 exposed:
  MedDefense had no visibility into this certificate's status until it
  was nearly too late.
```

```
Threshold: 60 days remaining
Alert Fires To: Sarah Park (IT Director)
Purpose: A check-in point specifically for any certificate NOT covered
  by ACME automation (the AD/LDAPS certificate, any commercial-CA-
  issued certificate), where a human-initiated renewal request needs to
  begin now to avoid a manual process running down to the wire the way
  the original portal certificate did.
```

```
Threshold: 30 days remaining
Alert Fires To: Sarah Park (IT Director) and James Chen (Deputy CISO)
Purpose: Escalation to the Deputy CISO specifically for any certificate
  still showing as unrenewed at this point, since a healthy, automated
  certificate should never reach this threshold at all; its presence
  here is itself a signal the automation has already failed silently
  and requires direct intervention, not passive monitoring.
```

```
Threshold: 7 days remaining
Alert Fires To: Sarah Park, James Chen, and the CEO's office (Dr.
  Morales), matching the exact urgency this program's own Board Pitch
  (1x03, Task 19) already treated as requiring immediate,
  organization-wide attention when this exact certificate reached 18
  days
Purpose: Treated as a Critical incident under the Incident Response
  Plan already drafted in this program's Quick Wins (1x03, Task 13),
  not a routine IT ticket, given the direct, immediate clinical impact
  an expired patient portal certificate carries for 800 daily patients.
```

---

## Part 4: Certificate Policy

```
1. All internal services must use certificates signed by MedDefense's
   internal CA or a trusted public CA. Self-signed certificates are
   prohibited in production, directly closing the gap this task's own
   Part 1 inventory found for the EHR internal TLS and NAS-01
   management interface certificates.

2. Every certificate must use ECDSA P-256 as its key algorithm unless a
   specific, documented compatibility requirement demands RSA-2048
   instead, matching this project's own established standard (Task 6,
   Task 8, Task 10) rather than leaving key algorithm choice
   unstandardized across MedDefense's certificate population.

3. Every publicly-resolvable MedDefense certificate must be issued
   through an ACME-automated process with auto-renewal configured to
   trigger at 30 days remaining; no publicly-resolvable certificate may
   be provisioned through a manual issuance process without the Deputy
   CISO's documented exception approval.

4. Every certificate in MedDefense's inventory must be recorded in the
   central certificate inventory this task establishes, including its
   issuer, expiration date, responsible owner, and monitoring status,
   before it is deployed to any production system; no certificate may
   go into production use without first being added to this inventory.

5. Wildcard certificates are prohibited across MedDefense's certificate
   population. Every certificate must list the specific, minimal set of
   hostnames it actually needs to cover as explicit Subject Alternative
   Name entries, directly matching the reasoning this project's own
   Task 8 already established: a wildcard certificate's broader
   validation scope is a wider attack surface than a small number of
   purpose-scoped certificates, a risk MedDefense does not need to
   accept when the narrower alternative covers every legitimate need.
