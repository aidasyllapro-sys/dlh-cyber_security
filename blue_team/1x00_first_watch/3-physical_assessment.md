# MedDefense Health Systems: Physical walk-through - risk decomposition

**Prepared by:** Aïda Sylla, Security Analys **Prepared for:** James Chen, Deputy CISO **Source material:** On-site physical walk-through of MedDefense Central, conducted with James Chen **Purpose:** Decompose each physical observation into its formal risk components (Vulnerability, Threat, Impact, Severity) as the physical-security input to the full security posture assessment.

**Framework used:** A risk exists where a **Vulnerability** (a specific weakness) can be exploited by a **Threat** (a plausible actor or scenario), producing an **Impact** measured against the CIA Triad. Severity is assessed relative to the other observations in this walk-through, based on ease of exploitation, breadth of what is exposed, and consequence if realized.

---

```
Observation 1: Server Room Access
  Vulnerability: The server room housing the Central site's core infrastructure
    (domain controllers, EHR servers, billing server, backup server and its
    co-located NAS) is accessible via a generic badge issued to every employee
    regardless of role (clinical, administrative, custodial), off a corridor shared
    with the public-adjacent cafeteria. There is no camera on the door and no
    visitor log.
  Threat: Any of the roughly 1,400 staff at Central, or anyone using a lost,
    stolen, or cloned badge, could enter the server room unsupervised, with no
    record of who entered, when, or why. This includes staff with no legitimate
    operational reason to be there (e.g., custodial or clinical staff).
  Impact: Availability and Integrity. Physical tampering with, theft of, or
    damage to any server is possible, including the backup NAS, which per prior
    findings already sits in the same room/rack as the systems it backs up
    (a single point of failure this observation makes physically exploitable,
    not just architecturally weak). Confidentiality is also at risk if a visitor
    connects a rogue device, copies data, or photographs screens/consoles. The
    absence of a camera and visitor log means none of this would be detectable
    or attributable after the fact.
  Severity: Critical. Unrestricted, unlogged, unmonitored physical access to
    the single room containing nearly all of Central's core infrastructure is
    the highest-value physical attack surface identified in this assessment.
```

```
Observation 2: Network Closet
  Vulnerability: A second-floor network closet housing switches and patch panels
    has no functioning lock (door ajar), and a laminated sheet with the switch
    management interface's username and password is taped to the wall in plain
    view inside it.
  Threat: Anyone able to walk into the closet (staff, contractor, or visitor who
    wanders off a public corridor) can read the posted credentials and log into
    the switch management interface directly, with no need for any technical
    skill to obtain valid administrative access.
  Impact: Integrity (unauthorized reconfiguration of switches or patch panels),
    Availability (a floor or building segment could be disconnected or
    misconfigured into an outage), and Confidentiality (an attacker with switch
    access could configure port mirroring to intercept traffic). This is
    especially severe given the already-documented lack of network segmentation
    at Central. Switch-level access here is not confined to a single floor's
    traffic.
  Severity: Critical. This combines a physical access failure with a
    credentials-exposure failure, giving virtually any passerby administrative
    control over core network infrastructure with no technical barrier at all.
```

```
Observation 3: Nurse Station
  Vulnerability: A third-floor nurse station workstation is logged into the EHR
    with a patient record visible on screen, unattended and idle for at least
    15 minutes, with no automatic session lock — reinforced by a posted sign
    instructing staff not to log out between shifts.
  Threat: Any patient, visitor, or family member passing the (frequently
    high-traffic) nurse station could view the currently displayed patient's
    record, or use the active, authenticated session to browse other patients'
    records. Any actions taken during this window would be attributed to the
    clinician whose session is open, not to whoever is actually at the keyboard.
  Impact: Confidentiality (PHI exposed to unauthorized viewers, consistent with
    the access-control weakness already seen in Incident B) and Integrity/
    accountability (any record changes made during the session cannot be
    reliably attributed to the person who made them, breaking non-repudiation).
  Severity: High. The exposure is real and immediate (a record is visibly
    unprotected right now), but exploitation still requires a person to be
    physically present at the station during the idle window, which is a
    narrower opportunity window than the always-open access in Observations
    1 and 2.
```

```
Observation 4: Medical IoT (Vital Signs Monitor)
  Vulnerability: A patient-room vital signs monitor is running firmware last
    updated in 2019 (over six years unpatched at the time of this assessment),
    displays its IP address and firmware version on-screen, and sits on the same
    IP range (10.10.x.x) as general-purpose nurse station workstations, i.e.,
    no network segmentation isolates clinical IoT devices from the rest of the
    network.
  Threat: An attacker with any foothold on the flat Central network (for
    example, via the exposed network closet in Observation 2, or a compromised
    workstation) could target this device directly. Six years of unpatched
    firmware makes it a plausible target for known, publicly documented
    vulnerabilities, and the on-screen IP/firmware disclosure removes the need
    for the attacker to even perform reconnaissance to find and identify it.
  Impact: Integrity (falsified vital-sign readings could mislead clinical staff
    into an incorrect treatment decision, a direct patient-safety consequence)
    and Availability (the device could be disrupted or disabled, interrupting
    continuous patient monitoring). This also confirms, at the level of a single
    physical device, the lack of medical-IoT network segmentation already
    flagged as a systemic concern in the environment summary.
  Severity: Critical. An unpatched, network-exposed device that directly
    reports patient vital signs carries a life-safety consequence if its
    integrity or availability is compromised, which places it above purely
    data-confidentiality risks in terms of consequence.
```

```
Observation 5: Emergency Exit
  Vulnerability: A fire exit connecting the public waiting area directly to the
    restricted administrative wing (including the IT department and James
    Chen's office) is permanently propped open with a wooden wedge, with a
    handwritten sign normalizing the practice ("please do not close, staff
    passage").
  Threat: Any member of the public (a patient, a visitor, or someone posing as
    either) can walk unchallenged from a public area directly into the
    administrative/IT wing, bypassing whatever badge or reception controls that
    wing is meant to have entirely.
  Impact: Primarily Confidentiality. Unsupervised physical proximity to IT
    staff areas creates opportunity for shoulder-surfing, document access, or
    reaching an unattended workstation, similar in nature to Observations 1 and
    2 but one step removed (this observation grants entry into the administrative
    wing, not direct access to the server room or network closet themselves).
    Secondary Integrity/Availability risk exists if the intruder proceeds further
    into IT operational areas.
  Severity: High. It removes a physical access-control barrier into a sensitive
    area, but unlike Observations 1, 2, and 4, it grants proximity and
    opportunity rather than immediate, direct access to core infrastructure or
    patient-safety systems.
```

---

## Summary table

| #   | Observation                                                | Primary impact pillar(s)                 | Severity |
| --- | ---------------------------------------------------------- | ---------------------------------------- | -------- |
| 1   | Server room accessible to any employee, no camera, no log  | Availability, Integrity, Confidentiality | Critical |
| 2   | Unlocked network closet, credentials posted on the wall    | Integrity, Availability, Confidentiality | Critical |
| 3   | Unattended, unlocked EHR session at nurse station          | Confidentiality, Integrity               | High     |
| 4   | Unpatched, unsegmented medical IoT monitor                 | Integrity, Availability                  | Critical |
| 5   | Fire exit propped open into restricted administrative wing | Confidentiality                          | High     |

## Cross-cutting observation

3 of the 5 findings (1, 2, 4) are variations of the same underlying condition already identified in the environment summary and the billing-srv-01 root-cause analysis: **MedDefense Central has no meaningful segmentation, physical or logical, between general-access areas and its most sensitive infrastructure.** The badge system does not differentiate access levels, the network has no VLANs, and a compromise of any single weak point (the network closet, in particular) has a direct path to core servers and unpatched medical devices on the same flat network. James's instinct that the server-room access issue was never resolved after being flagged five months ago appears correct, and this walk-through indicates the same class of gap (undifferentiated physical and network access) repeats across multiple, independent locations in the building rather than being an isolated oversight.
