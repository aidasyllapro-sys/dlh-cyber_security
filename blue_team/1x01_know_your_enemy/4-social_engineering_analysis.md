# MedDefense Health Systems: The Human Vector - Social Engineering Analysis

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** 7 MedDefense-specific social engineering scenarios, classified per the CompTIA Security+ 2.2 social engineering vector taxonomy **Purpose:** Classify each scenario by exact attack vector and psychological lever, identify observable red flags, and pair each with one technical and one administrative countermeasure.

---

```
Scenario 1:
  Vector Type: Phishing (email-delivered), using Brand Impersonation as
    its core technique (impersonating Fortinet vendor support)
  Target: Sarah Park, IT Director — vulnerable because she holds direct
    operational responsibility for the FortiGate and would feel
    professionally obligated to act on what appears to be an official
    vendor security advisory, especially given that patch management for
    this exact device is already a documented, real gap at MedDefense.
  Psychological Lever: Urgency (with Fear reinforcing it via the
    "service termination" threat)
  Red Flags:
    1. Sender domain "fortinet-support.net" is not Fortinet's actual
       corporate domain — a lookalike domain built to resemble, not
       match, the real vendor.
    2. An artificial 24-hour deadline paired with a severe consequence
       (service termination) is a classic urgency-manufacturing pattern
       designed to short-circuit careful verification.
    3. Legitimate vendors do not distribute firmware patches via an
       emailed "click here" link — official patches are retrieved
       through an authenticated vendor support portal, never a link in
       an unsolicited email.
  Technical Control: Email security gateway enforcing DMARC/SPF/DKIM
    validation with lookalike-domain detection, flagging or quarantining
    mail from domains that closely resemble known vendor brands.
  Administrative Control: A documented policy requiring all vendor
    security patches and advisories to be verified and retrieved
    directly through the vendor's official support portal — never
    through a link contained in an email — regardless of stated urgency.
```

```
Scenario 2:
  Vector Type: Business Email Compromise (BEC), specifically CEO/executive
    impersonation
  Target: Robert Kim, CFO — vulnerable because the message invokes the
    authority of the actual CEO, explicitly instructs him to bypass
    normal internal discussion/verification, and preemptively explains
    why the real CEO can't be reached to confirm ("in meetings all day,
    email only"), removing the most natural way to verify the request.
  Psychological Lever: Authority (with Urgency reinforcing it)
  Red Flags:
    1. The sender address subtly differs from the real CEO's known
       email address — the single most reliable indicator in this
       scenario, and one that requires only a careful character-by-
       character check.
    2. An explicit instruction to bypass normal process and avoid
       discussing the request with anyone else — legitimate high-value
       financial requests do not ask the recipient to keep them secret
       from internal colleagues.
    3. A high-value, one-off wire transfer request delivered entirely
       by email, with no phone call, no prior discussion, and no
       standard procurement/approval trail.
  Technical Control: Email authentication enforcement (DMARC/SPF/DKIM)
    combined with an automated internal-impersonation warning banner
    on any external email that displays an internal executive's name.
  Administrative Control: A mandatory out-of-band verification policy
    (a phone call to a previously known number, never a number provided
    in the suspicious email itself) for any wire transfer or financial
    request above a defined dollar threshold, with dual approval
    required regardless of confidentiality or urgency framing.
```

```
Scenario 3:
  Vector Type: Vishing (voice-based phishing), constructed using
    Pretexting (the fabricated "emergency security audit" scenario)
  Target: A nurse at MedDefense Central — vulnerable because clinical
    staff are trained toward helpfulness and compliance with requests
    that sound like legitimate, urgent internal IT operations, and
    because the caller references a real, recent incident (the billing
    server) to manufacture false credibility.
  Psychological Lever: Helpfulness (with Authority reinforcing it, via
    the caller posing as internal IT)
  Red Flags:
    1. A legitimate IT verification of "login works correctly" never
       requires disclosing a password out loud — this alone is
       sufficient grounds to refuse and escalate.
    2. Referencing a real, recent internal incident (the billing server)
       is a pretexting technique designed to borrow legitimacy from an
       event the target already knows is true.
    3. No independently verifiable identification was offered or
       requested — no ticket number, no employee ID, and no offer to
       call back through the official IT helpdesk number.
  Technical Control: Enforced multi-factor authentication on EHR access,
    so that even a disclosed password alone is insufficient to log in —
    directly closes the practical impact of this exact scenario (ties to
    GAP-017 from Project 0x00).
  Administrative Control: A strict, actively trained policy that IT
    staff never ask for a password over the phone under any
    circumstance, combined with a mandatory callback-verification
    procedure using the helpdesk's published number before any
    credential-related information is discussed.
```

```
Scenario 4:
  Vector Type: Smishing (SMS-delivered phishing), using Brand
    Impersonation of MedDefense's internal HR portal
  Target: All MedDefense employees (untargeted, mass distribution) —
    vulnerable because a parking permit is a mundane, low-suspicion
    pretext relevant to nearly anyone who drives to work, the towing
    threat creates fast, low-scrutiny compliance, and mobile devices
    make it harder to carefully inspect a URL before tapping it.
  Psychological Lever: Fear (of towing), with Urgency reinforcing it
  Red Flags:
    1. An unsolicited SMS containing a clickable link that requests
       Active Directory credentials — a combination legitimate internal
       systems essentially never use.
    2. Mass, generic wording sent to all employees rather than targeted
       messaging naming a specific individual, vehicle, or permit number.
    3. The landing page's domain does not match MedDefense's actual
       internal HR portal address — verifiable by checking the URL
       before entering any credentials.
  Technical Control: Mobile device management (MDM) with web-filtering
    and anti-phishing protection blocking known and newly-registered
    lookalike domains, combined with enforced MFA on AD credentials so a
    harvested password alone cannot be used to log in — ties directly to
    GAP-008 (no MDM) and GAP-017 (no MFA) from Project 0x00.
  Administrative Control: A clearly and repeatedly communicated policy
    that MedDefense never requests AD credentials via SMS link, paired
    with regular phishing/smishing simulation exercises — a program that
    does not currently exist at MedDefense (GAP-012, Project 0x00).
```

```
Scenario 5:
  Vector Type: Watering Hole Attack
  Target: MedDefense physicians who visit the Regional Healthcare
    Association's site monthly for CME credits — vulnerable because this
    is a routine, trusted third-party destination outside MedDefense's
    control, so physicians have no built-in reason for heightened
    suspicion, and the attack requires no active decision from the
    target beyond normal browsing behavior.
  Psychological Lever: Familiarity (implicit trust in a routinely-
    visited, seemingly legitimate site)
  Red Flags:
    1. Unexpected redirects, pop-ups, or new browser tabs/windows
       opening automatically during a routine visit to a normally
       predictable site.
    2. Unexpected browser or antivirus security warnings appearing
       during what should be an unremarkable page visit.
    3. Any noticeable change in the site's usual appearance or loading
       behavior — a weaker indicator, since watering hole attacks are
       specifically engineered to be silent and go unnoticed by design.
  Technical Control: Endpoint protection/EDR with browser exploit-
    prevention on physician workstations — a real gap at MedDefense,
    since endpoint antivirus explicitly excludes several device classes
    and this scenario specifically requires browser-level exploit
    defense on clinical endpoints (Task 12, GAP-005/GAP-008 pattern).
  Administrative Control: A policy isolating or restricting general
    external web browsing (CME sites, industry association portals) from
    the same endpoints used for EHR/clinical system access, so that even
    a successful compromise cannot pivot directly into patient-care
    systems — consistent with the network segmentation priorities
    already identified in GAP-014.
```

```
Scenario 6:
  Vector Type: Typosquatting, combined with Brand Impersonation of the
    patient portal
  Target: MedDefense patients (external to the organization) searching
    for the patient portal — vulnerable because they rely on search
    engine placement as an implicit trust signal, and a single-letter
    spelling substitution ("defence" vs. "defense") is easy to overlook,
    especially against a visually identical copy of the real site.
  Psychological Lever: Familiarity (visual and branded trust in what
    appears to be the expected, legitimate portal)
  Red Flags:
    1. The domain spelling itself — "meddefence" substitutes a British
       spelling variant for MedDefense's actual American-spelled domain,
       a classic typosquatting technique.
    2. The fraudulent result appears as a labeled paid advertisement
       positioned above the real, organic search result — a
       distinguishing visual cue directly in the search results page.
    3. Absence of MedDefense's genuine security indicators once on the
       page (certificate details, exact URL) — the most reliable check
       remaining even against a visually "pixel-perfect" copy.
  Technical Control: Defensive domain registration of common typosquat
    variants of MedDefense's own domain, combined with a brand/domain
    monitoring service enabling rapid detection and takedown requests
    for fraudulent lookalike domains and ad placements.
  Administrative Control: A patient-facing communication policy that
    publishes the official portal URL only through verified channels
    (appointment reminders, printed materials, official emails) and
    explicitly instructs patients to bookmark or directly type the
    address rather than search for it.
```

```
Scenario 7:
  Vector Type: Impersonation, executed through Tailgating (piggybacking)
    to defeat a physical access control
  Target: Any MedDefense staff member holding the badge-controlled door —
    vulnerable because strong visual cues of legitimacy (scrubs, a
    hospital-branded coffee cup, a stethoscope) combine with the social
    discomfort of challenging someone who appears to belong, and a warm,
    casual tone is designed to trigger reciprocal courtesy rather than
    scrutiny.
  Psychological Lever: Helpfulness (holding the door is a normal
    courteous act), reinforced by Familiarity (visual cues of belonging)
  Red Flags:
    1. A visitor badge that is both expired (by two days) and partially
       concealed — active concealment of an identity credential is a red
       flag independent of the expiration itself.
    2. An internal inconsistency in the story: claiming a badge is "in
       my locker" while actually wearing a (hidden) visitor badge — the
       excuse does not match the visible evidence.
    3. Generic visual props conveying general "hospital belonging"
       (scrubs, stethoscope, branded cup) without providing any specific,
       checkable identification — a legitimate staff badge displays a
       name, photo, and access level, none of which this person offered.
  Technical Control: Badge access system enforcing single-entry-per-
    badge-scan (no shared or tailgating entry permitted), with
    anti-passback controls specifically on the highest-sensitivity
    corridors — directly addresses GAP-007 (undifferentiated physical
    access, generic badge for all staff) from Project 0x00.
  Administrative Control: An explicit, trained "challenge culture"
    policy authorizing and expecting every staff member to politely stop
    and verify anyone following them through a restricted door,
    regardless of appearance, combined with mandatory visible and
    current visitor badges enforced at every restricted entry point.
```

---

## Summary Table

|#|Vector Type|Primary Lever|Target|
|---|---|---|---|
|1|Phishing / Brand Impersonation|Urgency|IT Director (Sarah Park)|
|2|Business Email Compromise|Authority|CFO (Robert Kim)|
|3|Vishing / Pretexting|Helpfulness|Clinical nurse|
|4|Smishing / Brand Impersonation|Fear|All employees|
|5|Watering Hole|Familiarity|Physicians (external site)|
|6|Typosquatting / Brand Impersonation|Familiarity|Patients|
|7|Impersonation / Tailgating|Helpfulness|Any badge-holding staff|

**Cross-cutting observation:** 5 of the 7 scenarios target a psychological lever (Urgency, Fear, or Authority) specifically designed to prevent the target from pausing to verify; the remaining two (Watering Hole, Typosquatting) instead exploit passive Familiarity, requiring no active decision from the target at all. This split matters operationally: awareness training can meaningfully counter the first group by teaching people to recognize and resist pressure to act immediately, but the second group can only be countered by technical controls (endpoint protection, domain monitoring) since the target may never consciously notice anything is wrong.
