# MedDefense Health Systems: The Network Posture

**Prepared by:** Aïda sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** `meddefense-vulnerability-scan.txt`, cross-referenced against the 0x00 network scan/asset registry and the 1x01 Gap-Threat Correlation (Task 15, where the flat network was independently identified as the single most-referenced gap across this entire program) **Purpose:** Quantify, CVE by CVE, exactly how much the absence of network segmentation amplifies the real-world risk of an individually-scored vulnerability. The finding underneath every finding in this scan report.

---

## CVE 1: CVE-2021-44790 (billing-srv-01)

sql

```sql
CVE: CVE-2021-44790
Host: billing-srv-01 (10.10.2.15)
CVSS Base Score: 9.8

Scenario A: Current (flat network)
  Who can reach this vulnerability: The entire 10.10.0.0/16 range —
    every workstation, every medical device, every server, and every
    site (Central, Westside, Corporate HQ) can route to port 80 on this
    host, with no network-layer control in between. Project 1x01's own
    Attack Surface Analysis (Task 7) further flagged a plausible
    contradiction suggesting this service may also be reachable directly
    from the internet, despite the assumed DMZ model.
  What the attacker can reach AFTER exploitation: Everything else on the
    same flat topology. This finding chains directly with Finding 002
    (local privilege escalation to root, already confirmed weaponized in
    Task 5 of this project), after which the compromised host sits on
    the identical 10.10.2.0/24 segment as ehr-srv-01, ehr-db-01,
    ad-dc-01, and NAS-01 — with no boundary preventing lateral movement
    to any of them, and no further boundary preventing continued
    movement from there into 10.10.1.0/24 (workstations) or 10.10.3.0/24
    (medical devices).
  Effective Risk: Critical. A single unauthenticated web request against
    one financial application server carries a realistic path to
    organization-wide compromise, not a contained financial-data
    incident.

Scenario B: Hypothetical (segmented network)
  Who can reach this vulnerability: Only systems within billing-srv-01's
    own dedicated segment — realistically the server itself and, at
    most, a small number of legitimately billing-related endpoints,
    under a least-privilege VLAN design.
  What the attacker can reach AFTER exploitation: The attacker is
    contained to that segment. Reaching ehr-db-01, ad-dc-01, or the
    medical device population would require either a specific,
    documented, narrowly-scoped firewall rule (e.g., authentication
    traffic to the domain controller only, not full network
    reachability) or a wholly separate vulnerability to breach the
    segment boundary itself — this exploit alone no longer gets an
    attacker there.
  Effective Risk: High, but genuinely contained. Still a serious breach
    of financial and PHI-adjacent billing data, but not an
    organization-wide event.

Risk Amplification Factor: Very high — realistically on the order of two
  orders of magnitude in terms of assets reachable post-exploitation.
  Currently, successful exploitation puts effectively the entire
  networked estate (hundreds of devices, per the 0x00 Asset Registry) in
  reach; in a segmented model, that number drops to a handful of
  intentionally-related endpoints. The CVSS score itself (9.8) does not
  change between the two scenarios — the score measures the flaw in
  isolation — but the real-world consequence of a successful exploit
  changes by roughly two orders of magnitude in reachable blast radius.
```

---

## CVE 2: CVE-2020-1938 / Ghostcat (ehr-srv-01)

sql

```sql
CVE: CVE-2020-1938
Host: ehr-srv-01 (10.10.2.10)
CVSS Base Score: 9.8

Scenario A: Current (flat network)
  Who can reach this vulnerability: The entire 10.10.0.0/16 range can
    reach port 8009 (AJP) on this host — identical reachability scope to
    Finding 001 above, since both sit on the same unsegmented topology.
  What the attacker can reach AFTER exploitation: This is the clearest
    case in this analysis of the flat network compounding a second,
    separate finding rather than merely enabling generic lateral
    movement. Ghostcat's arbitrary file read can expose ehr-db-01's
    database credentials directly from configuration files on
    ehr-srv-01. Those credentials are then immediately usable, because
    ehr-db-01 is separately confirmed (Finding 003) to accept
    connections from the entire 10.10.0.0/16 range with no restriction
    to ehr-srv-01 specifically. The flat network does not just let this
    attacker move laterally — it directly weaponizes a second, otherwise
    independent misconfiguration finding.
  Effective Risk: Critical, compounded. This single CVE, on this flat
    network, yields full read access to the complete patient database —
    not through further exploitation, but simply by using credentials
    the first flaw handed over, against a database that never checked
    where the connection came from.
Scenario B: Hypothetical (segmented network)
  Who can reach this vulnerability: Only hosts within a dedicated EHR
    application-tier segment, ideally isolated from general workstations
    and other server classes entirely.
  What the attacker can reach AFTER exploitation: The stolen ehr-db-01
    credentials remain dangerous, but if ehr-db-01 were also correctly
    segmented and restricted to accept connections only from ehr-srv-01
    specifically (closing Finding 003 as well, not just adding a VLAN
    boundary around it), the attacker's usable path narrows
    considerably — they would need to already be operating from within
    ehr-srv-01 itself to use the stolen credentials at all, rather than
    from anywhere on the network.
  Effective Risk: Still High to Critical for the EHR tier specifically —
    this remains the organization's most sensitive data, and this
    scenario does not eliminate risk to it — but the compromise no
    longer radiates outward to Central's workstations, the domain
    controller, or the medical device population.
Risk Amplification Factor: Very high, and structurally different from
  CVE 1's amplification: here the flat network does not just extend
  reach, it converts a single exploited finding into automatic access to
  a second, separately-scored finding (Finding 003) without any
  additional exploitation step required. Segmentation alone would
  reduce this; segmentation combined with actually restricting Finding
  003's own database access (rather than only wrapping a VLAN around the
  current configuration) is what closes this compounding effect fully.
```

---

## CVE 3: CVE-2017-0144 / EternalBlue (WS-RAD-01, MRI Workstation)

sql

```sql
CVE: CVE-2017-0144
Host: WS-RAD-01 (10.10.1.70)
CVSS Base Score: 8.1

Scenario A: Current (flat network)
  Who can reach this vulnerability: The entire 10.10.0.0/16 range — and
    the finding's own text specifically confirms this device sits on
    "the same subnet (10.10.1.0/24) as all other workstations with no
    VLAN isolation," meaning a medical device with no legitimate
    business reason to communicate with general clinical workstations is
    nonetheless directly reachable from, and directly able to reach,
    every one of them.
  What the attacker can reach AFTER exploitation: SYSTEM-level code
    execution on the MRI console is only the starting point. Because
    this device shares a subnet with reception and nurse-station
    workstations — the same endpoints most exposed to phishing and
    general internet browsing per this project's own Human Vector
    analysis (1x01, Task 4) — a compromised MRI workstation becomes a
    pivot point into the general clinical fleet just as readily as a
    compromised clinical workstation could pivot toward the MRI. The
    same flat topology also puts Central's servers (ad-dc-01, ehr-db-01)
    within reach from this single medical device.
  Effective Risk: Critical. What should be an isolated clinical device
    incident becomes a viable entry point into the organization's
    general IT environment, in either direction.
Scenario B: Hypothetical (segmented network)
  Who can reach this vulnerability: Only hosts within a dedicated
    medical device VLAN — this is not a hypothetical proposal invented
    for this document; it is precisely control P-001, already proposed
    as the top-priority compensating control for this exact device in
    Project 0x00 (Task 6), specifically because the device's regulatory
    constraints prevent replacing its OS directly.
  What the attacker can reach AFTER exploitation: The attacker remains
    contained to the medical device segment — potentially still reaching
    other medical devices co-located on that same VLAN (the BD Alaris
    infusion pumps, the Philips monitors) if no further micro-
    segmentation is applied within that segment, but critically no
    longer reaching general clinical workstations, Central's servers, or
    the domain controller.
  Effective Risk: Still meaningful — other medical devices remain at
    risk within the same segment — but the blast radius no longer
    extends into the organization's IT core.
Risk Amplification Factor: High, and this case demonstrates something
  the other two do not: MedDefense has already, independently, arrived
  at the correct mitigation for this exact amplification effect (P-001)
  through a completely separate line of analysis in Project 0x00 — this
  task's own segmentation-impact framework converges on the same
  conclusion that project reached by different reasoning, which is
  itself a form of validation that the recommendation is correct rather
  than merely convenient.
```

---

## Network Posture Summary

Across all 3 CVEs analyzed here, spanning a financial application server, a clinical application server, and a legacy medical device, 3 entirely different asset classes with 3 entirely different vulnerability types. The same structural pattern repeats: the flat network does not add a fixed amount of risk to each finding, it multiplies whatever risk that finding already carries by the size of the entire networked estate, because there is currently no boundary anywhere in MedDefense's environment that limits a successful exploit's reach to anything less than effectively the whole organization. This is not a new conclusion invented for this task. It is the sixth or seventh independent confirmation of the same finding across this entire two-project program, and Project 1x01's own Gap-Threat Correlation (Task 15) already quantified it precisely: the flat network (GAP-014) is the single most-referenced gap across every kill chain and scenario built in this project, appearing in 6 of 8 distinct attack paths, more than any other single weakness identified anywhere. **Network segmentation is arguably more impactful than patching any single CVE, including the 3 CVSS 9.8/8.1 vulnerabilities analyzed above, for a simple structural reason: patching closes exactly one door, while segmentation caps how far _any_ successful entry, through _any_ door, patched or not yet discovered, can reach.** Given this project's own introduction already established that roughly 80 new CVEs are disclosed industry-wide every day, a patching-only strategy is a permanent race against a stream of new openings that never stops, while a segmentation project, once completed, continues capping the damage of every vulnerability that follows it, including the ones nobody has found yet. Patching Findings 001, 020, and 004's underlying CVEs would still leave every other unpatched or future vulnerability in this environment equally free to reach the entire organization; segmenting the network once would meaningfully reduce the real-world consequence of all of them simultaneously, whether or not each individual CVE is ever patched at all.
