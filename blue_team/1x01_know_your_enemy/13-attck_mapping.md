# MedDefense Health Systems: MITRE ATT&CK Mapping

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** `attack-scenarios-attck.txt` (2 detailed attack narratives), cross-referenced against Project 0x00 findings and Tasks 1–12 of this project **Purpose:** Map each step of two realistic attack scenarios to MITRE ATT&CK Enterprise tactics and techniques, building the shared vocabulary every SOC uses to communicate about attacks precisely rather than narratively.

**Note on technique verification:** technique IDs below were cross-checked against MITRE's published documentation (attack.mitre.org and associated technique-mapping references) rather than recalled from memory alone, given how consequential precision is for this kind of reference document. Where a step plausibly maps to more than one technique, the most specific primary technique is given with alternates noted, per the task instructions.

---

## Scenario Alpha: "Operation Flatline"

```
Step 1: Affiliate purchases a target list (including MedDefense) from an
  Initial Access Broker, compiled via internet-wide scanning for
  FortiGate management interfaces cross-referenced with healthcare
  industry data.
  Tactic: Resource Development
  Technique: Acquire Access (T1650) — the specific technique covering
    adversaries purchasing or otherwise acquiring pre-existing access or
    target intelligence from a broker rather than developing it
    themselves.
  MedDefense Factor: MedDefense's FortiGate management interface was
    discoverable via internet-wide scanning at all — its patch/exposure
    status is unconfirmed anywhere in this project (GAP-016) — and its
    identity as a mid-size healthcare organization made it a
    marketable, priced entry on the broker's list, consistent with the
    victim profile BlackReef's own handbook explicitly targets (T2).
```

```
Step 2: A spear phishing email impersonating Fortinet support reaches
  Sarah Park; she downloads and opens a malicious document, whose macro
  executes a PowerShell command to deliver a reverse shell.
  Tactic: Initial Access
  Technique: Phishing: Spearphishing Link (T1566.002) — the email
    delivers a link to a hosted malicious document rather than an
    attachment directly, making this the more precise sub-technique
    over T1566.001. Immediately followed, within the same step, by
    Execution via User Execution: Malicious File (T1204.002) and
    Command and Scripting Interpreter: PowerShell (T1059.001) once the
    macro runs.
  MedDefense Factor: This is a near-exact match to the scenario already
    analyzed in this project's Human Vector assessment (T4, Scenario 1)
    — no email authentication/anti-spoofing control is confirmed
    (GAP-017's broader identity gap), and no phishing simulation
    program exists to have trained Sarah Park to recognize this exact
    lure (GAP-012).
```

```
Step 3: The reverse shell connects to C2; the affiliate installs a
  scheduled task disguised as Windows Update to re-establish the
  connection every 30 minutes.
  Tactic: Persistence
  Technique: Scheduled Task/Job: Scheduled Task (T1053.005). The
    ongoing C2 channel itself is Application Layer Protocol (T1071),
    and the disguise as a legitimate Windows process is Masquerading:
    Match Legitimate Name or Location (T1036.005) — both closely
    associated with this step but secondary to the Persistence
    mechanism itself.
  MedDefense Factor: No centralized detection or log correlation exists
    (GAP-004), so a new scheduled task recurring every 30 minutes under
    a disguised name generates no alert anywhere in the environment.
```

```
Step 4: Discovery commands (nltest, net group "Domain Admins", arp -a)
  map the entire 10.10.0.0/16 range from a single HQ workstation.
  Tactic: Discovery
  Technique: Remote System Discovery (T1018) as the general network
    mapping objective, using the specific commands Domain Trust
    Discovery (T1482, via nltest) and Permission Groups Discovery:
    Domain Groups (T1069.002, via the "Domain Admins" query).
  MedDefense Factor: The flat network (GAP-014), combined with the
    HQ-to-Central site-to-site VPN link, means discovery commands run
    from a single Corporate HQ workstation expose the entire
    organization's server subnet at once — no segmentation limits even
    the reconnaissance stage.
```

```
Step 5: Mimikatz dumps cached credentials from Sarah's workstation
  memory, revealing a domain admin account's (svc_backup) NTLM hash
  from a prior backup troubleshooting session.
  Tactic: Credential Access
  Technique: OS Credential Dumping: LSASS Memory (T1003.001).
  MedDefense Factor: No MFA exists anywhere in the organization
    (GAP-017), meaning a captured hash alone is sufficient for further
    access; a domain admin service account authenticating interactively
    on a standard HQ workstation for routine troubleshooting is itself
    an unaddressed credential-hygiene gap (consistent with the absence
    of any periodic compliance review, GAP-009).
```

```
Step 6: A pass-the-hash attack using the svc_backup hash authenticates
  directly to ad-dc-01, granting Domain Admin access; the affiliate
  verifies by querying all domain computer objects.
  Tactic: Lateral Movement
  Technique: Use Alternate Authentication Material: Pass the Hash
    (T1550.002). The verification query afterward is a brief Discovery
    action (Remote System Discovery, T1018, or Account Discovery:
    Domain Account, T1087.002).
  MedDefense Factor: The absence of MFA (GAP-017) means the hash alone
    is sufficient to authenticate as Domain Admin, and the flat network
    (GAP-014) means ad-dc-01 is directly reachable from the HQ-originated
    foothold with no additional segmentation barrier to cross.
```

```
Step 7: High-value data is located and extracted: ehr-db-01's
  PostgreSQL database (35GB via pg_dump) and file-srv-01's HR/financial
  documents (8GB), compressed and exfiltrated via Rclone over HTTPS to
  attacker-controlled cloud storage, with no alerts generated.
  Tactic: Collection
  Technique: Data from Information Repositories (T1213) for the
    database and file-share extraction, with Archive Collected Data
    (T1560) for the compression step. This step transitions directly
    into Exfiltration Over Web Service: Exfiltration to Cloud Storage
    (T1567.002) for the Rclone transfer — both tactics are present
    within this single narrative step, with Collection as the primary
    label since it defines the step's initiating action.
  MedDefense Factor: PostgreSQL on ehr-db-01 is reachable from the
    entire network with no additional authentication beyond OS-level
    access (GAP-003); no DLP exists to flag a 43GB combined outbound
    transfer (GAP-019); and no centralized detection (GAP-004) explains
    precisely why, as the narrative states, "no alerts are generated."
```

```
Step 8: The affiliate targets backup infrastructure directly — deleting
  all backup jobs and stored backups via NAS-01's web management
  interface, and deleting Volume Shadow Copies on all Windows systems.
  Tactic: Impact
  Technique: Inhibit System Recovery (T1490).
  MedDefense Factor: NAS-01 is co-located on the same flat network with
    no isolation (GAP-006/GAP-014), and once Domain Admin access is
    achieved, no additional access barrier protects the backup
    management interface (GAP-017). This step is a direct, evidenced
    match to BlackReef's own documented playbook instruction (T2) to
    neutralize backups before deploying ransomware.
```

```
Step 9: A malicious Group Policy Object deploys the ransomware payload
  to all domain-joined Windows systems at the next refresh cycle; Linux
  servers are targeted separately via SSH using credentials found in a
  configuration file on file-srv-01.
  Tactic: Impact
  Technique: Data Encrypted for Impact (T1486), deployed via Domain
    Policy Modification: Group Policy Modification (T1484.001) for
    Windows systems, and Remote Services: SSH (T1021.004) for Linux
    systems using credentials obtained through Unsecured Credentials:
    Credentials In Files (T1552.001).
  MedDefense Factor: Domain-joined Windows systems trust GPOs pushed
    from ad-dc-01 with no additional confirmation step; Linux servers
    (ehr-srv-01, billing-srv-01) have SSH credentials stored in a
    plaintext configuration file — a credential-hygiene gap consistent
    with the absence of any formal change/configuration management
    process (GAP-025); and the flat network (GAP-014) means both
    deployment paths are reachable from the same compromised position.
```

---

## Scenario Beta: "The Quiet Departure"

```
Step 1: Maria, facing an upcoming layoff, decides to use her existing,
  legitimate billing and read-only EHR access to steal patient data for
  resale.
  Tactic: Initial Access
  Technique: Valid Accounts (T1078). Note: this step does not represent
    a technical intrusion — Maria already legitimately holds the access
    she will misuse. It is mapped here because Valid Accounts is the
    ATT&CK technique specifically defined for adversary use of
    legitimate credentials, which fits an insider's abuse of
    pre-existing access more accurately than any other Initial Access
    technique, even though no new access was actually "gained" at this
    step.
  MedDefense Factor: MedDefense's insider risk posture already
    identifies this exact pattern — broad clinical/billing access is
    operationally necessary, and no technical control distinguishes
    "legitimate use" from "abuse" of the same valid account (a theme
    explored at length in this project's Insider File, T3).
```

```
Step 2: Maria assesses what she can access through her normal billing
  and read-only EHR applications, noting neither limits session volume
  nor alerts on unusual access.
  Tactic: Collection
  Technique: Data from Information Repositories (T1213) — viewing
    patient names, insurance information, diagnosis codes, and medical
    histories through legitimate application access is, functionally,
    the Collection tactic's defining activity, regardless of the fact
    that no technical exploitation was required to reach it.
  MedDefense Factor: The EHR and billing applications have no
    volume-based anomaly detection or session limits — a technical gap
    directly connected to the absence of centralized detection/behavioral
    monitoring (GAP-004).
```

```
Step 3: Over 2 weeks, Maria accesses ~200 records per day mixed with
  legitimate work, using the EHR's built-in export function to download
  CSV files, with no additional authorization required and no alert
  generated since the audit log is never reviewed.
  Tactic: Collection
  Technique: Data from Information Repositories (T1213), continued and
    intensified via the built-in export function.
  MedDefense Factor: The EHR audit log technically records this access
    (C-016 in the 0x00 Control Matrix), but its value is nullified by
    the complete absence of proactive review (GAP-004, GAP-009) — this
    is the exact "logs without review are security theater" pattern
    already identified via real-world breach validation in Project
    0x00's Task 13.
```

```
Step 4: Maria transfers the CSV files to a personal USB drive, unimpeded
  by any technical restriction, accumulating ~2,800 patient records over
  two weeks.
  Tactic: Exfiltration
  Technique: Exfiltration Over Physical Medium: Exfiltration Over USB
    (T1052.001).
  MedDefense Factor: No Group Policy restricts USB storage device use
    anywhere at MedDefense (GAP-024), and no DLP control exists to flag
    or block a large data transfer to removable media (GAP-019).
```

```
Step 5: Maria deletes the CSV files from her workstation and empties the
  recycle bin to cover her tracks, unaware that the EHR's own
  vendor-managed audit log (which she cannot access) still recorded her
  activity.
  Tactic: Defense Evasion
  Technique: Indicator Removal: File Deletion (T1070.004).
  MedDefense Factor: The EHR's separate audit log is, on a technical
    level, a control working as intended (Maria genuinely cannot alter
    it) — but its practical value is completely undermined by the
    48-hour export delay and the total absence of proactive review
    (GAP-004, GAP-009), meaning a working control produces no actual
    protective effect.
```

```
Step 6: Maria discovers and copies a billing application configuration
  file containing plaintext database connection credentials, giving her
  direct database access independent of her network account status.
  Tactic: Credential Access
  Technique: Unsecured Credentials: Credentials In Files (T1552.001).
  MedDefense Factor: Database connection credentials stored in plaintext
  in a workstation-accessible configuration file is a credential-hygiene
  gap connected to the absence of any formal change/configuration
  management standard (GAP-025) — and mirrors, almost exactly, the
  plaintext Active Directory credential pattern already identified in
  this project's Insider File (T3, Scenario 5, the overworked
  administrator).
```

```
Step 7: HR processes Maria's departure; the manager's account
  deactivation ticket sits unprocessed in the IT queue for 5 business
  days, during which her VPN credentials remain fully active.
  Tactic: Persistence
  Technique: Valid Accounts: Domain Accounts (T1078.002) — her
    continued, un-revoked access after termination is, structurally,
    the same technique an external adversary uses to persist via a
    compromised valid account, even though here the "adversary" is a
    departing insider and no new technical action occurs at this step.
  MedDefense Factor: No automated account deprovisioning is tied to HR
    termination events, and no SLA governs offboarding tickets
    (GAP-018) — this is the identical gap already identified and
    validated against a real-world 47-day comparable incident in this
    project's Insider File (T3, Scenario 2) and Reality Check exercises.
```

```
Step 8: Three days after her last day, Maria connects to the VPN from
  home using her still-active credentials, uses the saved database
  credentials to extract an additional 400 records directly from
  billing-srv-01, then disconnects permanently.
  Tactic: Collection
  Technique: Data from Information Repositories (T1213), executed via
    continued access under Valid Accounts: Domain Accounts (T1078.002)
    as established in Step 7.
  MedDefense Factor: VPN access was never revoked despite her
    termination (GAP-018), and the database credentials captured in
    Step 6 provide a second, redundant access path independent of her
    network account entirely — meaning even a timely VPN deactivation
    alone would not have fully closed this specific final step, since
    standing database credentials had already left the organization on
    her USB drive.
```

---

## ATT&CK Coverage Assessment

Despite representing 2 structurally opposite threat profiles, a sophisticated external ransomware affiliate executing a nine-step technical intrusion, versus a single insider using nothing but pre-existing, legitimate access over several weeks, both scenarios converge on the same five ATT&CK tactics: **Initial Access, Credential Access, Persistence, Collection, and Exfiltration.** This convergence is the single most important finding of this exercise: Initial Access naturally differs by actor type and is reasonably well-covered by MedDefense's (limited) perimeter-facing controls, but Credential Access, Persistence, Collection, and Exfiltration appear in both an external and an internal attack precisely because they map directly onto the same handful of gaps repeated throughout this entire project. No MFA (GAP-017) enabling Credential Access and Persistence alike, no centralized detection (GAP-004) allowing Collection to proceed for weeks unnoticed in both scenarios, and no DLP (GAP-019) leaving Exfiltration completely unmonitored regardless of whether the data leaves via Rclone to the cloud or a USB drive in someone's pocket. This tells MedDefense precisely where detection investment has the highest return: a single capability built to monitor credential use, persistence mechanisms, unusual data access volume, and outbound data movement would provide meaningful defense against both of these very different threat actors at once, rather than requiring 2 separate, actor-specific detection strategies.
