# Network Forensics Investigation Report

**Subject:** MedDefense Health Systems — Phishing-to-Exfiltration Incident
**Prepared for:** Incident Response Leadership
**Investigation basis:** Packet capture analysis (Wireshark Territory module, Tasks 0-8), correlated with the prior 4x00 Phishing Dissection findings
**Report status:** Draft for IR leadership review — network-layer findings only; not a substitute for endpoint, authentication or SIEM review

---

## Executive Summary

An employee (account: dmarsh@meddefense.com) clicked a spear-phishing link that led to a credential-harvesting page impersonating the MedDefense patient portal; network evidence shows this session on **2026-04-14 at 15:02:33 UTC**. Roughly 22 hours later, on **2026-04-15 at 13:45:22 UTC**, the same account's credentials were used to open an SSL-VPN session from an external IP geolocated to Nigeria (AS37340, Spectranet Limited), which was followed about 45 minutes later by an RDP connection from a clinical workstation into a billing server and, later the same night, by a DNS-tunneling channel exfiltrating structured records from that billing server. Packet evidence directly proves the network communication at every stage (DNS/TLS/RDP/DNS-tunnel traffic with exact timestamps) but cannot prove exactly what data left the network, since the DNS-tunnel payload was only partially decoded and its total content was not fully recovered from metadata alone. No packet evidence in this module shows the attacker reaching systems beyond the billing server segment reached by RDP, and no SMB-based enumeration or further lateral spread was observed in the captures analyzed.

## Investigation Scope

**PCAPs analyzed** (all under `threat_detection/4x01_wire_shark_territory/` in this repository):

| PCAP file | Purpose | Confirmed time window (UTC) | Confirmed packet count |
|---|---|---|---|
| `normal_baseline_clinical.pcap` | 30-minute baseline of normal clinical network traffic, for comparison | Baseline period, ~30 min | 2,842 |
| `phishing_click.pcap` | The credential-harvesting session following the phishing click | 2026-04-14, ~15:02:33-15:03:20 | 61 |
| `c2_beaconing.pcap` | Post-compromise beaconing traffic from the clicked host | 2026-04-15, 02:00:12-03:55:08 | 620 |
| `dns_exfil.pcap` | DNS-tunneling exfiltration from the billing server | 2026-04-16, ~00:15-00:45 | 974 |
| `lateral_movement.pcap` | Cross-subnet RDP/SMB activity from the clinical workstation | 2026-04-15, RDP observed at 14:30:12 | 864 |
| `full_timeline.pcap` | Composite capture spanning the VPN pivot through lateral movement | 2026-04-14 17:02:33 - 2026-04-16 00:16:00 | 202 |

**Tools used:** `tshark` (all protocol dissection and statistics — see `0-baseline_analysis.sh` through `8-evidence_crosscheck.sh` for every documented filter/command used), `capinfos` (file metadata verification), `whois` / Team Cymru whois (source-IP geolocation for the VPN pivot), `python3` (interval statistics, plaintext-marker decoding, JSON correlation). Wireshark's GUI was used only for ad hoc manual review during development, never as part of the automated findings below.

**Evidence sources NOT used in this report:** endpoint/EDR logs, Windows Security event logs or any authentication/directory service log, VPN gateway authentication logs, mail gateway/email security logs, SIEM alert history, and direct user interviews. Every finding below is therefore bounded by what is visible on the wire; Section 7 (Detection Gap Analysis) and the recommendations explicitly flag where one of these other sources is required to close a gap.

## Methodology

- **Baseline establishment** — `0-baseline_analysis.sh` characterized 30 minutes of normal clinical traffic (protocol mix, DNS query rate, connection durations, TLS profile) to give later anomaly findings something to be compared against, and confirmed the baseline period itself carried no traffic to any IOC later identified in this investigation.
- **Known-IOC search** — once `meddefense-portal.com` / `91.234.99.107` were confirmed as the phishing infrastructure (Task 1), every subsequent capture was checked for the same domain/IP, and the kill-chain and detection-rule work (Tasks 6-7) reused those same confirmed IOCs rather than re-guessing them capture by capture.
- **DNS analysis** — query name, type, response, and (for the exfiltration capture) leftmost-label length and encoding were extracted with `tshark -T fields` and analyzed for anomalies against the Task 0 baseline profile.
- **TLS metadata analysis** — ClientHello SNI, handshake/record content types, and application-data record sizes were used throughout to identify destinations and session characteristics without decrypting payload; where this module's synthetic captures embedded plaintext markers inside handshake-classified records (certificate fields, VPN auth context), that was detected and clearly labeled as a plaintext-marker extraction, not genuine X.509/TLS decryption.
- **Timing analysis** — session durations, inter-session intervals (beaconing regularity), and gaps between phases (VPN-to-RDP) were computed directly from `frame.time_epoch` values, never estimated.
- **Behavioral analysis** — the beaconing capture was assessed for interval regularity (mean/standard deviation) rather than by matching a specific signature, so the same method would generalize to a different beacon interval.
- **Cross-PCAP correlation** — `6-kill_chain.sh` combined all five incident PCAPs into one chronological timeline, and `8-evidence_crosscheck.sh` then re-examined every phase of that timeline to separate what the packets directly prove from what is inferred (see Section 4).

## Findings by Attack Phase

### Phase 1 — Initial Access (Spearphishing Link)
**MITRE ATT&CK:** T1566.002 (Spearphishing Link)
**Evidence citation:** Not packet evidence — no PCAP in this module records SMTP delivery. Context carried over from the 4x00 Phishing Dissection module: the phishing campaign targeted the `dmarsh@meddefense.com` account.
**Confidence level:** 4x00 CONTEXT (not independently verified by any packet capture in this investigation)
**What the packet evidence proves:** Nothing directly — this phase is included for narrative completeness only. Confirming the exact delivery timestamp, sender infrastructure and email content requires the mail gateway logs referenced in Section 7.

### Phase 2 — Credential Harvesting Session
**MITRE ATT&CK:** T1056.003 (Input Capture: Web Portal Capture)
**Evidence citation:** `phishing_click.pcap` — DNS query for `meddefense-portal.com` resolving to `91.234.99.107`, and a TLS ClientHello with SNI `meddefense-portal.com`, both within the session observed at **2026-04-14, 15:02:33-15:03:20 UTC**. The session exchanged approximately 1,633 bytes client-to-server and 14,521 bytes server-to-client across 8/31 TLS application-data segments respectively.
**Confidence level:** STRONG INFERENCE (the session to the phishing portal is CONFIRMED; that a credential form was actually submitted, and what was in it, is inferred from the session's shape, since TLS encrypts the content)
**What the packet evidence proves:** That the affected host visited the phishing portal and exchanged an amount of data consistent with a form submission and response. It does not prove what was typed, whether the user completed the form, or that a real credential was submitted rather than an aborted attempt.

### Phase 3 — Command-and-Control Beaconing
**MITRE ATT&CK:** T1071.001 (Application Layer Protocol: Web Protocols)
**Evidence citation:** `c2_beaconing.pcap` — 24 TLS sessions from `10.10.2.15` to `91.234.99.107` between **2026-04-15, 02:00:12 and 03:55:08 UTC**, at a mean interval of 299.8 seconds with a standard deviation of 5.3 seconds.
**Confidence level:** CONFIRMED (the session pattern itself, including its regularity, is directly observable in the packet timestamps)
**What the packet evidence proves:** That the compromised host maintained regular, automated contact with the same external IP used for credential harvesting, for nearly two hours. It does not prove what commands, if any, were exchanged inside the encrypted sessions.

### Phase 4 — External Access / VPN Pivot
**MITRE ATT&CK:** T1133 (External Remote Services)
**Evidence citation:** `full_timeline.pcap` — a TLS-wrapped TCP session from external IP `154.118.42.89:49872` to internal VPN endpoint `10.10.0.1:443`, beginning at **2026-04-15, 13:45:22 UTC** and closing (explicit FIN/RST) at approximately **14:33:47 UTC** (~48 minutes). A plaintext authentication-context marker within this session's packet data read `AUTH:user=dmarsh,pass=***,2fa=none`.
**Confidence level:** STRONG INFERENCE (the external-to-internal TLS session and its duration are CONFIRMED; that this represents successful authentication as `dmarsh`, versus an authentication attempt, is inferred from the marker and session behavior — this module's synthetic captures embed this marker in plaintext, which would not be the case for a genuinely encrypted production VPN, so the underlying detection principle, not this specific marker, is what should be relied on in a real environment)
**What the packet evidence proves:** That an external IP established a sustained encrypted session to the internal VPN gateway, for a duration consistent with active use, at the stated timestamps. Live geolocation of `154.118.42.89` (obtained on an internet-connected analysis host, not reproducible inside this report's own sandboxed testing environment) returned **AS37340, Spectranet Limited, Nigeria** — geographically and organizationally inconsistent with MedDefense's expected user base, pending confirmation against actual employee travel or remote-access records. No candidate "assigned internal IP" for the VPN client was found distinct from the gateway's own address in this capture.

### Phase 5 — Lateral Movement (RDP)
**MITRE ATT&CK:** T1021.001 (Remote Services: Remote Desktop Protocol)
**Evidence citation:** `lateral_movement.pcap` / `full_timeline.pcap` — an RDP (TCP/3389) connection from `10.10.2.15` (WS-NURSE-04, a clinical workstation) to `10.10.1.10` (billing-srv-01) at **2026-04-15, 14:30:12 UTC**, approximately 45 minutes after the VPN session began.
**Confidence level:** CONFIRMED (the connection itself, its endpoints, and its timing relative to the VPN session are directly observable)
**What the packet evidence proves:** That a clinical workstation — a system with no legitimate business reason to reach a billing server — opened an RDP session to that server, 45 minutes after external VPN access began. Because RDP with Network Level Authentication encrypts the logon exchange, the account name used for this specific RDP session is **not visible at the packet level** and cannot be confirmed as `dmarsh` from this capture alone; that link is an inference from timing and the VPN-side marker, not a packet-level fact.

### Phase 6 — Discovery (SMB Enumeration)
**MITRE ATT&CK:** T1135 (Network Share Discovery), T1083 (File and Directory Discovery)
**Evidence citation:** No SMB2 tree-connect, file-create, or query-directory activity was found in either `lateral_movement.pcap` or `full_timeline.pcap` when analyzed with `4-lateral_movement.sh` and `6-kill_chain.sh`.
**Confidence level:** NOT VISIBLE IN PCAP
**What the packet evidence proves:** Nothing — this phase is included because it is a common step in this attack pattern and its absence is itself a finding. The evidence-cross-check work in Task 8 deliberately reports this as not observed rather than assuming it occurred, since the alternative (asserting SMB enumeration happened without packet support) is the exact overclaiming this investigation is designed to avoid. Discovery activity may still have occurred outside this capture's window or scope; server- or endpoint-side logs (Section 7) would be needed to confirm or rule it out.

### Phase 7 — Exfiltration (DNS Tunneling)
**MITRE ATT&CK:** T1048.003 (Exfiltration Over Alternative Protocol)
**Evidence citation:** `dns_exfil.pcap` — of 487 total DNS queries from `billing-srv-01` (10.10.1.10) over a ~30-minute window beginning **2026-04-16, 00:15 UTC**, 120 were classified anomalous (leftmost query-label length 44-60 characters, average 52.2, at a steady 10.0-15.0-second interval versus a 1.3% TXT-query baseline established in Task 0). A sample of five anomalous labels decoded successfully as base32, yielding readable fragments including `patient_record:ID=4892,name=...` and `server_config:hostname=billin...`; a corresponding TXT response decoded as base64 to `CMD:continue,next_batch:4893-4900`.
**Confidence level:** CONFIRMED for the tunneling channel and pattern; STRONG INFERENCE for the specific data content, since only a five-label sample was decoded and the full 120-query payload was not reconstructed
**What the packet evidence proves:** That billing-srv-01 ran a sustained, regularly-timed DNS query pattern structurally consistent with DNS tunneling, carrying decodable fragments that reference patient-record identifiers. It does not prove the complete content or volume of data actually exfiltrated, nor that every one of the 120 anomalous queries carried patient data rather than command/control traffic (the decoded TXT response above appears to be a control instruction, not data).

## Network-Level IOC Table

| Type | Value | Source | Confidence | Detection utility |
|---|---|---|---|---|
| Domain | `meddefense-portal.com` | 4x01 Tasks 0, 1 (DNS + TLS SNI, confirmed) | Confirmed | High — exact-match SNI/DNS rule (see Detection 6) |
| IPv4 | `91.234.99.107` | 4x01 Tasks 0, 1, 3, 6 (phishing portal, also C2 beaconing destination) | Confirmed | High — firewall/proxy blocklist and beaconing-destination rule |
| IPv4 | `154.118.42.89` | 4x01 Task 5 (VPN pivot source), geolocated to AS37340 / Spectranet Limited / Nigeria | Confirmed | Medium — geo/ASN anomaly rule (Detection 3); a single IP is easy for an attacker to rotate away from |
| Account | `dmarsh@meddefense.com` / `dmarsh` | 4x00 (phishing target) and 4x01 Task 5 (VPN auth-context marker) | Strong inference (packet-level marker, not authentication-log confirmation) | High as a monitoring subject once flagged; not usable as a standalone detection value |
| Host | `billing-srv-01` (10.10.1.10) | 4x01 Tasks 3, 4, 5, 6 (RDP target, DNS-exfiltration source) | Confirmed | High — this host should be a monitoring priority regardless of other IOCs |
| Host | `WS-NURSE-04` (10.10.2.15) | 4x01 Tasks 4, 6 (RDP source, beaconing source) | Confirmed | High — likely patient-zero for this incident's network activity |
| Domain (real portal, for contrast) | `meddefense.com` | 4x01 Task 1 (post-click DNS to the legitimate portal, confirms user recognized the earlier domain was wrong) | Confirmed | Low as a detection value; useful for timeline narrative only |

This table combines every IOC independently confirmed within the 4x01 module's own packet analysis. It does **not** include the full IOC set from the original 4x00 Phishing Dissection report, since that document's IOC list was not available to this report's authors as a data source — Section 11 below covers the continuity relationship at a narrative level; a full IOC-table merge against 4x00's original list is recommended as a follow-up action.

## Impact Assessment

**Data likely exfiltrated:** Structured records referencing patient identifiers (e.g. `patient_record:ID=4892,name=...`) and billing-server configuration data, exfiltrated via DNS TXT tunneling from `billing-srv-01`. The exact volume and completeness of the exfiltrated dataset is **not confirmed** — only a five-label decoded sample exists; the remaining 115 anomalous queries were classified but not individually decoded in this report.

**Systems involved:** `WS-NURSE-04` (10.10.2.15, clinical workstation, apparent initial compromise/beaconing point), the VPN gateway (`10.10.0.1`), and `billing-srv-01` (10.10.1.10, RDP target and exfiltration source).

**Systems protected or not reached:** No SMB-based enumeration or spread beyond `billing-srv-01` was observed in any capture analyzed (Section 4, Phase 6). No evidence was found of the attacker reaching any host other than the two named above. This should be read as "not observed in these captures," not as a guarantee that no further systems were touched.

**Credential exposure:** The `dmarsh` account's credentials are strongly implicated in both the VPN pivot and the RDP session, based on packet-level markers and timing rather than authentication-log confirmation. The exact password is not recoverable from this evidence (the harvesting session was TLS-encrypted; the VPN marker redacts the password field).

**Regulatory/business concerns:** The exfiltrated fragments reference patient record identifiers from a healthcare billing system, which raises potential HIPAA breach-notification obligations pending legal/compliance review of exactly what data left the network. This report provides the network-forensics timeline needed to support that review but does not itself constitute a breach determination.

## Detection Gap Analysis

**What packet evidence revealed:** A complete, timestamped network path from a phishing click through C2 beaconing, VPN pivot, RDP lateral movement, and DNS-tunneling exfiltration, all traceable to specific packets in the captures listed in Section 2.

**What could have detected the activity earlier:**
- The credential-harvesting domain (`meddefense-portal.com`) and its IP were never referenced against a first-seen/IOC table until this investigation — an IOC-matching rule (Detection 6) would have flagged the very first DNS query to it.
- The beaconing pattern ran for nearly two hours at a highly regular interval before any other phase began — a frequency/regularity detection (Detection 1) would have caught this the same night.

**Behavioral detection gaps:** No evidence exists that the beaconing pattern's regularity (299.8s mean, 5.3s stdev) was monitored anywhere in the environment; this is a purely statistical signal that requires either SIEM correlation, a Zeek script, or flow analytics — none of which this investigation found evidence of being in place (Task 7, Detection 1).

**DNS tunneling detection gap:** 120 anomalous-length TXT queries were sent from a single production server over 30 minutes with no apparent alerting; a query-length and TXT-frequency rule (Task 7, Detections 2 and 5) would have caught this in real time rather than post-incident.

**VPN anomaly detection gap:** The VPN session originated from an ASN and country with no established relationship to MedDefense; there is no evidence a geo/ASN anomaly check exists on the VPN gateway (Task 7, Detection 3).

**Lateral movement detection gap:** A clinical workstation account reached a billing server over RDP with no apparent role-based restriction in place; a cross-role RDP rule (Task 7, Detection 4) would have flagged this connection at the moment it was established.

## Detection Rules Recommended

The following rules were fully specified, with pseudocode, test scenarios grounded in this incident's own confirmed evidence, expected false positives and required data sources, in `7-detection_rules.sh`. This table is a catalog summary; see that script's output for the complete logic.

| Rule name | Data source required | Attack phase detected | False positive considerations |
|---|---|---|---|
| C2 Beaconing (frequency + interval regularity) | Proxy/firewall logs, Zeek conn.log, or NetFlow | Phase 3 — Beaconing | Regular software update/monitoring/backup clients; needs a baseline/allowlist |
| DNS Query Length Anomaly | DNS resolver logs / Zeek dns.log | Phase 7 — Exfiltration | CDN/DKIM/some IoT provisioning schemes use long subdomain labels legitimately |
| VPN Geo-Anomaly | VPN auth logs + GeoIP/ASN feed + per-account geography baseline | Phase 4 — VPN Pivot | Legitimate travel, VPN relay services, ISP routing through a different ASN |
| Cross-Role RDP | RDP connection logs/PCAP + authentication logs + role/subnet mapping | Phase 5 — Lateral Movement | Legitimate IT helpdesk access from a non-jump-host workstation |
| DNS Tunneling TXT Query Pattern | DNS resolver logs / Zeek dns.log (type + frequency) | Phase 7 — Exfiltration | High-volume legitimate TXT usage (SPF/DKIM/DMARC bulk mail) |
| TLS to Recently Observed Lookalike Domain | TLS SNI metadata + maintained first-seen/IOC table | Phase 2 — Credential Harvesting | Low, by design; the table itself needs periodic review to avoid staleness |

## Recommendations

**Immediate (next 24 hours):**
- Isolate `WS-NURSE-04` (10.10.2.15) and `billing-srv-01` (10.10.1.10) from the network pending forensic imaging.
- Reset the `dmarsh` account's credentials and any credentials shared with or derived from it, and force re-authentication with MFA on all its active sessions.
- Block `91.234.99.107` and `154.118.42.89` (and the `meddefense-portal.com` domain) at the firewall/proxy/DNS-sinkhole layer.
- Preserve all five PCAPs listed in Section 2 and this report's generating scripts as evidence, per the chain-of-custody notes in Section 10.

**Short-term (next 7 days):**
- Deploy the behavioral detection logic cataloged in Section 8 (beaconing, DNS anomaly, VPN geo-anomaly, cross-role RDP), starting in detection-only mode given the false-positive considerations noted.
- Review VPN access logs for the `dmarsh` account and any other account authenticating from unexpected geographies over the same period.
- Review DNS egress visibility — confirm whether DNS resolver/query logs exist and are retained long enough to support the Detection 2/5 rules going forward.
- Search for additional hosts exhibiting the same beaconing pattern (regular ~300s TLS sessions to `91.234.99.107` or any newly-identified C2 infrastructure) across the wider environment, not just the hosts named in this report.

**Medium-term (next 30 days):**
- Enforce stronger email authentication policy (SPF/DKIM/DMARC alignment, link-rewriting/sandboxing) to reduce the chance of a repeat of Phase 1.
- Improve DNS anomaly detection coverage environment-wide, not just for the hosts identified in this incident.
- Implement role-based RDP restrictions so clinical-role accounts and workstations cannot reach server-subnet hosts by default.
- Conduct a healthcare data exposure review (with legal/compliance) of exactly what the exfiltrated DNS-tunnel records could have contained, to support any regulatory notification decision.

## Evidence Chain

| PCAP file | Purpose | Capture time window (UTC) | Storage / handling notes |
|---|---|---|---|
| `normal_baseline_clinical.pcap` | Baseline comparison | Baseline period, ~30 min | Analyzed by `0-baseline_analysis.sh`; retained alongside this report's repository |
| `phishing_click.pcap` | Credential-harvesting session | 2026-04-14, ~15:02:33-15:03:20 | Analyzed by `1-phishing_click.sh` |
| `c2_beaconing.pcap` | Post-compromise beaconing | 2026-04-15, 02:00:12-03:55:08 | Analyzed by `6-kill_chain.sh` (Phase 3) |
| `dns_exfil.pcap` | DNS-tunneling exfiltration | 2026-04-16, ~00:15-00:45 | Analyzed by `3-dns_tunnel.sh` |
| `lateral_movement.pcap` | Cross-subnet RDP/SMB activity | 2026-04-15, RDP observed 14:30:12 | Analyzed by `4-lateral_movement.sh` |
| `full_timeline.pcap` | Composite VPN-pivot-through-lateral-movement capture | 2026-04-14 17:02:33 - 2026-04-16 00:16:00 | Analyzed by `5-vpn_pivot.sh` and `6-kill_chain.sh` |

**Hash values:** Not independently computed for this report. `capinfos <file>.pcap` produces SHA1/SHA256 hashes for each capture (used ad hoc during script validation) and should be re-run and formally logged as part of any official evidence-handling process; this report does not substitute for that step.

**Storage/evidence-handling notes:** All PCAPs and the scripts that analyze them are version-controlled in this repository (`threat_detection/4x01_wire_shark_territory/`). This module's working practice has been to analyze each capture in an isolated, network-restricted environment and never modify the original files; each script reads its PCAP argument read-only. Formal chain-of-custody documentation (who collected each capture, from which tap/span point, and when) was not available to this report's authors and should be added by whoever originally captured this traffic.

## Continuity with 4x00

This investigation updates the 4x00 Phishing Dissection findings as follows:

- **Credential exposure moves from likely to strongly supported.** 4x00 identified the phishing campaign and its target account; this investigation adds a packet-level session to the credential-harvesting portal at an exact timestamp, and a plaintext authentication-context marker for the same account in a subsequent VPN session — evidence that was not available at the 4x00 stage.
- **A network timeline is now documented.** 4x00's findings were email-centric; this report adds a fully timestamped network path from the click (2026-04-14, 15:02:33 UTC) through VPN pivot (2026-04-15, 13:45:22 UTC), lateral movement (14:30:12 UTC) and DNS exfiltration (2026-04-16, ~00:15 UTC) — a documented ~32-hour window from first network evidence to last.
- **Campaign infrastructure is linked to post-click activity.** The same IP (`91.234.99.107`) confirmed as the phishing portal in 4x00/Task 1 is also the C2 beaconing destination confirmed in Task 6, directly connecting the phishing infrastructure to the post-compromise network activity rather than leaving them as separately-suspected pieces.
- **DNS exfiltration expands the impact assessment.** 4x00's scope ended at the phishing click; this investigation adds a confirmed data-exfiltration channel from a production billing server, materially changing the incident's severity and regulatory profile beyond what the original phishing assessment could show.

A full merge of this report's IOC table against 4x00's original IOC list is recommended as a follow-up action, since that source document was not available to this report's authors (see Section 5).
