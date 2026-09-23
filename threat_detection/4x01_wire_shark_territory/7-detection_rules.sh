#!/bin/bash
#
# 7-detection_rules.sh
#
# MedDefense Health Systems — Wireshark Territory (Task 7: The Detection
# Engineering)
#
# Purpose
#   Turns each gap identified in the kill-chain reconstruction (Task 6)
#   into an operational detection rule: rule logic/pseudocode, a concrete
#   test scenario grounded in this module's own confirmed evidence, the
#   attack phase it covers, expected false positives, and the data source
#   required to run it in production.
#
#   This script has no PCAP input and runs no tshark commands: it is a
#   detection-engineering plan, not a packet analyzer. The concrete values
#   used in each test scenario (IPs, domains, intervals, host names) are
#   not invented for this document — they are the same values confirmed
#   by tshark against the real PCAPs of this module in Tasks 0, 1, 3, 4
#   and 5 (0-baseline_analysis.sh, 1-phishing_click.sh, 3-dns_tunnel.sh,
#   4-lateral_movement.sh, 5-vpn_pivot.sh), reused here to ground each
#   rule's test scenario in this incident's actual findings rather than a
#   generic example.
#
# Usage
#   ./7-detection_rules.sh
#
set -uo pipefail

echo "\$ ./7-detection_rules.sh"
echo ""
echo "================================================================"
echo "   DETECTION ENGINEERING PLAN"
echo "================================================================"
echo ""

# ---------------------------------------------------------------------------
# Detection 1: C2 Beaconing
# ---------------------------------------------------------------------------
cat <<'EOF'
[*] Detection 1: C2 Beaconing
    Type: Frequency-based behavioral detection

    Logic (pseudocode):
      FOR EACH (src_ip, dst_ip) pair, in a sliding 3600-second window:
        sessions = sessions where src == src_ip AND dst == dst_ip
        IF count(sessions) > 10:
          intervals = time deltas between consecutive session start times
          mean = average(intervals)
          stddev = standard_deviation(intervals)
          IF stddev < mean * 0.15:
            ALERT "Possible C2 beaconing: <src_ip> -> <dst_ip>, "
                  "<count> sessions, mean=<mean>s, stddev=<stddev>s"

    Implementation options:
      - SIEM rule: a scheduled correlation search (e.g. Splunk SPL /
        Sentinel KQL) over proxy or firewall connection logs, grouping by
        (src_ip, dst_ip) in a rolling window and computing interval
        mean/stddev with the platform's stats functions.
      - Zeek script: a script hooking connection_state_remove, keyed on
        id$orig_h/id$resp_h, maintaining a per-pair vector of connection
        start times and evaluating the same threshold on each new
        connection; Zeek's conn.log already carries the timestamps needed.
      - Python scheduled analysis: a job run every N minutes against
        exported flow/proxy logs (pandas groupby on src/dst, rolling
        window, numpy for mean/stddev), suited to environments without a
        SIEM correlation engine or Zeek deployed.
      - NetFlow analytics: the same grouping and interval-regularity logic
        expressed against flow records (src/dst IP, port, timestamps) in a
        NetFlow/IPFIX collector, useful where full packet or proxy logs
        are not retained but flow records are.

    Test scenario (this module's confirmed evidence):
      10.10.2.15 connects to 91.234.99.107 every ~300 seconds for 24
      sessions between 2026-04-15 02:00 and 03:55 — confirmed by
      tshark against c2_beaconing.pcap (mean interval 299.8s, stdev 5.3s),
      well inside the stddev < mean * 0.15 threshold above.

    Would detect:
      Phase 3 (Beaconing) of the kill chain.

    Expected false positives:
      Software update clients, monitoring/heartbeat agents, backup
      software and health-check probes are often just as regular. This
      rule needs a baseline/allowlist of known-regular internal services
      before it is enabled in alerting mode, and should start in a
      detection-only (non-blocking) tier.

    Required data source:
      Proxy logs, firewall connection logs, Zeek conn.log, or NetFlow/
      IPFIX records with per-connection source IP, destination IP and
      timestamp — PCAP-derived session logs work equally well but are
      rarely retained long enough for production use.

EOF

# ---------------------------------------------------------------------------
# Detection 2: DNS Query Length Anomaly
# ---------------------------------------------------------------------------
cat <<'EOF'
[*] Detection 2: DNS Query Length Anomaly
    Type: Structural/statistical detection on DNS query names

    Logic (pseudocode):
      FOR EACH DNS query:
        leftmost_label = first dot-separated label of dns.qry.name
        IF length(leftmost_label) > 40:
          ALERT "Possible encoded/tunneled DNS label: <qname> "
                "from <src_ip>"

    Why an oversized label indicates possible tunneling:
      A legitimate hostname label is short and human-readable (a service
      or host name). DNS tunneling tools encode arbitrary data — file
      contents, command output, exfiltrated records — into the query
      name itself, typically via base32/base64/hex, because the label can
      carry up to 63 characters and the full query name up to 253. An
      encoded payload of any real size pushes the leftmost label toward
      that ceiling and gives it a flat, high-entropy character
      distribution (versus the short, low-entropy, dictionary-like labels
      of normal hostnames) — both are usable detection signals, and label
      length alone is the cheapest first-pass filter.

    Test scenario (this module's confirmed evidence):
      billing-srv-01 (10.10.1.10) issues DNS queries with leftmost labels
      44-60 characters long against a single base domain — confirmed by
      tshark against dns_exfil.pcap (120 of 487 total queries flagged,
      average anomalous label length 52.2 characters).

    Would detect:
      Phase 7 (Exfiltration) of the kill chain.

    Expected false positives:
      Some legitimate services encode data in subdomains by design (CDN
      edge routing, email authentication/DKIM selectors, certain cloud
      load-balancer health-check names). A fixed allowlist of these
      known-legitimate patterns, or combining this rule with the TXT/
      frequency criteria of Detection 5, reduces false positives.

    Required data source:
      DNS query logs (resolver logs, Zeek dns.log, or PCAP-derived DNS
      records) with the full query name and source IP per query.

EOF

# ---------------------------------------------------------------------------
# Detection 3: VPN Geo-Anomaly
# ---------------------------------------------------------------------------
cat <<'EOF'
[*] Detection 3: VPN Geo-Anomaly
    Type: Contextual/geolocation-based detection

    Logic (pseudocode):
      ON each successful VPN authentication event:
        geo = geolocate(source_ip)   # country, ASN, organization
        expected = expected_geo_set(account)  # per-account or per-org baseline
        IF geo.country NOT IN expected.countries
           OR geo.asn NOT IN expected.asns:
          IF account has no prior successful login from geo.country:
            ALERT "Suspicious VPN login: <account> from <source_ip> "
                  "(<geo.country>, AS<geo.asn>) — no prior history "
                  "from this geography"

    Would detect:
      Phase 4 (External Access / VPN Pivot) of the kill chain.

    Test scenario (this module's confirmed evidence):
      A VPN session authenticates as dmarsh from 154.118.42.89 at
      2026-04-15 13:45:22 — confirmed by tshark against
      full_timeline.pcap. On the machine running 5-vpn_pivot.sh with
      outbound network access, a live whois lookup resolved this IP to
      AS37340 / Spectranet Limited, Nigeria; that lookup could not be
      completed inside this sandbox (no outbound access to
      whois.cymru.com here), so this specific country/ASN pairing is
      reported as confirmed only where the live lookup actually ran, not
      assumed.

    Required data source:
      VPN authentication logs (account, source IP, timestamp) joined
      against an IP geolocation/ASN feed (commercial GeoIP database, or a
      WHOIS/RDAP lookup service such as Team Cymru's) and an
      account-level "expected geography" baseline built from historical
      successful logins — without that baseline, "anomalous" cannot be
      defined and this rule degrades to a static country blocklist.

    Expected false positives:
      Legitimate travel, VPN exit-node/relay services used by remote
      employees, and ISPs that route through a different country's ASN
      can all trigger this rule; it should feed a review queue rather
      than auto-block, at least until the per-account baseline matures.

EOF

# ---------------------------------------------------------------------------
# Detection 4: Cross-Role RDP
# ---------------------------------------------------------------------------
cat <<'EOF'
[*] Detection 4: Cross-Role RDP
    Type: Identity/role-based detection

    Logic (pseudocode):
      ON each RDP (TCP/3389) session establishment:
        account = resolve_account(session)      # from auth logs, not the PCAP alone
        dest_subnet = subnet_of(destination_ip)
        IF role_of(account) IN {clinical, non-IT}
           AND dest_subnet == server_subnet:
          ALERT "Possible lateral movement: <account> (role=<role>) "
                "RDP to <destination_ip> in server subnet"

    How to detect this from packet metadata vs. authentication logs:
      Packet metadata alone (source IP, destination IP, TCP/3389,
      timing) is enough to flag "workstation subnet -> server subnet RDP"
      as an anomaly, but NLA-encrypted RDP logons do not expose the
      account name at the packet level — this was directly observed in
      4-lateral_movement.sh, where the account field had to be reported
      as "not visible in this capture". Determining the account's ROLE
      (clinical vs. IT) therefore requires joining the connection event
      to an authentication log or directory service (Windows Security
      log 4624/4625 with logon type 10, or a Kerberos/NTLM auth log) by
      timestamp and source host, not to the PCAP alone.

    Test scenario (this module's confirmed evidence):
      WS-NURSE-04 (10.10.2.15) initiates an RDP connection to
      billing-srv-01 (10.10.1.10) at 2026-04-15 14:30:12 — confirmed by
      tshark against lateral_movement.pcap. A clinical workstation
      reaching a billing server over RDP is itself an anomaly by subnet
      role, independent of whether the account name can be recovered.

    Would detect:
      Phase 5 (Lateral Movement) of the kill chain.

    Expected false positives:
      Legitimate IT helpdesk or break-glass administrative access
      performed from a workstation rather than a jump host; a shared
      account whose "role" is not accurately reflected in the directory.
      Requiring a maintained role/subnet mapping and excluding known
      jump-host or PAM-brokered sessions reduces noise.

    Required data source:
      Network connection logs or PCAP for the RDP session itself, plus
      Windows Security event logs (or an equivalent authentication log)
      and a role/subnet mapping (which accounts are clinical/IT, which
      subnets are workstation/server) to join against.

EOF

# ---------------------------------------------------------------------------
# Detection 5: DNS Tunneling TXT Query Detection
# ---------------------------------------------------------------------------
cat <<'EOF'
[*] Detection 5: DNS Tunneling TXT Query Pattern
    Type: Frequency + structural detection on TXT queries

    Logic (pseudocode):
      FOR EACH (src_ip, base_domain), in a sliding 120-second window:
        txt_queries = TXT-type queries where src == src_ip
                      AND base_domain(qname) == base_domain
        IF count(txt_queries) > 10
           AND any(query has an encoded-looking leftmost label,
                   e.g. length > 40 or high character-set entropy):
          ALERT "Possible DNS tunneling: <src_ip> -> <base_domain>, "
                "<count> TXT queries in 120s with encoded labels"

    Test scenario (this module's confirmed evidence):
      billing-srv-01 (10.10.1.10) issues repeated TXT queries carrying
      base32/base64-encoded fragments (decoded examples during Task 3's
      validated run included "patient_record:ID=4892,name=..." and a TXT
      response "CMD:continue,next_batch:4893-4900") against a single base
      domain, at a steady 10-15 second interval — confirmed by tshark
      against dns_exfil.pcap.

    Would detect:
      Phase 7 (Exfiltration) of the kill chain. This complements
      Detection 2: Detection 2 flags the label-length signal alone (cheap,
      broad), Detection 5 adds query-type and frequency to reduce false
      positives before alerting.

    Expected false positives:
      Any legitimate high-volume TXT usage (SPF/DKIM/DMARC lookups during
      bulk mail processing, some IoT/device-provisioning schemes that use
      TXT records for configuration) — filtering to only the encoded-
      label subset, as this rule does, removes most of that overlap.

    Required data source:
      DNS query logs with query type, full query name, source IP and
      timestamp (resolver logs, Zeek dns.log, or PCAP-derived DNS
      records) — the same source as Detection 2, with type and frequency
      added.

EOF

# ---------------------------------------------------------------------------
# Detection 6: TLS to Recently Observed Lookalike Domain
# ---------------------------------------------------------------------------
cat <<'EOF'
[*] Detection 6: TLS to Recently Observed Lookalike Domain
    Type: IOC/first-seen-table detection (no live domain-age feed required)

    Logic (pseudocode):
      # ioc_table: a maintained list of {domain, first_seen_context}
      # populated from prior phishing/IOC investigations (e.g. this
      # module's own confirmed IOC: meddefense-portal.com), NOT a live
      # WHOIS domain-age lookup.
      ON each TLS ClientHello:
        sni = tls.handshake.extensions_server_name
        IF sni IN ioc_table:
          ALERT "TLS session to known phishing-campaign domain: <sni> "
                "from <src_ip>, first observed in <ioc_table[sni].context>"

    Why this does not require a live domain-age feed:
      Domain-age/WHOIS-registration-date feeds are one way to catch a
      lookalike domain BEFORE it is known malicious, but they need an
      external, often paid, real-time feed. This rule instead works from
      a first-seen/IOC table built from this organization's own prior
      investigations (exactly the kind of table Tasks 0/1 of this module
      populated when they confirmed meddefense-portal.com and
      91.234.99.107 as IOCs) — any TLS SNI matching that table is an
      alert. It catches re-use of known infrastructure immediately and
      with no external dependency, at the cost of only covering domains
      already known to this organization (a genuinely new lookalike
      domain would not be caught until it is first confirmed some other
      way and added to the table).

    Test scenario (this module's confirmed evidence):
      A TLS ClientHello with SNI meddefense-portal.com is observed from
      an internal host at 2026-04-14 15:02:33 — confirmed by tshark
      against phishing_click.pcap, and meddefense-portal.com /
      91.234.99.107 are the confirmed IOCs from this module's Tasks 0
      and 1.

    Would detect:
      Phase 2 (Credential Harvesting Session) of the kill chain.

    Expected false positives:
      Low, by design — an exact SNI match against a curated table rarely
      false-positives on unrelated traffic. The residual risk is the
      table going stale (a retired IOC kept in the table forever) or a
      legitimate service later acquiring a domain previously used
      maliciously; the table needs periodic review, not just append-only
      growth.

    Required data source:
      TLS handshake metadata with the SNI field (PCAP-derived, a TLS-
      terminating proxy log, or passive DNS at the resolver) plus a
      maintained first-seen/IOC table populated from this organization's
      own investigations.

EOF

echo "=== DETECTION COVERAGE UPDATE ==="
echo "Before packet analysis:"
echo "  campaign visible only as email IOCs (4x00 Phishing Dissection module)"
echo ""
echo "After packet analysis:"
echo "  detections cover phishing click (Detection 6), beaconing (Detection 1),"
echo "  VPN pivot (Detection 3), lateral movement (Detection 4) and DNS"
echo "  exfiltration (Detections 2 and 5)."
echo ""
echo "Remaining gaps:"
echo "  endpoint execution confirmation requires endpoint (EDR/host) logs, which"
echo "  are outside the scope of any PCAP in this module"
echo "  exact credential content cannot be recovered from encrypted TLS sessions"
echo "  whether MFA was enabled, and whether any SIEM alert actually fired during"
echo "  this incident, are not determinable from packet evidence alone"
echo "================================================================"
