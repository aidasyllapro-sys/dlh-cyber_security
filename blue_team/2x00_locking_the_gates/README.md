# MedDefense Health Systems: Locking the Gates

Three Linux servers, billing-srv-01, web-srv-01, and log-srv-01, are running today with default configurations already flagged as named findings: 1x02 Finding 009 (SSH password authentication), Finding 011 (Ubuntu 18.04 without Extended Security Maintenance, now resolved by an OS upgrade but still needing full hardening), and Finding 026 (an outdated kernel carrying 47 known CVEs). The CISA Crimson Tide advisory confirmed every hospital breach in the campaign started with a misconfigured service on a reachable server, exactly the condition these three servers are in right now.

This project produces no report. Every deliverable is a shell script: idempotent, producing structured JSON output, and capable of hardening a fresh system from zero to production-ready in one execution. Every hardening action is tied back to the specific finding or Crimson Tide phase it closes, and every CIS Benchmark recommendation not applied is documented with its justification and compensating control, not silently skipped.

See `0-baseline_snapshot.sh` onward for the full deliverable set.
