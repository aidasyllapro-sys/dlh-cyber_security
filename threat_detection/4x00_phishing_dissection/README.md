MedDefense Health Systems: Phishing Dissection

Eight emails hit the queue in a 57-hour window between April 14 and 16, 2026: six reported by end users through the helpdesk, two pulled straight from Proofpoint quarantine. One of them, E2, is not hypothetical — Diane Marsh (WS-NURSE-04) clicked the link roughly 36 hours before the batch was collected. Angela Rivera in Accounts Payable flagged an invoice that "looks wrong." Linda Patterson in Billing swears she never signed up for the benefits portal that keeps emailing her. James Chen, SOC Lead, needs this triaged, investigated, and turned into evidence-backed conclusions — and HC3 just confirmed the same campaign is hitting other healthcare orgs across the region.

This project produces no automated tooling. Every deliverable is a Markdown investigation document: full raw SMTP headers dissected by hand, SPF/DKIM/DMARC results read and interpreted rather than assumed, URLs and attachments investigated exclusively through sandboxes and command-line OSINT tools (never opened or navigated to directly), and every classification tied back to specific evidence in the headers, authentication results, or OSINT findings — never guessed.

See 0-initial_triage.md onward for the full deliverable set.
