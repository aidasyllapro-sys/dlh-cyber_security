1-healthcare_mobile_app.md
# Threat Modeling - Healthcare Mobile App


1. System Overview
### Features

- View medical records
- Schedule appointments
- Message healthcare providers
- Receive prescription refills



2. Architecture & Trust Boundary Diagram

```
+------------------+
|  User Browser    |
| (React Frontend) |
+--------+---------+
         |
         | HTTPS
         |
+--------v---------+
|   Node.js API    |
+--------+---------+
         |
   +-----+------+
   |            |
   |            |
   v            v
PostgreSQL   Stripe API
 Database
```

3. Question 1 — STRIDE Threats on the Checkout Process


STRIDE categories: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.



Threat 1 — Tampering: Client-Side Price Manipulation

FieldDetailSTRIDE categoryTamperingDescriptionThe React frontend sends cart/price data (item price, quantity, discount) in the checkout request body. If the backend trusts this data instead of recalculating it server-side, an attacker can intercept the request (e.g., via browser dev tools or a proxy like Burp Suite) and modify the price field before it reaches the API.Attack scenarioA user adds a $500 item to the cart, then uses the browser's network inspector or an intercepting proxy to change "price": 500 to "price": 1 in the outgoing checkout request before it hits the Node.js API.Potential impactDirect financial loss; attacker pays a fraction of the real price; if undetected, could be automated at scale (bulk fraud).Suggested mitigationNever trust price/amount values sent from the client. Recalculate the total order amount server-side by looking up authoritative prices from the PostgreSQL product table at checkout time. Sign or validate cart contents server-side before creating the Stripe payment intent.

Threat 2 — Information Disclosure: Payment Data Interception

FieldDetailSTRIDE categoryInformation DisclosureDescriptionPayment-related data (card details, tokens, personal billing info) transmitted between the frontend, the Node.js API, and Stripe could be exposed if transport isn't properly secured, or if the backend logs sensitive payment payloads.Attack scenarioAn attacker performs a man-in-the-middle attack on an unsecured network (e.g., public Wi-Fi) if TLS is misconfigured or absent on any hop, or extracts sensitive data from application logs/error messages that inadvertently include raw payment payloads.Potential impactExposure of cardholder data, potential PCI-DSS compliance violation, reputational damage, regulatory fines.Suggested mitigationEnforce HTTPS/TLS everywhere (HSTS enabled). Never let raw card data touch your own backend — use Stripe Elements/Checkout so card data goes directly from the browser to Stripe, and your API only ever handles Stripe tokens. Scrub logs of sensitive fields, and audit for accidental logging of request bodies.

Threat 3 — Repudiation: Lack of Transaction Audit Trail

FieldDetailSTRIDE categoryRepudiationDescriptionIf the system does not log who initiated a checkout, when, and with what parameters, a user (or an attacker who compromised an account) could deny having made a purchase, or dispute a charge with no way for the platform to prove the transaction's legitimacy.Attack scenarioA user completes a purchase, then later files a chargeback claiming "I never made this order." Without immutable, timestamped, user-attributed logs tying the checkout action to an authenticated session, the platform cannot counter the dispute.Potential impactFinancial loss from fraudulent chargebacks, inability to investigate account takeover fraud, loss of legal/audit evidence.Suggested mitigationImplement structured, tamper-evident audit logging for all checkout events (user ID, session ID, IP, timestamp, order ID, Stripe payment intent ID). Store logs in an append-only or write-once store. Correlate with Stripe's own event logs (webhooks) for cross-verification.

Note: a strong fourth candidate worth considering is Elevation of Privilege via IDOR on order endpoints (e.g., /orders/{id} accessible by changing the ID to view another user's order) — flagging this since the task only asked for three, but it's a very common real-world issue in this exact architecture.


4. Question 2 — Trust Boundaries

At least three trust boundaries exist in this system:


Browser ↔ Node.js API (Client/Server boundary).
Everything coming from the React frontend — cart contents, search queries, checkout payloads — originates in an untrusted environment fully controllable by the end user (browser dev tools, intercepting proxies, modified JS). This is the most critical boundary: all data crossing it must be treated as untrusted and re-validated server-side.
API ↔ PostgreSQL database (Application/Data layer boundary).
Even though the API itself is "trusted" infrastructure, any user-influenced value that flows into a SQL query (search terms, filters, IDs) crosses into the data layer and must be parameterized/sanitized. A compromise or bug at the API layer (e.g., SQL injection) lets an attacker pivot straight into the data boundary.
API ↔ Stripe (Internal/Third-party service boundary).
Data leaving the platform's own infrastructure to a third party (and data coming back via webhooks) crosses an external trust boundary. The platform must authenticate Stripe webhooks (signature verification) and must not blindly trust anything claiming to be a Stripe callback.
(Optional fourth boundary) Unauthenticated ↔ Authenticated zones within the API itself.
Browsing and cart actions require no authentication, while checkout and order history do. This is an internal trust boundary: session/auth middleware must correctly gate access so that unauthenticated requests can never reach authenticated-only logic (e.g., order history for another user).



5. Question 3 — DREAD Scoring: SQL Injection in Product Search


Note on methodology: DREAD scores are inherently a qualitative, subjective risk-ranking exercise — the numbers below reflect reasoned judgment for this scenario (each factor scored 1–10), not an empirically measured statistic. Treat this as a documented rationale, not a precise, verified figure — worth revisiting with real data (WAF logs, actual traffic volume) if this were a live system.



Formula: DREAD Score = (Damage + Reproducibility + Exploitability + Affected Users + Discoverability) / 5

FactorScore (1–10)JustificationDamage8If the search query is not parameterized, an attacker could potentially read or exfiltrate data across the whole database (not just products) — depending on DB user privileges, this could include user accounts and order data. High damage potential, though not "10" since it assumes a worst-case misconfiguration (overly broad DB permissions) rather than a guaranteed outcome.Reproducibility9If the vulnerability exists, it is reliably reproducible: the same crafted input in the search box will trigger the same behavior every time, with no race conditions or timing dependencies involved.Exploitability7Exploiting it requires only basic-to-intermediate SQL injection knowledge and widely available tooling (e.g., SQLMap). No authentication is required, which lowers the bar significantly — but modern parameterized-query frameworks and ORMs make blind, unprotected SQLi somewhat less likely by default, so it's not a "trivial" 10.Affected Users9Product search is unauthenticated and public-facing, meaning every visitor (not just registered users) is exposed to the vulnerable endpoint. If exploited to pivot into other tables, the data impact could affect the entire user base, not just searchers.Discoverability8Search bars are one of the first things both manual testers and automated scanners (or attackers) probe on any e-commerce site, since they're a well-known classic injection point. Easily discoverable with minimal reconnaissance.

Total: (8 + 9 + 7 + 9 + 8) / 5 = 8.2 / 10 → High Risk

Suggested Mitigation


Use parameterized queries / prepared statements (or an ORM with built-in parameter binding) for all search and filter logic — never string-concatenate user input into SQL.
Apply least-privilege DB credentials for the API's database user (no unnecessary read access to unrelated tables like users or payments from the product-search code path).
Add input validation (allow-list expected characters/length for search terms) as defense-in-depth, not as the primary control.
Consider a WAF rule set (e.g., OWASP Core Rule Set) to catch common SQLi payload patterns as an additional layer.



6. Summary Risk Priority

ThreatSTRIDE / TypeEstimated SeveritySQL Injection in product searchTampering / Info DisclosureHigh (DREAD 8.2)Client-side price manipulationTamperingHighPayment data interceptionInformation DisclosureHighMissing audit trailRepudiationMedium

All scores above are reasoned estimates for this exercise, produced following the DREAD methodology described in the course resources — they should be re-validated against real traffic, actual DB permissions, and a real pentest if this were a production system.

