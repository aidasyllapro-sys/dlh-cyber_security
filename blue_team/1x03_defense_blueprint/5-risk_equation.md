# MedDefense Health Systems: The Risk Equation

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO, and Robert Kim, CFO **Source material:** `risk-scenarios.txt`, calculated using the standard quantitative risk formulas (SLE = AV x EF, ALE = SLE x ARO) and cross-referenced against every relevant finding from Projects 0x00, 1x01, and 1x02 **Purpose:** Replace "High risk" with a dollar figure a CFO can actually budget against. Every number below shows its full calculation and states plainly which assumption, if wrong, would change that number the most.

---

## Scenario 1: Ransomware Attack on Billing Server

**Asset Value (AV):** Not the server's hardware replacement cost, which is trivial, but the total financial exposure of a successful attack: 18 days of downtime at $16,000 per day ($288,000), plus recovery costs ($85,000), plus a mid-range HIPAA penalty for the exposed financial and patient-adjacent data ($100,000). AV = $288,000 + $85,000 + $100,000 = **$473,000**

**Exposure Factor (EF):** A successful ransomware attack on this server realistically triggers the full downtime period, the full recovery effort, and a plausible regulatory penalty all at once, not a fraction of any of them. EF = **100%**

**SLE = AV x EF = $473,000 x 1.0 = $473,000**

**ARO:** The sector rate given is one attack every 3 to 4 years for a similarly-profiled hospital. Using the midpoint of that range (3.5 years): ARO = 1 / 3.5 = **0.29**

**ALE = SLE x ARO = $473,000 x 0.29 = $137,170**

**Confidence: Medium.** The single assumption most likely to swing this number is whether the HIPAA penalty applies at all. This calculation assumes the attack exposes financial and patient-adjacent data sufficient to trigger a regulatory penalty; if the incident is contained to encryption alone with no confirmed data exfiltration, the $100,000 penalty component may not apply, dropping AV to $373,000 and ALE to roughly $108,170, a meaningful swing from a single yes-or-no assumption about what the attacker actually accessed.

---

## Scenario 2: Patient Data Breach via EHR System

**Asset Value (AV):** The full cost of a breach event, not the EHR system's own value: 50,000 records at $165 per record ($8,250,000), plus fixed HIPAA breach notification costs ($25,000), plus estimated litigation exposure ($200,000), plus the estimated reputational cost of 5% patient attrition over two years ($600,000). AV = $8,250,000 + $25,000 + $200,000 + $600,000 = **$9,075,000**

**Exposure Factor (EF):** As the task's own hint states, a breach event tends to trigger essentially all of these associated costs together rather than a partial subset. EF = **100%**

**SLE = AV x EF = $9,075,000 x 1.0 = $9,075,000**

**ARO:** The sector baseline given works out to roughly 1 breach every 3 years (ARO of approximately 0.33), but the supporting data explicitly states MedDefense carries higher-than-average risk. That elevation is not a vague impression; it traces to three specific, independently confirmed gaps from this program's own prior work: GAP-014 (no network segmentation), GAP-004 (no centralized detection), and GAP-003 (the EHR database's own network-wide exposure). Adjusting the sector baseline upward to reflect these confirmed, specific weaknesses: ARO = **0.45**

**ALE = SLE x ARO = $9,075,000 x 0.45 = $4,083,750**

**Confidence: Medium-Low.** The ARO adjustment from the 0.33 sector baseline to 0.45 is a judgment call, not data MedDefense directly measured, and it is the single largest driver of uncertainty in this figure. Had the unadjusted sector baseline of 0.33 been used instead, ALE would be $2,994,750, a difference of roughly $1.1 million from one assumption alone. The $165-per-record figure is also an industry average (Ponemon 2024), not a MedDefense-specific measurement.

---

## Scenario 3: Insider Data Theft (Negligent)

**Asset Value (AV):** The supporting data already expresses this scenario as a fully-loaded cost per incident, investigation ($30,000), containment ($25,000), remediation ($40,000), and regulatory reporting ($25,000), summing to the given $120,000 average. Rather than re-deriving a separate theoretical maximum, this figure is used directly as the value at stake per event. AV = **$120,000**

**Exposure Factor (EF):** Since the $120,000 figure already represents the realized, fully-loaded cost of one incident occurring, not a partial or best-case outcome. EF = **100%**

**SLE = AV x EF = $120,000 x 1.0 = $120,000**

**ARO:** The supporting data already isolates the negligent-specific estimate directly: 2 to 3 incidents per year, given MedDefense's 2,000 staff, 280 unrestricted clinical workstations, and confirmed absence of DLP or USB controls. Using the midpoint: ARO = **2.5**

**ALE = SLE x ARO = $120,000 x 2.5 = $300,000**

**Confidence: Medium.** The ARO range of 2 to 3 incidents per year is itself a sector-informed estimate adjusted for MedDefense's specific lack of controls, not a MedDefense-measured figure; if MedDefense's actual exposure runs higher, given 280 completely unrestricted workstations with no monitoring to catch smaller incidents before they compound, the true ARO could run higher than 3, and each additional incident per year adds $120,000 directly to the ALE. The $120,000 average incident cost is also a national Ponemon figure, not specific to MedDefense's own scale or record type.

---

## Scenario 4: Medical Device Compromise (BD Alaris Infusion Pumps)

The task's own hint correctly separates this into two distinct scenarios with very different probability and impact profiles; combining them into one figure would obscure more than it reveals.

**Denial-of-Service scenario:**

**AV:** This project's own prior research (1x02, Task 15) already established that this specific vulnerability class forces a pump into manual operation rather than destroying it or corrupting dosing directly, so device replacement cost is not the relevant driver here. The relevant cost is the operational disruption of running manual dosing while devices are quarantined: 5 days at $20,000 per day. AV = 5 x $20,000 = **$100,000**

**EF:** A DoS event, if it occurs, realizes the full disruption period as given. EF = **100%**

**SLE = $100,000 x 1.0 = $100,000**

**ARO:** Given directly as 1 in 10 years. ARO = **0.1**

**ALE (DoS) = $100,000 x 0.1 = $10,000**

**Patient-safety scenario:**

**AV:** The liability range given is wide, $500,000 to $5,000,000, and the midpoint is used here as the central estimate, plus FDA investigation costs ($150,000) plus the same operational disruption cost this event would also trigger ($100,000). AV = $2,750,000 + $150,000 + $100,000 = **$3,000,000**

**EF:** If a patient-safety event occurs, the full range of consequences realistically follows together. EF = **100%**

**SLE = $3,000,000 x 1.0 = $3,000,000**

**ARO:** Given directly as 1 in 50 years. ARO = **0.02**

**ALE (patient safety) = $3,000,000 x 0.02 = $60,000**

**Combined ALE for this risk = $10,000 + $60,000 = $70,000 per year.**

**Confidence: Low, specifically for the patient-safety component.** The liability range spans a full order of magnitude, $500,000 to $5,000,000, and this is by far the most consequential single judgment call in this entire document. Using the low end of that range instead of the midpoint drops the patient-safety AV to $750,000, its ALE to $15,000, and the combined figure to $25,000; using the high end raises AV to $5,250,000, its ALE to $105,000, and the combined figure to $115,000. The final combined ALE for this scenario could reasonably range from roughly $25,000 to $115,000 depending on this one input alone, a wider band than any other scenario in this document.

---

## Scenario 5: VPN Compromise Leading to Full Network Access

**Asset Value (AV):** The task's own hint frames this precisely: the maximum aggregate loss if an attacker enters through the FortiGate VPN and executes a full ransomware-plus-data-exfiltration campaign, meaning the combined AV of Scenarios 1 and 2, since this device is confirmed as the entry point for both Kill Chain 1 and Kill Chain 2 from 1x01. AV = AV(Scenario 1) + AV(Scenario 2) = $473,000 + $9,075,000 = **$9,548,000**

**Exposure Factor (EF):** Framed as the "gateway" scenario, a successful compromise here is assumed to enable the full combined campaign rather than a partial subset of it. EF = **100%**

**SLE = AV x EF = $9,548,000 x 1.0 = $9,548,000**

**ARO:** Given directly, based on VPN compromise being the number-one initial access vector in 38% of healthcare ransomware attacks sector-wide. ARO = **0.3**

**ALE = SLE x ARO = $9,548,000 x 0.3 = $2,864,400**

**Confidence: Low.** This figure stacks two already-uncertain scenario estimates on top of each other, meaning every source of uncertainty already identified in Scenarios 1 and 2 above compounds here rather than cancels out. The supporting data also states directly that "MedDefense's patching cadence for the FortiGate is unknown, not covered in scan," a genuine and material gap in this program's own evidence base, not a minor caveat. The single assumption most likely to change this number: whether a successful VPN compromise truly realizes 100% of the combined Scenario 1 plus Scenario 2 impact together, a full double-extortion campaign, versus a more partial outcome (ransomware without confirmed data exfiltration, or the reverse). If EF were instead estimated at 65% rather than 100%, reflecting a more partial, single-track outcome, ALE would drop to approximately $1,861,860, still a very large figure, but nearly $1 million lower from a single exposure-factor assumption.

---

## Summary Table

|Scenario|AV|EF|SLE|ARO|ALE|
|---|---|---|---|---|---|
|1. Ransomware, billing-srv-01|$473,000|100%|$473,000|0.29|$137,170|
|2. EHR data breach|$9,075,000|100%|$9,075,000|0.45|$4,083,750|
|3. Negligent insider|$120,000|100%|$120,000|2.5|$300,000|
|4a. Medical device DoS|$100,000|100%|$100,000|0.1|$10,000|
|4b. Medical device patient-safety|$3,000,000|100%|$3,000,000|0.02|$60,000|
|5. VPN compromise (gateway)|$9,548,000|100%|$9,548,000|0.3|$2,864,400|

**A note on Scenario 5's relationship to Scenarios 1 and 2, worth stating explicitly before these figures are used in later budget planning:** Scenario 5 is not an additional, independent risk to be summed alongside Scenarios 1 and 2; it is the same underlying risk viewed through its most common entry point. Treating all three as separately additive would materially overstate MedDefense's total risk exposure, a distinction the next stage of this program's quantitative work needs to carry forward carefully.
