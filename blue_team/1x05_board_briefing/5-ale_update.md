# MedDefense Health Systems: The ALE Update

**Prepared by:** Aïda Sylla, Security Analyst 
**Source material:** The original ransomware risk calculation (1x03, Task 5 and Task 6), the Crimson Tide advisory's confirmed victim data, and current AHA/CDC hospital population statistics, verified directly for this document 
**Purpose:** Risk analysis is continuous, not one-time. New intelligence produces new numbers, and new numbers can change which budget decisions are justified. This document shows the full arithmetic, not just the conclusion.

---

## Part 1: Original vs Updated ALE

**Original calculation (1x03, Task 5/Task 6, Risk 1: Ransomware via VPN Gateway):**

|Variable|Original Value|Source|
|---|---|---|
|AV (Asset Value)|$9,548,000|Combined EHR breach + billing ransomware exposure (1x03, Task 5)|
|EF (Exposure Factor)|100%|1x03, Task 5|
|SLE (Single Loss Expectancy)|$9,548,000|AV x EF|
|ARO (Annualized Rate of Occurrence)|0.3|Sector base rate, general ransomware threat landscape, 1x03, Task 5|
|**ALE (original)**|**$2,864,400**|SLE x ARO|

**Updated ARO, calculated with new data, shown in full rather than asserted:**

**Step 1: Establish the target population size**, using real, current AHA/CDC hospital statistics rather than an assumed figure. Hospitals in the 100-499 bed range (matching Crimson Tide's own stated targeting profile of 100-500 bed hospitals) total approximately **2,017 facilities nationally** (983 at 100-199 beds, 535 at 200-299, 322 at 300-399, 177 at 400-499).

**Step 2: Extrapolate Crimson Tide's own observed attack velocity.** 5 confirmed attacks in 10 days, extrapolated forward at the same rate for a full year: 5/10 x 365 = **182.5 attacks per year**, stated explicitly as an upper-bound assumption, since the advisory itself describes this as an "escalating" campaign, meaning the most recent 10-day window may reflect a recent acceleration rather than a stable annual average.

**Step 3: Calculate the naive, population-average annual probability**, treating every one of the 2,017 hospitals as equally likely to be targeted: 182.5 / 2,017 = **0.0905 (approximately 9%)**. This is the baseline rate for an average hospital in this population, from Crimson Tide alone, not accounting for MedDefense's specific circumstances.

**Step 4: Adjust for MedDefense's confirmed, non-average exposure**, rather than treating MedDefense as a generic member of the population. Two specific facts justify an upward adjustment beyond the naive population rate: first, 3 of the 5 confirmed victims (60%) are in MedDefense's own geographic region, a concentration far higher than the region's likely share of the national 2,017-hospital population; second, this program's own Task 0 analysis already confirmed MedDefense is EXPOSED, not merely "similar," on 5 of the 7 documented attack phases, a direct technical match, not a profile resemblance.

**Updated ARO: 0.45.** This reflects analyst judgment applied on top of the calculated base rate, the same practice this program's own original risk work already used (1x03, Task 5 adjusted its own baseline ARO upward from 0.33 given confirmed gap exposure); it is not a purely mechanical output, and is stated as such rather than presented with false precision. It combines the original 0.3 sector-wide baseline (which already existed before Crimson Tide was identified by name) with the specific, confirmed regional and technical concentration this advisory newly reveals.

|Variable|Updated Value|
|---|---|
|SLE (unchanged; the financial impact if the event occurs has not changed)|$9,548,000|
|Updated ARO|0.45|
|**Updated ALE**|**$4,296,600**|

**What changed, and why:** the SLE did not change; MedDefense's assets and their value are the same today as they were in 1x03. What changed is the confidence behind the probability estimate. The original 0.3 ARO was a general sector base rate, reasonable but generic. The updated 0.45 ARO is grounded in a named, currently active campaign with a confirmed regional concentration and a confirmed technical match to MedDefense's own documented weaknesses (Task 0), not a hypothetical sector average. The ALE increases by **$1,432,200, a 50% increase**, entirely from this improved confidence in the probability estimate, not from any change in what a successful attack would actually cost.

---

## Part 2: Budget Impact

**Are any controls that were previously "Not Justified" now justified?**

The only control rated Not Justified in the original cost-benefit analysis (1x03, Task 7) was Control 7, 24/7 SOC monitoring, at $120,000 cost against an $80,000 incremental ALE reduction, a net value of -$40,000. That incremental value was built specifically around faster detection of exactly the kind of live ransomware behavior Crimson Tide's own advisory documents (unusual FortiGate CLI commands, `vssadmin delete shadows`, out-of-window GPO creation). Applying the same 50% increase in confidence this document just calculated to that control's own value case: $80,000 x 1.5 = approximately $120,000 in incremental benefit, moving the net value from -$40,000 to approximately **breakeven, near $0**. This is not a clean, obviously-justified flip; it is a case that moves from clearly rejected to genuinely close, and the honest recommendation reflects that: a breakeven financial case, combined with the qualitative factors this program's own prior work already flagged ALE alone cannot fully capture (tail risk, patient-safety exposure, regulatory response), is enough to recommend the Board revisit this decision specifically, not enough to claim the financial case alone now demands approval outright.

**Does the emergency FortiGate support contract renewal ($2,400) have a positive ROI against the updated ALE?**

Yes, overwhelmingly, and the ratio is worth stating precisely rather than left as a vague "yes": $4,296,600 updated ALE against a $2,400 cost is a **1,790-to-1 return**, the single highest-leverage dollar-for-dollar decision available to the Board tomorrow morning, consistent with this program's own Critical Finding (Task 0) identifying this exact action as the single most urgent step in the next 4 hours.

**Should the Board approve emergency spending beyond the $120,000 budget?**

For the FortiGate renewal specifically, **no, not beyond the existing budget, and this is worth stating precisely rather than assumed.** The original $120,000 budget (1x03, Task 8) funded 6 controls totaling $95,800, leaving **$24,200 already approved and unspent in reserve**. The $2,400 renewal fits comfortably within that existing reserve, leaving $21,800 still available, meaning the Board is not being asked to approve new spending beyond what it already authorized weeks ago, only to release a small piece of it tonight. If the Board separately chooses to revisit Control 7 (24/7 SOC) given this document's updated, near-breakeven analysis, that decision would require budget beyond the original $120,000 entirely, a materially different and larger request the Board should evaluate as its own distinct decision, not bundled with tonight's far smaller and already-affordable renewal.
