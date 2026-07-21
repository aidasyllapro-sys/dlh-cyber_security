# MedDefense Health Systems: The Budget Game

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO, and Robert Kim, CFO **Source material:** The 8 cost-benefit evaluations from Task 7 **Purpose:** $120,000. Not $121,000. This document makes the binding allocation decision, with every dollar tied to a specific, already-justified reason, and states plainly what MedDefense accepts by not funding everything.

**A reconciliation note stated once, upfront, rather than left unaddressed:** several of these 8 controls overlap directly with narrower remediation items already costed in Project 1x02's own remediation plan (Task 20), Control 1's segmentation work and Control 6's Westside firewall in particular. This document treats the $120,000 annual security budget as the single, real figure MedDefense has to work with, and treats the 8-control framework from Task 7 as the consolidated, superseding strategy for that budget going forward, not as new spending stacked on top of 1x02's earlier estimates. Where this program's prior work already allocated dollars to a narrower version of the same fix, that allocation is understood to be absorbed into the broader control described here, not duplicated.

---

## Part 1: The Selection

**Funded this fiscal year:**

|Control|Cost|Net Value (Task 7)|
|---|---|---|
|1. Network Segmentation|$40,000|$1,821,860|
|2. MFA Deployment|$2,000|$1,430,200|
|3. Enterprise SIEM (Wazuh)|$25,000|$1,318,848|
|4. Offsite Backup Replication|$4,000|$241,250|
|5. EDR Upgrade (Intercept X)|$23,000|$902,540|
|6. Westside Dedicated Firewall|$1,800|$358,200|
|**Total**|**$95,800**|**$6,168,698 in combined ALE reduction**|

**Deferred to next fiscal year:**

**Control 8, Full Medical Device Network Isolation ($18,000).** This is deferred for two independent reasons, not budget scarcity alone, worth distinguishing directly. First, Task 7's own evaluation already recommended deferral: this control's quantified net value ($35,000) rests only on the BD Alaris component, since no dedicated ALE calculation exists yet for the MRI or Philips monitor components this broader control would also protect, meaning its true value is likely higher but is not a number this program can currently defend. Second, even though $18,000 would technically fit within the remaining budget after the six funded controls above, deliberately holding this reserve rather than spending down to the last dollar is itself a sound decision: it preserves flexibility for exactly the follow-up analysis (a dedicated MRI/Philips ALE calculation) that would justify funding this control properly, with evidence, next cycle, rather than funding it now on an admittedly incomplete case.

**Rejected entirely:**

**Control 7, 24/7 SOC Staffing ($120,000).** Rejected on the math itself, not merely deferred: Task 7 found this control's net value to be negative (-$40,000) once evaluated honestly against the incremental benefit it provides beyond Control 3's SIEM, already funded above. A control with a negative net value is not a timing question to revisit next year with more budget; it is not currently the right control at all, regardless of available funds, unless MedDefense's risk profile or program maturity changes enough to reopen the calculation.

**Total spend vs. budget:** $95,800 funded against a $120,000 (120000) annual budget, leaving **$24,200 in budget remaining**, deliberately held as reserve rather than allocated to Control 8's still-incomplete business case.

---

## Part 2: The Opportunity Cost

**By deferring Control 8 (Full Medical Device Network Isolation), MedDefense accepts an estimated $53,000 in annual risk exposure that would otherwise be reduced,** calculated directly from Task 7's own figures for the BD Alaris component ($70,000 ALE before, $17,000 ALE after, a $53,000 reduction left unrealized). This is stated as a floor, not a ceiling: the true opportunity cost is very likely higher, since this figure captures only the infusion pump component of a control that would also extend protection to the MRI workstation (Finding 004, three independently weaponized, CISA KEV-listed CVEs) and the Philips patient monitors (Finding 016, a confirmed patient-safety escalation path established in this program's own Task 15 of 1x02). MedDefense is accepting at least $53,000 in avoidable annual risk by deferring this control, and plausibly meaningfully more, in exchange for one additional budget cycle to build the evidence needed to defend the larger number honestly.

**A distinct note on Control 7's rejection, since it is not the same kind of decision as a deferral:** rejecting a control with a negative net value does not carry an opportunity cost in the same sense. MedDefense is not giving up $40,000 in avoided risk by rejecting Control 7; it is avoiding spending $120,000 to achieve less protection than Control 3 already provides at a fifth of the cost. The correct way to state this is the inverse of an opportunity cost: by rejecting Control 7, MedDefense preserves $120,000 in budget capacity that would otherwise have purchased negative net value, capacity that instead funds the six controls delivering over $6.1 million in combined ALE reduction above.

---

## Part 3: The Alternative

**A genuinely lower cost alternative exists, and it is presented here honestly, including the conclusion that it is not actually the better choice.** Consider dropping Control 1 (Network Segmentation, $40,000, the single most expensive item in the funded set) and reallocating that freed budget toward funding Control 8 immediately instead of deferring it, alongside the remaining five originally-funded controls.

**Alternative allocation:** Controls 2, 3, 4, 5, 6, and 8, total cost $73,800, total ALE reduction $4,341,838.

**Compare this to the primary recommendation directly, side by side:**

||Primary Allocation|Alternative Allocation|
|---|---|---|
|Total Cost|$95,800|$73,800|
|Total ALE Reduction|$6,168,698|$4,341,838|
|Budget Remaining|$24,200|$46,200|

The alternative costs **$22,000 less** and leaves substantially more budget headroom, a genuinely attractive-looking feature at first glance when you compare the two totals directly. But it achieves **$1,826,860 less** in total annual risk reduction, because Control 1 alone accounts for nearly a third of the primary allocation's entire value. Measured in pure return on investment, Control 1 returns approximately $45 in avoided risk for every dollar spent, a ratio no other single control in this program comes close to matching, including Control 8, whose inclusion in this alternative returns a comparatively modest amount for its cost. **This alternative is not recommended.** Saving $22,000 in exchange for foregoing $1.83 million in annual risk reduction is not a close call once both numbers are placed side by side; it is presented here specifically because a defensible budget process should be able to show its work on the roads not taken, not only the one ultimately chosen, and because the honest comparison is itself the strongest evidence that the primary allocation, despite being the more expensive option, is the financially correct one.
