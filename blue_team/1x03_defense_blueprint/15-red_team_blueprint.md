# MedDefense Health Systems: Red Team Your Blueprint

**Prepared by:** Aïda Sylla, Security Analyst, writing from the perspective of a BlackReef affiliate **Prepared for:** James Chen, Deputy CISO **Source material:** The funded controls from Task 8 (Segmentation, MFA, SIEM, Offsite Backup, EDR, Westside Firewall), the deferred and rejected controls from that same task, and the honest limitations already documented in the Segmentation Architecture (Task 14) **Purpose:** A plan that only survives review by the people who wrote it is not tested. This document switches sides deliberately, assuming every funded control from Task 8 is fully implemented, and asks what a real BlackReef affiliate would do next.

---

## Part 1: The Attacker's Perspective

### Which kill chain is still viable, and why

**Kill Chain 2, the opportunistic escalation from billing-srv-01 to the domain controller, remains fully viable, and this is not a hypothetical weakness. It was already identified honestly in this program's own Segmentation Architecture (Task 14).** That document acknowledged directly that the funded design groups every production server, including billing-srv-01 and ad-dc-01, into a single Server VLAN. Network segmentation blocks lateral movement between zones, not within one. As BlackReef, I do not need to defeat MFA, EDR, or the new segmentation architecture at all to run this kill chain; I only need what has already worked twice against this exact host: a web-layer compromise of billing-srv-01's own Apache installation (a vulnerability MedDefense's own vulnerability assessment already documented, and which network architecture does not touch), followed by lateral movement to the domain controller sitting in the same VLAN. This chain does not require bypassing anything MedDefense spent money on this year.

### An alternative attack path exploiting what the budget could not close

The budget allocation (Task 8) deferred Control 8 (full medical device network isolation with dedicated monitoring, covering the MRI and the Philips monitor fleet beyond the narrower BD Alaris fix) and rejected Control 7 (24/7 SOC staffing) entirely. Both decisions were financially correct given the evidence available at the time. Both are also exactly where I would go next.

```
Step 1: Initial Access. Rather than attacking MedDefense's network
  perimeter directly, I compromise a legitimate remote-maintenance
  session belonging to one of the medical device vendors (BD or
  Philips), a path that enters through the Medical Device VLAN's
  permitted vendor access, not through anything MedDefense's own
  segmentation rules were designed to block from outside.

Step 2: Lateral Movement within the Medical Device VLAN. MedDefense's
  segmentation architecture restricts this VLAN's traffic to the Server
  VLAN, but it does not restrict device-to-device traffic within the
  Medical Device VLAN itself. From the compromised vendor session, I
  reach WS-RAD-01, the MRI workstation, still running the same three
  weaponized, CISA KEV-listed vulnerabilities this program identified
  months ago and could never patch, since the underlying operating
  system remains permanently end-of-life regardless of any network
  control funded this year.

Step 3: Staging. I use WS-RAD-01 as a pivot point to reach the BD Alaris
  pumps and Philips monitors sharing the same VLAN, since Full Medical
  Device Isolation with dedicated, device-specific monitoring, the one
  control that would have specifically watched this segment, was
  deferred pending a follow-up ALE study that has not yet been funded.

Step 4: Detection Evasion. MedDefense funded a SIEM (Control 3) but
  rejected 24/7 staffing (Control 7). A two-person team reviews alerts
  during business hours. I schedule the active phase of this operation
  for a weekend, the same timing pattern documented across real
  healthcare ransomware incidents this program's own threat intelligence
  already cited, maximizing the window before anyone reviews the log.

Step 5: Impact. Using the same HL7 and DICOM pathways MedDefense's own
  1x02 assessment already documented as carrying no built-in
  authentication, I move from the Medical Device VLAN toward ehr-srv-01
  through the exact application-port exception the segmentation
  architecture must permit for legitimate clinical workflow to function
  at all, achieving data access comparable to what the original,
  pre-segmentation kill chains modeled, while also holding direct
  reach to patient-connected devices, a dimension of impact the original
  ransomware-only kill chains never fully captured.
```

### An insider threat scenario that remains dangerous

**The "Ghost Account" scenario, built directly in 1x01's Insider File (Task 3) and later dramatized as "The Departed Administrator" (1x01, Task 14, Scenario 2), remains exactly as dangerous today as it was before this year's entire security investment, because none of the eight controls evaluated in Task 7, and none of the six ultimately funded in Task 8, address GAP-018 at all.** MFA verifies that whoever is authenticating holds the correct credential and device; it does nothing if that credential and device belong to someone MedDefense terminated three weeks ago and never deprovisioned. Segmentation restricts what a network position can reach; it does nothing to a legitimate account with legitimate access rights it was never stripped of. As BlackReef, I do not need to breach anything this program built this year. I need a MedDefense employee to leave, and I need MedDefense's HR-to-IT offboarding process, the one gap this entire eight-control analysis simply never evaluated, to remain exactly as informal as it is today.

---

## Part 2: The Honest Assessment

**Overall residual risk: High.** This is a genuine downgrade from where this program started, not a dismissal of a year's real progress: RISK-001 through RISK-004 and RISK-010 in the Risk Register are all meaningfully reduced by funded controls with verified ALE reductions in the millions of dollars. But High, not Medium or Low, is the honest rating, because this red team exercise found a fully viable, low-effort kill chain (Kill Chain 2) requiring no new attacker capability whatsoever, a concrete attack path exploiting two deliberately deferred and rejected controls, and an entire threat category, insider account lifecycle abuse, that this year's budget process never funded a control for at all, not even as a "Not Justified" line item. A residual risk rating of Medium or Low would imply this program closed the gaps that matter most; it closed the gaps that were most expensive when left open, which is not quite the same claim.

**The single biggest remaining gap: GAP-018, the absence of automated account deprovisioning tied to HR termination events.** This is the sharpest finding of this entire red team exercise, not because it is the most technically sophisticated gap, but because it is the most surprising one: across eight controls evaluated with full cost-benefit rigor in Task 7, this gap was never even considered, let alone rejected on the merits. It defeats MFA entirely, it is untouched by network segmentation, and this program's own prior work already built a complete, realistic scenario proving it is exploitable (1x01, Task 14).

**Recommendation for next year's budget: automated, HR-triggered account deprovisioning should be the #1 priority, ahead of even completing the deferred Full Medical Device Isolation control.** This recommendation is made specifically because this red team exercise is what surfaced it, not because it was already known and set aside; a gap this cheap to close (this program's own earlier work, 1x02 Task 19, estimated a comparable fix at roughly $3,000) and this dangerous to leave open should not enter next year's budget cycle competing against Control 8's $18,000 request as an equal, unranked option. It should be funded first, precisely because this exercise proved that a real adversary, thinking through MedDefense's own newly-funded defenses exactly as this document just did, would find it before MedDefense's security team would have without deliberately looking.
