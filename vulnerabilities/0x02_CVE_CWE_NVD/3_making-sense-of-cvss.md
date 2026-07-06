Making sense of CVSS: measuring the severity of security vulnerabilities

If you have ever reviewed the results of a vulnerability scan, you've probably noticed scores such as 5.3, 7.5, or 9.8 attached to each finding. Those numbers often drive remediation priorities, maintenance windows, and discussions with management.

But what do they actually represent?

A higher score generally indicates a more severe vulnerability, but the number is not based on intuition or media attention. It comes from a standardized methodology designed to assess vulnerabilities consistently across vendors and technologies. That methodology is the Common Vulnerability Scoring System (CVSS).


Why CVSS exists

In the previous articles, we saw that the CVE Program provides a unique identifier for publicly disclosed vulnerabilities. A CVE answers one question:

"Which vulnerability are we talking about?"

It says nothing about how dangerous that vulnerability is.

Before CVSS, software vendors used their own severity ratings. A "High" vulnerability from one vendor might have been considered "Medium" by another, making comparisons difficult for organizations managing diverse environments.

To solve this inconsistency, the cybersecurity community adopted CVSS, maintained by the Forum of Incident Response and Security Teams (FIRST), as a common framework for evaluating vulnerability severity.


What does a CVSS score measure?

CVSS measures the technical severity of a vulnerability. It evaluates characteristics such as:


how the attack is performed;
whether authentication is required;
the complexity of exploitation;
the impact on confidentiality, integrity, and availability.


The result is a score between 0.0 and 10.0, grouped into four categories:


Low (0.1–3.9)
Medium (4.0–6.9)
High (7.0–8.9)
Critical (9.0–10.0)


These categories simplify communication, while the numerical score provides a more precise assessment.


How is the score determined?

Rather than relying on subjective opinions, CVSS evaluates measurable technical characteristics.

Among the questions it considers are:


Can the vulnerability be exploited remotely?
Does the attacker need valid credentials?
Is user interaction required?
How difficult is exploitation?
What is the impact if the attack succeeds?


A remotely exploitable vulnerability requiring no authentication and leading to full system compromise will naturally receive a much higher score than one requiring local access and producing only limited effects.

This structured approach allows different organizations to evaluate vulnerabilities using the same criteria.


What CVSS does not tell you

A common misconception is that the CVSS score represents the overall business risk.

It does not.

CVSS evaluates the vulnerability itself, not the environment where it exists.

Consider the same vulnerability affecting two organizations. In one case, it is installed on an isolated internal test server. In the other, it affects a public-facing customer portal processing financial transactions.

The CVSS score remains identical because the technical characteristics have not changed. The business risk, however, is clearly very different.

This is why mature security teams never rely on CVSS alone.


From severity to risk

Effective vulnerability management combines CVSS with additional context before deciding what to remediate first.

Typical questions include:


Is the affected system business-critical?
Is exploit code publicly available?
Are attackers actively exploiting the vulnerability?
Do existing security controls reduce exposure?
Can temporary mitigations be applied?


This broader approach, often called risk-based vulnerability management, focuses on reducing overall organizational risk instead of simply patching vulnerabilities from highest score to lowest.


Why CVSS remains essential

Although it does not capture business context, CVSS remains one of the most valuable standards in cybersecurity.

It enables:


vulnerability scanners to prioritize findings;
vendors to communicate severity consistently;
compliance programs to define remediation thresholds;
security teams to speak a common technical language.


Without a standardized scoring system, comparing vulnerabilities across products and vendors would be far more difficult.


Final thoughts

CVSS provides an objective way to measure the technical severity of vulnerabilities by evaluating how easily they can be exploited and what impact they may have. It gives organizations a consistent foundation for prioritizing remediation.

Still, severity is only one part of the equation. Business context, asset criticality, and current threat intelligence ultimately determine which vulnerabilities deserve immediate attention.

Next up: we will look beneath the final score and examine how CVSS is actually calculated, exploring the metrics that explain why two seemingly similar vulnerabilities can receive very different scores.
