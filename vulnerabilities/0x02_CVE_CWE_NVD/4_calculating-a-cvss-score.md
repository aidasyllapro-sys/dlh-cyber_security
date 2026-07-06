Calculating a CVSS score: What really determines vulnerability severity?

After learning that CVSS provides a standardized way to measure vulnerability severity, the next logical question is simple: how is that score actually calculated?

For many people, the final score is all they ever see. A vulnerability scanner reports a 9.8, a security advisory labels it as Critical, and remediation begins. The number becomes the focus, while the reasoning behind it is often overlooked.

Understanding how CVSS is built is valuable because it helps security professionals move beyond the number itself. Instead of simply accepting a score, they can understand why a vulnerability is considered severe and whether that severity reflects the reality of their own environment.


More than a mathematical formula

Although CVSS relies on a mathematical calculation, it is not based on arbitrary numbers.

The framework evaluates several characteristics of a vulnerability that influence both the likelihood of successful exploitation and the potential consequences if an attacker succeeds.

Rather than asking a single question such as "How dangerous is this vulnerability?", CVSS breaks the problem into smaller, measurable components.

This structured approach makes vulnerability assessments far more consistent across vendors, researchers, and security tools.


The base metrics: The core of every CVSS score

Every CVSS score begins with a set of Base Metrics. These describe the intrinsic characteristics of the vulnerability itself, regardless of where it exists.

Several factors are evaluated.

Attack Vector

The Attack Vector measures how close an attacker must be to exploit the vulnerability.

A vulnerability that can be exploited over the Internet generally presents greater risk than one requiring physical access to a device.

CVSS distinguishes between scenarios such as:


Network
Adjacent Network
Local
Physical


Remote vulnerabilities typically receive higher scores because they can often be exploited on a much larger scale.

Attack Complexity

Not every vulnerability is equally easy to exploit.

Some require highly specific system configurations or unusual conditions before an attack can succeed. Others can be exploited with little effort once a vulnerable system is identified.

The Attack Complexity metric reflects this difference.

Lower complexity generally increases the overall severity score because attackers need fewer prerequisites to succeed.

Privileges Required

Some vulnerabilities can be exploited by anyone.

Others require an attacker to authenticate first.

The Privileges Required metric evaluates whether administrative privileges, standard user accounts, or no credentials at all are necessary before exploitation becomes possible.

Naturally, vulnerabilities requiring no prior access tend to receive higher scores.

User Interaction

Certain attacks succeed only if a legitimate user performs an action.

Opening a malicious attachment, clicking a crafted link, or approving an unexpected request are common examples.

If exploitation depends on user involvement, the vulnerability generally receives a lower score than one that can be exploited automatically.

This metric reminds us that human behavior sometimes becomes part of the attack path.

Scope

One of the more interesting CVSS metrics is Scope.

It evaluates whether exploiting a vulnerability allows an attacker to affect resources beyond the originally vulnerable component.

For example, imagine compromising a web application that subsequently provides access to the underlying operating system.

Because the impact extends beyond the initial security boundary, the overall severity may increase.


Measuring the impact

The second half of the calculation focuses on what happens after exploitation.

CVSS evaluates the potential impact on 3 well-known security objectives:


Confidentiality
Integrity
Availability


Together, these form the familiar CIA Triad used throughout cybersecurity.

If exploitation allows sensitive information to be stolen, confidentiality is affected.

If attackers can modify data or execute unauthorized commands, integrity suffers.

If services become unavailable through crashes or denial-of-service attacks, availability is compromised.

The greater the combined impact across these three areas, the higher the final score.


Environmental context matters

One mistake I frequently encounter is assuming that the published CVSS score automatically reflects every organization's level of risk.

It does not.

The official score represents the vulnerability's technical characteristics, but organizations can also calculate Environmental Metrics that consider their own infrastructure.

A vulnerability affecting a public payment platform may deserve a much higher remediation priority than the same vulnerability affecting an isolated laboratory system.

This flexibility allows organizations to adapt technical severity to their own operational reality instead of relying exclusively on generic scores.


Why 2 similar vulnerabilities can receive different scores

At first glance, two vulnerabilities may appear almost identical.

Both affect web applications.

Both allow unauthorized access.

Both have publicly available exploits.

Yet one receives a score of 7.5, while the other reaches 9.8.

The explanation often lies in the underlying metrics.

Perhaps one requires user interaction while the other does not. One may require authentication, while the other is completely unauthenticated. One might affect only confidentiality, whereas the other compromises confidentiality, integrity, and availability simultaneously.

Small differences in technical characteristics can significantly influence the final score.


CVSS helps standardize decisions

Security teams rarely calculate CVSS scores manually. Most vulnerability scanners, security advisories, and vulnerability databases already provide them.

Even so, understanding how those scores are derived offers several advantages.

It allows analysts to validate automated findings instead of accepting them blindly.

It improves communication with developers by explaining why a vulnerability has been prioritized.

It also helps management understand that vulnerability severity is based on objective technical criteria rather than personal judgment.

Perhaps most importantly, it encourages security professionals to look beyond the final number and consider the characteristics that truly drive risk.


Final thoughts

A CVSS score is far more than a number displayed in a vulnerability report. It reflects a structured evaluation of how a vulnerability can be exploited and what impact it could have on the confidentiality, integrity, and availability of affected systems.

Understanding the individual metrics behind the score allows security professionals to make more informed decisions, challenge assumptions when necessary, and apply vulnerability management more intelligently. While automated tools perform the calculations, knowing what those numbers represent is essential for anyone responsible for protecting modern IT environments.

In the next article, we'll shift our focus from vulnerabilities to Common Weakness Enumeration (CWE) and explore how understanding software weaknesses helps developers prevent vulnerabilities before they ever receive a CVE.
