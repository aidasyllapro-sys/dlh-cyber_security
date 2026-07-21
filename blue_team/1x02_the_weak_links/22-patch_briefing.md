# MedDefense Health Systems: The Patch Briefing

**For:** Board of Directors **From:** James Chen, Deputy CISO **Re:** 3 fixes this week

We found 31 issues in last week's security scan. 3 of them need to be fixed in the next 2 days, not weeks. Here they are.

**1. Our patient records database will talk to anyone who asks.** Right now, any computer inside our network, not just approved medical systems, can connect directly to the database holding every patient's complete record. No hacking skill is required, only network access, which multiple weaker systems on our network already provide. Fix: a configuration change restricting that connection to the one approved server. Cost: under $1,000 and one day of IT staff time.

**2. Our MRI's computer runs software with no security updates since 2014**, and it has 3 known break-in methods that criminal groups actively use today, including one added to the federal government's active-threat list just last month. If exploited, imaging stops across the hospital, and there is a real risk the images themselves could be altered without anyone noticing. Fix: isolate this one machine on its own protected section of the network immediately, while we plan its eventual replacement. Cost: roughly $25,000, covering both the immediate fix and the fuller project.

**3. A flaw in our medical records software lets an attacker read the database password directly off the server**, using a publicly available tool. We found this specific weakness because a routine investigation followed up on something that looked minor. Fix: a same-day configuration change. Cost: under $1,000.

**Combined cost for all three: roughly $27,000, and two days of work.**

In 3 weeks, we went from not knowing what we had, to knowing exactly who wants to attack it, to knowing exactly where the holes are and what to fix first. That is not luck. That is the program working.
