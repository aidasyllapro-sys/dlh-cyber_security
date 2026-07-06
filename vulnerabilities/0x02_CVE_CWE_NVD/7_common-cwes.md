Common CWEs every developer should know

One of the most common misconceptions I encounter during security assessments is that software vulnerabilities begin with a CVE. In reality, they often begin much earlier, when a developer unknowingly introduces a weakness into the code. That weakness may never receive a CVE identifier if no one discovers or exploits it, but it still represents a risk.

This is exactly where Common Weakness Enumeration (CWE) becomes valuable.

Rather than documenting individual vulnerabilities, CWE focuses on recurring programming mistakes. It provides a shared language for developers, security engineers, auditors, and tool vendors to describe the underlying causes of security issues. Understanding these common weaknesses allows teams to prevent vulnerabilities before they ever become security incidents.


Why developers should care about CWE

Security is often perceived as something that happens after development. Code is written, tested, deployed, and eventually scanned for vulnerabilities. Unfortunately, many security problems originate long before a vulnerability scanner is ever executed.

Many organizations discover that fixing a weakness during development is significantly easier than correcting it after deployment. Beyond the technical effort, late fixes often involve emergency patches, production downtime, additional testing, and sometimes difficult conversations with customers.

Learning the most common CWEs helps developers recognize risky coding patterns early. Instead of memorizing thousands of individual vulnerabilities, they can focus on avoiding the classes of mistakes that repeatedly lead to security problems.


CWE-79: Cross-Site Scripting (XSS)

One of the best-known weaknesses is CWE-79, commonly associated with Cross-Site Scripting.

This weakness occurs when an application includes untrusted input in a web page without properly validating or encoding it. An attacker can inject malicious JavaScript that executes in another user's browser.

In practice, this can lead to stolen session cookies, account hijacking, or malicious actions performed on behalf of legitimate users.

A customer feedback form, a search field, or a profile description may all become attack vectors if user input is displayed without proper output encoding.

Fortunately, modern frameworks provide built-in protection, but developers still need to understand when automatic escaping is insufficient.


CWE-89: SQL Injection

Few weaknesses have remained as relevant as CWE-89, better known as SQL Injection.

The problem arises when applications build SQL queries using untrusted user input instead of parameterized statements.

Imagine a login form where the application simply concatenates the username into the SQL query. A carefully crafted input could completely change the logic of that query, allowing unauthorized access or exposing sensitive information.

Although this weakness has been known for decades, it continues to appear because legacy applications and rushed development projects still rely on unsafe coding practices.

Parameterized queries, prepared statements, and object-relational mapping (ORM) frameworks dramatically reduce this risk when used correctly.


CWE-787: Out-of-Bounds Write

While web applications often receive the most attention, lower-level software introduces different classes of weaknesses.

CWE-787, Out-of-Bounds Write, occurs when a program writes data outside the allocated memory boundaries.

Languages such as C and C++ provide tremendous flexibility but also require developers to manage memory carefully. A single programming mistake may overwrite adjacent memory, potentially leading to crashes or arbitrary code execution.

Several high-profile vulnerabilities affecting operating systems and embedded devices have originated from memory corruption issues like this one.

Modern languages such as Rust are gaining popularity partly because they eliminate many memory safety problems during compilation.


CWE-22: Path Traversal

Applications frequently interact with files stored on a server. If user input determines which file is accessed, developers must validate that input carefully.

CWE-22, commonly known as Path Traversal, allows attackers to escape intended directories by manipulating file paths.

For example,an application designed to display user-uploaded documents may accidentally expose sensitive system files if it blindly trusts filenames supplied by users.

Restricting file access to approved directories and validating user input significantly reduces this risk.


CWE-798: Hard-Coded Credentials

Convenience during development sometimes creates long-term security problems.

CWE-798 refers to applications that contain usernames, passwords, API keys, or cryptographic secrets directly embedded in the source code.

One mistake I frequently encounter during code reviews is developers leaving temporary credentials in configuration files while planning to remove them later. Those credentials often remain in production for years.

Modern secret management solutions, environment variables, and dedicated vault technologies make hard-coded credentials largely unnecessary.


CWE-862: Missing Authorization

Authentication verifies who a user is.

Authorization determines what that user is allowed to do.

Confusing these two concepts leads to CWE-862, Missing Authorization.

A user may successfully authenticate but still gain access to administrative functions because the application never verifies whether they actually have permission to perform the requested action.

These flaws are particularly dangerous because attackers do not always need sophisticated techniques. Sometimes changing a URL or modifying an API request is enough to access restricted resources.

Consistent authorization checks should be applied on the server side for every sensitive operation.


The pattern behind most weaknesses

Although these CWEs appear very different, they share an interesting characteristic.

Very few results from advanced hacking techniques.

Most originate from small design decisions, missing validation, unsafe assumptions, or overlooked edge cases. Security failures often emerge not because developers lack talent, but because software has become incredibly complex.

This is precisely why secure coding standards, peer reviews, automated testing, and developer education remain essential parts of a mature Secure Software Development Lifecycle (SSDLC).

The objective is not to memorize hundreds of CWE entries. It is to recognize recurring patterns and build habits that naturally avoid introducing them.


From weaknesses to better software

Understanding common CWEs changes how developers think about software security.

Instead of viewing security as a collection of isolated vulnerabilities, they begin recognizing families of recurring mistakes that can be prevented through better engineering practices.

This shift has practical benefits. Security tools become easier to interpret, code reviews become more effective, and vulnerability remediation becomes faster because teams understand not only what is wrong, but also why it happened.

For organizations embracing DevSecOps, this knowledge is equally valuable. Automated scanners can detect many weaknesses, but preventing them starts with developers writing secure code from the beginning.

Security works best when it becomes part of everyday development rather than an inspection performed just before release.


Looking ahead

Recognizing common weaknesses is only the first step. The CWE catalog contains hundreds of entries organized into a structured hierarchy that helps security professionals classify, prioritize, and analyze software weaknesses more effectively.

In the next article, we will explore Understanding the CWE Taxonomy and see how this classification system helps developers, security teams, and vulnerability management programs speak the same language when assessing software risk.
