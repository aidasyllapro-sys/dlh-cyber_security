# PASSWORD POLICY

## SecureBank Financial Services

---

# Document Control

| Field | Value |
|------|------|
| Policy ID | POL-PWD-002 |
| Version | 1.0 |
| Effective Date | 2026-07-08 |
| Review Date | 2027-07-08 |
| Policy Owner | Information Security Manager |
| Approved By | Chief Information Security Officer (CISO) |
| Classification | Internal |

---

# 1. Purpose

This Password Policy establishes security requirements for creating, managing, storing, and protecting passwords used within SecureBank Financial Services.

The objective of this policy is to protect critical financial systems, customer information, and organizational assets against unauthorized access.

This policy supports compliance with:

- PCI-DSS v4.0
- SOX requirements
- FFIEC security expectations
- NIST Digital Identity Guidelines

---

# 2. Scope

## 2.1 Applicability

This policy applies to:

- All employees
- Contractors
- Third-party service providers
- System administrators
- Developers
- Privileged account users

---

## 2.2 Systems/Assets Covered

This policy applies to:

- Core banking system
- Customer portal
- Employee workstations
- Administrative systems
- Development environments
- Cloud services
- Remote access systems

---

## 2.3 Exclusions

Systems managed entirely by external providers are excluded only when equivalent contractual security controls are documented and approved.

---

# 3. Policy Statements

---

# 3.1 Password Requirements

All passwords used to access SecureBank systems must meet minimum security requirements.

## Requirements

Users must:

- Use passwords with a minimum length of **14 characters**.
- Use passwords that are unique and not reused across company systems.
- Use passphrases when possible.
- Avoid predictable passwords.

Passwords must not contain:

- Usernames
- Employee IDs
- Company names
- Common dictionary words
- Previously compromised passwords
- Easily guessed personal information

Password screening must prevent the use of known compromised passwords.

---

# 3.2 Password Management

Passwords must be securely managed throughout their lifecycle.

## Requirements

Account creation:

- Initial passwords must be randomly generated.
- Users must change temporary passwords at first login.
- Default vendor passwords must be changed before system deployment.

Password reset:

- Identity verification is required before password resets.
- Password reset requests must be logged.
- Temporary passwords must expire after a defined period.

Account protection:

- Accounts must be locked or delayed after repeated failed authentication attempts.
- Authentication sessions must automatically expire after inactivity.
- Password recovery processes must use approved security controls.

---

# 3.3 Multi-Factor Authentication (MFA)

MFA must be implemented for systems requiring enhanced protection.

## MFA is mandatory for:

- Administrative accounts
- Core banking systems
- Remote access
- Customer-facing applications
- Privileged operations

## Approved MFA methods:

- Hardware security keys
- Authenticator applications
- Cryptographic authentication methods
- Approved biometric authentication

SMS-based authentication should only be used when stronger methods are unavailable and approved by Security Management.

---

# 3.4 Password Storage

Passwords must never be stored in readable format.

## Requirements

Systems storing passwords must:

- Store passwords using approved cryptographic hashing algorithms.
- Use unique salts for each password.
- Protect authentication databases from unauthorized access.
- Follow secure development practices.

Approved password hashing methods include:

- Argon2id
- bcrypt
- PBKDF2

Plaintext password storage is prohibited.

---

# 3.5 Password Managers

Password managers are required for securely managing multiple credentials.

## Requirements

Users must:

- Use company-approved password managers.
- Protect password manager access with MFA.
- Avoid storing company credentials in personal password managers.

---

# 3.6 Privileged Account Requirements

Privileged accounts require enhanced security controls.

## Requirements

Privileged accounts must:

- Use MFA.
- Have unique credentials.
- Not be shared between users.
- Be monitored continuously.
- Follow Privileged Access Management (PAM) procedures.

Administrative passwords must:

- Be stored using approved PAM solutions.
- Be rotated according to risk requirements.
- Be reviewed regularly.

---

# 4. Roles and Responsibilities

| Role | Responsibilities |
|------|------------------|
| Executive Management | Approve policy and provide security resources. |
| Information Security Team | Define requirements, monitor compliance, perform reviews. |
| System Administrators | Configure authentication systems and enforce controls. |
| Developers | Implement secure authentication mechanisms. |
| Department Managers | Ensure employee compliance. |
| Employees | Protect passwords and report security incidents. |
| Privileged Users | Follow enhanced account security requirements. |

---

# 5. Compliance

## 5.1 Monitoring

The Security Team monitors:

- Authentication logs
- Failed login attempts
- MFA usage
- Privileged account activity
- Password policy compliance

---

## 5.2 Reporting

Users must immediately report:

- Suspected credential compromise
- Lost authentication devices
- Unauthorized account access
- Suspicious login activity

Reports must be submitted through approved security channels.

---

## 5.3 Auditing

Password controls shall be reviewed:

- Annually
- During regulatory assessments
- During security audits

Audit activities include:

- Password configuration reviews
- Privileged account reviews
- MFA verification
- Access control testing

---

# 6. Enforcement

## 6.1 Violations

Violations may result in:

- Security awareness training
- Removal of access privileges
- Account suspension
- Disciplinary action
- Termination
- Legal action where applicable

---

## 6.2 Reporting Violations

Suspected violations must be reported to the Information Security Team.

---

# 7. Exceptions

## 7.1 Exception Process

Exceptions require:

1. Written request.
2. Business justification.
3. Security risk assessment.
4. Compensating controls.
5. Approval by Information Security Management.

---

## 7.2 Exception Duration

Exceptions must:

- Have an expiration date.
- Be reviewed at least annually.
- Be documented.

---

# 8. Definitions

| Term | Definition |
|------|------------|
| MFA | Authentication requiring multiple verification factors. |
| PAM | Privileged Access Management solution used to secure administrative accounts. |
| Hashing | One-way cryptographic process used to protect passwords. |
| Privileged Account | Account with elevated permissions. |

---

# 9. Related Documents

- NIST SP 800-63B Digital Identity Guidelines
- OWASP Authentication Cheat Sheet
- PCI-DSS v4.0 Requirement 8
- CISA MFA Guidance
- SecureBank Access Control Policy
- SecureBank Incident Response Policy

---

# 10. Revision History

| Version | Date | Author | Description |
|---------|------|--------|-------------|
| 1.0 | 2026-07-08 | Security Team | Initial release |

---

# 11. Acknowledgment

By accessing SecureBank Financial Services systems, users acknowledge that they have read, understood, and agree to comply with this Password Policy.

---

# End of Policy Document
Fichier : password_standards.md
# PASSWORD TECHNICAL STANDARDS

## SecureBank Financial Services

---

# 1. Password Length

Minimum password length:

- Standard user accounts: 14 characters
- Privileged accounts: 20 characters recommended

Long passphrases are encouraged.

---

# 2. Password Complexity

Passwords should:

- Contain multiple character types when required by the authentication system.
- Avoid predictable patterns.
- Avoid personal information.

Complexity alone must not replace password length requirements.

---

# 3. Password History

Systems must prevent:

- Reuse of previous passwords.
- Use of recently compromised credentials.

Minimum password history:

- Last 10 passwords cannot be reused.

---

# 4. Account Lockout

Authentication systems must implement:

- Failed login monitoring.
- Temporary lockout or progressive delays.
- Security alerts for suspicious activity.

Recommended threshold:

- Lock account after 5 failed attempts.

---

# 5. Password Expiration

Password expiration must be risk-based.

Forced periodic password changes are required when:

- Password compromise is suspected.
- Administrative accounts require rotation.
- Regulatory requirements apply.

---

# 6. Password Storage Requirements

Passwords must:

- Never be stored in plaintext.
- Use salted cryptographic hashing.
- Use approved algorithms:

Approved:

- Argon2id
- bcrypt
- PBKDF2

---

# 7. Privileged Account Standards

Privileged accounts require:

- MFA
- PAM management
- Individual accountability
- Activity logging
- Regular access reviews

Shared administrator accounts are prohibited unless formally approved.

---

# 8. Compliance References

- NIST SP 800-63B
- OWASP Authentication Cheat Sheet
- PCI-DSS v4.0 Requirement 8
- CISA MFA Guide

---

End of Technical Standards
