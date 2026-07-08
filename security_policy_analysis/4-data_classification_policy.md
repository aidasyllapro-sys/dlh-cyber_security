# HealthPlus Medical Group
# Data Classification Policy

---

## Document Control

| Document Information | Details |
|---|---|
| Document Name | Data Classification Policy |
| Company | HealthPlus Medical Group |
| Version | 1.0 |
| Document Owner | Information Security Department |
| Classification | Internal Use |
| Effective Date | July 8, 2026 |
| Review Frequency | Annually or after significant regulatory/business changes |
| Next Review Date | July 8, 2027 |
| Approved By | Chief Information Security Officer (CISO) |
| Approval Date | July 8, 2026 |
| Contact Information | security@healthplus.example.com |

---

# 1. Purpose

The purpose of this Data Classification Policy is to establish a consistent framework for identifying, categorizing, handling, storing, transmitting, and disposing of HealthPlus Medical Group information according to its sensitivity and business impact.

This policy ensures that confidential healthcare information, personal data, financial information, research data, and operational information receive appropriate protection.

The policy supports compliance with:

- HIPAA Security Rule requirements for protecting Protected Health Information (PHI)
- GDPR requirements for protecting personal data
- Applicable state privacy regulations
- Internal security and risk management objectives

---

# 2. Scope

This policy applies to:

- All HealthPlus Medical Group employees
- Contractors
- Temporary workers
- Healthcare providers
- Third-party partners with access to company information

This policy applies to all information assets including:

- Electronic files
- Databases
- Applications
- Cloud storage
- Paper documents
- Removable media
- Communication systems

All company information must be assigned a classification level before storage, sharing, or disposal.

---

# 3. Policy Statement

HealthPlus Medical Group classifies information into four security levels:

| Classification Level | Description | Examples |
|---|---|---|
| PUBLIC | Information approved for public release | Marketing materials, website content |
| INTERNAL | Information intended only for employees and authorized partners | Internal memos, organizational charts |
| CONFIDENTIAL | Information that could cause harm if disclosed | Employee PII, financial records |
| RESTRICTED | Highly sensitive information requiring maximum protection | Patient PHI, authentication credentials |

Information owners are responsible for ensuring that information receives the correct classification level.

Users handling company information must follow the protection requirements associated with each classification.

---

# 4. Data Classification Levels and Handling Requirements

## 4.1 Classification Requirements Matrix

| Requirement | PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED |
|---|---|---|---|---|
| Labeling Required | Yes | Yes | Yes | Yes |
| Encryption at Rest | No | Recommended | Required | Required |
| Encryption in Transit | Recommended | Required for external transmission | Required | Required |
| Access Control | Public access approved by owner | Employees and approved partners | Authorized personnel with business need | Strict need-to-know access |

---

# 5. Classification Level Requirements

# 5.1 PUBLIC Information

## Description

Information approved for public distribution that creates no security risk when disclosed.

## Examples

- Website content
- Public announcements
- Marketing brochures
- Public reports

## Labeling

Required:

- Documents must include the label:

```
PUBLIC
```

- File names should clearly identify public documents.

Example:

```
HealthPlus_Public_Annual_Report.pdf
```

## Storage

Approved:

- Public website
- Approved marketing platforms
- Public document repositories

Prohibited:

- Storage with restricted information
- Unapproved personal devices

## Transmission

Allowed:

- Public websites
- Approved communication channels

Restrictions:

- Users must verify that information is approved before external sharing.

## Disposal

Requirements:

- Digital files must be securely deleted when no longer needed.
- Paper documents may be recycled after confirmation of public status.

## Access Control

Access:

- Public access allowed.
- Publication requires approval from the information owner.

Review:

- Content owners review public information periodically.

---

# 5.2 INTERNAL Information

## Description

Information intended for business operations and internal communication.

## Examples

- Internal policies
- Employee directories
- Organizational charts
- Internal procedures

## Labeling

Required:

Documents must contain:

```
INTERNAL
```

Example:

```
INTERNAL_HR_Organization_Chart.xlsx
```

## Storage

Approved:

- Company file servers
- Approved cloud storage
- Internal collaboration platforms

Prohibited:

- Personal cloud storage
- Public file-sharing platforms

## Transmission

Allowed:

- Internal email
- Approved collaboration tools

External transmission requires:

- Business approval
- Verification of recipient authorization

## Disposal

Requirements:

- Digital files securely deleted.
- Paper documents placed in secure disposal containers.

## Access Control

Access:

- Employees with legitimate business requirements.
- Contractors only with authorization.

Review:

- Access permissions reviewed annually.

---

# 5.3 CONFIDENTIAL Information

## Description

Information that could negatively impact employees, customers, or the organization if disclosed.

## Examples

- Employee Personally Identifiable Information (PII)
- Financial information
- Contracts
- Business plans

## Labeling

Required:

Documents must contain:

```
CONFIDENTIAL
```

Example:

```
CONFIDENTIAL_Employee_Salary_Data.xlsx
```

## Storage

Required:

- Encryption at rest
- Approved company systems only

Approved:

- Encrypted databases
- Secure enterprise storage

Prohibited:

- Personal devices without approval
- Unencrypted removable media

## Transmission

Required:

- Encryption during transmission
- Approved secure file transfer systems

Email:

- Confidential files must use encryption or password protection.

## Disposal

Requirements:

Paper:

- Must be shredded using approved secure disposal services.

Electronic:

- Secure deletion required.
- Storage media must be sanitized according to NIST SP 800-88 guidelines.

## Access Control

Access:

- Granted only based on business need.
- Requires manager approval.

Controls:

- Role-Based Access Control (RBAC)
- Multi-Factor Authentication (MFA)

Review:

- Access reviewed at least annually.

---

# 5.4 RESTRICTED Information

## Description

The highest sensitivity classification. Unauthorized disclosure could result in severe legal, financial, operational, or reputational damage.

## Examples

- Patient medical records (PHI)
- Medical histories
- Authentication credentials
- Encryption keys

## Labeling

Required:

Documents must contain:

```
RESTRICTED
```

Example:

```
RESTRICTED_Patient_Record_001.pdf
```

## Storage

Required:

- Encryption at rest
- Approved healthcare systems only
- Strong authentication controls

Approved:

- HIPAA-compliant systems
- Secure encrypted databases

Prohibited:

- Local personal storage
- Unauthorized cloud services
- Unencrypted devices

## Transmission

Required:

- Encryption in transit
- Approved secure communication channels

Restrictions:

- PHI must only be transmitted through approved HIPAA-compliant systems.
- Recipient identity must be verified.

## Disposal

Paper:

- Cross-cut shredding required.

Electronic:

- Secure deletion.
- Media sanitization according to NIST SP 800-88.

## Access Control

Access:

- Strict need-to-know basis.

Required controls:

- Role-Based Access Control
- MFA
- Access logging
- Periodic access review

Review:

- Access reviewed at least every six months.

---

# 6. Data Classification Responsibilities

## Information Owners

Responsibilities:

- Determine appropriate classification.
- Approve access requests.
- Review classification accuracy.

---

## Employees and Users

Responsibilities:

- Apply correct labels.
- Protect information according to classification.
- Report suspected misuse or exposure.

---

## IT Department

Responsibilities:

- Implement technical controls.
- Maintain encryption systems.
- Monitor access controls.

---

## Information Security Department

Responsibilities:

- Maintain this policy.
- Perform compliance monitoring.
- Investigate violations.

---

## Management

Responsibilities:

- Approve policy enforcement.
- Ensure adequate resources for compliance.

---

# 7. Access Control Requirements

HealthPlus Medical Group follows the principle of least privilege.

Access must be:

- Authorized
- Business justified
- Reviewed periodically
- Removed when no longer required

Access methods include:

- Role-Based Access Control (RBAC)
- Multi-Factor Authentication (MFA)
- Identity verification
- Logging and monitoring

---

# 8. Policy Exceptions

Exceptions to this policy require:

1. Written justification
2. Business owner approval
3. Security risk assessment
4. Defined expiration date
5. Approval from Information Security

Temporary exceptions must be reviewed before expiration.

---

# 9. Enforcement

Failure to comply with this policy may result in:

- Removal of access privileges
- Mandatory security training
- Disciplinary action
- Contract termination
- Legal action when applicable

HealthPlus Medical Group may perform:

- Security audits
- Access reviews
- Compliance assessments
- Monitoring activities

---

# 10. Policy Review and Maintenance

This policy must be reviewed:

- At least annually
- After major security incidents
- After regulatory changes
- After significant technology changes

Updates require approval from the Information Security Department.

---

# Quick Reference Guide
# Data Classification Summary for Employees

## Protect Information Correctly

| Level | Meaning | Examples | Main Rule |
|---|---|---|---|
| PUBLIC | Safe to share externally | Website, marketing | May be shared publicly |
| INTERNAL | Company use only | Internal documents | Do not share externally |
| CONFIDENTIAL | Sensitive business/person data | PII, financial data | Protect and encrypt |
| RESTRICTED | Highest sensitivity | PHI, passwords | Strict access only |

---

# Before Sharing Information

Ask:

1. What classification level is this information?
2. Is the recipient authorized?
3. Is encryption required?
4. Am I using an approved system?

---

# Required Protection

## PUBLIC

- Label documents PUBLIC
- Verify approval before publishing

## INTERNAL

- Use company-approved systems
- Do not share externally without approval

## CONFIDENTIAL

- Encrypt files
- Limit access
- Use secure transmission methods

## RESTRICTED

- Use approved healthcare systems only
- Apply MFA
- Share only with authorized personnel

---

# Report Problems

Report:

- Lost documents
- Unauthorized access
- Incorrect sharing
- Suspected data exposure

Contact:

Information Security Department

security@healthplus.example.com

---

End of Document
