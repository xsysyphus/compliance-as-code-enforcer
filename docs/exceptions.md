# Compliance Exceptions Registry

Document approved compliance exceptions to prevent false positives and maintain a full audit trail. Every exception must have an owner, a justification, an expiry date, and approval evidence.

## How to Register an Exception

1. Add a record to the table below.
2. Tag the Terraform resource with `Exception = "<id>"` and `ExpiresOn = "YYYY-MM-DD"`.
3. Include `Justification` and `ApprovedBy` tags on the resource when applicable.
4. Review and renew or expire the exception before the deadline.

| ID | Resource / Stack | Policy / Control | Severity | Justification | Owner | Approved By | Expires On | Evidence |
|----|------------------|------------------|----------|---------------|-------|-------------|------------|----------|
| EX-0001 | _e.g. aws_security_group.bastion_ | SOC2-CC6.6 (public SG) | HIGH | Break-glass access during migration | network-team | CISO | 2026-03-31 | Change ticket #123 |

## Guidelines

- Exceptions must be **temporary**: max 90 days for production, 30 days for migration windows.
- Renewal requires re-evaluation of the risk and new approval.
- Remove expired exceptions in the next hardening cycle.
- Attach links to tickets (Jira, ServiceNow) and risk assessment evidence.

## Quarterly Review

- **Owner**: Security / Compliance team.
- **Action**: Scan `Exception` tags, cross-reference with this table, and remove any expired entries.
