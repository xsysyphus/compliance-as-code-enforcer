# Compliance Controls to Policy Mapping

This document maps each OPA policy to specific SOC2 Trust Services Criteria, LGPD articles, and ISO 27001 controls.

## SOC2 Trust Services Criteria

### Common Criteria (CC)

#### CC6 - Logical and Physical Access Controls

| Policy File | SOC2 Control | Description | Severity | Auto-Remediate |
|-------------|--------------|-------------|----------|----------------|
| `s3_encryption.rego` | CC6.1, CC6.7 | Restricts logical access - Encryption protects data at rest | CRITICAL | ✅ |
| `no_plaintext_secrets.rego` | CC6.1 | Manages credentials - Secrets must be protected | CRITICAL | ❌ |
| `cloudtrail_enabled.rego` | CC6.7 | Encrypts data at rest - CloudTrail logs must be encrypted | CRITICAL | ✅ |
| `security_group_public_access.rego` | CC6.6 | Restricts network access - Critical ports must not be public | HIGH | ⚠️  |

#### CC7 - System Operations

| Policy File | SOC2 Control | Description | Severity | Auto-Remediate |
|-------------|--------------|-------------|----------|----------------|
| `cloudtrail_enabled.rego` | CC7.2, CC7.3 | Detects anomalies - CloudTrail provides audit trail for incident response | CRITICAL | ✅ |

### Availability Criteria (A)

| Policy File | SOC2 Control | Description | Severity | Auto-Remediate |
|-------------|--------------|-------------|----------|----------------|
| `rds_backup_retention.rego` | A1.2 | Backup and recovery - Ensures data can be restored after incidents | HIGH | ✅ |

---

## LGPD (Lei Geral de Proteção de Dados - Brazil)

| Policy File | LGPD Article | Requirement | Notes |
|-------------|--------------|-------------|-------|
| `s3_encryption.rego` | Art. 46, 49 | Security measures - Encryption of personal data | Mandatory for sensitive data |
| `no_plaintext_secrets.rego` | Art. 46 | Administrative and technical safeguards | Prevents credential exposure |
| `cloudtrail_enabled.rego` | Art. 37, 48 | Audit logs for data processing activities | Required for accountability |
| `rds_backup_retention.rego` | Art. 46 | Business continuity and disaster recovery | Data availability guarantee |

---

## ISO 27001:2013 Controls

| Policy File | ISO Control | Control Name | Implementation |
|-------------|-------------|--------------|----------------|
| `s3_encryption.rego` | A.10.1.1 | Cryptographic controls | S3 encryption at rest with AES-256 or KMS |
| `no_plaintext_secrets.rego` | A.9.4.1 | Information access restriction | Secrets Manager integration |
| `cloudtrail_enabled.rego` | A.12.4.1 | Event logging | CloudTrail multi-region with encryption |
| `rds_backup_retention.rego` | A.12.3.1 | Information backup | Automated RDS backups >= 7 days |
| `security_group_public_access.rego` | A.13.1.1 | Network controls | Restrict public access to critical services |

---

## Policy Severity Levels

### CRITICAL
- **Block deployment**: Violations prevent merge/deployment
- **Immediate remediation**: Must be fixed before production
- **Examples**: Unencrypted data, public databases, missing CloudTrail

### HIGH
- **Block deployment**: Should prevent merge (configurable)
- **Remediation required**: Fix within 24 hours
- **Examples**: Weak backup retention, overly permissive security groups

### MEDIUM
- **Warning only**: Does not block deployment
- **Remediation recommended**: Fix within 7 days
- **Examples**: Missing tags, suboptimal configurations

### LOW
- **Informational**: Best practice recommendations
- **Remediation optional**: Consider for future improvements
- **Examples**: Missing documentation, non-critical optimizations

---

## Auto-Remediation Capabilities

### ✅ Fully Automated
Violations can be automatically fixed without human intervention:
- Enable S3 encryption
- Set RDS backup retention
- Enable CloudTrail with encryption

### ⚠️  Requires Approval
Auto-remediation available but requires manual approval due to impact:
- Modify security group rules (production)
- Change encryption keys

### ❌ Manual Only
Requires developer intervention (cannot be automated safely):
- Migrate plaintext secrets to Secrets Manager
- Refactor code to remove hardcoded credentials

---

## Compliance Framework Coverage

### Current Coverage (Phase 1)

| Framework | Controls Covered | Total Controls | Coverage % |
|-----------|------------------|----------------|------------|
| SOC2 | 7 | 64 | 11% |
| LGPD | 4 | 10 (key articles) | 40% |
| ISO 27001 | 5 | 114 | 4% |

### Roadmap for Full Coverage

**Phase 2 (Runtime Monitoring):**
- IAM password policies (SOC2-CC6.1)
- MFA enforcement (SOC2-CC6.1)
- Encryption in transit (SOC2-CC6.7)
- Resource tagging compliance (LGPD-Art.37)

**Phase 3 (Advanced Controls):**
- Data residency checks (LGPD-Art.33)
- Incident response automation (SOC2-CC7.3)
- Vendor risk management (SOC2-CC9.2)
- GDPR right-to-deletion automation (LGPD-Art.18)

---

## Testing Policy Compliance

### Test Individual Policy

```bash
# Test S3 encryption policy against sample Terraform
conftest test terraform/test-infrastructure/s3.tf \
  --policy policies/soc2/s3_encryption.rego

# Test all SOC2 policies
conftest test terraform/test-infrastructure/*.tf \
  --policy policies/soc2/
```

### Verify Policy Correctness

```bash
# Run OPA unit tests
opa test policies/ -v

# Check for policy compilation errors
opa check policies/soc2/*.rego
```

### Generate Compliance Report

```bash
# Generate JSON report of all violations
conftest test terraform/ --policy policies/ --output json > compliance-report.json

# Parse and count violations by severity
jq '[.[] | .failures[] | .metadata.severity] | group_by(.) | map({severity: .[0], count: length})' compliance-report.json
```

---

## Exception Handling

### Granting Exceptions

For legitimate business needs that violate policies:

1. **Add exception tag** to Terraform resource:
   ```hcl
   resource "aws_security_group" "bastion" {
     # ... config ...
     tags = {
       Exception = "bastion"  # Recognized by security_group_public_access.rego
       Justification = "Jump host for admin access"
       ApprovedBy = "security-team@example.com"
       ExpiresOn = "2026-12-31"
     }
   }
   ```

2. **Document in exception registry**: Update `docs/exceptions.md`

3. **Review quarterly**: Security team reviews all exceptions

### Exception Expiration

Exceptions should be temporary:
- **Bastion hosts**: Annual review
- **Development resources**: 90 days
- **Migration windows**: 30 days

---

## References

- [SOC 2 Trust Services Criteria](https://www.aicpa.org/soc4so)
- [LGPD Full Text (Portuguese)](http://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm)
- [ISO/IEC 27001:2013 Controls](https://www.iso.org/standard/54534.html)
- [OPA Policy Language Reference](https://www.openpolicyagent.org/docs/latest/policy-language/)
