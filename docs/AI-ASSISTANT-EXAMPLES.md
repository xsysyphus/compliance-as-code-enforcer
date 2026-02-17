# AI Assistant — Usage Examples

Practical examples showing the expected output of each assistant command.

---

## Example 1: Explain a Policy

```bash
./scripts/ai-assistant.py explain policies/soc2/s3_encryption.rego
```

**Expected output:**
```
🤖 Explaining policy: s3_encryption.rego
Provider: Ollama (phi3:mini)

═══════════════════════════════════════════════════════════════════

📋 WHAT THIS POLICY DOES:

Checks that all S3 buckets have encryption at rest enabled.
This is a CRITICAL security control required by:
- SOC2 CC6.1 and CC6.7 (Data Protection)
- LGPD Art. 46 (Technical Safeguards)
- ISO 27001 A.10.1.1 (Cryptographic Controls)

🔍 CHECKS PERFORMED:

1. ✓ Bucket has server_side_encryption_configuration defined
2. ✓ Encryption algorithm is AES256 or aws:kms
3. ✓ KMS is used for sensitive buckets (recommended)
4. ✓ Bucket key is enabled (reduces KMS costs)

❌ VIOLATIONS DETECTED:

- CRITICAL: Bucket with no encryption at all
- HIGH: Bucket using an unsupported algorithm
- MEDIUM: Bucket missing bucket_key_enabled (warning only)

💡 WHY IT MATTERS:

Data stored in S3 may include sensitive customer information.
Without encryption at rest, physical access to AWS storage or
an exploited vulnerability exposes data in plaintext.

🛠️ HOW TO FIX:

resource "aws_s3_bucket" "example" {
  bucket = "my-secure-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.mykey.arn
    }
    bucket_key_enabled = true
  }
}

═══════════════════════════════════════════════════════════════════
⏱️  Time: 2.3s | 💾 Cache: MISS
```

---

## Example 2: Get Remediation Advice

```bash
./scripts/ai-assistant.py remediate \
  --policy policies/soc2/no_plaintext_secrets.rego \
  --violation "RDS instance 'production-db' has plaintext password" \
  --context terraform/test-infrastructure/main.tf
```

**Expected output:**
```
🤖 Analyzing violation and suggesting remediation...
Provider: Ollama (phi3:mini)

═══════════════════════════════════════════════════════════════════

🚨 VIOLATION DETECTED:

Type: CRITICAL [SOC2-CC6.1]
Resource: aws_db_instance.production-db
Issue: RDS password is hardcoded in the Terraform source

⚠️  SECURITY IMPACT:

1. Password is visible in source code and Git history
2. Anyone with repository access can see the password
3. CI/CD logs may expose the password
4. Violates SOC2 CC6.1, LGPD Art. 46, ISO 27001 A.9.4.1

🛠️ RECOMMENDED SOLUTIONS:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OPTION 1: RDS Managed Password (most secure) ⭐ RECOMMENDED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

resource "aws_db_instance" "production_db" {
  identifier = "production-db"
  engine     = "postgres"

  # AWS manages the password and stores it in Secrets Manager
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.db_secrets.id
}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OPTION 2: Terraform Variable with CI/CD Secrets
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# variables.tf
variable "db_password" {
  type      = string
  sensitive = true
}

# GitHub Actions workflow
env:
  TF_VAR_db_password: ${{ secrets.RDS_PASSWORD }}

═══════════════════════════════════════════════════════════════════
⏱️  Time: 3.1s | 💾 Cache: MISS
```

---

## Example 3: Generate a New Policy

```bash
./scripts/ai-assistant.py generate \
  --requirement "All EC2 instances must have mandatory tags: Environment, Owner, CostCenter" \
  --compliance "SOC2-A1.2" \
  --severity "HIGH" \
  --output policies/custom/ec2_tagging.rego
```

**Expected output:**
```
🤖 Generating OPA policy from requirements...
Provider: Ollama (phi3:mini)

═══════════════════════════════════════════════════════════════════

📝 REQUIREMENT ANALYZED:

"All EC2 instances must have mandatory tags: Environment, Owner, CostCenter"
Framework: SOC2-A1.2 | Severity: HIGH

🔍 GENERATED POLICY:

# SOC2 Control: A1.2 (Asset Inventory and Classification)
# ISO 27001: A.8.1.1 (Inventory of assets)
# Severity: HIGH

package custom.ec2_tagging

import future.keywords.if
import future.keywords.in

required_tags    := ["Environment", "Owner", "CostCenter"]
valid_environments := ["production", "staging", "development", "qa"]

deny[msg] {
    instance    := input.resource.aws_instance[name]
    missing_tag := get_missing_tags(instance)[_]

    msg := {
        "msg": sprintf("HIGH [SOC2-A1.2]: EC2 instance '%s' missing required tag '%s'", [name, missing_tag]),
        "severity": "HIGH",
        "compliance": ["SOC2-A1.2"],
    }
}

get_missing_tags(instance) := missing {
    instance_tags := {tag | instance.tags[tag]}
    missing := [tag | tag := required_tags[_]; not tag in instance_tags]
}

✅ Policy written to: policies/custom/ec2_tagging.rego

═══════════════════════════════════════════════════════════════════
⏱️  Time: 4.7s | 💾 Cache: MISS
```

---

## Example 4: Simulate Test Scenarios

```bash
./scripts/ai-assistant.py simulate policies/soc2/security_group_public_access.rego
```

**Expected output:**
```
🤖 Generating test scenarios for the policy...
Provider: Ollama (phi3:mini)

═══════════════════════════════════════════════════════════════════

🧪 GENERATED TEST SCENARIOS

Policy: security_group_public_access.rego

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SCENARIO 1: Public SSH access (should FAIL — CRITICAL)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

resource "aws_security_group" "public_ssh" {
  name = "public-ssh-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SCENARIO 2: Restricted access (should PASS)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

resource "aws_security_group" "app_tier" {
  name = "app-tier-sg"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from internet"
  }
}

📋 HOW TO TEST:

conftest test terraform/tests/sg_test.tf \
  --policy policies/soc2/security_group_public_access.rego

# Expected: FAIL for scenario 1, PASS for scenario 2

═══════════════════════════════════════════════════════════════════
⏱️  Time: 3.8s | 💾 Cache: MISS
```

---

## Useful Commands

```bash
# View cache statistics
./scripts/ai-assistant.py cache-stats

# Clear cache
./scripts/ai-assistant.py cache-clear

# Force a specific provider
./scripts/ai-assistant.py explain policy.rego --provider ollama
./scripts/ai-assistant.py explain policy.rego --provider perplexity

# Debug mode
./scripts/ai-assistant.py --verbose explain policy.rego
```

---

## Performance Reference

| Command | Ollama (local) | Perplexity (cloud) |
|---------|---------------|-------------------|
| explain | 2–3s | 1–2s |
| remediate | 3–5s | 2–3s |
| generate | 4–7s | 3–4s |
| simulate | 3–6s | 2–4s |

---

## Common Workflows

### Fix a detected violation

```bash
# 1. Run policy scan
conftest test terraform/test-infrastructure/main.tf \
  --policy policies/soc2 \
  --output json > violations.json

# 2. Get remediation for a specific violation
./scripts/ai-assistant.py remediate \
  --violation "Security group 'web-sg' exposes port 22 to internet" \
  --context terraform/test-infrastructure/main.tf

# 3. Apply the suggested fix, then re-test
conftest test terraform/test-infrastructure/main.tf --policy policies/soc2
```

### Create a new policy from scratch

```bash
# 1. Generate the base policy
./scripts/ai-assistant.py generate \
  --requirement "ALB must have access logs enabled and stored in an encrypted S3 bucket" \
  --output policies/soc2/alb_access_logs.rego

# 2. Review the generated policy, then test it
conftest test terraform/test-infrastructure/main.tf \
  --policy policies/soc2/alb_access_logs.rego
```
