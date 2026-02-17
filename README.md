# 🛡️ Compliance-as-Code Enforcer

> **Production-grade continuous compliance validation engine for AWS infrastructure**
> Translate SOC2/LGPD/ISO27001 controls into executable policies, enforce them in CI/CD pipelines, and monitor runtime compliance drift.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Terraform](https://img.shields.io/badge/Terraform-1.5+-623CE4?logo=terraform)](https://www.terraform.io/)
[![OPA](https://img.shields.io/badge/Policy-OPA%2FRego-blue)](https://www.openpolicyagent.org/)
[![AWS](https://img.shields.io/badge/AWS-Compliance-orange)](https://aws.amazon.com/)

---

## 🎯 Problem Statement

Compliance frameworks like SOC2, LGPD, and ISO27001 require **continuous evidence** that security controls are enforced. Traditional approaches rely on:
- Manual quarterly audits (expensive, slow, point-in-time snapshots)
- Spreadsheets tracking compliance status (error-prone, outdated)
- Reactive incident response (violations discovered after deployment)

**The cost of non-compliance**: Failed audits, security breaches, regulatory fines, customer trust erosion.

## Solution: Compliance-as-Code Enforcer

Translate compliance controls into **executable policies** that validate infrastructure **before** deployment (shift-left) and continuously monitor **runtime** for drift, providing automated evidence collection for auditors.

---

## 🎯 What This Project Does

1. **Policy-as-Code**: SOC2/LGPD/ISO27001 controls written as executable Rego policies (OPA)
2. **Shift-Left Validation**: Pre-commit hooks + CI/CD gates block non-compliant infrastructure before deployment
3. **Runtime Monitoring**: Daily Lambda scans detect configuration drift and compliance violations
4. **Evidence Automation**: Immutable audit logs + automated evidence collection for auditors
5. **Observability**: Real-time compliance dashboards showing % compliance, trends, and violations
6. **AI-Powered Assistant**: Local LLM (Ollama) + Cloud AI (Perplexity) for policy explanations, remediation advice, and test generation

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    COMPLIANCE-AS-CODE ENFORCER                  │
└─────────────────────────────────────────────────────────────────┘

  PHASE 1: PRE-DEPLOYMENT
  ┌─────────────┐
  │   Git Repo  │
  │  (Terraform)│
  └──────┬──────┘
         │
         ▼
  ┌─────────────────┐
  │  Pre-commit     │──► Conftest + OPA Policies
  │  Hook           │    (Local validation)
  └─────────────────┘
         │
         ▼
  ┌──────────────────┐
  │   GitHub PR      │
  └────────┬─────────┘
           │
           ▼
  ┌─────────────────────────┐
  │  GitHub Actions CI/CD   │
  │  - OPA Policy Scan      │
  │  - Checkov/tfsec        │
  │  - Block on violations  │
  └─────────────────────────┘

  PHASE 2: RUNTIME MONITORING
  Lambda scanner diário → DynamoDB (histórico) → S3 (evidências imutáveis)

  PHASE 3: OBSERVABILITY
  CloudWatch Alarms → Grafana Dashboards → Auto-remediation (opcional)
```

---

## 📂 Estrutura do Repositório

```
compliance-as-code-enforcer/
├── policies/
│   └── soc2/                      # OPA Rego policies + tests (SOC2 controls)
│       ├── s3_encryption.rego
│       ├── rds_backup_retention.rego
│       ├── cloudtrail_enabled.rego
│       ├── security_group_public_access.rego
│       ├── no_plaintext_secrets.rego
│       └── *_test.rego            # OPA unit tests for each policy
├── terraform/
│   ├── backend/                   # Remote state (S3 + DynamoDB lock)
│   ├── test-infrastructure/       # Demo infra with intentional violations
│   └── runtime-monitoring/        # Lambda, DynamoDB, EventBridge
├── lambda/
│   ├── scanner/                   # Runtime compliance scanner
│   └── remediator/                # Auto-remediation functions
├── .github/
│   └── workflows/
│       ├── compliance-check.yml   # OPA + Checkov + tfsec on PRs
│       └── policy-tests.yml       # OPA unit tests with coverage gate
├── dashboards/
│   └── grafana/                   # Grafana dashboard JSON
├── tests/
│   └── unit/                      # Python unit tests for Lambda functions
├── scripts/                       # Helper scripts
│   ├── ai-assistant.py            # AI-powered policy assistant (Ollama/Perplexity)
│   ├── setup.sh                   # Development environment setup
│   ├── quick-demo.sh              # Demo script
│   └── test-phase1.sh             # Policy validation test script
├── config/
│   └── ai-config.yaml             # AI assistant configuration
└── docs/
    ├── policies-mapping.md        # Maps Rego policies to SOC2 controls
    ├── exceptions.md              # Documented compliance exceptions
    └── AI-ASSISTANT-SETUP.md      # AI assistant setup guide
```

---

## 🚀 Quick Start

### Prerequisites

- **Terraform** >= 1.5.0
- **OPA (Open Policy Agent)** >= 0.58.0
- **Conftest** >= 0.45.0
- **AWS CLI** configured with appropriate credentials
- **Python** >= 3.11 (for Lambda functions)
- **Go** >= 1.21 (optional, for Lambda in Go)

### Installation

```bash
# 1. Clone repository
git clone https://github.com/xsysyphus/compliance-as-code-enforcer.git
cd compliance-as-code-enforcer

# 2. Install OPA and Conftest
brew install opa conftest  # macOS
# OR download from https://www.openpolicyagent.org/docs/latest/#running-opa

# 3. Configure Terraform backend (first-time setup)
cd terraform/backend
terraform init
terraform apply
# This creates S3 bucket + DynamoDB table for remote state

# 4. Install Python dependencies for Lambda
cd ../../lambda/scanner
pip install -r requirements.txt -t ./package/
```

### Running Policy Validation Locally

```bash
# Test policies against sample Terraform code
cd terraform/test-infrastructure

# Run OPA policies via Conftest
conftest test *.tf --policy ../../policies/soc2/

# Expected output:
# FAIL - main.tf - S3 bucket 'non-compliant-bucket' missing encryption
# FAIL - database.tf - RDS backup retention is 3 days (required: >= 7)
# PASS - cloudtrail.tf - CloudTrail properly configured
```

### Using the AI Assistant

The project includes an AI-powered assistant for policy analysis and remediation:

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Install Ollama (local LLM - free, unlimited)
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull phi3:mini

# 3. Verify setup
./scripts/ai-assistant.py setup

# 4. Use the assistant
./scripts/ai-assistant.py explain policies/soc2/s3_encryption.rego
./scripts/ai-assistant.py remediate --violation "S3 bucket lacks encryption"
./scripts/ai-assistant.py generate --requirement "EC2 instances must have tags"
```

For detailed setup instructions, see [docs/AI-ASSISTANT-SETUP.md](docs/AI-ASSISTANT-SETUP.md).

### Deploying to AWS

```bash
# Phase 2: Deploy runtime monitoring infrastructure
cd terraform/runtime-monitoring

terraform init
terraform plan
terraform apply

# This provisions:
# - Lambda scanner function
# - DynamoDB table for scan results
# - S3 bucket for evidence storage
# - EventBridge rule (daily trigger)
# - IAM roles with least privilege
```

---

## 🧪 Demo: Testing Policy Enforcement

### Scenario 1: Detect S3 Encryption Violation

```bash
# 1. Create non-compliant Terraform file
cat > test.tf << 'EOF'
resource "aws_s3_bucket" "bad_bucket" {
  bucket = "my-non-encrypted-bucket"
  # Missing: server_side_encryption_configuration
}
EOF

# 2. Run policy validation
conftest test test.tf --policy policies/soc2/

# Output:
# FAIL - test.tf - SOC2-CC6.1: S3 bucket must enable encryption at rest
```

### Scenario 2: Block Non-Compliant PR

1. Create PR with non-compliant infrastructure
2. GitHub Actions runs automatically
3. Pipeline fails with compliance violations commented on PR
4. Developer fixes issues locally using `conftest` before re-pushing
5. PR approved only after all critical violations resolved

---

## 📊 Compliance Policies Coverage

| **Policy**                          | **SOC2 Control** | **Severity** | **Auto-Remediate** |
|-------------------------------------|------------------|--------------|---------------------|
| S3 Encryption at Rest               | CC6.1, CC6.7     | CRITICAL     | ✅                  |
| RDS Backup Retention >= 7 days      | A1.2             | HIGH         | ✅                  |
| No Plaintext Secrets in Code        | CC6.1            | CRITICAL     | ❌                  |
| CloudTrail Enabled + Encrypted      | CC7.2, CC7.3     | CRITICAL     | ✅                  |
| Security Groups - No 0.0.0.0/0:22   | CC6.6            | HIGH         | ⚠️  (Manual review) |

**See [docs/policies-mapping.md](docs/policies-mapping.md) for complete control mapping.**

---

## 🎯 Key Features

### 1. Shift-Left Security
- Policies run on developer workstations (pre-commit)
- Fast feedback loop (< 10 seconds)
- No credentials needed for local validation

### 2. CI/CD Integration
- Automated GitHub Actions workflows
- PR comments show exact violations + remediation steps
- Customizable severity levels (block/warn/info)

### 3. Runtime Monitoring
- Lambda scans actual deployed AWS resources (not just IaC)
- Detects manual changes bypassing IaC
- Historical trending (compliance improving/degrading)

### 4. Evidence Collection
- S3 versioned bucket with Glacier transition
- Immutable audit logs
- AWS Config snapshots
- Ready for auditor export

### 5. Observability
- Real-time Grafana dashboard
- Compliance score per team/project
- Trend analysis
- CloudWatch alarms for critical violations

---

## 🔧 Configuration

### Customizing Policies

Edit Rego files in `policies/soc2/*.rego`:

```rego
# Example: Enforce MFA delete on S3 buckets
package soc2.s3_mfa_delete

violation[msg] {
    resource := input.resource.aws_s3_bucket[name]
    not resource.versioning[_].mfa_delete

    msg := sprintf("S3 bucket '%s' must enable MFA delete (SOC2-CC6.1)", [name])
}
```

### Adjusting Severity Levels

In GitHub Actions workflow (`.github/workflows/compliance.yml`):

```yaml
- name: Run OPA Policies
  run: |
    conftest test terraform/*.tf \
      --policy policies/soc2/ \
      --fail-on-warn  # Change to: --no-fail to warn only
```

---

## 📈 Monitoring & Dashboards

### Grafana Dashboard

1. Import `dashboards/grafana/compliance-dashboard.json`
2. Configure datasource pointing to CloudWatch/DynamoDB
3. View:
   - Overall compliance score (0-100%)
   - Violations by severity
   - Top 5 most violated controls
   - Compliance trend (last 30 days)

### CloudWatch Alarms

Auto-configured alarms for:
- CloudTrail disabled in any region
- S3 bucket encryption removed
- RDS backup retention reduced below threshold

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Adding new policies
- Extending to other compliance frameworks (HIPAA, PCI-DSS)
- Testing guidelines

---

## 🔒 Security Considerations

- **Secrets**: All secrets stored in AWS Secrets Manager (never in code)
- **IAM**: Least privilege roles using IAM policy conditions
- **Encryption**: All data at rest encrypted (S3-KMS, DynamoDB encryption)
- **Audit**: CloudTrail logs all API calls to compliance resources
- **Network**: Lambda runs in private subnet with VPC endpoints

---

## 💰 Cost Estimation

**Monthly AWS costs (assuming 100 resources scanned daily):**

| Service              | Usage                          | Cost/Month |
|----------------------|--------------------------------|------------|
| Lambda               | 1 invocation/day (128MB, 30s)  | < $0.01    |
| DynamoDB             | 1000 writes/month              | < $1.00    |
| S3 (Evidence)        | 10GB storage                   | $0.23      |
| CloudWatch Logs      | 5GB ingestion                  | $2.50      |
| AWS Config           | 100 resources recorded         | $20.00     |
| **Total**            |                                | **~$24/month** |

**Free Tier eligible**: Lambda, DynamoDB (within limits)

---

## 📚 Additional Resources

- [Open Policy Agent Documentation](https://www.openpolicyagent.org/docs/)
- [SOC2 Compliance Guide](https://www.aicpa.org/soc4so)
- [AWS Config Best Practices](https://docs.aws.amazon.com/config/latest/developerguide/best-practices.html)
- [Conftest Policy Examples](https://github.com/open-policy-agent/conftest/tree/master/examples)

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file

---

## 🙋 Support

- **Issues**: [GitHub Issues](https://github.com/xsysyphus/compliance-as-code-enforcer/issues)
- **Discussions**: [GitHub Discussions](https://github.com/xsysyphus/compliance-as-code-enforcer/discussions)

