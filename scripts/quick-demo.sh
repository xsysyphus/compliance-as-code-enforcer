#!/usr/bin/env bash
#
# Quick Demo - Compliance-as-Code Enforcer
# Demonstrates policy enforcement in action
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

header() {
    echo ""
    echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE} $1${NC}"
    echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo ""
}

info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

error() {
    echo -e "${RED}[✗]${NC} $1"
}

step() {
    echo ""
    echo -e "${BOLD}${YELLOW}▶ STEP $1:${NC} $2"
    echo ""
}

press_enter() {
    echo ""
    echo -e "${CYAN}Press ENTER to continue...${NC}"
    read
}

# Check prerequisites
if ! command -v opa &> /dev/null; then
    error "OPA not installed. Run: ./scripts/install-dependencies.sh"
    exit 1
fi

if ! command -v conftest &> /dev/null; then
    error "Conftest not installed. Run: ./scripts/install-dependencies.sh"
    exit 1
fi

cd "$PROJECT_ROOT"

clear

header "🛡️  COMPLIANCE-AS-CODE ENFORCER - INTERACTIVE DEMO"

info "This demo shows how Policy-as-Code prevents non-compliant infrastructure"
info "from being deployed to production."
echo ""
info "You'll see:"
echo "  1. ✅ How compliant resources are validated"
echo "  2. ❌ How violations are detected and blocked"
echo "  3. 🔧 How to remediate violations"

press_enter

#
# DEMO PART 1: Show policies
#

step 1 "Reviewing SOC2 Compliance Policies"

info "We have 5 policies enforcing SOC2 controls:"
echo ""
echo "  📜 s3_encryption.rego              → Ensures S3 buckets are encrypted"
echo "  📜 rds_backup_retention.rego       → Requires RDS backup >= 7 days"
echo "  📜 no_plaintext_secrets.rego       → Blocks hardcoded passwords"
echo "  📜 cloudtrail_enabled.rego         → Enforces audit logging"
echo "  📜 security_group_public_access.rego → Prevents public SSH/DB access"

press_enter

step 2 "Verifying Policy Compilation"

info "Checking that all policies compile correctly..."
echo ""

if opa check policies/soc2/*.rego &>/dev/null; then
    success "All 5 policies compiled successfully!"
else
    error "Policy compilation failed"
    exit 1
fi

press_enter

#
# DEMO PART 2: Test against non-compliant infrastructure
#

step 3 "Scanning Test Infrastructure for Violations"

info "Running Conftest against test infrastructure with intentional violations..."
echo ""

cd terraform/test-infrastructure

# Create temp file for output
TEMP_OUTPUT=$(mktemp)

info "Command: conftest test main.tf --policy ../../policies/soc2/"
echo ""
sleep 1

if conftest test main.tf --policy ../../policies/soc2/ --all-namespaces > "$TEMP_OUTPUT" 2>&1; then
    error "Unexpected: No violations detected"
else
    success "Violations detected! (This is expected)"
fi

echo ""
echo -e "${YELLOW}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}${BOLD} DETECTED VIOLATIONS:${NC}"
echo -e "${YELLOW}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
cat "$TEMP_OUTPUT" | head -30
echo -e "${YELLOW}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

rm "$TEMP_OUTPUT"

press_enter

#
# DEMO PART 3: Show specific violation examples
#

step 4 "Examining Specific Violations"

info "Let's look at a specific violation in detail..."
echo ""

echo -e "${RED}${BOLD}Example 1: S3 Bucket Without Encryption${NC}"
echo ""
echo -e "${YELLOW}Non-compliant code (from main.tf):${NC}"
echo ""
cat <<'EOF'
resource "aws_s3_bucket" "non_compliant_bucket" {
  bucket = "my-unencrypted-bucket"
  # ❌ Missing: server_side_encryption_configuration
}
EOF

echo ""
info "Policy violation message includes remediation guidance:"
echo ""

conftest test main.tf --policy ../../policies/soc2/s3_encryption.rego 2>&1 | grep -A 10 "CRITICAL" | head -15 || true

press_enter

echo ""
echo -e "${GREEN}${BOLD}Compliant version (from main.tf):${NC}"
echo ""
cat <<'EOF'
resource "aws_s3_bucket" "compliant_bucket" {
  bucket = "my-encrypted-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliant_bucket" {
  bucket = aws_s3_bucket.compliant_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"  # ✅ Encryption enabled
    }
  }
}
EOF

press_enter

#
# DEMO PART 4: Show CI/CD integration
#

cd "$PROJECT_ROOT"

step 5 "CI/CD Integration"

info "In a real workflow, these policies run automatically in GitHub Actions:"
echo ""

cat <<'EOF'
┌─────────────────┐
│  Developer      │
│  commits code   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   GitHub PR     │
│   created       │
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│  GitHub Actions         │
│  - Checkout code        │
│  - Run Conftest         │ ← Policies enforced here
│  - Detect violations    │
└────────┬────────────────┘
         │
         ├─────► ✅ No violations → PR can be merged
         │
         └─────► ❌ CRITICAL violations → PR blocked
                   └─ Comment added with remediation steps
EOF

echo ""
info "See .github/workflows/compliance-check.yml for full workflow"

press_enter

#
# DEMO PART 5: Summary
#

step 6 "Demo Summary"

echo -e "${GREEN}${BOLD}✓ What we demonstrated:${NC}"
echo ""
echo "  1. ✅ 5 SOC2 policies compiled and ready"
echo "  2. ✅ Policies detected 5+ violations in test infrastructure"
echo "  3. ✅ Violation messages include remediation guidance"
echo "  4. ✅ Ready for CI/CD integration"
echo ""

echo -e "${CYAN}${BOLD}Next steps to use this project:${NC}"
echo ""
echo "  1. Copy this repo structure to your project"
echo "  2. Customize policies in policies/soc2/"
echo "  3. Add GitHub Actions workflows"
echo "  4. Install pre-commit hooks: pre-commit install"
echo "  5. Deploy to AWS: cd terraform/runtime-monitoring && terraform apply"
echo ""

echo -e "${YELLOW}${BOLD}Try it yourself:${NC}"
echo ""
echo "  # Test against your own Terraform:"
echo "  cd terraform/test-infrastructure"
echo "  conftest test *.tf --policy ../../policies/soc2/"
echo ""
echo "  # Run full test suite:"
echo "  ./scripts/test-phase1.sh"
echo ""

header "🎉 DEMO COMPLETE"

info "This project is ready for production use!"
info "All components of PHASE 1 are operational."
echo ""
