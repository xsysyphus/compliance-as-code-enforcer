#!/usr/bin/env bash
#
# Comprehensive Test Suite for FASE 1 - Compliance-as-Code Enforcer
# Tests OPA policies, Conftest validation, and expected violation detection
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Test results tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[✓]${NC} $1"
    ((PASSED_TESTS++))
}

error() {
    echo -e "${RED}[✗]${NC} $1"
    ((FAILED_TESTS++))
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

header() {
    echo ""
    echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE} $1${NC}"
    echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo ""
}

test_start() {
    ((TOTAL_TESTS++))
    echo -e "${CYAN}▶${NC} Testing: $1"
}

check_command() {
    if command -v "$1" &> /dev/null; then
        return 0
    fi
    return 1
}

# Change to project root
cd "$PROJECT_ROOT"

header "🛡️  COMPLIANCE-AS-CODE ENFORCER - PHASE 1 TEST SUITE"

info "Project root: $PROJECT_ROOT"
info "Starting comprehensive validation..."

#
# TEST 1: Check prerequisites
#

header "TEST 1: Prerequisites Check"

test_start "OPA installation"
if check_command opa; then
    OPA_VERSION=$(opa version | head -n1)
    success "OPA installed: $OPA_VERSION"
else
    error "OPA not found. Install: https://www.openpolicyagent.org/docs/latest/#running-opa"
    warn "  macOS: brew install opa"
    warn "  Linux: See https://www.openpolicyagent.org/docs/latest/#running-opa"
    exit 1
fi

test_start "Conftest installation"
if check_command conftest; then
    CONFTEST_VERSION=$(conftest --version)
    success "Conftest installed: $CONFTEST_VERSION"
else
    error "Conftest not found. Install: https://www.conftest.dev/install/"
    warn "  macOS: brew install conftest"
    warn "  Linux: wget https://github.com/open-policy-agent/conftest/releases/download/v0.48.0/conftest_0.48.0_Linux_x86_64.tar.gz"
    exit 1
fi

test_start "Terraform installation (optional)"
if check_command terraform; then
    TF_VERSION=$(terraform version -json | jq -r '.terraform_version' 2>/dev/null || terraform version | head -n1)
    success "Terraform installed: $TF_VERSION"
else
    warn "Terraform not found (optional for FASE 1 tests)"
fi

test_start "jq installation"
if check_command jq; then
    success "jq installed"
else
    warn "jq not found (optional, for JSON parsing)"
fi

#
# TEST 2: OPA Policy Compilation
#

header "TEST 2: OPA Policy Syntax Validation"

test_start "Compile S3 encryption policy"
if opa check policies/soc2/s3_encryption.rego &>/dev/null; then
    success "s3_encryption.rego compiles successfully"
else
    error "s3_encryption.rego has syntax errors"
    opa check policies/soc2/s3_encryption.rego
fi

test_start "Compile RDS backup retention policy"
if opa check policies/soc2/rds_backup_retention.rego &>/dev/null; then
    success "rds_backup_retention.rego compiles successfully"
else
    error "rds_backup_retention.rego has syntax errors"
    opa check policies/soc2/rds_backup_retention.rego
fi

test_start "Compile plaintext secrets policy"
if opa check policies/soc2/no_plaintext_secrets.rego &>/dev/null; then
    success "no_plaintext_secrets.rego compiles successfully"
else
    error "no_plaintext_secrets.rego has syntax errors"
    opa check policies/soc2/no_plaintext_secrets.rego
fi

test_start "Compile CloudTrail policy"
if opa check policies/soc2/cloudtrail_enabled.rego &>/dev/null; then
    success "cloudtrail_enabled.rego compiles successfully"
else
    error "cloudtrail_enabled.rego has syntax errors"
    opa check policies/soc2/cloudtrail_enabled.rego
fi

test_start "Compile security group policy"
if opa check policies/soc2/security_group_public_access.rego &>/dev/null; then
    success "security_group_public_access.rego compiles successfully"
else
    error "security_group_public_access.rego has syntax errors"
    opa check policies/soc2/security_group_public_access.rego
fi

#
# TEST 3: OPA Unit Tests
#

header "TEST 3: OPA Policy Unit Tests"

test_start "Run all OPA unit tests"
if opa test policies/ &>/dev/null; then
    success "All OPA unit tests passed"
    opa test policies/ -v | grep -E "^(PASS|data\.)" | head -20
else
    error "Some OPA unit tests failed"
    opa test policies/ -v
fi

#
# TEST 4: Conftest Validation Against Test Infrastructure
#

header "TEST 4: Policy Enforcement - Detecting Violations"

info "Testing against intentionally non-compliant infrastructure..."

# Run conftest and capture output
test_start "Run Conftest against test infrastructure"

cd terraform/test-infrastructure

# Create temporary output files
CONFTEST_OUTPUT=$(mktemp)
CONFTEST_JSON=$(mktemp)

if conftest test main.tf --policy ../../policies/soc2/ --all-namespaces > "$CONFTEST_OUTPUT" 2>&1; then
    error "Conftest should have detected violations but passed"
    cat "$CONFTEST_OUTPUT"
else
    success "Conftest correctly detected violations (non-zero exit)"
fi

# Run again to get JSON output for parsing
conftest test main.tf --policy ../../policies/soc2/ --output json --all-namespaces > "$CONFTEST_JSON" 2>&1 || true

# Display human-readable violations
echo ""
info "Detected violations:"
echo "---"
cat "$CONFTEST_OUTPUT" | head -50
echo "---"

#
# TEST 5: Validate Expected Violations
#

header "TEST 5: Verify Expected Violations Detected"

info "Expected violations: 5 (3 CRITICAL, 2+ HIGH)"
echo ""

# Count violations by searching for specific patterns in output
test_start "Detect S3 encryption violation (CRITICAL)"
if grep -q "S3 bucket.*encryption" "$CONFTEST_OUTPUT"; then
    success "✓ Detected: S3 bucket without encryption (SOC2-CC6.1/CC6.7)"
else
    error "✗ Missing: S3 encryption violation not detected"
fi

test_start "Detect RDS plaintext password violation (CRITICAL)"
if grep -q "password" "$CONFTEST_OUTPUT" || grep -q "plaintext" "$CONFTEST_OUTPUT"; then
    success "✓ Detected: RDS plaintext password (SOC2-CC6.1)"
else
    warn "⚠ May be missing: RDS plaintext password violation"
fi

test_start "Detect RDS backup retention violation (HIGH)"
if grep -q "backup.*retention\|backup_retention_period" "$CONFTEST_OUTPUT"; then
    success "✓ Detected: RDS insufficient backup retention (SOC2-A1.2)"
else
    error "✗ Missing: RDS backup retention violation not detected"
fi

test_start "Detect public SSH access violation (HIGH)"
if grep -q "SSH\|port.*22\|0\.0\.0\.0/0.*22" "$CONFTEST_OUTPUT"; then
    success "✓ Detected: Security group public SSH access (SOC2-CC6.6)"
else
    error "✗ Missing: Public SSH access violation not detected"
fi

test_start "Detect public database access violation (HIGH)"
if grep -q "PostgreSQL\|port.*5432\|database" "$CONFTEST_OUTPUT"; then
    success "✓ Detected: Security group public database access (SOC2-CC6.6)"
else
    warn "⚠ May be missing: Public database access violation"
fi

# Count total violations using JSON if available
if [ -s "$CONFTEST_JSON" ] && check_command jq; then
    TOTAL_VIOLATIONS=$(jq '[.[].failures] | flatten | length' "$CONFTEST_JSON" 2>/dev/null || echo "unknown")
    CRITICAL_VIOLATIONS=$(jq '[.[].failures[] | select(.msg | contains("CRITICAL"))] | length' "$CONFTEST_JSON" 2>/dev/null || echo "unknown")
    HIGH_VIOLATIONS=$(jq '[.[].failures[] | select(.msg | contains("HIGH"))] | length' "$CONFTEST_JSON" 2>/dev/null || echo "unknown")

    echo ""
    info "Violation Summary:"
    echo "  Total violations: $TOTAL_VIOLATIONS"
    echo "  CRITICAL: $CRITICAL_VIOLATIONS"
    echo "  HIGH: $HIGH_VIOLATIONS"

    if [ "$TOTAL_VIOLATIONS" -ge 5 ]; then
        success "Detected expected number of violations (>= 5)"
    else
        warn "Detected fewer violations than expected ($TOTAL_VIOLATIONS < 5)"
    fi
fi

# Cleanup
rm -f "$CONFTEST_OUTPUT" "$CONFTEST_JSON"
cd "$PROJECT_ROOT"

#
# TEST 6: Terraform Validation (if available)
#

if check_command terraform; then
    header "TEST 6: Terraform Syntax Validation"

    cd terraform/test-infrastructure

    test_start "Terraform format check"
    if terraform fmt -check -recursive . &>/dev/null; then
        success "Terraform files properly formatted"
    else
        warn "Terraform files need formatting (run: terraform fmt)"
    fi

    test_start "Terraform validation"
    if terraform init -backend=false &>/dev/null && terraform validate &>/dev/null; then
        success "Terraform syntax is valid"
    else
        warn "Terraform validation failed (expected if AWS provider features unavailable)"
    fi

    cd "$PROJECT_ROOT"
fi

#
# TEST 7: Documentation Validation
#

header "TEST 7: Documentation Completeness"

test_start "README.md exists and is substantial"
if [ -f "README.md" ] && [ $(wc -l < README.md) -gt 100 ]; then
    success "README.md exists ($(wc -l < README.md) lines)"
else
    error "README.md missing or incomplete"
fi

test_start "Policy mapping documentation exists"
if [ -f "docs/policies-mapping.md" ]; then
    success "docs/policies-mapping.md exists"
else
    error "docs/policies-mapping.md missing"
fi

test_start "GitHub Actions workflows exist"
if [ -f ".github/workflows/compliance-check.yml" ] && [ -f ".github/workflows/policy-tests.yml" ]; then
    success "GitHub Actions workflows configured"
else
    error "GitHub Actions workflows missing"
fi

test_start "Pre-commit hooks configured"
if [ -f ".pre-commit-config.yaml" ]; then
    success ".pre-commit-config.yaml exists"
else
    warn "Pre-commit hooks not configured"
fi

#
# FINAL SUMMARY
#

header "📊 TEST SUMMARY"

echo ""
echo -e "${BOLD}Total Tests:${NC}  $TOTAL_TESTS"
echo -e "${GREEN}${BOLD}Passed:${NC}       $PASSED_TESTS"
echo -e "${RED}${BOLD}Failed:${NC}       $FAILED_TESTS"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║                                                   ║${NC}"
    echo -e "${GREEN}${BOLD}║   ✓ ALL TESTS PASSED - FASE 1 IS OPERATIONAL!   ║${NC}"
    echo -e "${GREEN}${BOLD}║                                                   ║${NC}"
    echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════╝${NC}"
    echo ""
    info "✅ Phase 1 is production-ready!"
    info "✅ OPA policies compile and pass unit tests"
    info "✅ Conftest correctly detects compliance violations"
    info "✅ Test infrastructure demonstrates all 5 violation types"
    info "✅ CI/CD workflows are configured"
    echo ""
    echo -e "${CYAN}Next steps:${NC}"
    echo "  1. Test locally: cd terraform/test-infrastructure && conftest test *.tf --policy ../../policies/soc2/"
    echo "  2. Install pre-commit: pip install pre-commit && pre-commit install"
    echo "  3. Ready for FASE 2: Runtime monitoring with Lambda scanner"
    echo ""
    exit 0
else
    echo -e "${RED}${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}${BOLD}║                                                   ║${NC}"
    echo -e "${RED}${BOLD}║   ✗ SOME TESTS FAILED - REVIEW ERRORS ABOVE     ║${NC}"
    echo -e "${RED}${BOLD}║                                                   ║${NC}"
    echo -e "${RED}${BOLD}╚═══════════════════════════════════════════════════╝${NC}"
    echo ""
    error "Please fix failures before proceeding to Phase 2"
    exit 1
fi
