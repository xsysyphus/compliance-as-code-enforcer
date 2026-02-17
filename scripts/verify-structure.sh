#!/usr/bin/env bash
#
# Verify Project Structure - No dependencies required
# Validates that all Phase 1 files exist and are properly structured
#

set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SUCCESS=0
FAILURES=0

info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[✓]${NC} $1"
    ((SUCCESS++))
}

error() {
    echo -e "${RED}[✗]${NC} $1"
    ((FAILURES++))
}

check_file() {
    local file="$1"
    local desc="$2"
    if [ -f "$PROJECT_ROOT/$file" ]; then
        success "$desc: $file"
        return 0
    else
        error "$desc missing: $file"
        return 1
    fi
}

check_dir() {
    local dir="$1"
    local desc="$2"
    if [ -d "$PROJECT_ROOT/$dir" ]; then
        success "$desc: $dir"
        return 0
    else
        error "$desc missing: $dir"
        return 1
    fi
}

check_executable() {
    local file="$1"
    if [ -x "$PROJECT_ROOT/$file" ]; then
        success "Executable: $file"
        return 0
    else
        error "Not executable: $file"
        return 1
    fi
}

cd "$PROJECT_ROOT"

echo ""
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN} 🛡️  PROJECT STRUCTURE VERIFICATION${NC}"
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""

info "Project root: $PROJECT_ROOT"
echo ""

#
# Core Documentation
#

echo -e "${BOLD}📚 Documentation${NC}"
check_file "README.md" "Main README"
check_file "TESTING.md" "Testing guide"
check_file "QUICKSTART-TEST.md" "Quick start guide"
check_file "CONTRIBUTING.md" "Contributing guide"
check_file "LICENSE" "License file"
echo ""

#
# Policy Files
#

echo -e "${BOLD}📜 OPA Policies${NC}"
check_file "policies/soc2/s3_encryption.rego" "S3 encryption policy"
check_file "policies/soc2/rds_backup_retention.rego" "RDS backup policy"
check_file "policies/soc2/no_plaintext_secrets.rego" "Plaintext secrets policy"
check_file "policies/soc2/cloudtrail_enabled.rego" "CloudTrail policy"
check_file "policies/soc2/security_group_public_access.rego" "Security group policy"
echo ""

#
# Policy Tests
#

echo -e "${BOLD}🧪 Policy Unit Tests${NC}"
check_file "policies/soc2/s3_encryption_test.rego" "S3 encryption tests"
check_file "policies/soc2/rds_backup_retention_test.rego" "RDS backup tests"
echo ""

#
# Test Infrastructure
#

echo -e "${BOLD}🏗️  Test Infrastructure${NC}"
check_file "terraform/test-infrastructure/main.tf" "Test infrastructure"
check_file "terraform/test-infrastructure/variables.tf" "Test variables"
check_file "terraform/test-infrastructure/outputs.tf" "Test outputs"
check_file "terraform/test-infrastructure/README.md" "Test infra docs"
echo ""

#
# CI/CD Workflows
#

echo -e "${BOLD}🔄 CI/CD Workflows${NC}"
check_file ".github/workflows/compliance-check.yml" "Compliance check workflow"
check_file ".github/workflows/policy-tests.yml" "Policy tests workflow"
echo ""

#
# Scripts
#

echo -e "${BOLD}🧰 Test Scripts${NC}"
check_file "scripts/test-phase1.sh" "Full test suite"
check_file "scripts/quick-demo.sh" "Interactive demo"
check_file "scripts/install-dependencies.sh" "Dependency installer"
check_file "scripts/setup.sh" "Setup script"

echo ""
echo -e "${BOLD}🔒 Script Permissions${NC}"
check_executable "scripts/test-phase1.sh"
check_executable "scripts/quick-demo.sh"
check_executable "scripts/install-dependencies.sh"
check_executable "scripts/setup.sh"
check_executable "scripts/verify-structure.sh"
echo ""

#
# Configuration Files
#

echo -e "${BOLD}⚙️  Configuration Files${NC}"
check_file ".gitignore" "Git ignore"
check_file ".pre-commit-config.yaml" "Pre-commit hooks"
check_file "terraform/terraform.tfvars.example" "Terraform vars example"
echo ""

#
# Documentation
#

echo -e "${BOLD}📖 Additional Documentation${NC}"
check_file "docs/policies-mapping.md" "Policy mapping docs"
check_file "docs/phase1-validation-checklist.md" "Validation checklist"
echo ""

#
# File Content Checks
#

echo -e "${BOLD}📝 Content Validation${NC}"

# Check README has substantial content
if [ $(wc -l < README.md) -gt 100 ]; then
    success "README.md has substantial content ($(wc -l < README.md) lines)"
else
    error "README.md too short ($(wc -l < README.md) lines)"
fi

# Check each policy has package declaration
POLICIES=(
    "policies/soc2/s3_encryption.rego"
    "policies/soc2/rds_backup_retention.rego"
    "policies/soc2/no_plaintext_secrets.rego"
    "policies/soc2/cloudtrail_enabled.rego"
    "policies/soc2/security_group_public_access.rego"
)

for policy in "${POLICIES[@]}"; do
    if grep -q "^package soc2" "$policy" 2>/dev/null; then
        success "$(basename $policy) has package declaration"
    else
        error "$(basename $policy) missing package declaration"
    fi
done

# Check test infrastructure has violations
if grep -q "non_compliant" terraform/test-infrastructure/main.tf; then
    success "Test infrastructure contains non-compliant resources"
else
    error "Test infrastructure missing non-compliant resources"
fi

# Check workflows have required steps
if grep -q "conftest" .github/workflows/compliance-check.yml; then
    success "Compliance workflow includes Conftest"
else
    error "Compliance workflow missing Conftest step"
fi

echo ""

#
# Summary
#

echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN} 📊 VERIFICATION SUMMARY${NC}"
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${BOLD}Total Checks:${NC}  $((SUCCESS + FAILURES))"
echo -e "${GREEN}${BOLD}Passed:${NC}       $SUCCESS"
echo -e "${RED}${BOLD}Failed:${NC}       $FAILURES"
echo ""

if [ $FAILURES -eq 0 ]; then
    echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║                                                   ║${NC}"
    echo -e "${GREEN}${BOLD}║   ✓ PROJECT STRUCTURE IS COMPLETE!              ║${NC}"
    echo -e "${GREEN}${BOLD}║                                                   ║${NC}"
    echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════╝${NC}"
    echo ""
    info "✅ All required files present and properly structured"
    info "✅ Ready for functional testing"
    echo ""
    echo -e "${CYAN}Next steps:${NC}"
    echo "  1. Install dependencies: ./scripts/install-dependencies.sh"
    echo "  2. Run tests: ./scripts/test-phase1.sh"
    echo "  3. Try demo: ./scripts/quick-demo.sh"
    echo ""
    exit 0
else
    echo -e "${RED}${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}${BOLD}║                                                   ║${NC}"
    echo -e "${RED}${BOLD}║   ✗ SOME FILES MISSING OR INCORRECT             ║${NC}"
    echo -e "${RED}${BOLD}║                                                   ║${NC}"
    echo -e "${RED}${BOLD}╚═══════════════════════════════════════════════════╝${NC}"
    echo ""
    error "Please ensure all required files are present"
    echo ""
    exit 1
fi
