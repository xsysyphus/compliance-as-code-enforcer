#!/usr/bin/env bash
#
# Install dependencies for Compliance-as-Code Enforcer
# Installs OPA, Conftest, and optional tools
#

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

check_command() {
    if command -v "$1" &> /dev/null; then
        return 0
    fi
    return 1
}

info "Installing Compliance-as-Code Enforcer dependencies..."
echo ""

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux*)
        info "Detected Linux"
        OS_TYPE="linux"
        ;;
    Darwin*)
        info "Detected macOS"
        OS_TYPE="darwin"
        ;;
    *)
        warn "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Detect architecture
case "$ARCH" in
    x86_64|amd64)
        ARCH_TYPE="x86_64"
        ;;
    arm64|aarch64)
        ARCH_TYPE="arm64"
        ;;
    *)
        warn "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

info "OS: $OS_TYPE | Architecture: $ARCH_TYPE"
echo ""

#
# Install OPA
#

info "Installing Open Policy Agent (OPA)..."

if check_command opa; then
    OPA_VERSION=$(opa version | head -n1)
    success "OPA already installed: $OPA_VERSION"
else
    if [ "$OS_TYPE" = "darwin" ] && check_command brew; then
        info "Installing OPA via Homebrew..."
        brew install opa
        success "OPA installed via Homebrew"
    else
        info "Installing OPA from GitHub releases..."
        OPA_VERSION="v0.60.0"  # Update to latest stable

        if [ "$OS_TYPE" = "linux" ]; then
            OPA_URL="https://github.com/open-policy-agent/opa/releases/download/${OPA_VERSION}/opa_linux_${ARCH_TYPE}_static"
        else
            OPA_URL="https://github.com/open-policy-agent/opa/releases/download/${OPA_VERSION}/opa_darwin_${ARCH_TYPE}"
        fi

        curl -L -o /tmp/opa "$OPA_URL"
        chmod +x /tmp/opa
        sudo mv /tmp/opa /usr/local/bin/opa
        success "OPA installed to /usr/local/bin/opa"
    fi
fi

#
# Install Conftest
#

info "Installing Conftest..."

if check_command conftest; then
    CONFTEST_VERSION=$(conftest --version)
    success "Conftest already installed: $CONFTEST_VERSION"
else
    if [ "$OS_TYPE" = "darwin" ] && check_command brew; then
        info "Installing Conftest via Homebrew..."
        brew install conftest
        success "Conftest installed via Homebrew"
    else
        info "Installing Conftest from GitHub releases..."
        CONFTEST_VERSION="0.48.0"

        if [ "$OS_TYPE" = "linux" ]; then
            CONFTEST_FILE="conftest_${CONFTEST_VERSION}_Linux_${ARCH_TYPE}.tar.gz"
        else
            CONFTEST_FILE="conftest_${CONFTEST_VERSION}_Darwin_${ARCH_TYPE}.tar.gz"
        fi

        CONFTEST_URL="https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/${CONFTEST_FILE}"

        curl -L -o /tmp/conftest.tar.gz "$CONFTEST_URL"
        tar -xzf /tmp/conftest.tar.gz -C /tmp
        sudo mv /tmp/conftest /usr/local/bin/conftest
        rm /tmp/conftest.tar.gz
        success "Conftest installed to /usr/local/bin/conftest"
    fi
fi

#
# Install optional tools
#

info "Installing optional tools..."

# jq for JSON parsing
if check_command jq; then
    success "jq already installed"
else
    if [ "$OS_TYPE" = "darwin" ] && check_command brew; then
        brew install jq
        success "jq installed"
    elif [ "$OS_TYPE" = "linux" ]; then
        if check_command apt-get; then
            sudo apt-get update && sudo apt-get install -y jq
            success "jq installed"
        elif check_command yum; then
            sudo yum install -y jq
            success "jq installed"
        else
            warn "Could not install jq automatically. Please install manually."
        fi
    fi
fi

# Terraform (optional)
if check_command terraform; then
    TF_VERSION=$(terraform version -json | jq -r '.terraform_version' 2>/dev/null || terraform version | head -n1)
    success "Terraform already installed: $TF_VERSION"
else
    warn "Terraform not installed (optional)"
    info "Install from: https://www.terraform.io/downloads"
fi

# pre-commit (optional)
if check_command pre-commit; then
    success "pre-commit already installed"
else
    if check_command pip3; then
        info "Installing pre-commit via pip..."
        pip3 install --user pre-commit
        success "pre-commit installed"
    else
        warn "pre-commit not installed (requires Python pip)"
        info "Install: pip3 install pre-commit"
    fi
fi

echo ""
info "═══════════════════════════════════════"
success "Installation complete!"
info "═══════════════════════════════════════"
echo ""

# Verify installations
echo "Installed versions:"
echo "  OPA:      $(opa version | head -n1)"
echo "  Conftest: $(conftest --version)"
[ -x "$(command -v jq)" ] && echo "  jq:       $(jq --version)"
[ -x "$(command -v terraform)" ] && echo "  Terraform: $(terraform version | head -n1)"
[ -x "$(command -v pre-commit)" ] && echo "  pre-commit: $(pre-commit --version)"

echo ""
info "Next steps:"
echo "  1. Run tests: ./scripts/test-phase1.sh"
echo "  2. Install pre-commit hooks: pre-commit install"
echo "  3. Test policies: cd terraform/test-infrastructure && conftest test *.tf --policy ../../policies/soc2/"
echo ""
