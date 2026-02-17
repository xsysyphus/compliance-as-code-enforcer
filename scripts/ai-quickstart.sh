#!/bin/bash
# Quick demonstration of AI Assistant capabilities

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  AI Assistant Quick Start Demo${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Step 1: Check setup
echo -e "${YELLOW}[1/5] Checking AI Assistant Setup...${NC}"
python3 scripts/ai-assistant.py setup
echo ""

# Step 2: Test explain command (if Ollama is available)
if curl -s http://localhost:11434/api/version >/dev/null 2>&1; then
    echo -e "${YELLOW}[2/5] Testing 'explain' command (using Ollama)...${NC}"
    echo -e "${GREEN}Command: ./scripts/ai-assistant.py explain --policy policies/soc2/s3_encryption.rego${NC}"
    echo ""
    python3 scripts/ai-assistant.py explain --policy policies/soc2/s3_encryption.rego
    echo ""
else
    echo -e "${YELLOW}[2/5] Skipping 'explain' demo (Ollama not running)${NC}"
    echo -e "${RED}Install Ollama: https://ollama.ai${NC}"
    echo ""
fi

# Step 3: Show example remediate command
echo -e "${YELLOW}[3/5] Example 'remediate' command:${NC}"
echo -e "${GREEN}./scripts/ai-assistant.py remediate \\${NC}"
echo -e "${GREEN}  --violation \"RDS instance 'test-db' is publicly accessible\" \\${NC}"
echo -e "${GREEN}  --file terraform/test-infrastructure/main.tf${NC}"
echo ""

# Step 4: Show example generate command
echo -e "${YELLOW}[4/5] Example 'generate' command:${NC}"
echo -e "${GREEN}./scripts/ai-assistant.py generate \\${NC}"
echo -e "${GREEN}  --requirement \"EKS clusters must use private endpoints\" \\${NC}"
echo -e "${GREEN}  --framework SOC2,LGPD${NC}"
echo ""

# Step 5: Show example simulate command
echo -e "${YELLOW}[5/5] Example 'simulate' command:${NC}"
echo -e "${GREEN}./scripts/ai-assistant.py simulate \\${NC}"
echo -e "${GREEN}  --resource rds \\${NC}"
echo -e "${GREEN}  --scenarios 5${NC}"
echo ""

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  Next Steps${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""
echo "1. Install Ollama (free, local): https://ollama.ai"
echo "   - Download and run: ollama serve"
echo "   - Pull model: ollama pull phi3:mini"
echo ""
echo "2. (Optional) Configure Perplexity API:"
echo "   - Get API key: https://www.perplexity.ai/settings/api"
echo "   - Set env: export PERPLEXITY_API_KEY='your-key'"
echo ""
echo "3. Read full documentation: docs/AI-ASSISTANT.md"
echo ""
echo "4. Try the commands:"
echo "   - Explain policies: ./scripts/ai-assistant.py explain --policy policies/soc2/s3_encryption.rego"
echo "   - Get remediation: ./scripts/ai-assistant.py remediate --violation 'your violation'"
echo "   - Generate policy: ./scripts/ai-assistant.py generate --requirement 'your requirement'"
echo "   - Simulate tests: ./scripts/ai-assistant.py simulate --resource s3 --scenarios 3"
echo ""
