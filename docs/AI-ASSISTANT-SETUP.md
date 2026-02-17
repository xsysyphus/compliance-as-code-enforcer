# AI-Powered Policy Assistant

The AI assistant uses a **hybrid approach** combining a local LLM (Ollama) with an optional cloud provider (Perplexity) to explain policies, suggest remediations, generate new Rego rules, and create test scenarios.

| Command | Description | Default Provider | Cost |
|---------|-------------|------------------|------|
| `explain` | Explains a policy in plain language | Ollama (local) | Free |
| `remediate` | Suggests fixes for a violation | Ollama (local) | Free |
| `generate` | Generates new OPA/Rego policies | Perplexity (cloud) | ~$0.02/request |
| `simulate` | Creates Terraform test scenarios | Perplexity (cloud) | ~$0.02/request |

---

## System Requirements

### Ollama (Local LLM — required for free tier)

| Model | RAM Required | Disk |
|-------|-------------|------|
| `phi3:mini` | 4 GB | 2.3 GB |
| `mistral:7b` | 8 GB | 4.1 GB |
| `llama3:8b` | 16 GB | 4.7 GB |

- OS: Linux, macOS, or Windows with WSL
- CPU: Any modern processor (GPU optional but speeds up inference)

### Perplexity (Cloud — optional, for complex tasks)

- Perplexity API key
- Internet connection
- Model used: `llama-3.1-sonar-small-128k-online` (~$0.20 per million tokens)

---

## Step 1: Install Python Dependencies

```bash
pip install -r requirements.txt

# Or using a virtual environment (recommended):
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Step 2: Install Ollama

```bash
# Linux / macOS
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model (phi3:mini is the recommended starting point)
ollama pull phi3:mini

# Verify installation
ollama list
```

### Start Ollama as a service (optional)

```bash
# systemd (Linux)
sudo systemctl enable ollama && sudo systemctl start ollama

# Or run manually in the background
ollama serve &
```

## Step 3: Configure the Assistant

The default configuration in `config/ai-config.yaml` is ready to use with Ollama only — no changes needed to get started.

### Enable Perplexity (optional)

1. Get your API key at https://www.perplexity.ai/settings/api
2. Set the environment variable:

```bash
export PERPLEXITY_API_KEY="pplx-xxxxxxxxxxxxx"

# Persist across sessions
echo 'export PERPLEXITY_API_KEY="pplx-xxxxxxxxxxxxx"' >> ~/.bashrc
```

### Customize task routing

Edit `config/ai-config.yaml` to control which provider handles each task:

```yaml
task_routing:
  explain: "ollama"       # frequent tasks → local (free)
  remediate: "ollama"
  generate: "perplexity"  # complex tasks → cloud (better quality)
  simulate: "perplexity"
```

---

## Step 4: Verify Setup

```bash
./scripts/ai-assistant.py setup
```

Expected output:

```
✓ Ollama: Connected (model: phi3:mini)
✗ Perplexity: Disabled (optional)
✓ Cache: Configured (.ai-cache/)

Status: Ready to use!
```

---

## Usage

### Explain a policy

```bash
./scripts/ai-assistant.py explain policies/soc2/s3_encryption.rego

# With additional context
./scripts/ai-assistant.py explain \
  --policy policies/soc2/cloudtrail_enabled.rego \
  --context "I'm new to CloudTrail, explain it simply"
```

### Get remediation advice

```bash
./scripts/ai-assistant.py remediate \
  --violation "RDS instance 'insecure-db' is publicly accessible" \
  --file terraform/test-infrastructure/main.tf
```

### Generate a new policy

```bash
./scripts/ai-assistant.py generate \
  --requirement "EKS clusters must use private endpoints and envelope encryption with KMS" \
  --output policies/soc2/eks_security.rego
```

### Simulate test scenarios

```bash
./scripts/ai-assistant.py simulate \
  --resource rds \
  --scenarios 5
```

### Global flags

```bash
--no-cache          # Skip cache, force a new request
--provider ollama   # Force a specific provider
--provider perplexity
--verbose           # Show debug details
```

---

## Caching

Responses are cached by default to reduce API costs and speed up repeated queries:

```yaml
cache:
  enabled: true
  directory: ".ai-cache"
  ttl: 604800  # 7 days
```

The `.ai-cache/` directory is excluded from version control via `.gitignore`.

To clear the cache manually:

```bash
./scripts/ai-assistant.py cache-clear
# or
rm -rf .ai-cache/
```

---

## Cost Estimation (Perplexity)

| Usage | Monthly Cost |
|-------|-------------|
| 100 generate/simulate requests | ~$2–$5 |
| explain/remediate (Ollama) | Free |
| With $5/month budget | ~50–100 cloud requests |

Use Ollama for `explain` and `remediate` (80% of tasks) and Perplexity only for `generate` and `simulate` to stay well within a $5/month budget.

---

## Troubleshooting

**Ollama not responding:**
```bash
curl http://localhost:11434/api/tags
ollama serve  # start manually if needed
```

**Model not found:**
```bash
ollama pull phi3:mini
ollama list
```

**Perplexity 401 error:**
```bash
echo $PERPLEXITY_API_KEY  # check the variable is set
```

**Script not executable:**
```bash
chmod +x scripts/ai-assistant.py
```

---

## Additional Resources

- [Ollama Documentation](https://github.com/ollama/ollama)
- [Perplexity API](https://docs.perplexity.ai/)
- [OPA / Rego Language](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Conftest](https://www.conftest.dev/)
