#!/usr/bin/env python3
"""
AI-Powered Compliance Assistant
Hybrid solution using Ollama (local) + Perplexity API (cloud)

Usage:
  ./scripts/ai-assistant.py explain --policy policies/soc2/s3_encryption.rego
  ./scripts/ai-assistant.py remediate --violation "RDS public access" --file main.tf
  ./scripts/ai-assistant.py generate --requirement "EKS clusters must use private endpoints"
  ./scripts/ai-assistant.py simulate --resource rds --scenarios 5
"""

import argparse
import json
import os
import sys
import subprocess
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import yaml

# Configuration
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
CACHE_DIR = PROJECT_ROOT / ".ai-cache"
CONFIG_FILE = PROJECT_ROOT / "config" / "ai-config.yaml"

# Colors for terminal output
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_info(msg: str):
    print(f"{Colors.CYAN}[INFO]{Colors.END} {msg}")

def print_success(msg: str):
    print(f"{Colors.GREEN}[✓]{Colors.END} {msg}")

def print_warning(msg: str):
    print(f"{Colors.YELLOW}[!]{Colors.END} {msg}")

def print_error(msg: str):
    print(f"{Colors.RED}[✗]{Colors.END} {msg}")

def print_section(title: str):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE} {title}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}\n")


class AIConfig:
    """Manages AI assistant configuration"""

    DEFAULT_CONFIG = {
        'ollama': {
            'enabled': True,
            'model': 'phi3:mini',  # Lightweight, fast, good quality
            'base_url': 'http://localhost:11434',
            'use_for': [
                'explain',
                'validate',
                'simple_remediation',
                'code_generation'
            ]
        },
        'perplexity': {
            'enabled': False,  # User needs to add API key
            'api_key_env': 'PERPLEXITY_API_KEY',
            'model': 'llama-3.1-sonar-small-128k-online',
            'use_for': [
                'research',
                'complex_analysis',
                'vulnerability_search',
                'best_practices'
            ]
        },
        'cache': {
            'enabled': True,
            'ttl_hours': 24,
            'max_size_mb': 100
        },
        'preferences': {
            'default_provider': 'ollama',  # ollama or perplexity
            'fallback_enabled': True,
            'verbose': False
        }
    }

    def __init__(self):
        self.config = self._load_config()

    def _load_config(self) -> Dict:
        """Load configuration from file or create default"""
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r') as f:
                return yaml.safe_load(f)
        else:
            # Create default config
            CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(CONFIG_FILE, 'w') as f:
                yaml.dump(self.DEFAULT_CONFIG, f, default_flow_style=False)
            print_info(f"Created default config at {CONFIG_FILE}")
            return self.DEFAULT_CONFIG

    def get_provider_for_task(self, task_type: str) -> str:
        """Determine which AI provider to use for given task"""
        # Check task_routing configuration
        if 'task_routing' in self.config:
            provider = self.config['task_routing'].get(task_type)
            if provider and self.config.get(provider, {}).get('enabled', False):
                return provider

        # Fallback: try Ollama first, then Perplexity
        if self.config.get('ollama', {}).get('enabled', False):
            return 'ollama'
        if self.config.get('perplexity', {}).get('enabled', False):
            return 'perplexity'

        # Default to ollama
        return 'ollama'


class OllamaProvider:
    """Ollama local LLM provider"""

    def __init__(self, config: Dict):
        self.model = config.get('model', 'phi3:mini')
        self.base_url = config.get('base_url', 'http://localhost:11434')

    def is_available(self) -> bool:
        """Check if Ollama is running"""
        try:
            result = subprocess.run(
                ['curl', '-s', f'{self.base_url}/api/tags'],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except:
            return False

    def check_model_installed(self) -> bool:
        """Check if the configured model is installed"""
        try:
            result = subprocess.run(
                ['ollama', 'list'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return self.model in result.stdout
        except:
            return False

    def pull_model(self):
        """Download the model if not installed"""
        print_info(f"Downloading Ollama model: {self.model}")
        print_info("This may take a few minutes on first run...")
        try:
            subprocess.run(['ollama', 'pull', self.model], check=True)
            print_success(f"Model {self.model} downloaded successfully")
        except subprocess.CalledProcessError as e:
            print_error(f"Failed to download model: {e}")
            raise

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate response using Ollama"""
        import requests

        payload = {
            'model': self.model,
            'prompt': prompt,
            'stream': False
        }

        if system_prompt:
            payload['system'] = system_prompt

        try:
            response = requests.post(
                f'{self.base_url}/api/generate',
                json=payload,
                timeout=60
            )
            response.raise_for_status()
            return response.json()['response']
        except Exception as e:
            raise Exception(f"Ollama generation failed: {e}")


class PerplexityProvider:
    """Perplexity AI API provider"""

    def __init__(self, config: Dict):
        self.model = config.get('model', 'llama-3.1-sonar-small-128k-online')
        self.api_key = os.getenv(config.get('api_key_env', 'PERPLEXITY_API_KEY'))

    def is_available(self) -> bool:
        """Check if API key is configured"""
        return self.api_key is not None and len(self.api_key) > 0

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate response using Perplexity API"""
        import requests

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.model,
            "messages": messages
        }

        try:
            response = requests.post(
                "https://api.perplexity.ai/chat/completions",
                headers=headers,
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            return response.json()['choices'][0]['message']['content']
        except Exception as e:
            raise Exception(f"Perplexity API failed: {e}")


class CacheManager:
    """Manages response caching to save API calls"""

    def __init__(self, config: Dict):
        self.enabled = config.get('enabled', True)
        self.cache_dir = CACHE_DIR
        if self.enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_key(self, prompt: str, provider: str) -> str:
        """Generate cache key from prompt"""
        content = f"{provider}:{prompt}"
        return hashlib.sha256(content.encode()).hexdigest()

    def get(self, prompt: str, provider: str) -> Optional[str]:
        """Retrieve cached response"""
        if not self.enabled:
            return None

        cache_file = self.cache_dir / f"{self._get_cache_key(prompt, provider)}.json"
        if cache_file.exists():
            with open(cache_file, 'r') as f:
                data = json.load(f)
                print_info("Using cached response")
                return data['response']
        return None

    def set(self, prompt: str, provider: str, response: str):
        """Cache response"""
        if not self.enabled:
            return

        cache_file = self.cache_dir / f"{self._get_cache_key(prompt, provider)}.json"
        with open(cache_file, 'w') as f:
            json.dump({
                'prompt': prompt,
                'provider': provider,
                'response': response
            }, f, indent=2)


class AIAssistant:
    """Main AI Assistant orchestrator"""

    def __init__(self):
        self.config = AIConfig()
        self.cache = CacheManager(self.config.config['cache'])
        self.ollama = OllamaProvider(self.config.config['ollama'])
        self.perplexity = PerplexityProvider(self.config.config['perplexity'])

    def setup_check(self) -> bool:
        """Check if AI providers are properly configured"""
        print_section("AI Assistant Setup Check")

        all_ok = True

        # Check Ollama
        if self.config.config['ollama']['enabled']:
            print_info("Checking Ollama...")
            if not self.ollama.is_available():
                print_error("Ollama is not running")
                print_info("Install: https://ollama.ai")
                print_info("Then run: ollama serve")
                all_ok = False
            elif not self.ollama.check_model_installed():
                print_warning(f"Model {self.ollama.model} not installed")
                print_info("Attempting to download...")
                try:
                    self.ollama.pull_model()
                except:
                    all_ok = False
            else:
                print_success(f"Ollama ready with model: {self.ollama.model}")

        # Check Perplexity
        if self.config.config['perplexity']['enabled']:
            print_info("Checking Perplexity API...")
            if not self.perplexity.is_available():
                print_warning("Perplexity API key not configured")
                print_info("Set environment variable: export PERPLEXITY_API_KEY='your-key'")
                print_info("Get key: https://www.perplexity.ai/settings/api")
            else:
                print_success("Perplexity API key configured")

        return all_ok

    def generate(self, prompt: str, task_type: str = 'explain',
                 system_prompt: Optional[str] = None, use_cache: bool = True) -> str:
        """Generate AI response with automatic provider selection"""

        # Check cache first
        if use_cache:
            cached = self.cache.get(prompt, task_type)
            if cached:
                return cached

        # Select provider
        provider_name = self.config.get_provider_for_task(task_type)
        print_info(f"Using provider: {provider_name}")

        # Try primary provider
        try:
            if provider_name == 'ollama':
                response = self.ollama.generate(prompt, system_prompt)
            else:
                response = self.perplexity.generate(prompt, system_prompt)

            # Cache response
            if use_cache:
                self.cache.set(prompt, provider_name, response)

            return response

        except Exception as e:
            print_warning(f"Provider {provider_name} failed: {e}")

            # Try fallback
            if self.config.config.get('fallback', {}).get('enabled', True):
                fallback = 'perplexity' if provider_name == 'ollama' else 'ollama'
                print_info(f"Trying fallback provider: {fallback}")

                try:
                    if fallback == 'ollama':
                        response = self.ollama.generate(prompt, system_prompt)
                    else:
                        response = self.perplexity.generate(prompt, system_prompt)

                    if use_cache:
                        self.cache.set(prompt, fallback, response)

                    return response
                except Exception as e2:
                    print_error(f"Fallback also failed: {e2}")
                    raise
            else:
                raise


# Command implementations

def cmd_explain(args, assistant: AIAssistant):
    """Explain a policy file in simple terms"""
    print_section(f"Explaining Policy: {args.policy}")

    policy_file = Path(args.policy)
    if not policy_file.exists():
        print_error(f"Policy file not found: {args.policy}")
        return 1

    with open(policy_file, 'r') as f:
        policy_content = f.read()

    system_prompt = """You are a security compliance expert specializing in OPA/Rego policies.
Explain policies in clear, simple terms that developers can understand.
Focus on: what it checks, why it matters, and how to fix violations."""

    prompt = f"""Explain this OPA/Rego compliance policy:

{policy_content}

Provide:
1. What this policy checks (in simple terms)
2. Why this matters for security/compliance
3. Common violations and how to fix them
4. Example of compliant vs non-compliant code
"""

    response = assistant.generate(prompt, 'explain', system_prompt)
    print(response)
    return 0


def cmd_remediate(args, assistant: AIAssistant):
    """Get AI-powered remediation advice for a violation"""
    print_section(f"Remediation Advice: {args.violation}")

    context = ""
    if args.file:
        file_path = Path(args.file)
        if file_path.exists():
            with open(file_path, 'r') as f:
                context = f.read()

    system_prompt = """You are an AWS security expert specializing in Terraform.
Provide specific, actionable remediation steps with code examples."""

    prompt = f"""I have a compliance violation: {args.violation}

"""

    if context:
        prompt += f"""Here is the relevant Terraform code:

```terraform
{context}
```

"""

    prompt += """Provide:
1. Root cause analysis
2. Step-by-step remediation
3. Corrected Terraform code
4. Best practices to prevent this in future
"""

    response = assistant.generate(prompt, 'simple_remediation', system_prompt)
    print(response)
    return 0


def cmd_generate(args, assistant: AIAssistant):
    """Generate a new OPA policy from requirements"""
    print_section(f"Generating Policy: {args.requirement}")

    system_prompt = """You are an expert in writing OPA/Rego compliance policies.
Generate production-ready policies following SOC2/compliance best practices."""

    prompt = f"""Generate an OPA/Rego policy for this requirement:

"{args.requirement}"

The policy should:
1. Follow the structure of existing policies in this project
2. Include proper SOC2/compliance control mappings
3. Have detailed violation messages with remediation
4. Handle edge cases
5. Include helper functions if needed

Output format:
- Package declaration
- Comments with control mappings
- Policy rules (deny/warn)
- Remediation guidance in messages
"""

    response = assistant.generate(prompt, 'code_generation', system_prompt)
    print(response)

    # Optionally save to file
    if args.output:
        output_path = Path(args.output)
        with open(output_path, 'w') as f:
            f.write(response)
        print_success(f"Policy saved to: {output_path}")

    return 0


def cmd_simulate(args, assistant: AIAssistant):
    """Generate test scenarios for a policy"""
    print_section(f"Generating Test Scenarios: {args.resource}")

    system_prompt = """You are an expert in AWS infrastructure testing and Terraform.
Generate realistic test scenarios with both compliant and non-compliant examples."""

    prompt = f"""Generate {args.scenarios} different Terraform test scenarios for {args.resource} resources.

Include:
- Mix of compliant and non-compliant examples
- Edge cases
- Common misconfigurations
- Production-like configurations

Output as valid Terraform HCL code with comments explaining each scenario.
"""

    response = assistant.generate(prompt, 'code_generation', system_prompt)
    print(response)

    if args.output:
        output_path = Path(args.output)
        with open(output_path, 'w') as f:
            f.write(response)
        print_success(f"Test scenarios saved to: {output_path}")

    return 0


def cmd_setup(args, assistant: AIAssistant):
    """Interactive setup wizard"""
    assistant.setup_check()
    return 0


def main():
    parser = argparse.ArgumentParser(
        description='AI-Powered Compliance Assistant',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Setup command
    subparsers.add_parser('setup', help='Check AI provider setup')

    # Explain command
    explain_parser = subparsers.add_parser('explain', help='Explain a policy')
    explain_parser.add_argument('--policy', required=True, help='Path to policy file')

    # Remediate command
    remediate_parser = subparsers.add_parser('remediate', help='Get remediation advice')
    remediate_parser.add_argument('--violation', required=True, help='Violation description')
    remediate_parser.add_argument('--file', help='Terraform file with violation')

    # Generate command
    generate_parser = subparsers.add_parser('generate', help='Generate new policy')
    generate_parser.add_argument('--requirement', required=True, help='Policy requirement')
    generate_parser.add_argument('--output', help='Output file path')

    # Simulate command
    simulate_parser = subparsers.add_parser('simulate', help='Generate test scenarios')
    simulate_parser.add_argument('--resource', required=True, help='AWS resource type')
    simulate_parser.add_argument('--scenarios', type=int, default=5, help='Number of scenarios')
    simulate_parser.add_argument('--output', help='Output file path')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    assistant = AIAssistant()

    if args.command == 'setup':
        return cmd_setup(args, assistant)
    elif args.command == 'explain':
        return cmd_explain(args, assistant)
    elif args.command == 'remediate':
        return cmd_remediate(args, assistant)
    elif args.command == 'generate':
        return cmd_generate(args, assistant)
    elif args.command == 'simulate':
        return cmd_simulate(args, assistant)

    return 0


if __name__ == '__main__':
    sys.exit(main())
