# Contributing to Compliance-as-Code Enforcer

Thank you for considering contributing to this project! We welcome contributions from the community.

## How to Contribute

### Reporting Bugs

- Use GitHub Issues with the `bug` label
- Include reproduction steps, expected vs actual behavior
- Provide Terraform/OPA versions and AWS region if applicable

### Adding New Policies

1. Fork the repository
2. Create a new `.rego` file in `policies/soc2/` (or appropriate framework)
3. Follow the naming convention: `<resource>_<control>.rego`
4. Include:
   - Package declaration
   - SOC2 control mapping in comments
   - Clear violation messages with remediation guidance
   - Test cases co-located in `policies/soc2/` (e.g. `s3_encryption_test.rego`)

**Example:**

```rego
# SOC2 Control: CC6.1 - Logical and Physical Access Controls
# Description: Ensure EBS volumes are encrypted
package soc2.ebs_encryption

violation[msg] {
    resource := input.resource.aws_ebs_volume[name]
    not resource.encrypted

    msg := sprintf(
        "EBS volume '%s' must be encrypted (SOC2-CC6.1). Add: encrypted = true",
        [name]
    )
}
```

### Pull Request Process

1. Update README.md if adding features
2. Add tests for new policies
3. Ensure `conftest verify` passes
4. Update `docs/policies-mapping.md` with new control mappings
5. Follow conventional commits: `feat:`, `fix:`, `docs:`, `test:`

### Code Style

**Rego:**
- Use snake_case for package and rule names
- Include comments explaining business logic
- Keep rules focused (one violation per rule)

**Terraform:**
- Use terraform fmt
- Include comments for complex logic
- Follow AWS naming conventions

**Python:**
- Follow PEP 8
- Use type hints
- Maximum line length: 100 characters

### Testing

Before submitting:

```bash
# Test Rego policies
opa test policies/

# Validate Terraform
terraform fmt -check -recursive
terraform validate

# Run unit tests (from repo root)
python3 -m pytest tests/unit/
```

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Assume positive intent

## Questions?

Open a GitHub Discussion or reach out via Issues.
