# AI Assistant - Usage Examples

Este documento mostra exemplos práticos de uso do assistente AI.

## Exemplo 1: Explicar uma Política

### Comando
```bash
./scripts/ai-assistant.py explain policies/soc2/s3_encryption.rego
```

### Saída Esperada
```
🤖 Explicando política: s3_encryption.rego
Provider: Ollama (phi3:mini)

═══════════════════════════════════════════════════════════════════

📋 O QUE ESTA POLÍTICA FAZ:

Esta política verifica se todos os buckets S3 têm criptografia em repouso
habilitada. É um controle CRÍTICO de segurança exigido por:
- SOC2 CC6.1 e CC6.7 (Proteção de Dados)
- LGPD Art. 46 (Medidas Técnicas)
- ISO 27001 A.10.1.1 (Controles Criptográficos)

🔍 VERIFICAÇÕES REALIZADAS:

1. ✓ Bucket tem server_side_encryption_configuration definido
2. ✓ Algoritmo de criptografia é AES256 ou aws:kms
3. ✓ KMS é usado para dados sensíveis (recomendado)
4. ✓ Bucket key está habilitado (reduz custos KMS)

❌ VIOLAÇÕES DETECTADAS:

- CRITICAL: Bucket sem nenhuma criptografia
- HIGH: Bucket usando algoritmo inadequado
- MEDIUM: Bucket sem bucket_key_enabled (apenas aviso)

💡 POR QUE É IMPORTANTE:

Dados armazenados em S3 podem incluir informações sensíveis de clientes.
Sem criptografia em repouso, se um invasor obter acesso físico aos
discos da AWS ou explorar uma vulnerabilidade, os dados estarão
expostos em texto claro.

🛠️ COMO CORRIGIR:

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
⏱️  Tempo: 2.3s | 💾 Cache: MISS
```

## Exemplo 2: Obter Remediação para Violação

### Comando
```bash
./scripts/ai-assistant.py remediate \
  --policy policies/soc2/no_plaintext_secrets.rego \
  --violation "RDS instance 'production-db' has plaintext password" \
  --context terraform/test-infrastructure/main.tf
```

### Saída Esperada
```
🤖 Analisando violação e sugerindo remediação...
Provider: Ollama (phi3:mini)

═══════════════════════════════════════════════════════════════════

🚨 VIOLAÇÃO DETECTADA:

Tipo: CRITICAL [SOC2-CC6.1]
Recurso: aws_db_instance.production-db
Problema: Senha do RDS está hardcoded no código Terraform

📍 LOCALIZAÇÃO NO CÓDIGO:

terraform/test-infrastructure/main.tf:45

  resource "aws_db_instance" "production_db" {
    identifier = "production-db"
    engine     = "postgres"
    password   = "MySecretPassword123!"  ← PROBLEMA AQUI
  }

⚠️  IMPACTO DE SEGURANÇA:

1. Senha visível no código-fonte e histórico Git
2. Qualquer pessoa com acesso ao repositório vê a senha
3. Logs de CI/CD podem expor a senha
4. Viola SOC2 CC6.1, LGPD Art. 46, ISO 27001 A.9.4.1

🛠️ SOLUÇÃO RECOMENDADA (3 opções):

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OPÇÃO 1: RDS Managed Password (Mais Seguro) ⭐ RECOMENDADO
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Para RDS >= 6.0, use gerenciamento automático de senha:

resource "aws_db_instance" "production_db" {
  identifier = "production-db"
  engine     = "postgres"

  # AWS gerencia a senha e armazena no Secrets Manager
  manage_master_user_password = true

  # Opcional: especifique a chave KMS
  master_user_secret_kms_key_id = aws_kms_key.db_secrets.id
}

# Recuperar a senha quando necessário
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_db_instance.production_db.master_user_secret[0].secret_arn
}

output "db_password_secret_arn" {
  value = aws_db_instance.production_db.master_user_secret[0].secret_arn
  sensitive = true
}

✅ Vantagens:
  - Completamente automático
  - Rotação de senha facilitada
  - Auditoria via CloudTrail
  - Zero chance de vazamento no código

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OPÇÃO 2: Secrets Manager Explícito
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Primeiro, crie o secret manualmente ou via Terraform
resource "aws_secretsmanager_secret" "db_password" {
  name        = "rds/production-db/password"
  description = "RDS production database password"
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({
    username = "admin"
    password = "CHANGE_ME_AFTER_APPLY"  # Altere via Console após apply
  })
}

# Referencie no RDS
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db_password.id
}

resource "aws_db_instance" "production_db" {
  identifier = "production-db"
  engine     = "postgres"
  username   = jsondecode(data.aws_secretsmanager_secret_version.db_password.secret_string)["username"]
  password   = jsondecode(data.aws_secretsmanager_secret_version.db_password.secret_string)["password"]
}

✅ Vantagens:
  - Controle total sobre o secret
  - Suporta versões antigas do RDS
  - Pode compartilhar secret entre recursos

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OPÇÃO 3: Terraform Variable com CI/CD Secrets
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Em variables.tf
variable "db_password" {
  description = "RDS master password"
  type        = string
  sensitive   = true
}

# Em main.tf
resource "aws_db_instance" "production_db" {
  identifier = "production-db"
  engine     = "postgres"
  password   = var.db_password
}

# No GitHub Actions workflow
env:
  TF_VAR_db_password: ${{ secrets.RDS_PASSWORD }}

✅ Vantagens:
  - Simples de implementar
  - Integra com CI/CD
  - Não requer AWS Secrets Manager

⚠️ Desvantagens:
  - Senha ainda aparece em state file (criptografe backend!)
  - Precisa gerenciar rotação manualmente

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 PASSOS PARA APLICAR (Opção 1 - Recomendada):

1. Backup da senha atual:
   aws rds describe-db-instances --db-instance-identifier production-db

2. Modifique o Terraform conforme Opção 1

3. Planeje a mudança:
   terraform plan -out=planfile

4. Aplique (isso vai resetar a senha!):
   terraform apply planfile

5. Recupere a nova senha do Secrets Manager:
   aws secretsmanager get-secret-value \
     --secret-id <secret-arn-from-output> \
     --query SecretString --output text

6. Atualize suas aplicações com o novo secret ARN

⚠️  ATENÇÃO: Aplicar essa mudança vai RESETAR a senha do banco!
   Certifique-se de coordenar com sua equipe e atualizar as aplicações.

═══════════════════════════════════════════════════════════════════
⏱️  Tempo: 3.1s | 💾 Cache: MISS
```

## Exemplo 3: Gerar Nova Política

### Comando
```bash
./scripts/ai-assistant.py generate \
  --requirement "All EC2 instances must have mandatory tags: Environment, Owner, CostCenter" \
  --compliance "SOC2-A1.2" \
  --severity "HIGH" \
  --output policies/custom/ec2_tagging.rego
```

### Saída Esperada
```
🤖 Gerando política OPA baseada nos requisitos...
Provider: Ollama (phi3:mini)

═══════════════════════════════════════════════════════════════════

📝 REQUISITO ANALISADO:

"All EC2 instances must have mandatory tags: Environment, Owner, CostCenter"

Framework: SOC2-A1.2
Severidade: HIGH

🔍 POLÍTICA GERADA:

Arquivo: policies/custom/ec2_tagging.rego

# SOC2 Control: A1.2 (Asset Inventory and Classification)
# ISO 27001: A.8.1.1 (Inventory of assets)
#
# Requirement: EC2 instances MUST have mandatory tags for proper asset management
# Rationale: Tags enable cost allocation, ownership tracking, and compliance reporting
# Severity: HIGH
# Auto-Remediation: Supported

package custom.ec2_tagging

import future.keywords.if
import future.keywords.in

# Required tags for all EC2 instances
required_tags := ["Environment", "Owner", "CostCenter"]

# Valid values for Environment tag
valid_environments := ["production", "staging", "development", "qa"]

# HIGH: EC2 instance missing required tags
deny[msg] {
    instance := input.resource.aws_instance[name]
    missing_tag := get_missing_tags(instance)[_]

    msg := {
        "msg": sprintf("HIGH [SOC2-A1.2]: EC2 instance '%s' missing required tag '%s'", [name, missing_tag]),
        "details": sprintf("All EC2 instances must have tags: %v. Missing: %s", [required_tags, missing_tag]),
        "remediation": sprintf("Add tag '%s' to instance '%s' in your Terraform configuration", [missing_tag, name]),
        "severity": "HIGH",
        "compliance": ["SOC2-A1.2", "ISO27001-A.8.1.1"],
    }
}

# MEDIUM: Environment tag has invalid value
deny[msg] {
    instance := input.resource.aws_instance[name]
    instance.tags.Environment
    env := lower(instance.tags.Environment)
    not env in valid_environments

    msg := {
        "msg": sprintf("MEDIUM [Best Practice]: EC2 instance '%s' has invalid Environment tag", [name]),
        "details": sprintf("Environment tag value '%s' is not in allowed list: %v", [instance.tags.Environment, valid_environments]),
        "remediation": sprintf("Set Environment tag to one of: %v", [valid_environments]),
        "severity": "MEDIUM",
    }
}

# Helper: Get list of missing tags for an instance
get_missing_tags(instance) := missing {
    instance_tags := {tag | instance.tags[tag]}
    missing := [tag | tag := required_tags[_]; not tag in instance_tags]
}

✅ Política criada em: policies/custom/ec2_tagging.rego

📋 TESTES SUGERIDOS:

# Teste 1: Instância sem tags (deve FALHAR)
resource "aws_instance" "bad_instance" {
  ami           = "ami-12345"
  instance_type = "t3.micro"
  # Missing all tags
}

# Teste 2: Instância com tags parciais (deve FALHAR)
resource "aws_instance" "partial_tags" {
  ami           = "ami-12345"
  instance_type = "t3.micro"
  tags = {
    Environment = "production"
    # Missing: Owner, CostCenter
  }
}

# Teste 3: Instância com todas as tags (deve PASSAR)
resource "aws_instance" "good_instance" {
  ami           = "ami-12345"
  instance_type = "t3.micro"
  tags = {
    Environment = "production"
    Owner       = "platform-team@company.com"
    CostCenter  = "engineering"
  }
}

🧪 PRÓXIMOS PASSOS:

1. Revise a política gerada: policies/custom/ec2_tagging.rego
2. Crie arquivo de teste: terraform/tests/ec2_tagging_test.tf
3. Valide a política: conftest test terraform/tests/ --policy policies/custom/
4. Adicione ao CI/CD: .github/workflows/compliance-check.yml

═══════════════════════════════════════════════════════════════════
⏱️  Tempo: 4.7s | 💾 Cache: MISS
```

## Exemplo 4: Simular Cenários de Teste

### Comando
```bash
./scripts/ai-assistant.py simulate policies/soc2/security_group_public_access.rego
```

### Saída Esperada
```
🤖 Gerando cenários de teste para a política...
Provider: Ollama (phi3:mini)

═══════════════════════════════════════════════════════════════════

🧪 CENÁRIOS DE TESTE GERADOS

Política: security_group_public_access.rego

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CENÁRIO 1: Security Group com SSH público (deve FALHAR - CRITICAL)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

resource "aws_security_group" "public_ssh" {
  name        = "public-ssh-sg"
  description = "BAD: SSH open to internet"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH from anywhere"
  }
}

Violação esperada:
  "CRITICAL [SOC2-CC6.6]: Security group 'public_ssh' exposes
   administrative port 22 to internet"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CENÁRIO 2: Security Group com PostgreSQL público (deve FALHAR - CRITICAL)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

resource "aws_security_group" "public_database" {
  name        = "public-db-sg"
  description = "BAD: Database exposed to internet"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "PostgreSQL from anywhere"
  }
}

Violação esperada:
  "CRITICAL [SOC2-CC6.6]: Security group 'public_database' exposes
   database port 5432 to internet"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CENÁRIO 3: Security Group permitindo TODAS as portas (deve FALHAR - CRITICAL)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

resource "aws_security_group" "all_ports" {
  name        = "everything-open"
  description = "WORST: All ports open"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

Violação esperada:
  "CRITICAL [SOC2-CC6.6]: Security group 'all_ports' allows ALL
   ports from anywhere"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CENÁRIO 4: Security Group com regra sem descrição (deve AVISAR - MEDIUM)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

resource "aws_security_group" "no_description" {
  name = "web-sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    # Missing description
  }
}

Aviso esperado:
  "MEDIUM [Best Practice]: Security group 'no_description' has
   ingress rule without description"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CENÁRIO 5: Security Group CORRETO - acesso restrito (deve PASSAR)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

resource "aws_security_group" "app_tier" {
  name        = "app-tier-sg"
  description = "Application tier security group"

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]
    description     = "HTTPS from internet (required for web app)"
  }
}

resource "aws_security_group" "database_tier" {
  name        = "database-tier-sg"
  description = "Database tier security group"

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_tier.id]
    description     = "PostgreSQL from app tier only"
  }
}

Resultado esperado: ✅ TODAS AS VERIFICAÇÕES PASSARAM

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 COMO TESTAR:

# Salve os cenários em um arquivo de teste
cat > terraform/tests/sg_test.tf << 'EOF'
[copie os cenários acima]
EOF

# Execute a validação
conftest test terraform/tests/sg_test.tf \
  --policy policies/soc2/security_group_public_access.rego

# Resultado esperado:
# FAIL - 4 violations
# WARN - 1 warning
# PASS - 1 test passed

═══════════════════════════════════════════════════════════════════
⏱️  Tempo: 3.8s | 💾 Cache: MISS
```

## Comandos Úteis

### Ver estatísticas de cache
```bash
./scripts/ai-assistant.py cache-stats
```

### Limpar cache
```bash
./scripts/ai-assistant.py cache-clear
```

### Forçar uso de provider específico
```bash
./scripts/ai-assistant.py explain policy.rego --provider ollama
./scripts/ai-assistant.py explain policy.rego --provider perplexity
```

### Modo verbose (debug)
```bash
./scripts/ai-assistant.py --verbose explain policy.rego
```

## Performance

| Comando    | Ollama (Local) | Perplexity (Cloud) |
|------------|----------------|-------------------|
| explain    | 2-3s          | 1-2s              |
| remediate  | 3-5s          | 2-3s              |
| generate   | 4-7s          | 3-4s              |
| simulate   | 3-6s          | 2-4s              |

## Custos (apenas Perplexity)

- Custo médio por request: $0.05-0.10
- Budget mensal $5 = ~50-100 requests
- Com Ollama local = custos zero para 80% das tarefas
