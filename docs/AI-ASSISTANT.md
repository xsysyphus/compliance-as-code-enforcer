# AI-Powered Policy Assistant

O **AI Assistant** é um sistema híbrido que combina **Ollama** (local, gratuito) com **Perplexity API** (cloud, pago) para fornecer sugestões inteligentes de melhorias em políticas e simulação de cenários.

## 🎯 Funcionalidades

| Comando | Descrição | Provider Padrão | Custo |
|---------|-----------|-----------------|-------|
| `explain` | Explica políticas em linguagem simples | Ollama (local) | Gratuito |
| `remediate` | Sugere correções para violações | Ollama (local) | Gratuito |
| `generate` | Gera novas políticas OPA/Rego | Perplexity (cloud) | ~$0.02/requisição |
| `simulate` | Cria cenários de teste Terraform | Perplexity (cloud) | ~$0.02/requisição |

## 📦 Instalação

### 1. Instalar Ollama (Recomendado - Gratuito)

**Linux:**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

**macOS:**
```bash
brew install ollama
```

**Iniciar Ollama:**
```bash
ollama serve
```

**Baixar modelo (em outro terminal):**
```bash
# Opção 1: phi3:mini (2.3GB) - Rápido e leve
ollama pull phi3:mini

# Opção 2: mistral:7b (4.1GB) - Melhor qualidade
ollama pull mistral:7b

# Opção 3: llama3:8b (4.7GB) - Máxima qualidade
ollama pull llama3:8b
```

**Requisitos de Hardware:**
- **phi3:mini**: 4GB RAM (recomendado para seu caso)
- **mistral:7b**: 8GB RAM
- **llama3:8b**: 16GB RAM

### 2. Configurar Perplexity (Opcional - Para tarefas complexas)

1. Obtenha sua API key em: https://www.perplexity.ai/settings/api
2. Configure a variável de ambiente:
   ```bash
   export PERPLEXITY_API_KEY='pplx-your-key-here'
   ```
3. Adicione ao `~/.bashrc` ou `~/.zshrc` para persistir:
   ```bash
   echo 'export PERPLEXITY_API_KEY="pplx-your-key-here"' >> ~/.bashrc
   ```

**Custo Estimado (Perplexity):**
- Modelo usado: `llama-3.1-sonar-small-128k-online`
- Preço: $0.20 por 1 milhão de tokens
- Requisição típica: 1000 tokens = $0.0002
- Com $5/mês: ~25.000 requisições

## 🚀 Uso

### Setup e Verificação

```bash
# Verificar configuração
./scripts/ai-assistant.py setup

# Saída esperada:
# ✓ Ollama is running (model: phi3:mini)
# ✓ Perplexity API configured
```

### 1. Explicar Políticas (explain)

Explica uma política OPA/Rego em linguagem simples.

```bash
# Explicar política de criptografia S3
./scripts/ai-assistant.py explain --policy policies/soc2/s3_encryption.rego

# Explicar política específica com contexto
./scripts/ai-assistant.py explain \
  --policy policies/soc2/cloudtrail_enabled.rego \
  --context "Sou novo em CloudTrail, explique como se eu tivesse 5 anos"
```

**Exemplo de Saída:**
```
=== Explicação da Política ===

Esta política garante que o CloudTrail esteja configurado corretamente.

O que verifica:
1. Se CloudTrail existe
2. Se está em multi-região
3. Se tem validação de logs
4. Se usa criptografia KMS

Por que importa:
CloudTrail é como uma câmera de segurança para sua conta AWS.
Sem ele, você não sabe quem fez o quê e quando.

Violações:
CRITICAL - Sem CloudTrail = Você está voando cego
CRITICAL - Sem criptografia = Logs podem ser lidos por qualquer um
...
```

### 2. Remediar Violações (remediate)

Obtém sugestões detalhadas de como corrigir uma violação.

```bash
# Remediar violação de RDS público
./scripts/ai-assistant.py remediate \
  --violation "RDS instance 'insecure-db' is publicly accessible" \
  --file terraform/test-infrastructure/main.tf

# Remediar com contexto adicional
./scripts/ai-assistant.py remediate \
  --violation "S3 bucket lacks encryption" \
  --resource "aws_s3_bucket.sensitive_data" \
  --context "Este bucket armazena dados de clientes LGPD"
```

**Exemplo de Saída:**
```
=== Análise da Violação ===

Problema: RDS está acessível pela internet
Severidade: CRITICAL
Impacto: Qualquer um pode tentar se conectar ao banco

Causa Raiz:
O atributo 'publicly_accessible = true' expõe o RDS à internet.

Correção Passo a Passo:

1. Remover acesso público:
   resource "aws_db_instance" "insecure-db" {
     publicly_accessible = false  # ← MUDAR AQUI
     ...
   }

2. Configurar Security Group restritivo:
   resource "aws_security_group" "db" {
     ingress {
       from_port       = 5432
       to_port         = 5432
       protocol        = "tcp"
       security_groups = [aws_security_group.app.id]  # Apenas app tier
     }
   }

3. Conectar via bastion host ou VPN:
   - Opção A: AWS Systems Manager Session Manager
   - Opção B: Bastion host em subnet pública
   - Opção C: VPN site-to-site

Abordagens Alternativas:
- RDS Proxy para conexões de apps
- AWS PrivateLink para acesso de outras contas
...
```

### 3. Gerar Novas Políticas (generate)

Cria políticas OPA/Rego a partir de requisitos em linguagem natural.

```bash
# Gerar política para EKS
./scripts/ai-assistant.py generate \
  --requirement "EKS clusters must use private endpoints and enable envelope encryption with KMS"

# Gerar política com framework específico
./scripts/ai-assistant.py generate \
  --requirement "Lambda functions must have reserved concurrency and DLQ configured" \
  --framework "SOC2,LGPD"
```

**Exemplo de Saída:**
```
=== Política Gerada ===

Arquivo sugerido: policies/soc2/eks_security.rego

package soc2.eks_security

import future.keywords.if

# CRITICAL: EKS clusters must use private endpoints
deny[msg] {
    cluster := input.resource.aws_eks_cluster[name]
    not cluster.vpc_config[_].endpoint_private_access
    
    msg := {
        "msg": sprintf("CRITICAL [SOC2-CC6.6]: EKS cluster '%s' lacks private endpoint", [name]),
        "details": "Public endpoints expose cluster API to internet...",
        "remediation": "...",
        "severity": "CRITICAL",
        "compliance": ["SOC2-CC6.6"],
    }
}
...
```

### 4. Simular Cenários de Teste (simulate)

Gera cenários Terraform de teste (compliant e non-compliant).

```bash
# Simular cenários para RDS
./scripts/ai-assistant.py simulate \
  --resource rds \
  --scenarios 5

# Simular com foco em compliance específico
./scripts/ai-assistant.py simulate \
  --resource lambda \
  --compliance "SOC2-CC6.1" \
  --scenarios 3
```

**Exemplo de Saída:**
```
=== Cenários de Teste Gerados ===

# Cenário 1: RDS Compliant (Seguro)
resource "aws_db_instance" "compliant_rds" {
  identifier          = "secure-database"
  engine              = "postgres"
  storage_encrypted   = true
  kms_key_id          = aws_kms_key.rds.arn
  publicly_accessible = false
  ...
}

# Cenário 2: RDS sem criptografia (CRITICAL)
resource "aws_db_instance" "no_encryption" {
  identifier        = "unencrypted-db"
  storage_encrypted = false  # ← Violação
  ...
}

# Cenário 3: RDS público (CRITICAL)
resource "aws_db_instance" "public_db" {
  publicly_accessible = true  # ← Violação
  ...
}
...

Para testar:
1. Copie para terraform/test-cases/
2. Execute: conftest test terraform/test-cases/ --policy policies/
```

## ⚙️ Configuração Avançada

### Customizar Roteamento de Tarefas

Edite `config/ai-config.yaml`:

```yaml
task_routing:
  explain: "ollama"      # Tarefas frequentes = local (gratuito)
  remediate: "ollama"
  generate: "perplexity" # Tarefas complexas = cloud (melhor qualidade)
  simulate: "perplexity"
```

### Ajustar Modelos

```yaml
ollama:
  model: "mistral:7b"  # Trocar para modelo maior

perplexity:
  model: "llama-3.1-sonar-large-128k-online"  # Melhor qualidade ($1/M tokens)
  temperature: 0.1  # Mais determinístico (0.0-1.0)
```

### Cache para Economizar

O cache está habilitado por padrão e economiza custos:

```yaml
cache:
  enabled: true
  directory: ".ai-cache"
  ttl: 604800  # 7 dias
```

**Como funciona:**
- Requisições idênticas usam resposta em cache
- Cache é limpo automaticamente após TTL
- Limpar manualmente: `rm -rf .ai-cache/`

## 🎛️ Opções de Linha de Comando

### Opções Globais

```bash
--no-cache          # Desabilitar cache (força nova requisição)
--provider ollama   # Forçar provider específico
--provider perplexity
--verbose           # Mostrar detalhes de debug
```

### Exemplos Combinados

```bash
# Explicar sem cache (forçar nova análise)
./scripts/ai-assistant.py explain --policy policies/soc2/s3_encryption.rego --no-cache

# Remediar usando Perplexity (melhor qualidade)
./scripts/ai-assistant.py remediate \
  --violation "CloudTrail without encryption" \
  --provider perplexity

# Gerar política usando Ollama (economizar API)
./scripts/ai-assistant.py generate \
  --requirement "API Gateway must use WAF" \
  --provider ollama
```

## 📊 Monitoramento de Custos

### Estimar Uso da Perplexity

```bash
# Ver estatísticas de cache
du -sh .ai-cache/
ls -1 .ai-cache/ | wc -l  # Número de requisições cacheadas

# Calcular custo estimado (assumindo 1000 tokens/req)
# Requisições não-cacheadas × 1000 tokens × $0.0000002 = custo
```

### Otimizar Custos

1. **Use cache agressivamente** (TTL de 7 dias)
2. **Prefira Ollama para tarefas simples** (explain, remediate)
3. **Agrupe requisições** (gere múltiplas políticas de uma vez)
4. **Use modelo small** do Perplexity ($0.2/M vs $1/M)

**Com $5/mês você pode fazer:**
- ~100 generate requests (sem cache)
- ~200 simulate requests (sem cache)
- ∞ explain/remediate (Ollama local gratuito)

## 🔧 Troubleshooting

### Ollama não está rodando

```bash
# Verificar se Ollama está instalado
which ollama

# Iniciar Ollama em background
ollama serve &

# Verificar se modelo está baixado
ollama list
```

### Perplexity API retorna erro 401

```bash
# Verificar se API key está configurada
echo $PERPLEXITY_API_KEY

# Testar API key manualmente
curl -X POST https://api.perplexity.ai/chat/completions \
  -H "Authorization: Bearer $PERPLEXITY_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "llama-3.1-sonar-small-128k-online", "messages": [{"role": "user", "content": "test"}]}'
```

### Timeout ao gerar políticas

```bash
# Aumentar timeout no config/ai-config.yaml
ollama:
  timeout: 300  # 5 minutos

# Ou usar modelo menor
ollama:
  model: "phi3:mini"  # Mais rápido
```

### Cache não funciona

```bash
# Verificar permissões
ls -la .ai-cache/

# Limpar e recriar
rm -rf .ai-cache/
mkdir .ai-cache/
```

## 🧪 Exemplos de Workflow

### Workflow 1: Criar Nova Política do Zero

```bash
# 1. Gerar política base
./scripts/ai-assistant.py generate \
  --requirement "ALB must have access logs enabled and stored in encrypted S3 bucket" \
  > policies/soc2/alb_access_logs.rego

# 2. Explicar a política gerada
./scripts/ai-assistant.py explain --policy policies/soc2/alb_access_logs.rego

# 3. Gerar cenários de teste
./scripts/ai-assistant.py simulate --resource alb --scenarios 3 \
  > terraform/test-cases/alb-tests.tf

# 4. Testar
conftest test terraform/test-cases/alb-tests.tf --policy policies/
```

### Workflow 2: Corrigir Violações Encontradas

```bash
# 1. Executar scan
conftest test terraform/test-infrastructure/ --policy policies/ > violations.txt

# 2. Para cada violação, obter remediação
./scripts/ai-assistant.py remediate \
  --violation "S3 bucket 'insecure-bucket' lacks encryption" \
  --file terraform/test-infrastructure/main.tf

# 3. Aplicar correção
# (editar main.tf com as sugestões)

# 4. Re-testar
conftest test terraform/test-infrastructure/ --policy policies/
```

### Workflow 3: Onboarding de Novo Desenvolvedor

```bash
# Explicar todas as políticas
for policy in policies/soc2/*.rego; do
  echo "=== $(basename $policy) ==="
  ./scripts/ai-assistant.py explain --policy "$policy"
  echo ""
done > docs/policy-explanations.md
```

## 📚 Recursos Adicionais

- **Ollama Docs**: https://ollama.ai/docs
- **Perplexity API**: https://docs.perplexity.ai
- **OPA/Rego**: https://www.openpolicyagent.org/docs/latest/
- **Conftest**: https://www.conftest.dev/

## 🤝 Contribuindo

Melhorias nos system prompts são bem-vindas! Edite `config/ai-config.yaml`:

```yaml
system_prompts:
  explain: |
    Seu prompt customizado aqui...
```
