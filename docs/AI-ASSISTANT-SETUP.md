# AI Assistant Setup Guide

Este guia mostra como configurar e usar o assistente AI para análise de políticas de compliance.

## Arquitetura Híbrida

O assistente usa uma **abordagem híbrida inteligente**:

- **Ollama (Local)** - 80% das tarefas
  - Gratuito, ilimitado
  - Rápido (local)
  - Sem custo de API
  - Funciona offline

- **Perplexity (Cloud)** - 20% das tarefas complexas
  - Pesquisa online
  - Análise profunda
  - $5/mês dura o mês todo

## Requisitos do Sistema

### Para Ollama (Local LLM)
- **RAM**: 4GB mínimo (modelo phi3:mini usa ~2.3GB)
- **Disco**: 3GB livres
- **OS**: Linux, macOS, ou Windows com WSL
- **CPU**: Qualquer processador moderno (CPU é suficiente, GPU opcional)

### Para Perplexity (Opcional)
- Chave API da Perplexity
- Conexão com internet

## Passo 1: Instalar Dependências Python

```bash
# Navegue para o diretório do projeto
cd /home/user/compliance-as-code-enforcer

# Instale as dependências
pip install -r requirements.txt

# Ou use um ambiente virtual (recomendado):
python3 -m venv venv
source venv/bin/activate  # No Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Passo 2: Instalar e Configurar Ollama

### Instalação

```bash
# Linux/macOS
curl -fsSL https://ollama.ai/install.sh | sh

# Ou manualmente:
# - Baixe de https://ollama.ai/download
# - Extraia e mova para /usr/local/bin/
```

### Baixar o Modelo

```bash
# Baixa o modelo phi3:mini (2.3GB, ~4 minutos)
ollama pull phi3:mini

# Verificar que funcionou
ollama list
```

### Testar Ollama

```bash
# Teste rápido
ollama run phi3:mini "What is OPA?"

# Deve retornar uma resposta sobre Open Policy Agent
```

### Iniciar Ollama como Serviço (Opcional)

```bash
# Linux com systemd
sudo systemctl enable ollama
sudo systemctl start ollama

# Ou manualmente em cada sessão
ollama serve &
```

## Passo 3: Configurar o AI Assistant

### Configuração Básica (Só Ollama)

O arquivo `config/ai-config.yaml` já está configurado para usar apenas Ollama:

```yaml
ollama:
  enabled: true
  model: "phi3:mini"

perplexity:
  enabled: false  # Desabilitado por padrão
```

**Não precisa mudar nada para começar!**

### Configuração Avançada (Com Perplexity)

Se quiser adicionar Perplexity para tarefas complexas:

1. **Obtenha uma API key da Perplexity**:
   - Acesse https://www.perplexity.ai/settings/api
   - Gere uma nova chave
   - Copie a chave

2. **Configure a chave**:

```bash
# Opção 1: Variável de ambiente (recomendado)
export PERPLEXITY_API_KEY="pplx-xxxxxxxxxxxxx"

# Opção 2: Edite config/ai-config.yaml
# Descomente e adicione sua chave:
# perplexity:
#   enabled: true
#   api_key: "pplx-xxxxxxxxxxxxx"
```

## Passo 4: Testar o Assistente

### Verificar Instalação

```bash
./scripts/ai-assistant.py setup
```

Deve mostrar:
```
✓ Ollama: Conectado (modelo: phi3:mini)
✗ Perplexity: Desabilitado (opcional)
✓ Cache: Configurado (.cache/ai-responses)

Status: Pronto para usar!
```

### Comandos Básicos

#### 1. Explicar uma Política

```bash
# Explicar em termos simples
./scripts/ai-assistant.py explain policies/soc2/s3_encryption.rego

# Resultado: Explicação em português sobre o que a política faz
```

#### 2. Obter Remediação para Violações

```bash
# Analisar violações e sugerir correções
./scripts/ai-assistant.py remediate \
  --policy policies/soc2/no_plaintext_secrets.rego \
  --violation "RDS instance 'my-db' has plaintext password"

# Resultado: Passos específicos para corrigir, com código de exemplo
```

#### 3. Gerar Nova Política

```bash
# Gerar política a partir de requisitos
./scripts/ai-assistant.py generate \
  --requirement "Check that all EC2 instances have proper tags for cost allocation" \
  --output policies/custom/ec2_tagging.rego

# Resultado: Arquivo .rego gerado com política completa
```

#### 4. Simular Cenários de Teste

```bash
# Gerar cenários de teste para uma política
./scripts/ai-assistant.py simulate policies/soc2/cloudtrail_enabled.rego

# Resultado: Casos de teste em Terraform para validar a política
```

### Exemplos Práticos

#### Workflow Completo: Corrigir Violação

```bash
# 1. Rodar políticas
conftest test terraform/test-infrastructure/main.tf \
  --policy policies/soc2 \
  --output json > violations.json

# 2. Pedir remediação para violação específica
./scripts/ai-assistant.py remediate \
  --violation "Security group 'web-sg' exposes port 22 to internet" \
  --context terraform/test-infrastructure/main.tf

# 3. Aplicar a correção sugerida
# (editar o arquivo main.tf conforme sugerido)

# 4. Re-testar
conftest test terraform/test-infrastructure/main.tf --policy policies/soc2
```

#### Criar Nova Política Customizada

```bash
# 1. Gerar política base
./scripts/ai-assistant.py generate \
  --requirement "All Lambda functions must have DLQ configured" \
  --compliance "SOC2-A1.2" \
  --output policies/custom/lambda_dlq.rego

# 2. Revisar e ajustar a política gerada

# 3. Testar contra infraestrutura
conftest test terraform/ --policy policies/custom/lambda_dlq.rego
```

## Opções Avançadas

### Configurar Provider Preferido

```bash
# Forçar uso de Ollama
./scripts/ai-assistant.py explain policy.rego --provider ollama

# Forçar uso de Perplexity (se configurado)
./scripts/ai-assistant.py explain policy.rego --provider perplexity
```

### Modo Verbose

```bash
# Ver detalhes de execução
./scripts/ai-assistant.py --verbose explain policy.rego
```

### Limpar Cache

```bash
# Limpar cache de respostas (libera espaço)
./scripts/ai-assistant.py cache-clear
```

## Monitoramento de Custos (Perplexity)

Se estiver usando Perplexity:

```bash
# Ver uso de API e custos estimados
./scripts/ai-assistant.py cost-report

# Resultado:
# Perplexity API Usage (Mês Atual):
# - Requests: 47
# - Tokens: 123,456
# - Custo estimado: $1.23 / $5.00 (24.6%)
# - Restante: $3.77
```

## Troubleshooting

### Ollama não conecta

```bash
# Verificar se Ollama está rodando
curl http://localhost:11434/api/tags

# Se não responder, inicie manualmente
ollama serve
```

### Modelo não encontrado

```bash
# Baixar o modelo novamente
ollama pull phi3:mini

# Listar modelos disponíveis
ollama list
```

### Erro de permissão

```bash
# Tornar script executável
chmod +x scripts/ai-assistant.py
```

### Cache crescendo muito

```bash
# Limitar tamanho do cache em config/ai-config.yaml
cache:
  max_size_mb: 50  # Reduzir de 100MB para 50MB
```

## Performance e Uso de Recursos

### Ollama (Local)

- **Primeira execução**: ~5-10 segundos (carrega modelo)
- **Execuções seguintes**: ~2-3 segundos
- **RAM em uso**: ~2.5GB enquanto ativo
- **RAM em idle**: 0GB (pode descarregar modelo)

### Perplexity (Cloud)

- **Latência**: ~1-3 segundos
- **Custo por request**: ~$0.05-0.10
- **Limite mensal**: ~50-100 requests com $5

### Recomendações

1. **Use Ollama para 80% das tarefas**:
   - Explicar políticas
   - Validar sintaxe
   - Gerar código básico
   - Remediação simples

2. **Use Perplexity para 20% das tarefas complexas**:
   - Pesquisar CVEs específicos
   - Análise arquitetural profunda
   - Comparar frameworks de compliance
   - Buscar best practices atuais

3. **Aproveit o cache**:
   - Mesmo prompt = resposta instantânea
   - Economiza API calls
   - TTL de 7 dias (configurável)

## Próximos Passos

1. Execute `./scripts/ai-assistant.py setup` para verificar instalação
2. Teste com `./scripts/ai-assistant.py explain policies/soc2/s3_encryption.rego`
3. Explore os outros comandos (remediate, generate, simulate)
4. Configure Perplexity quando precisar de recursos avançados

## Suporte

- **Issues**: GitHub Issues no repositório
- **Docs OPA**: https://www.openpolicyagent.org/docs/
- **Ollama Docs**: https://github.com/ollama/ollama
- **Perplexity API**: https://docs.perplexity.ai/
