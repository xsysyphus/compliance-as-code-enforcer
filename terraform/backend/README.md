# Terraform Backend Bootstrap

Provisiona os recursos de backend remoto para armazenar estado Terraform de forma segura:
- S3 com versionamento e criptografia (AES256)
- DynamoDB para locking e recuperação point-in-time

## Uso
```bash
cd terraform/backend
terraform init
terraform apply
```

Variáveis úteis (`-var` ou `terraform.tfvars`):
- `aws_region` (default: `us-east-1`)
- `project_name` (default: `compliance-as-code`)
- `environment` (default: `shared`)
- `force_destroy` (default: `false`)

## Como consumir no restante do projeto
Após criar o bucket e a tabela, adicione um backend block nos demais módulos:
```hcl
terraform {
  backend "s3" {
    bucket         = "<state_bucket_output>"
    key            = "runtime-monitoring/terraform.tfstate"
    region         = "<region_output>"
    dynamodb_table = "<dynamodb_lock_table_output>"
    encrypt        = true
  }
}
```
Sugestão de `key` por stack:
- `runtime-monitoring/terraform.tfstate`
- `test-infrastructure/terraform.tfstate` (se quiser testar remoto)

## Notas de segurança
- `force_destroy` deve permanecer `false` em produção.
- Política de bucket bloqueia transporte inseguro e acesso público.
- DynamoDB com PITR habilitado para proteger locks e histórico de estado.
