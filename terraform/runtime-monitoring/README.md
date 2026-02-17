# Runtime Monitoring Stack

Provisiona o scanner Lambda diário que valida recursos AWS em runtime e grava achados em DynamoDB + evidências em S3.

## Componentes
- Lambda `compliance-as-code-<env>-scanner`
- Tabela DynamoDB `<project>-<env>-compliance-runs` (PITR on)
- Bucket S3 de evidências versionado e criptografado
- EventBridge Rule `cron` diário
- IAM role com permissões de leitura (S3, RDS, SGs, CloudTrail) e escrita (DynamoDB, S3, Logs)

## Pré-requisitos
1. Backend remoto pronto (`terraform/backend`). Configure o backend S3/Dynamo antes de rodar `init`.
2. AWS credenciais com permissão para criar os recursos acima.

## Como usar
```bash
cd terraform/runtime-monitoring

# (opcional) configure backend "s3" apontando para o bucket/lock criados pelo módulo backend
terraform init
terraform plan -out tfplan
terraform apply tfplan
```

Variáveis principais (`-var` ou `terraform.tfvars`):
- `aws_region` (default: us-east-1)
- `project_name` (default: compliance-as-code)
- `environment` (default: prod)
- `scan_schedule` (default: cron(0 2 * * ? *))
- `evidence_retention_days` (default: 2555 ~7 anos)
- `log_retention_days` (default: 90)
- `min_rds_backup_days` (default: 7)

## Resultados
- DynamoDB: item por recurso por execução (`pk=RUN#<uuid>`, `sk=<resource_id>`) com status/severity/control.
- S3: `scans/YYYY/MM/DD/scan-<uuid>.json` contendo todos os achados.
- CloudWatch Logs: `/aws/lambda/<function>` com JSON estruturado.

## Extensões futuras
- Avaliação via OPA bundle em vez de validações embutidas em Python.
- Integração com AWS Config Rules / Cloud Custodian.
- Auto-remediação para violações LOW/MEDIUM (se habilitado).
