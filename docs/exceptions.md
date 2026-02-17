# Compliance Exceptions Registry

Documente exceções de conformidade aprovadas para evitar falsos positivos e garantir rastreabilidade de auditoria. Cada exceção deve ter dono, justificativa, prazo e evidência de aprovação.

## Como registrar
1. Adicione um registro na tabela abaixo.
2. Tag no recurso Terraform com `Exception = "<id>"` e `ExpiresOn = "YYYY-MM-DD"`.
3. Inclua `Justification` e `ApprovedBy` nas tags quando aplicável.
4. Revise e renove/expire no prazo.

| ID | Recurso/Stack | Política/Controle | Severidade | Justificativa | Dono | Aprovado por | Expira em | Evidência |
|----|---------------|-------------------|------------|---------------|------|--------------|-----------|-----------|
| EX-0001 | _ex.: aws_security_group.bastion_ | SOC2-CC6.6 (SG pública) | HIGH | Acesso de break-glass para migração | time-net | CISO | 2026-03-31 | Change ticket #123 |

## Diretrizes
- Exceções devem ser temporárias (máx. 90 dias para prod; 30 dias para migração).
- Renovar exige revalidação do risco e nova aprovação.
- Remover exceções expiradas no próximo ciclo de hardening.
- Anexar links para tickets (Jira/ServiceNow) e evidências de avaliação de risco.

## Revisões trimestrais
- Responsável: Security/Compliance.
- Ação: varrer tags `Exception`, comparar com tabela e remover exceções vencidas.
