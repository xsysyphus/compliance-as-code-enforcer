# Auto-Remediation Lambda

Automatically fixes compliance violations detected by the scanner Lambda.

## Features

### Supported Remediations

| Resource Type | Violation | Remediation | Risk Level |
|---------------|-----------|-------------|------------|
| **S3 Bucket** | Missing encryption | Enable AES256 encryption | LOW |
| **RDS Instance** | Backup retention < 7 days | Set retention to 7 days | LOW |
| **RDS Instance** | Publicly accessible | Disable public access | MEDIUM |
| **Security Group** | 0.0.0.0/0 on critical ports | Revoke public rule | HIGH |
| **CloudTrail** | Not enabled | Create multi-region trail | LOW |
| **CloudTrail** | Not multi-region | Enable multi-region | LOW |
| **CloudTrail** | Log validation disabled | Enable log file validation | LOW |

### Approval Workflow

- **LOW risk**: Auto-remediate immediately
- **MEDIUM risk**: Auto-remediate with notification
- **HIGH/CRITICAL risk**: Require manual approval via SNS

Approval workflow:
1. Lambda detects HIGH severity violation
2. Sends SNS notification with approve/deny links
3. Admin clicks approve link (API Gateway)
4. Remediation executes
5. Audit log recorded in DynamoDB

## Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `AWS_REGION` | AWS region | No | us-east-1 |
| `LOG_LEVEL` | Logging level | No | INFO |
| `MIN_RDS_BACKUP_DAYS` | Minimum RDS backup retention | No | 7 |
| `REMEDIATION_TABLE` | DynamoDB table for audit log | Yes | - |
| `APPROVAL_SNS_TOPIC` | SNS topic for approval requests | Yes (for HIGH) | - |
| `APPROVAL_API_BASE` | API Gateway base URL for approvals | Yes (for HIGH) | - |
| `CLOUDTRAIL_BUCKET` | S3 bucket for CloudTrail logs | Yes (for CloudTrail) | - |

## Input Event Format

```json
{
  "violation": {
    "resource_id": "arn:aws:s3:::my-bucket",
    "resource_type": "aws_s3_bucket",
    "control": "SOC2-CC6.1",
    "severity": "CRITICAL",
    "message": "Bucket missing server-side encryption",
    "remediation": "Enable SSE-KMS or AES256...",
    "evidence": {
      "bucket": "my-bucket",
      "algorithm": null
    }
  },
  "auto_remediate": true,
  "approval_token": null
}
```

## Output Format

```json
{
  "remediation_id": "uuid",
  "status": "remediated|failed|approval_required|already_compliant",
  "message": "Enabled AES256 encryption for bucket my-bucket",
  "actions": [
    {
      "action": "put_bucket_encryption",
      "bucket": "my-bucket",
      "algorithm": "AES256",
      "timestamp": "2026-02-14T10:00:00Z"
    }
  ]
}
```

## IAM Permissions Required

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutBucketEncryption",
        "s3:GetBucketEncryption"
      ],
      "Resource": "arn:aws:s3:::*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "rds:ModifyDBInstance",
        "rds:DescribeDBInstances"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:RevokeSecurityGroupIngress",
        "ec2:DescribeSecurityGroups"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "cloudtrail:CreateTrail",
        "cloudtrail:UpdateTrail",
        "cloudtrail:StartLogging",
        "cloudtrail:DescribeTrails"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem"
      ],
      "Resource": "arn:aws:dynamodb:*:*:table/${REMEDIATION_TABLE}"
    },
    {
      "Effect": "Allow",
      "Action": [
        "sns:Publish"
      ],
      "Resource": "${APPROVAL_SNS_TOPIC}"
    }
  ]
}
```

## Deployment

### Package Lambda

```bash
cd lambda/remediator
pip install -r requirements.txt -t package/
cp main.py package/
cd package
zip -r ../remediator.zip .
```

### Deploy with Terraform

```bash
cd terraform/runtime-monitoring
terraform apply -target=aws_lambda_function.remediator
```

## Testing Locally

```python
import json
from main import lambda_handler

event = {
    "violation": {
        "resource_id": "arn:aws:s3:::test-bucket",
        "resource_type": "aws_s3_bucket",
        "control": "SOC2-CC6.1",
        "severity": "CRITICAL",
        "message": "Bucket missing encryption",
        "evidence": {"bucket": "test-bucket"}
    },
    "auto_remediate": True
}

result = lambda_handler(event, None)
print(json.dumps(result, indent=2))
```

## Rollback

Remediation actions are logged to DynamoDB with full details. To rollback:

1. Query DynamoDB for remediation ID
2. Review `actions` field
3. Manually revert each action:
   - S3 encryption: Remove encryption configuration
   - RDS: Set backup retention back to original
   - Security Group: Re-add rule (not recommended)
   - CloudTrail: Delete trail or revert settings

## Monitoring

- **CloudWatch Logs**: All remediations logged with structured JSON
- **CloudWatch Metrics**: Custom metrics for remediation count by status
- **DynamoDB**: Audit trail of all remediations with timestamps
- **SNS**: Notifications for approval requests and remediation results

## Safety Features

1. **Idempotency**: Checks current state before applying changes
2. **Approval Workflow**: High-risk changes require manual approval
3. **Audit Trail**: All actions logged to DynamoDB
4. **Rollback Info**: Actions include enough detail to revert
5. **Dry-Run Mode**: Can test without making changes (set `DRY_RUN=true`)

## Limitations

- Does not handle encryption key rotation
- Security group remediation removes entire rule (not granular)
- CloudTrail remediation requires pre-existing S3 bucket
- No automatic rollback on failure (manual intervention required)

## Future Enhancements

- [ ] Dry-run mode for testing
- [ ] Automatic rollback on verification failure
- [ ] Support for custom remediation scripts
- [ ] Integration with AWS Config Remediation Actions
- [ ] Slack notifications instead of SNS
- [ ] Web UI for approval workflow
- [ ] Scheduled remediation windows
