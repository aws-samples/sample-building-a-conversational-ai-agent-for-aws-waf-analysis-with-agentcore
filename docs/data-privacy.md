# Data Privacy

[中文版](data-privacy_zh.md)

## Where Your Data Lives

All data stays within **your AWS account**. Nothing is sent to external services.

| Data | Storage | Retention |
|------|---------|-----------|
| Conversation messages | DynamoDB (your account) | 30-day TTL (auto-delete) |
| Cross-session memory (facts, preferences) | AgentCore Memory (managed service, your account) | STM: 30-day expiry. LTM: until manually deleted. |
| AWS WAF logs | CloudWatch Logs or S3 (your existing config) | Read-only access, not modified |

## User Isolation

Each user can only access their own session history. Isolation is enforced server-side:

- DynamoDB partition key = user email (extracted from JWT by the backend)
- The backend decodes the JWT token to derive user identity — client-supplied headers are not trusted
- There is no API to query another user's sessions

## Administrator Visibility

AWS account administrators with DynamoDB console/API access can view all users' session history. This is consistent with the AWS shared responsibility model — the data resides in your account under your control.

## Stronger Isolation (Optional)

For environments requiring per-user encryption at rest:

- Use [AWS Database Encryption SDK](https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/what-is-database-encryption-sdk.html) for client-side encryption of DynamoDB items
- Each user's data can be encrypted with a separate KMS key, making it unreadable even to DynamoDB administrators

This is not implemented by default — for a 5–20 person internal tool, the operational overhead outweighs the benefit. Consider it if deploying for larger teams or regulated environments.

## Data Deletion

- **Automatic**: 30-day TTL on all DynamoDB items
- **User-initiated**: Delete button on each session in the sidebar
- **Full wipe**: Delete the DynamoDB table or the CloudFormation stack
