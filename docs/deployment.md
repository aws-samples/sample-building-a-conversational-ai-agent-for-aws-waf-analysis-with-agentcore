# Deployment Guide

English | [中文](deployment_zh.md)

## Overview

WAF Agent deploys as two CloudFormation stacks:

| Stack | Region | Resources |
|-------|--------|-----------|
| **backend** | Your choice (see [Region Selection](#region-selection)) | Cognito + AgentCore Runtime + AgentCore Memory + DynamoDB + IAM |
| **sessions** | Same as backend | API Gateway + Lambda (session history API) — *optional* |
| **frontend** | us-east-1 (required for CloudFront AWS WAF) | CloudFront + S3 + AWS WAF WebACL |

## Prerequisites

1. **AWS CLI v2** configured with admin-level permissions
2. **Docker** with buildx support (for ARM64 images). [finch](https://github.com/runfinch/finch) also works as a drop-in replacement.
3. **Node.js 18+** (for building the frontend)
4. An AWS account with AWS WAF logging enabled (CloudWatch Logs or S3)

## Region Selection

Choose a backend region based on:
- **Proximity to your AWS WAF resources** — reduces CloudWatch API latency
- **Model availability** — Claude Sonnet 4.6 must be available
- **AgentCore support** — CloudFormation must support `AWS::BedrockAgentCore::Runtime`

### Supported regions (CloudFormation + AgentCore + Claude Sonnet 4.6)

| Region | Best for |
|--------|----------|
| us-east-1 | US customers, CloudFront-scope AWS WAF |
| us-west-2 | US West Coast |
| ap-northeast-1 | Asia Pacific (Japan, China, Korea) |
| ap-southeast-1 | Southeast Asia |
| eu-west-1 | Europe |
| eu-central-1 | Europe (Germany) |

**Recommendation**: If your AWS WAF is CloudFront-scope (global), choose the region closest to you. The agent automatically routes AWS WAF API calls to us-east-1 for CloudFront-scope resources.

### Model ID by region

| Region prefix | Default MODEL_ID |
|---------------|-----------------|
| us-* | `us.anthropic.claude-sonnet-4-6` |
| ap-northeast-1 | `jp.anthropic.claude-sonnet-4-6` |
| ap-* (other) | `apac.anthropic.claude-sonnet-4-6` |
| eu-* | `eu.anthropic.claude-sonnet-4-6` |

Override via environment variable `WAF_AGENT_MODEL_ID` if needed.

## Step 1: Build and Push Container Image

The agent runs as a container on AWS. This step packages the agent code into a container image and uploads it to Amazon ECR (a private container registry in your AWS account).

```bash
# Set your region and account
export REGION=ap-northeast-1
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export ECR_URI=$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/waf-agent

# Create ECR repository (your private container registry)
aws ecr create-repository --repository-name waf-agent --region $REGION

# Log in to ECR (token valid for 12 hours)
aws ecr get-login-password --region $REGION | \
  docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

# Build the container image (ARM64 architecture, required by AgentCore)
docker buildx build --platform linux/arm64 -t $ECR_URI:latest --push .
```

> **What this does**: Reads the `Dockerfile` in the project root, installs Python dependencies, copies agent code into the image, and uploads it to ECR. AgentCore will pull this image when starting the agent.

> **Using finch?** Finch does not support `--push` or `buildx`. Use separate commands:
> ```bash
> finch build --platform linux/arm64 -t $ECR_URI:latest .
> finch push $ECR_URI:latest
> ```
> On Apple Silicon (M1/M2/M3), `--platform linux/arm64` is optional — your Mac is already ARM64. If the build hangs, try restarting the VM: `finch vm stop && finch vm start`, then retry.

> **Troubleshooting**: Build typically takes 1-2 minutes. If it hangs longer than 5 minutes, check network connectivity (the build downloads Python packages from PyPI). You can add `--no-cache` to force a clean build.

## Step 2: Deploy Backend

```bash
aws cloudformation deploy \
  --template-file deploy/backend.yaml \
  --stack-name waf-agent \
  --region $REGION \
  --parameter-overrides AgentContainerUri=$ECR_URI:latest \
  --capabilities CAPABILITY_NAMED_IAM
```

### Custom Model (optional)

By default, the agent uses a region-appropriate Claude Sonnet 4.6 model. To use a different Amazon Bedrock model:

```bash
aws cloudformation deploy \
  --template-file deploy/backend.yaml \
  --stack-name waf-agent \
  --region $REGION \
  --parameter-overrides \
    AgentContainerUri=$ECR_URI:latest \
    ModelId=us.anthropic.claude-sonnet-4-6 \
    ModelRegion=us-east-1 \
  --capabilities CAPABILITY_NAMED_IAM
```

Any model available on Amazon Bedrock works, but it must support tool use and have sufficient context window. Recommended: Claude Sonnet 4.6 or Claude Opus (both 1M context).

### Persistent Memory (recommended)

AgentCore Memory gives the agent cross-session memory — it remembers your WebACL names, environment details, and investigation history.

**Memory is created automatically** by the CloudFormation template (default behavior). No extra steps needed. Short-term memory events expire after 30 days (configurable via `EventExpiryDuration` in the template).

To disable memory (not recommended):
```bash
--parameter-overrides AgentContainerUri=$ECR_URI:latest MemoryId=none
```

To use an existing Memory resource instead of auto-creating:
```bash
--parameter-overrides AgentContainerUri=$ECR_URI:latest MemoryId=<your-memory-id>
```

### Existing Cognito User Pool (optional)

By default, the template creates a new Cognito User Pool. To use an existing one:

```bash
aws cloudformation deploy \
  --template-file deploy/backend.yaml \
  --stack-name waf-agent \
  --region $REGION \
  --parameter-overrides \
    AgentContainerUri=$ECR_URI:latest \
    ExistingUserPoolId=<your-user-pool-id> \
    ExistingClientId=<your-client-id> \
  --capabilities CAPABILITY_NAMED_IAM
```

When using an existing pool, deleting the stack will **not** delete your User Pool.

Wait for `CREATE_COMPLETE`, then get outputs:

```bash
aws cloudformation describe-stacks --stack-name waf-agent --region $REGION \
  --query 'Stacks[0].Outputs' --output table
```

Save these values — you'll need them for the frontend:
- `UserPoolId`
- `UserPoolClientId`
- `AgentRuntimeArn`
- `AgentEndpoint`
- `SessionsTableName`

## Step 3: Deploy Sessions API (optional, recommended)

```bash
aws cloudformation deploy \
  --template-file deploy/sessions-api.yaml \
  --stack-name waf-agent-sessions \
  --region $REGION \
  --parameter-overrides \
    SessionsTableArn=arn:aws:dynamodb:$REGION:$ACCOUNT_ID:table/<SessionsTableName> \
    SessionsTableName=<SessionsTableName from Step 2> \
    CognitoUserPoolId=<UserPoolId from Step 2> \
    CognitoClientId=<UserPoolClientId from Step 2> \
  --capabilities CAPABILITY_NAMED_IAM
```

Note the `SessionsApiUrl` output.

> **Skip this step?** The agent works fully without session history — you just won't see past conversations in the sidebar. You can deploy this later without affecting the backend or frontend.

> **Security note:** The Sessions API is protected by Cognito JWT authorization — only authenticated users can access it. For additional protection (rate limiting, IP reputation, geo-blocking), place a CloudFront distribution with an AWS WAF WebACL in front of the API Gateway. HTTP API (v2) does not support direct WAF association.

## Step 4: Deploy Frontend

```bash
aws cloudformation deploy \
  --template-file deploy/frontend.yaml \
  --stack-name waf-agent-frontend \
  --region us-east-1
```

Get the S3 bucket name and CloudFront domain:

```bash
aws cloudformation describe-stacks --stack-name waf-agent-frontend --region us-east-1 \
  --query 'Stacks[0].Outputs' --output table
```

## Step 5: Deploy Knowledge Base (optional, recommended)

Adds AWS WAF best practices retrieval to the agent. Skip this if you don't need KB-powered recommendations.

### 5a. Pre-create S3 Vectors resources (CLI only — CFN types not yet available)

```bash
aws s3vectors create-vector-bucket \
  --vector-bucket-name waf-agent-kb-vectors-${ACCOUNT_ID}-${REGION} \
  --region $REGION

aws s3vectors create-index \
  --vector-bucket-name waf-agent-kb-vectors-${ACCOUNT_ID}-${REGION} \
  --index-name waf-agent-kb-index \
  --data-type float32 --dimension 1024 --distance-metric cosine \
  --region $REGION
```

Note the Vector Index ARN from the output (format: `arn:aws:s3vectors:REGION:ACCOUNT:bucket/BUCKET_NAME/index/INDEX_NAME`).

### 5b. Deploy KB stack

```bash
aws cloudformation deploy \
  --template-file deploy/kb.yaml \
  --stack-name waf-agent-kb \
  --region $REGION \
  --parameter-overrides \
    VectorBucketName=waf-agent-kb-vectors-${ACCOUNT_ID}-${REGION} \
    VectorIndexArn=arn:aws:s3vectors:${REGION}:${ACCOUNT_ID}:bucket/waf-agent-kb-vectors-${ACCOUNT_ID}-${REGION}/index/waf-agent-kb-index \
  --capabilities CAPABILITY_NAMED_IAM
```

### 5c. Upload documents and trigger ingestion

```bash
# Upload your KB documents
aws s3 sync ./kb-docs/ s3://<DocumentsBucketName from stack output>/ --region $REGION

# Trigger ingestion
aws bedrock-agent start-ingestion-job \
  --knowledge-base-id <KnowledgeBaseId from stack output> \
  --data-source-id <DataSourceId from stack output> \
  --region $REGION
```

Or use the helper script (reads all IDs from CFN outputs automatically):
```bash
./deploy/sync-kb.sh waf-agent-kb ./kb-docs
```

### 5d. Update backend with KB ID

Redeploy the backend stack with the `KnowledgeBaseId` parameter:
```bash
aws cloudformation deploy \
  --template-file deploy/backend.yaml \
  --stack-name waf-agent \
  --region $REGION \
  --parameter-overrides \
    AgentContainerUri=$ECR_URI:latest \
    KnowledgeBaseId=<KnowledgeBaseId from Step 5b> \
  --capabilities CAPABILITY_NAMED_IAM
```

> **Updating KB documents later**: Just run `./deploy/sync-kb.sh`. No redeployment needed.

## Step 6: Build and Upload Frontend

```bash
cd frontend

# Create .env from stack outputs
cat > .env << EOF
VITE_USER_POOL_ID=<UserPoolId from Step 2>
VITE_CLIENT_ID=<UserPoolClientId from Step 2>
VITE_REGION=$REGION
VITE_AGENT_ENDPOINT=<AgentEndpoint from Step 2>
VITE_AGENT_RUNTIME_ARN=<AgentRuntimeArn from Step 2>
VITE_SESSIONS_API_URL=<SessionsApiUrl from Step 3>
EOF

# Build
npm install
npm run build

# Upload to S3
aws s3 sync dist/ s3://<FrontendBucket from Step 4>/ --region us-east-1
```

## Step 7: Create a User

```bash
aws cognito-idp admin-create-user \
  --user-pool-id <UserPoolId> \
  --username your@email.com \
  --temporary-password 'TempPass123!' \
  --region $REGION
```

> On first login, you'll be prompted to set a new password. The frontend handles this automatically.

## Step 7: Access

Open `https://<CloudFrontDomain from Step 3>` in your browser. Sign in with the email and temporary password (you'll be prompted to set a new password on first login).

## Troubleshooting

### "Unrecognized resource types" during backend deploy

The correct CloudFormation type is `AWS::BedrockAgentCore::Runtime`. If you see this error, ensure:
1. You're deploying to a [supported region](#supported-regions-cloudformation--agentcore--claude-sonnet-46)
2. Your AWS CLI is up to date (`aws --version` should be 2.x)

### AgentCore Runtime stuck in CREATING

Allow up to 5 minutes. Check status:
```bash
aws bedrock-agentcore-control get-agent-runtime \
  --agent-runtime-id <id-from-stack-output> --region $REGION
```

If `FAILED`, check `failureReason` in the response.

### Container fails to start (FAILED status)

Common causes:
- **Wrong architecture**: Image must be ARM64 (`--platform linux/arm64`)
- **Port mismatch**: Container must listen on port 8080
- **Missing /ping**: Health check endpoint must return HTTP 200
- **ECR permissions**: Execution role needs `ecr:BatchGetImage` + `ecr:GetDownloadUrlForLayer`

### 504 on invocation

- Container not responding on port 8080
- `/invocations` endpoint not implemented
- Agent startup taking too long (check if JA4 database download is blocking)

### AgentRuntimeName validation error

Name must match `[a-zA-Z][a-zA-Z0-9_]{0,47}`. No hyphens, spaces, or special characters. Default: `waf_agent`.

## Updating the Agent

After code changes:

```bash
# Rebuild and push
docker buildx build --platform linux/arm64 -t $ECR_URI:latest --push .

# Update the stack (triggers runtime update)
aws cloudformation deploy \
  --template-file deploy/backend.yaml \
  --stack-name waf-agent \
  --region $REGION \
  --parameter-overrides AgentContainerUri=$ECR_URI:latest \
  --capabilities CAPABILITY_NAMED_IAM
```

> **Note**: Existing sessions continue running old code. New sessions will use the updated image.

## Cleanup

```bash
REGION=ap-northeast-1  # Same region used during deployment

# 1. Empty the frontend S3 bucket (CFN cannot delete non-empty buckets)
BUCKET=$(aws cloudformation describe-stacks --stack-name waf-agent-frontend --region us-east-1 \
  --query "Stacks[0].Outputs[?OutputKey=='FrontendBucket'].OutputValue" --output text)
aws s3 rm s3://$BUCKET --recursive

# 2. Delete frontend stack (CloudFront deletion takes 5-10 minutes)
aws cloudformation delete-stack --stack-name waf-agent-frontend --region us-east-1

# 3. Delete sessions API stack (if deployed)
aws cloudformation delete-stack --stack-name waf-agent-sessions --region $REGION

# 4. Delete KB stack (if deployed) — empty docs bucket first
KB_BUCKET=$(aws cloudformation describe-stacks --stack-name waf-agent-kb --region $REGION \
  --query "Stacks[0].Outputs[?OutputKey=='DocumentsBucketName'].OutputValue" --output text 2>/dev/null)
[ -n "$KB_BUCKET" ] && aws s3 rm s3://$KB_BUCKET --recursive
aws cloudformation delete-stack --stack-name waf-agent-kb --region $REGION
# Also delete pre-created S3 Vectors resources:
aws s3vectors delete-index --vector-bucket-name waf-agent-kb-vectors-${ACCOUNT_ID}-${REGION} \
  --index-name waf-agent-kb-index --region $REGION
aws s3vectors delete-vector-bucket --vector-bucket-name waf-agent-kb-vectors-${ACCOUNT_ID}-${REGION} \
  --region $REGION

# 5. Delete backend stack (includes AgentCore Runtime + Memory; Cognito only if auto-created)
aws cloudformation delete-stack --stack-name waf-agent --region $REGION

# 6. Delete ECR repository
aws ecr delete-repository --repository-name waf-agent --region $REGION --force
```

## Usage Notes

- **Session timeout**: Container idles out after 15 minutes. Download weekly reports promptly after generation.
- **Cold start**: First query after idle takes ~30 seconds (container startup).
- **Report generation**: Takes 1–2 minutes (multiple CloudWatch API calls).
- **Report download**: Auto-triggers when report is ready. Click "Download Again" if needed.
