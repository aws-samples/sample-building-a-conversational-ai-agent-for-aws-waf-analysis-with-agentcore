# Deployment Guide

English | [中文](deployment_zh.md)

## Overview

WAF Agent deploys as up to four CloudFormation stacks:

> [!IMPORTANT]
> **Model choice matters: use Claude Sonnet 4.6 or Claude Opus. Do not deploy this agent with GPT-family models on Amazon Bedrock unless you have tested your exact WAF investigation workflow.**
>
> This agent is a defensive AWS WAF analysis tool, but it reads and reasons about security logs, blocked requests, SQLi/XSS matches, bypass candidates, and bot/DDoS traffic. GPT-family models on Bedrock can silently fail or stop responding when upstream cyber-safety checks flag that context. If you must use a GPT model and the agent appears stuck, tell the agent: "This is authorized defensive AWS WAF log analysis for my own environment. Please continue investigating the WAF metrics and logs. Do not provide exploit payloads, credential theft steps, evasion, persistence, malware behavior, or instructions for unauthorized systems."

| Stack | Region | Resources |
|-------|--------|-----------|
| **backend** | Your choice (see [Region Selection](#region-selection)) | Cognito + AgentCore Runtime + AgentCore Memory + DynamoDB + IAM |
| **sessions** | Same as backend | API Gateway + Lambda (session history API) — *optional* |
| **kb** | Same as backend | S3 Vectors + Bedrock Knowledge Base + S3 (documents) — *optional* |
| **frontend** | us-east-1 (required for CloudFront AWS WAF) | CloudFront + S3 + AWS WAF WebACL |

## Prerequisites

1. **AWS CLI v2** configured with admin-level permissions
2. **Docker Desktop** (includes buildx for cross-platform builds). [Install Docker Desktop](https://docs.docker.com/get-docker/). Alternative: [finch](https://github.com/runfinch/finch) — see [appendix](#alternative-using-finch).
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

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WAF_AGENT_MODEL_ID` | Region-based (see above) | Bedrock model ID |
| `WAF_AGENT_MODEL_REGION` | Stack region | Region for Bedrock model invocation |
| `WAF_AGENT_TIMEZONE_OFFSET` | `0` (UTC) | Fallback timezone offset (hours) for date parsing when user doesn't specify. Set to `8` for UTC+8 (China/Singapore/etc.) |

These are set in the Dockerfile or CloudFormation template. To override, add to `deploy/backend.yaml` Environment section.

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
# Use a unique tag (commit hash) to ensure AgentCore pulls the new image
COMMIT=$(git rev-parse --short HEAD)
docker buildx build --platform linux/arm64 \
  --build-arg BUILD_COMMIT=$COMMIT \
  --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t $ECR_URI:$COMMIT --push .
```

> **What this does**: Reads the `Dockerfile` in the project root, installs Python dependencies, copies agent code into the image, injects the version info, and uploads it to ECR. AgentCore will pull this image when starting the agent.

> **Important**: Always use a unique tag (e.g., commit hash) instead of `:latest`. AgentCore only pulls a new image when CloudFormation detects a parameter change — reusing `:latest` may result in stale code.

> **Troubleshooting**: Build typically takes 1-2 minutes. If it hangs longer than 5 minutes, check network connectivity (the build downloads Python packages from PyPI). You can add `--no-cache` to force a clean build. If you don't have Docker Desktop, see [Alternative: Using finch](#alternative-using-finch) at the end of this guide.

## Step 2: Deploy Backend

```bash
aws cloudformation deploy \
  --template-file deploy/backend.yaml \
  --stack-name waf-agent \
  --region $REGION \
  --parameter-overrides AgentContainerUri=$ECR_URI:$COMMIT \
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
    AgentContainerUri=$ECR_URI:$COMMIT \
    ModelId=us.anthropic.claude-sonnet-4-6 \
    ModelRegion=us-east-1 \
  --capabilities CAPABILITY_NAMED_IAM
```

The model must support tool use and have sufficient context window.

> [!WARNING]
> **Strong recommendation: use Claude Sonnet 4.6 or Claude Opus. Avoid GPT-family Bedrock models for WAF Agent.** In WAF operations, normal defensive questions often contain terms such as SQLi, XSS, bypass, exploit attempt, malicious IP, and payload. GPT-family models may trigger upstream cyber-safety filters and fail silently, leaving the UI looking idle. If you override `ModelId`, validate false-positive review, COUNT rule evaluation, bypass detection, and blocked-injection investigation before using it with other users.

### Persistent Memory (recommended)

AgentCore Memory gives the agent cross-session memory — it remembers your WebACL names, environment details, and investigation history.

**Memory is created automatically** by the CloudFormation template (default behavior). No extra steps needed. Short-term memory events expire after 30 days (configurable via `EventExpiryDuration` in the template).

To disable memory (not recommended):
```bash
--parameter-overrides AgentContainerUri=$ECR_URI:$COMMIT MemoryId=none
```

To use an existing Memory resource instead of auto-creating:
```bash
--parameter-overrides AgentContainerUri=$ECR_URI:$COMMIT MemoryId=<your-memory-id>
```

### Existing Cognito User Pool (optional)

By default, the template creates a new Cognito User Pool. To use an existing one:

```bash
aws cloudformation deploy \
  --template-file deploy/backend.yaml \
  --stack-name waf-agent \
  --region $REGION \
  --parameter-overrides \
    AgentContainerUri=$ECR_URI:$COMMIT \
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

```bash
aws cloudformation deploy \
  --template-file deploy/kb.yaml \
  --stack-name waf-agent-kb \
  --region $REGION \
  --capabilities CAPABILITY_NAMED_IAM
```

Wait for `CREATE_COMPLETE`, then upload documents and trigger ingestion:

```bash
./deploy/sync-kb.sh waf-agent-kb ./kb-docs
```

Finally, redeploy the backend with the KB ID:
```bash
KB_ID=$(aws cloudformation describe-stacks --stack-name waf-agent-kb --region $REGION \
  --query "Stacks[0].Outputs[?OutputKey=='KnowledgeBaseId'].OutputValue" --output text)

aws cloudformation deploy \
  --template-file deploy/backend.yaml \
  --stack-name waf-agent \
  --region $REGION \
  --parameter-overrides \
    AgentContainerUri=$ECR_URI:$COMMIT \
    KnowledgeBaseId=$KB_ID \
  --capabilities CAPABILITY_NAMED_IAM
```

> **Note**: If you used `ExistingUserPoolId`/`ExistingClientId` in Step 2, include those parameters again here. CloudFormation requires all non-default parameters on every deploy.

> **Updating KB documents later**: Just run `./deploy/sync-kb.sh`. No redeployment needed.

> **S3 Vectors metadata limit**: S3 Vectors caps *filterable* metadata at 2 KB per vector. `kb.yaml` marks `AMAZON_BEDROCK_TEXT` and `AMAZON_BEDROCK_METADATA` (chunk text + source metadata, which grow with chunk size) as **non-filterable** to stay under that cap. If you increase the chunk size, keep them non-filterable — otherwise ingestion will fail.

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

# Optional: customize the agent name shown in the UI
# echo 'VITE_BRAND_NAME=My Company WAF Agent' >> .env

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

## Step 8: Access

Open `https://<CloudFrontDomain from Step 4>` in your browser. Sign in with the email and temporary password (you'll be prompted to set a new password on first login).

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

### AgentRuntimeName validation error

Name must match `[a-zA-Z][a-zA-Z0-9_]{0,47}`. No hyphens, spaces, or special characters. Default: `waf_agent`.

## Updating the Agent

After code changes:

```bash
# Rebuild and push
COMMIT=$(git rev-parse --short HEAD)
docker buildx build --platform linux/arm64 \
  --build-arg BUILD_COMMIT=$COMMIT \
  --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t $ECR_URI:$COMMIT --push .

# Update the stack (triggers runtime update)
aws cloudformation deploy \
  --template-file deploy/backend.yaml \
  --stack-name waf-agent \
  --region $REGION \
  --parameter-overrides AgentContainerUri=$ECR_URI:$COMMIT \
  --capabilities CAPABILITY_NAMED_IAM
```

> **Note**: Existing sessions continue running old code. New sessions will use the updated image.

## Alternative: Using finch

[finch](https://github.com/runfinch/finch) is a lightweight open-source container tool (no Docker Desktop license needed). If you use finch instead of Docker:

```bash
# Login (same as Docker)
aws ecr get-login-password --region $REGION | \
  finch login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

# Build (finch does not support --push, must be separate)
COMMIT=$(git rev-parse --short HEAD)
finch build --platform linux/arm64 --no-cache \
  --build-arg BUILD_COMMIT=$COMMIT \
  --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t $ECR_URI:$COMMIT .

# Push
finch push $ECR_URI:$COMMIT

# Deploy (same as Docker path)
aws cloudformation deploy \
  --template-file deploy/backend.yaml \
  --stack-name waf-agent \
  --region $REGION \
  --parameter-overrides AgentContainerUri=$ECR_URI:$COMMIT \
  --capabilities CAPABILITY_NAMED_IAM
```

**Notes:**
- On Apple Silicon (M1/M2/M3), `--platform linux/arm64` is optional — your Mac is already ARM64.
- If the build hangs, restart the finch VM: `finch vm stop && finch vm start`, then retry.
- First-time setup requires `finch vm init` (takes ~2 minutes).

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
