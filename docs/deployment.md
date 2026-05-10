# Deployment Guide

## Overview

WAF Agent deploys as two CloudFormation stacks:

| Stack | Region | Resources |
|-------|--------|-----------|
| **backend** | Your choice (see [Region Selection](#region-selection)) | Cognito + AgentCore Runtime + IAM |
| **frontend** | us-east-1 (required for CloudFront WAF) | CloudFront + S3 + WAF WebACL |

## Prerequisites

1. **AWS CLI v2** configured with admin-level permissions
2. **finch** or **Docker** with buildx (for ARM64 images)
3. **Node.js 18+** (for building the frontend)
4. An AWS account with WAF logging enabled (CloudWatch Logs or S3)

## Region Selection

Choose a backend region based on:
- **Proximity to your WAF resources** — reduces CloudWatch API latency
- **Model availability** — Claude Sonnet 4.6 must be available
- **AgentCore support** — CloudFormation must support `AWS::BedrockAgentCore::Runtime`

### Supported regions (CloudFormation + AgentCore + Claude Sonnet 4.6)

| Region | Best for |
|--------|----------|
| us-east-1 | US customers, CloudFront-scope WAF |
| us-west-2 | US West Coast |
| ap-northeast-1 | Asia Pacific (Japan, China, Korea) |
| ap-southeast-1 | Southeast Asia |
| eu-west-1 | Europe |
| eu-central-1 | Europe (Germany) |

**Recommendation**: If your WAF is CloudFront-scope (global), choose the region closest to you. The agent automatically routes WAF API calls to us-east-1 for CloudFront-scope resources.

### Model ID by region

| Region prefix | Default MODEL_ID |
|---------------|-----------------|
| us-* | `us.anthropic.claude-sonnet-4-6` |
| ap-northeast-1 | `jp.anthropic.claude-sonnet-4-6` |
| ap-* (other) | `apac.anthropic.claude-sonnet-4-6` |
| eu-* | `eu.anthropic.claude-sonnet-4-6` |

Override via environment variable `WAF_AGENT_MODEL_ID` if needed.

## Step 1: Build and Push Image

```bash
# Set your region and account
export REGION=ap-northeast-1
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export ECR_URI=$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/waf-agent

# Create ECR repository
aws ecr create-repository --repository-name waf-agent --region $REGION

# Authenticate
aws ecr get-login-password --region $REGION | \
  finch login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

# Generate lockfile (if not present)
uv lock

# Build ARM64 image and push
finch build --platform linux/arm64 -t $ECR_URI:latest .
finch push $ECR_URI:latest
```

> **Note**: AgentCore requires ARM64 images. x86_64 images will fail with "incompatible binary" error.

## Step 2: Deploy Backend

```bash
aws cloudformation deploy \
  --template-file deploy/backend.yaml \
  --stack-name waf-agent \
  --region $REGION \
  --parameter-overrides AgentContainerUri=$ECR_URI:latest \
  --capabilities CAPABILITY_NAMED_IAM
```

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

## Step 3: Deploy Frontend

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

## Step 4: Build and Upload Frontend

```bash
cd frontend

# Create .env from stack outputs
cat > .env << EOF
VITE_USER_POOL_ID=<UserPoolId from Step 2>
VITE_CLIENT_ID=<UserPoolClientId from Step 2>
VITE_REGION=$REGION
VITE_AGENT_ENDPOINT=<AgentEndpoint from Step 2>
VITE_AGENT_RUNTIME_ARN=<AgentRuntimeArn from Step 2>
EOF

# Build
npm install
npm run build

# Upload to S3
aws s3 sync dist/ s3://<FrontendBucket from Step 3>/ --region us-east-1
```

## Step 5: Create a User

```bash
aws cognito-idp admin-create-user \
  --user-pool-id <UserPoolId> \
  --username your@email.com \
  --temporary-password 'TempPass123!' \
  --region $REGION
```

## Step 6: Access

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
finch build --platform linux/arm64 -t $ECR_URI:latest .
finch push $ECR_URI:latest

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
# Delete frontend
aws cloudformation delete-stack --stack-name waf-agent-frontend --region us-east-1

# Delete backend
aws cloudformation delete-stack --stack-name waf-agent --region $REGION

# Delete ECR repository
aws ecr delete-repository --repository-name waf-agent --region $REGION --force
```
