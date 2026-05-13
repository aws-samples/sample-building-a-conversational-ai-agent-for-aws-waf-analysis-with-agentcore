# 部署指南

[English](deployment.md) | 中文

## 概述

WAF Agent 通过两个 CloudFormation Stack 部署：

| Stack | 区域 | 资源 |
|-------|------|------|
| **backend** | 自选（见[区域选择](#区域选择)） | Cognito + AgentCore Runtime + AgentCore Memory + DynamoDB + IAM |
| **sessions** | 与 backend 相同 | API Gateway + Lambda（会话历史 API）— *可选* |
| **frontend** | us-east-1（CloudFront AWS WAF 要求） | CloudFront + S3 + AWS WAF WebACL |

## 前置条件

1. **AWS CLI v2**，配置了管理员权限
2. **Docker**（需要 buildx 支持）。[finch](https://github.com/runfinch/finch) 也可以作为替代。
3. **Node.js 18+**（构建前端）
4. 已开启 AWS WAF 日志的 AWS 账号（CloudWatch Logs 或 S3）

## 区域选择

选择后端区域时考虑：
- **靠近你的 AWS WAF 资源** — 减少 CloudWatch API 延迟
- **模型可用性** — Claude Sonnet 4.6 必须可用
- **AgentCore 支持** — CloudFormation 必须支持 `AWS::BedrockAgentCore::Runtime`

### 支持的区域

| 区域 | 适合 |
|------|------|
| us-east-1 | 美国客户，CloudFront 范围的 AWS WAF |
| us-west-2 | 美国西海岸 |
| ap-northeast-1 | 亚太（日本、中国、韩国） |
| ap-southeast-1 | 东南亚 |
| eu-west-1 | 欧洲 |
| eu-central-1 | 欧洲（德国） |

**建议**：如果你的 AWS WAF 是 CloudFront 范围（全球），选择离你最近的区域。Agent 会自动将 AWS WAF API 调用路由到 us-east-1。

### 各区域的模型 ID

| 区域前缀 | 默认 MODEL_ID |
|---------|--------------|
| us-* | `us.anthropic.claude-sonnet-4-6` |
| ap-northeast-1 | `jp.anthropic.claude-sonnet-4-6` |
| ap-*（其他） | `apac.anthropic.claude-sonnet-4-6` |
| eu-* | `eu.anthropic.claude-sonnet-4-6` |

可通过环境变量 `WAF_AGENT_MODEL_ID` 覆盖。

## 第 1 步：构建并推送容器镜像

Agent 以容器形式运行在 AWS 上。此步骤将 Agent 代码打包为容器镜像，并上传到 Amazon ECR（您 AWS 账户中的私有容器仓库）。

```bash
# 设置区域和账号
export REGION=ap-northeast-1
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export ECR_URI=$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/waf-agent

# 创建 ECR 仓库（私有容器仓库）
aws ecr create-repository --repository-name waf-agent --region $REGION

# 登录 ECR（令牌有效期 12 小时）
aws ecr get-login-password --region $REGION | \
  docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

# 构建 ARM64 镜像并推送
docker buildx build --platform linux/arm64 -t $ECR_URI:latest --push .
```

> **这一步做了什么**：读取项目根目录的 `Dockerfile`，安装 Python 依赖，将 Agent 代码复制到镜像中，然后上传到 ECR。AgentCore 启动 Agent 时会从 ECR 拉取此镜像。

> **排查**：构建通常需要 1-2 分钟。如果超过 5 分钟没有反应，检查网络连接（构建过程需要从 PyPI 下载 Python 包）。可以加 `--no-cache` 强制全新构建。如果没有 Docker Desktop，参见本文末尾的[替代方案：使用 finch](#替代方案使用-finch)。

## 第 2 步：部署后端

```bash
aws cloudformation deploy \
  --template-file deploy/backend.yaml \
  --stack-name waf-agent \
  --region $REGION \
  --parameter-overrides AgentContainerUri=$ECR_URI:latest \
  --capabilities CAPABILITY_NAMED_IAM
```

### 自定义模型（可选）

默认使用当前区域对应的 Claude Sonnet 4.6。如需使用其他 Amazon Bedrock 模型：

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

模型必须支持 tool use 并有足够的上下文窗口。推荐 Claude Sonnet 4.6 或 Claude Opus（均为 1M 上下文）。

### 持久记忆（推荐）

AgentCore Memory 让 Agent 拥有跨会话记忆——它会记住你的 WebACL 名称、环境信息和调查历史。

**Memory 由 CloudFormation 模板自动创建**（默认行为）。无需额外步骤。短期记忆事件 30 天后过期（可在模板中通过 `EventExpiryDuration` 调整）。

禁用 Memory（不推荐）：
```bash
--parameter-overrides AgentContainerUri=$ECR_URI:latest MemoryId=none
```

使用已有的 Memory 资源（而非自动创建）：
```bash
--parameter-overrides AgentContainerUri=$ECR_URI:latest MemoryId=<your-memory-id>
```

### 使用现有 Cognito User Pool（可选）

默认情况下模板会创建新的 Cognito User Pool。如需使用现有的：

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

使用现有 Pool 时，删除 stack **不会**删除你的 User Pool。

等待 `CREATE_COMPLETE`，然后获取输出：

```bash
aws cloudformation describe-stacks --stack-name waf-agent --region $REGION \
  --query 'Stacks[0].Outputs' --output table
```

记下这些值（前端配置需要）：
- `UserPoolId`
- `UserPoolClientId`
- `AgentRuntimeArn`
- `AgentEndpoint`
- `SessionsTableName`

## 第 3 步：部署会话 API（可选，推荐）

```bash
aws cloudformation deploy \
  --template-file deploy/sessions-api.yaml \
  --stack-name waf-agent-sessions \
  --region $REGION \
  --parameter-overrides \
    SessionsTableArn=arn:aws:dynamodb:$REGION:$ACCOUNT_ID:table/<SessionsTableName> \
    SessionsTableName=<第 2 步的 SessionsTableName> \
    CognitoUserPoolId=<第 2 步的 UserPoolId> \
    CognitoClientId=<第 2 步的 UserPoolClientId> \
  --capabilities CAPABILITY_NAMED_IAM
```

记下输出中的 `SessionsApiUrl`。

> **可以跳过此步骤吗？** Agent 不部署会话历史也能完整工作——只是侧边栏不会显示历史对话。可以之后再部署，不影响后端或前端。

> **安全说明：** 会话 API 受 Cognito JWT 授权保护——只有认证用户可以访问。如需额外防护（频率限制、IP 信誉、地理封锁），可在 API Gateway 前面加一个 CloudFront 分配并关联 AWS WAF WebACL。HTTP API (v2) 不支持直接关联 WAF。

## 第 4 步：部署前端

```bash
aws cloudformation deploy \
  --template-file deploy/frontend.yaml \
  --stack-name waf-agent-frontend \
  --region us-east-1
```

获取 S3 桶名和 CloudFront 域名：

```bash
aws cloudformation describe-stacks --stack-name waf-agent-frontend --region us-east-1 \
  --query 'Stacks[0].Outputs' --output table
```

## 第 5 步：部署知识库（可选，推荐）

为 Agent 添加 AWS WAF 最佳实践检索能力。不需要可跳过。

### 5a. 预创建 S3 Vectors 资源（CFN 暂不支持，需用 CLI）

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

记录输出中的 Vector Index ARN。

### 5b. 部署 KB 堆栈

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

### 5c. 上传文档并触发索引

```bash
./deploy/sync-kb.sh waf-agent-kb ./kb-docs
```

### 5d. 更新后端（传入 KB ID）

```bash
aws cloudformation deploy \
  --template-file deploy/backend.yaml \
  --stack-name waf-agent \
  --region $REGION \
  --parameter-overrides \
    AgentContainerUri=$ECR_URI:latest \
    KnowledgeBaseId=<第 5b 步输出的 KnowledgeBaseId> \
  --capabilities CAPABILITY_NAMED_IAM
```

> **后续更新文档**：只需运行 `./deploy/sync-kb.sh`，无需重新部署。

## 第 6 步：构建并上传前端

```bash
cd frontend

# 用第 2、3 步的输出填写 .env
cat > .env << EOF
VITE_USER_POOL_ID=<第 2 步的 UserPoolId>
VITE_CLIENT_ID=<第 2 步的 UserPoolClientId>
VITE_REGION=$REGION
VITE_AGENT_ENDPOINT=<第 2 步的 AgentEndpoint>
VITE_AGENT_RUNTIME_ARN=<第 2 步的 AgentRuntimeArn>
VITE_SESSIONS_API_URL=<第 3 步的 SessionsApiUrl>
EOF

# 构建
npm install
npm run build

# 上传到 S3
aws s3 sync dist/ s3://<第 4 步的 FrontendBucket>/ --region us-east-1
```

## 第 7 步：创建用户

```bash
aws cognito-idp admin-create-user \
  --user-pool-id <UserPoolId> \
  --username your@email.com \
  --temporary-password 'TempPass123!' \
  --region $REGION
```

> 首次登录时会提示设置新密码，前端会自动处理。

## 第 7 步：访问

浏览器打开 `https://<第 3 步的 CloudFrontDomain>`，用邮箱和临时密码登录。

## 故障排查

### 部署后端时报 "Unrecognized resource types"

CloudFormation 类型名是 `AWS::BedrockAgentCore::Runtime`。如果报错：
1. 确认部署在[支持的区域](#支持的区域)
2. 确认 AWS CLI 是最新版（`aws --version` 应为 2.x）

### AgentCore Runtime 卡在 CREATING

最多等 5 分钟。检查状态：
```bash
aws bedrock-agentcore-control get-agent-runtime \
  --agent-runtime-id <stack 输出的 id> --region $REGION
```

如果是 `FAILED`，查看响应中的 `failureReason`。

### 容器启动失败（FAILED 状态）

常见原因：
- **架构错误**：镜像必须是 ARM64（`--platform linux/arm64`）
- **端口不对**：容器必须监听 8080 端口
- **缺少 /ping**：健康检查端点必须返回 HTTP 200
- **ECR 权限**：执行角色需要 `ecr:BatchGetImage` + `ecr:GetDownloadUrlForLayer`

### 调用时返回 504

- 容器没有在 8080 端口响应
- `/invocations` 端点未实现
- Agent 启动太慢（检查 JA4 数据库下载是否阻塞）

### AgentRuntimeName 验证错误

名称必须匹配 `[a-zA-Z][a-zA-Z0-9_]{0,47}`。不能有连字符、空格或特殊字符。默认值：`waf_agent`。

## 更新 Agent

代码修改后：

```bash
# 重新构建并推送
docker buildx build --platform linux/arm64 -t $ECR_URI:latest --push .

# 更新 Stack（触发 runtime 更新）
aws cloudformation deploy \
  --template-file deploy/backend.yaml \
  --stack-name waf-agent \
  --region $REGION \
  --parameter-overrides AgentContainerUri=$ECR_URI:latest \
  --capabilities CAPABILITY_NAMED_IAM
```

> **注意**：已有会话继续运行旧代码，新会话使用更新后的镜像。

## 替代方案：使用 finch

[finch](https://github.com/runfinch/finch) 是一个轻量级开源容器工具（无需 Docker Desktop 许可证）。如果使用 finch：

```bash
# 登录（和 Docker 相同）
aws ecr get-login-password --region $REGION | \
  finch login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

# 构建（finch 不支持 --push，必须分开执行）
finch build --platform linux/arm64 -t $ECR_URI:latest .

# 推送
finch push $ECR_URI:latest
```

**注意：**
- 在 Apple Silicon（M1/M2/M3）上，`--platform linux/arm64` 可省略——Mac 本身就是 ARM64。
- 如果构建卡住，重启 finch VM：`finch vm stop && finch vm start`，然后重试。
- 首次使用需要 `finch vm init`（约 2 分钟）。

## 清理

```bash
REGION=ap-northeast-1  # 与部署时使用的区域一致

# 1. 清空前端 S3 桶（CFN 无法删除非空桶）
BUCKET=$(aws cloudformation describe-stacks --stack-name waf-agent-frontend --region us-east-1 \
  --query "Stacks[0].Outputs[?OutputKey=='FrontendBucket'].OutputValue" --output text)
aws s3 rm s3://$BUCKET --recursive

# 2. 删除前端栈（CloudFront 删除需要 5-10 分钟）
aws cloudformation delete-stack --stack-name waf-agent-frontend --region us-east-1

# 3. 删除会话 API 栈（如已部署）
aws cloudformation delete-stack --stack-name waf-agent-sessions --region $REGION

# 4. 删除知识库栈（如已部署）— 先清空文档桶
KB_BUCKET=$(aws cloudformation describe-stacks --stack-name waf-agent-kb --region $REGION \
  --query "Stacks[0].Outputs[?OutputKey=='DocumentsBucketName'].OutputValue" --output text 2>/dev/null)
[ -n "$KB_BUCKET" ] && aws s3 rm s3://$KB_BUCKET --recursive
aws cloudformation delete-stack --stack-name waf-agent-kb --region $REGION
# 删除预创建的 S3 Vectors 资源：
aws s3vectors delete-index --vector-bucket-name waf-agent-kb-vectors-${ACCOUNT_ID}-${REGION} \
  --index-name waf-agent-kb-index --region $REGION
aws s3vectors delete-vector-bucket --vector-bucket-name waf-agent-kb-vectors-${ACCOUNT_ID}-${REGION} \
  --region $REGION

# 5. 删除后端栈（包含 AgentCore Runtime + Memory；Cognito 仅在自动创建时删除）
aws cloudformation delete-stack --stack-name waf-agent --region $REGION

# 6. 删除 ECR 仓库
aws ecr delete-repository --repository-name waf-agent --region $REGION --force
```

## 使用须知

- **会话超时**：容器空闲 15 分钟后释放。生成周报后请及时下载。
- **冷启动**：空闲后首次查询需要约 30 秒（容器启动）。
- **周报生成**：约需 1-2 分钟（多次 CloudWatch API 调用）。
- **报告下载**：报告就绪后自动触发下载。如需再次下载点击 "Download Again"。
