# 部署指南

[English](deployment.md) | 中文

## 概述

WAF Agent 通过两个 CloudFormation Stack 部署：

| Stack | 区域 | 资源 |
|-------|------|------|
| **backend** | 自选（见[区域选择](#区域选择)） | Cognito + AgentCore Runtime + IAM |
| **frontend** | us-east-1（CloudFront WAF 要求） | CloudFront + S3 + WAF WebACL |

## 前置条件

1. **AWS CLI v2**，配置了管理员权限
2. **Docker**（需要 buildx 支持）。[finch](https://github.com/runfinch/finch) 也可以作为替代。
3. **Node.js 18+**（构建前端）
4. 已开启 WAF 日志的 AWS 账号（CloudWatch Logs 或 S3）

## 区域选择

选择后端区域时考虑：
- **靠近你的 WAF 资源** — 减少 CloudWatch API 延迟
- **模型可用性** — Claude Sonnet 4.6 必须可用
- **AgentCore 支持** — CloudFormation 必须支持 `AWS::BedrockAgentCore::Runtime`

### 支持的区域

| 区域 | 适合 |
|------|------|
| us-east-1 | 美国客户，CloudFront 范围的 WAF |
| us-west-2 | 美国西海岸 |
| ap-northeast-1 | 亚太（日本、中国、韩国） |
| ap-southeast-1 | 东南亚 |
| eu-west-1 | 欧洲 |
| eu-central-1 | 欧洲（德国） |

**建议**：如果你的 WAF 是 CloudFront 范围（全球），选择离你最近的区域。Agent 会自动将 WAF API 调用路由到 us-east-1。

### 各区域的模型 ID

| 区域前缀 | 默认 MODEL_ID |
|---------|--------------|
| us-* | `us.anthropic.claude-sonnet-4-6` |
| ap-northeast-1 | `jp.anthropic.claude-sonnet-4-6` |
| ap-*（其他） | `apac.anthropic.claude-sonnet-4-6` |
| eu-* | `eu.anthropic.claude-sonnet-4-6` |

可通过环境变量 `WAF_AGENT_MODEL_ID` 覆盖。

## 第 1 步：构建并推送镜像

```bash
# 设置区域和账号
export REGION=ap-northeast-1
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export ECR_URI=$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/waf-agent

# 创建 ECR 仓库
aws ecr create-repository --repository-name waf-agent --region $REGION

# 登录 ECR
aws ecr get-login-password --region $REGION | \
  docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

# 构建 ARM64 镜像并推送
docker buildx build --platform linux/arm64 -t $ECR_URI:latest --push .
```

> **注意**：AgentCore 要求 ARM64 镜像。x86_64 镜像会报 "incompatible binary" 错误。
>
> 如果使用 **finch**，将上面命令中的 `docker` 替换为 `finch` 即可。

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

默认使用当前区域对应的 Claude Sonnet 4.6。如需使用其他 Bedrock 模型：

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
--parameter-overrides AgentContainerUri=$ECR_URI:latest MemoryId=mem-xxxxxxxxxxxx
```

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

## 第 3 步：部署前端

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

## 第 4 步：构建并上传前端

```bash
cd frontend

# 用第 2、3 步的输出填写 .env
cat > .env << EOF
VITE_USER_POOL_ID=<第 2 步的 UserPoolId>
VITE_CLIENT_ID=<第 2 步的 UserPoolClientId>
VITE_REGION=$REGION
VITE_AGENT_ENDPOINT=<第 2 步的 AgentEndpoint>
VITE_AGENT_RUNTIME_ARN=<第 2 步的 AgentRuntimeArn>
EOF

# 构建
npm install
npm run build

# 上传到 S3
aws s3 sync dist/ s3://<第 3 步的 FrontendBucket>/ --region us-east-1
```

## 第 5 步：创建用户

```bash
aws cognito-idp admin-create-user \
  --user-pool-id <UserPoolId> \
  --username your@email.com \
  --temporary-password 'TempPass123!' \
  --region $REGION
```

> 首次登录时会提示设置新密码，前端会自动处理。

## 第 6 步：访问

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

## 清理

```bash
# 删除前端（CloudFront 删除需要 5-10 分钟）
aws cloudformation delete-stack --stack-name waf-agent-frontend --region us-east-1

# 删除后端
aws cloudformation delete-stack --stack-name waf-agent --region $REGION

# 删除 ECR 仓库
aws ecr delete-repository --repository-name waf-agent --region $REGION --force
```

## 使用须知

- **会话超时**：容器空闲 15 分钟后释放。生成周报后请及时下载。
- **冷启动**：空闲后首次查询需要约 30 秒（容器启动）。
- **周报生成**：约需 1-2 分钟（多次 CloudWatch API 调用）。
- **报告下载**：报告就绪后自动触发下载。如需再次下载点击 "Download Again"。
