# IAM 权限说明

[English](iam-permissions.md)

本文档列出 WAF Agent 需要的所有 IAM 权限、用途，以及是否会修改你的生产环境。

## 总结

**WAF Agent 对你的生产资源是只读的。** 它不能修改 WAF 规则、删除日志组、更改 CloudFront 分配或改动任何生产配置。唯一的写操作是：

1. 在专用数据库中创建/删除**临时 Athena 表**（会话结束时自动清理）
2. 写入自身的**容器日志**到 CloudWatch

## 权限详情

### WAF（只读）

| 权限 | 用途 | 生产环境影响 |
|---|---|---|
| `wafv2:ListWebACLs` | 列出可用的 WebACL | 无（只读） |
| `wafv2:GetWebACL` | 读取 WebACL 规则和配置 | 无（只读） |
| `wafv2:GetLoggingConfiguration` | 发现 WAF 日志发送到哪里 | 无（只读） |
| `wafv2:ListResourcesForWebACL` | 查找哪些 CloudFront/ALB 资源使用了某个 WebACL | 无（只读） |

### CloudWatch 指标（只读）

| 权限 | 用途 | 生产环境影响 |
|---|---|---|
| `cloudwatch:GetMetricData` | 查询 WAF 指标（AllowedRequests、BlockedRequests 等） | 无（只读） |
| `cloudwatch:ListMetrics` | 发现可用的指标名称 | 无（只读） |

### CloudWatch 日志（只读）

| 权限 | 用途 | 生产环境影响 |
|---|---|---|
| `logs:StartQuery` | 在 WAF 日志上运行 Logs Insights 查询 | 无（只读）。查询是只读的，不能修改日志数据。 |
| `logs:GetQueryResults` | 获取查询结果 | 无（只读） |
| `logs:StopQuery` | 取消正在运行的查询（清理） | 无（停止一个读操作） |
| `logs:DescribeLogGroups` | 查找 WAF 日志组 | 无（只读） |

### Athena（有限写入）

| 权限 | 用途 | 生产环境影响 |
|---|---|---|
| `athena:StartQueryExecution` | 在 S3 WAF 日志上运行 SQL 查询 | **见下方说明** |
| `athena:GetQueryExecution` | 检查查询状态 | 无（只读） |
| `athena:GetQueryResults` | 获取查询结果 | 无（只读） |

**Athena 写入影响：** Athena 查询本身是只读的（SELECT）。Agent 还会创建临时表（CREATE TABLE）用于分区投影——见下方 Glue 部分。

### S3（只读）

| 权限 | 用途 | 生产环境影响 |
|---|---|---|
| `s3:GetObject` | 从 S3 读取 WAF 日志文件 | 无（只读） |
| `s3:ListBucket` | 发现日志文件路径和分区结构 | 无（只读） |

### Firehose（只读）

| 权限 | 用途 | 生产环境影响 |
|---|---|---|
| `firehose:DescribeDeliveryStream` | 发现基于 Firehose 的 WAF 日志的 S3 投递路径 | 无（只读） |

### Glue 数据目录（有限写入）

| 权限 | 用途 | 生产环境影响 |
|---|---|---|
| `glue:GetTable` | 查找现有的 WAF 日志 Athena 表 | 无（只读） |
| `glue:GetDatabase` | 检查数据库是否存在 | 无（只读） |
| `glue:CreateDatabase` | 创建 `waf_agent_temp` 数据库（如不存在） | **创建一个新的空数据库。** 不会触碰现有数据库。 |
| `glue:CreateTable` | 创建带分区投影的临时表 | **仅在 `waf_agent_temp` 数据库中创建表。** 不会修改现有表。 |
| `glue:DeleteTable` | 会话结束时清理临时表 | **仅删除 Agent 自己创建的表**（在 `waf_agent_temp` 数据库中）。 |

**Glue 安全保证：**
- Agent 只在专用的 `waf_agent_temp` 数据库中创建表
- 会话结束时自动删除表（SIGTERM 处理器）
- 如果清理失败（如容器被强制终止），`waf_agent_temp` 中的孤立表可以安全手动删除
- Agent 永远不会修改其他数据库中的表

### Bedrock（模型调用）

| 权限 | 用途 | 生产环境影响 |
|---|---|---|
| `bedrock:InvokeModel` | 调用 LLM（Claude）进行推理 | 无（调用 Bedrock 服务的 API） |
| `bedrock:InvokeModelWithResponseStream` | 流式 LLM 响应 | 无（调用 Bedrock 服务的 API） |

### ECR（容器拉取）

| 权限 | 用途 | 生产环境影响 |
|---|---|---|
| `ecr:BatchGetImage` | 拉取 Agent 容器镜像 | 无（只读） |
| `ecr:GetDownloadUrlForLayer` | 下载容器层 | 无（只读） |
| `ecr:GetAuthorizationToken` | ECR 认证 | 无（认证令牌） |

### CloudWatch 日志（Agent 自身日志）

| 权限 | 用途 | 生产环境影响 |
|---|---|---|
| `logs:CreateLogGroup` | 为 Agent 容器日志创建日志组 | 仅创建 `/aws/bedrock-agentcore/runtimes/*` 日志组 |
| `logs:CreateLogStream` | 在 Agent 日志组内创建日志流 | 仅在 Agent 自身日志组内 |
| `logs:PutLogEvents` | 写入 Agent 容器日志 | 仅在 Agent 自身日志组内 |

**注意：** 这些权限的范围限定为 `/aws/bedrock-agentcore/runtimes/*` (scoped by CloudFormation)——Agent 不能写入任何其他日志组。

## Agent 不能做什么

- ❌ 修改 WAF 规则（没有 `wafv2:UpdateWebACL`、`wafv2:CreateRule` 等）
- ❌ 删除或修改日志组（没有 `logs:DeleteLogGroup`、`logs:PutRetentionPolicy`）
- ❌ 修改 S3 对象（没有 `s3:PutObject`、`s3:DeleteObject`）
- ❌ 修改 CloudFront 分配
- ❌ 创建或修改 Firehose 投递流
- ❌ 修改现有 Glue 表或数据库（仅在 `waf_agent_temp` 中创建）
- ❌ 访问上述未列出的任何服务
