# 数据隐私

[English](data-privacy.md)

## 数据存储位置

所有数据都保留在**你的 AWS 账户**内。不会发送到外部服务。

| 数据 | 存储 | 保留期 |
|------|------|--------|
| 对话消息 | DynamoDB（你的账户） | 30 天 TTL（自动删除） |
| 跨会话记忆（事实、偏好） | AgentCore Memory（托管服务，你的账户） | STM：30 天过期。LTM：手动删除前一直保留。 |
| AWS WAF 日志 | CloudWatch Logs 或 S3（你现有的配置） | 只读访问，不会修改 |

## 用户隔离

每个用户只能访问自己的会话历史。隔离在服务端强制执行：

- DynamoDB 分区键 = 用户邮箱（由后端从 JWT 提取）
- 后端解码 JWT token 获取用户身份——不信任客户端提供的 header
- 没有 API 可以查询其他用户的会话

## 管理员可见性

拥有 DynamoDB 控制台/API 权限的 AWS 账户管理员可以查看所有用户的会话历史。这符合 AWS 共享责任模型——数据在你的账户中，由你控制。

## 更强的隔离（可选）

如果环境要求对每个用户的数据进行静态加密：

- 使用 [AWS Database Encryption SDK](https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/what-is-database-encryption-sdk.html) 对 DynamoDB 项目进行客户端加密
- 每个用户的数据可以用单独的 KMS 密钥加密，即使 DynamoDB 管理员也无法读取

默认未实现——对于 5-20 人的内部工具，运维开销大于收益。如果部署给更大的团队或受监管环境，可以考虑。

## 数据删除

- **自动**：所有 DynamoDB 项目 30 天 TTL
- **用户发起**：侧边栏每个会话的删除按钮
- **完全清除**：删除 DynamoDB 表或 CloudFormation stack
