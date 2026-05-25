# 优化 Firehose 日志投递以提升 WAF Agent 查询性能

[English](firehose-minute-partitioning.md) | 中文

## 问题

如果您的 AWS WAF 日志通过 Amazon Data Firehose 以**默认前缀**（`YYYY/MM/dd/HH/`）投递到 S3，Athena 每次查询都会扫描整个小时的数据——即使您只需要 5 分钟的日志。对于高流量 WebACL（>10K 请求/小时），这会导致：

- 查询超时（>5 分钟）
- 调查流程缓慢
- Athena 扫描费用增加

## 解决方案：添加分钟级分区

将 Firehose S3 前缀从小时级改为分钟级。这是一次性的在线配置变更——无需重建 stream、无数据丢失、无停机。

### 变更前（默认）
```
s3://bucket/2026/05/25/14/  ← 整个小时的文件都在一个目录
```

### 变更后（分钟级）
```
s3://bucket/2026/05/25/14/00/  ← 仅 00-04 分钟的文件
s3://bucket/2026/05/25/14/05/  ← 仅 05-09 分钟的文件
...
```

Athena 现在只扫描相关的几分钟数据——**查询速度提升 10-60 倍**。

## 操作步骤

### 方式 A：AWS 控制台

1. 打开 [Amazon Data Firehose 控制台](https://console.aws.amazon.com/firehose/)
2. 选择您的 `aws-waf-logs-*` 投递流
3. 点击 S3 目标配置的 **编辑**
4. 将 **S3 存储桶前缀** 改为：
   ```
   !{timestamp:yyyy/MM/dd/HH/mm/}
   ```
5. 将 **S3 存储桶错误输出前缀** 设为：
   ```
   errors/!{firehose:error-output-type}/!{timestamp:yyyy/MM/dd/HH/}
   ```
6. 保存

### 方式 B：AWS CLI

```bash
# 第 1 步：获取当前 stream 版本和目标 ID
STREAM_NAME="aws-waf-logs-your-stream-name"

VERSION=$(aws firehose describe-delivery-stream \
  --delivery-stream-name $STREAM_NAME \
  --query 'DeliveryStreamDescription.VersionId' --output text)

DEST_ID=$(aws firehose describe-delivery-stream \
  --delivery-stream-name $STREAM_NAME \
  --query 'DeliveryStreamDescription.Destinations[0].DestinationId' --output text)

# 第 2 步：更新前缀
aws firehose update-destination \
  --delivery-stream-name $STREAM_NAME \
  --current-delivery-stream-version-id $VERSION \
  --destination-id $DEST_ID \
  --extended-s3-destination-update '{
    "Prefix": "!{timestamp:yyyy/MM/dd/HH/mm/}",
    "ErrorOutputPrefix": "errors/!{firehose:error-output-type}/!{timestamp:yyyy/MM/dd/HH/}"
  }'
```

### 方式 C：保留 Account/WebACL 路径（多 WebACL 推荐）

如果多个 WebACL 共用同一个 Firehose stream，建议硬编码标识符：

```bash
aws firehose update-destination \
  --delivery-stream-name $STREAM_NAME \
  --current-delivery-stream-version-id $VERSION \
  --destination-id $DEST_ID \
  --extended-s3-destination-update '{
    "Prefix": "AWSLogs/您的账号ID/WAFLogs/您的区域/您的WebACL名称/!{timestamp:yyyy/MM/dd/HH/mm/}",
    "ErrorOutputPrefix": "errors/!{firehose:error-output-type}/!{timestamp:yyyy/MM/dd/HH/}"
  }'
```

这会产生与 WAF 原生 S3 投递（Vended Logs）相同的路径结构。

## 重要说明

- **无停机**：更新期间 stream 保持活跃，几分钟内生效
- **旧数据不受影响**：已有文件保持原位，仅新数据使用新前缀
- **WAF Agent 自动适配**：前缀变更后，WAF Agent 会在下次查询时自动检测新分区结构并重建 Athena 表
- **无额外费用**：时间戳前缀是 Firehose 标准功能，不产生额外费用（与 Dynamic Partitioning 不同，后者按 GB 收费）
- **ErrorOutputPrefix 必填**：当 Prefix 包含 `!{timestamp:...}` 表达式时，必须同时设置 ErrorOutputPrefix 并包含 `!{firehose:error-output-type}`，否则 API 会返回验证错误
- **Buffer interval 建议**：考虑将 buffer interval 从默认 300s 降低到 60s，以提升日志实时性。这会略微增加 S3 PUT 费用，但能改善日志新鲜度

## 语法参考

| 表达式 | 含义 | 输出示例 |
|---|---|---|
| `!{timestamp:yyyy}` | 年（4 位） | 2026 |
| `!{timestamp:MM}` | 月（2 位，大写） | 05 |
| `!{timestamp:dd}` | 日（2 位） | 25 |
| `!{timestamp:HH}` | 时（24 小时制，2 位） | 14 |
| `!{timestamp:mm}` | 分（2 位，小写） | 30 |

⚠️ 大小写敏感：`MM` = 月份，`mm` = 分钟。如果用 `mm` 表示月份会产生错误路径。

## 验证

更新后等待几分钟让新数据到达，然后检查 S3：

```bash
aws s3 ls s3://your-bucket/ --recursive | tail -5
```

您应该能看到带分钟级目录的路径（如 `.../14/30/...`）。
