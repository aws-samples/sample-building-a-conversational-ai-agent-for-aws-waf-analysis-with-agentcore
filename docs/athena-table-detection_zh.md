# Athena 表自动检测

[English](athena-table-detection.md) | 中文

## 工作原理

当 Agent 需要查询存储在 S3 中的 WAF 日志时，按以下顺序执行：

1. **解析 S3 路径** — 从 WAF 日志配置的 ARN 推导出 S3 路径
2. **搜索 Glue Data Catalog** — 查找与 S3 路径匹配且包含 WAF 日志列（`action`、`httprequest`）的现有表
3. **如果找到** — 验证表的分区格式和间隔是否与 S3 实际目录结构一致，一致则复用
4. **如果未找到** — 在 `waf_analysis_tmp` 数据库中自动创建表

## Partition Projection（非 Hive 分区）

Agent 使用 **Athena partition projection** — 与 [Athena 文档: Partition Projection](https://docs.aws.amazon.com/athena/latest/ug/partition-projection.html) 中描述的机制完全相同。**不使用** Hive 风格的分区（`ALTER TABLE ADD PARTITION`）。

Agent 创建的表包含以下 TBLPROPERTIES：

```
'projection.enabled'                = 'true'
'projection.log_time.type'          = 'date'
'projection.log_time.format'        = 'yyyy/MM/dd/HH/mm'   （或 yyyy/MM/dd/HH）
'projection.log_time.interval'      = '5'                   （或 1）
'projection.log_time.interval.unit' = 'minutes'             （或 hours）
'storage.location.template'         = 's3://bucket/path/${log_time}'
```

这意味着：
- 无需分区管理 — 新的时间段自动纳入
- `SHOW PARTITIONS` 返回空结果（partition projection 表的正常行为）
- 无需 Glue Crawler
- 查询性能与手动创建的 partition projection 表一致

## 现有表检测

Agent 搜索 **所有 Glue 数据库**（不仅是 `waf_analysis_tmp`），查找 `LOCATION` 是已解析 S3 路径前缀的表。表必须同时包含 `action` 和 `httprequest` 列才会被识别。

### 检测成功的条件

- 从 WAF 日志配置解析出的 S3 路径**以你的表的 `LOCATION` 开头**（即表的 LOCATION 等于或是解析路径的父前缀）
- 表包含 `action` 和 `httprequest` 两个列
- 分区间隔与 S3 实际目录结构一致

### 检测可能失败的场景

| 场景 | 失败原因 | 解决方法 |
|------|---------|---------|
| Firehose 前缀完全由动态表达式组成 | 解析出的路径仅为桶根目录，无法匹配表更具体的 LOCATION | 参见下方"已知限制" |
| 数据库中表数量超过 100 张 | 分页尚未实现 | 将 WAF 表放在较小的数据库中，或放在 `waf_analysis_tmp` |
| 自定义列名 | `httprequest` 使用了其他名称（如 `http_request`） | 将列名改为 `httprequest`，或等待未来的"指定表"功能 |
| 不同的分区列名 | 你的表使用 `datehour` 而非 `log_time` | 当前不支持 — Agent 的查询在 WHERE 子句中使用 `log_time` |

## 按投递方式解析 S3 路径

### S3 直接投递（Vended Logs）

- WAF 配置 ARN：`arn:aws:s3:::aws-waf-logs-{bucket}`
- 解析路径：`s3://{bucket}/AWSLogs/{account}/WAFLogs/{region}/{webacl}/`
- 分区格式：固定为 `yyyy/MM/dd/HH/mm`，5 分钟间隔（由 AWS 管理）

### Firehose 投递

- WAF 配置 ARN：`arn:aws:firehose:{region}:{account}:deliverystream/aws-waf-logs-{name}`
- 解析路径：调用 `DescribeDeliveryStream` → 提取 S3 桶 + 静态前缀（动态表达式如 `!{timestamp:...}` 会被去除）
- 分区格式：从 S3 目录结构检测 — 小时级（`yyyy/MM/dd/HH`）或分钟级（`yyyy/MM/dd/HH/mm`）

**重要：** 如果你的 Firehose 使用小时级分区（默认设置），Agent 会阻止查询，因为在生产流量下查询会超时。参见 [Firehose 优化指南](firehose-minute-partitioning_zh.md) 解决此问题。

## Agent 创建的表

- 数据库：`waf_analysis_tmp`（不存在时自动创建）
- 表名：`waf_logs_{webacl名称}`（特殊字符替换为下划线）
- 分区列：`log_time`（string 类型，partition projection）
- 这些表是**永久的**，跨会话复用 — 无重复创建开销
- 它们是指向现有 S3 日志数据的只读外部表（不复制数据）
- 可安全删除：`DROP TABLE waf_analysis_tmp.waf_logs_xxx` 或 `DROP DATABASE waf_analysis_tmp CASCADE`

> **注意：** 如果你已有自己的 partition projection 表但使用了不同的分区列名，Agent 会在旁边创建自己的表。两张表指向相同的 S3 数据 — 无重复、无冲突。你可以同时保留两张表，或在调查结束后删除 Agent 的表。

## 已知限制

1. **分区列名硬编码为 `log_time`。** 如果你的现有表使用其他分区列（如 `datehour`、`dt`），Agent 无法复用它 — 会在旁边创建自己的表。

2. **暂不支持"指定表"配置。** 目前无法告诉 Agent "使用数据库 Y 中的表 X"。它始终自动检测或创建。

3. **Glue 分页未实现。** 如果某个数据库中表数量超过 100 张，检测可能遗漏。

4. **Vended Logs 的自定义 S3 前缀不可见。** 如果通过 API（非控制台）配置了自定义前缀，Agent 可能无法解析正确路径，因为 `GetLoggingConfiguration` 不返回前缀信息。
