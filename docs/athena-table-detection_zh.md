# Athena 表自动检测

[English](athena-table-detection.md) | 中文

## 工作原理

需要查询存在 S3 上的 WAF 日志时，Agent 按这个顺序来：

1. **解析 S3 路径** — 从 WAF 日志配置的 ARN 推出来
2. **搜索 Glue Data Catalog** — 找一张 `LOCATION` 覆盖该路径、带有 WAF 日志列（`action`、`httprequest`）、并且用 `date` 类型 partition projection 按**一个**时间列分区的表。列叫什么无所谓：`log_time`、`datehour`、`dt` 都行
3. **找到了** — 拿表里声明的分区配置跟 S3 上真实的目录结构对一遍，然后复用
4. **没找到** — 在 `waf_analysis_tmp` 库里自动建一张

每次日志查询都会说明用了哪张表，以及如果跳过了某张表，为什么跳过。所以"Agent 自己建了一张表"这个结果，永远附带它没用你那张的原因。

### 自动自愈

Agent 自己那张临时表（`waf_analysis_tmp.waf_logs_{webacl}`）在位置失效时会自愈。典型场景是把某个 WebACL 的日志投递从 **Vended Logs**（`AWSLogs/.../WAFLogs/{scope}/{webacl}/`）换成 **Firehose**（自定义的桶根前缀）。旧表还指着原来那个已经空了的路径，于是查询返回 0 行，而 CloudWatch 指标照样显示有流量。

下一次查询时，Agent 会拿现有表的 `LOCATION` 跟新解析出的 S3 路径比：

- **位置一致** → 原样复用，不重建，无中断
- **位置不同** → 删掉临时表，在正确路径上重建

这一步是自动的，不需要你手动 `DROP TABLE`。（删除 external 表不会碰底层的 S3 数据。）

### 多 WebACL 共用桶

如果多个 WebACL 把日志投到**同一个** Firehose 桶前缀，解析出来的表位置就是共享的，不加处理会把各个 WebACL 的记录混在一起。Agent 发现表位置并非当前 WebACL 专属时，会给每个日志查询自动加上 `webaclid` 过滤，让结果只反映正在调查的那个 WebACL。基于指标的数字本来就按 CloudWatch 维度隔离，不受影响。

## Partition Projection（非 Hive 分区）

Agent 用的是 **Athena partition projection**，也就是 [Athena 文档：Partition Projection](https://docs.aws.amazon.com/athena/latest/ug/partition-projection.html) 里那套机制，**不**用 Hive 风格的分区（`ALTER TABLE ADD PARTITION`）。

Agent 建的表带这些 TBLPROPERTIES：

```
'projection.enabled'                = 'true'
'projection.log_time.type'          = 'date'
'projection.log_time.format'        = 'yyyy/MM/dd/HH/mm'   （或 yyyy/MM/dd/HH）
'projection.log_time.interval'      = '1'
'projection.log_time.interval.unit' = 'minutes'             （或 hours）
'projection.log_time.range'         = '2026/01/01/00/00,NOW'（起点跟着数据走）
'storage.location.template'         = 's3://bucket/path/${log_time}'
```

interval 恒为 `1`。Firehose 用缓冲区刷盘那一刻的分钟数给对象命名，所以分钟目录是任意值，目录之间的间隔推不出任何有意义的东西。早先的版本会去推断 interval，可能推出一个只投影每 N 分钟的值，夹在中间的对象就永远读不到。

**range 的起点跟着你的数据走**，走一遍桶找出来，再下取整到那个月的 1 号。以前是固定的 `2020/01/01`，大约 346 万个分钟分区。Athena 会先把声明的整个 range 展开，然后才套你的 `WHERE`，所以规划时间跟着表属性里的 range 走，跟你问的窗口没关系。在一个小测试桶上量过：五张表只差这一个值，同一个 5 分钟查询，起点写 2020 时规划要 4.4 到 5.0 秒，起点往前推两个月只要 0.19 到 0.25 秒，两边扫描的字节数完全一样。另外 Athena [单次扫描读不了超过 1,000,000 个分区](https://docs.aws.amazon.com/athena/latest/ug/partition-projection.html)，光是 2020 这个起点就超了。

### 桶里两种格式并存

Firehose 的前缀从小时级改成分钟级之后，桶里切换之前是小时目录，之后是分钟目录。`projection.<col>.format` 只能填一个值，没有哪张表能同时描述两种。

Agent 声明最新那种，也就是分钟级，剩下的写在查询输出的 `TABLE:` 块里：分钟级从哪天开始，桶里最早的数据是哪天。这两个日期之间的数据都在小时目录里，任何分钟级的表都读不到。Athena 对这些路径返回零行而且不报错，所以 Agent 会提前说出来，不让一个空结果替它解释。

投影起点下取整到切换那个月的 1 号，这样它永远不会晚于你的分钟级数据。切换的**那一天**是尽力而为：它在那个月里搜出来，前提是格式只换过一次，所以一个反复切换的桶可能报得偏晚一点。旧的那段怎么读，见[小时级与分钟级分区](hourly-vs-minute-partitioning_zh.md)。

这意味着：

- 不需要管理分区，新的时间段自动包含进来
- `SHOW PARTITIONS` 返回空，投影表本来如此
- 不需要 Glue Crawler
- 查询性能跟手工建的 partition projection 表一样

## 现有表检测

Agent 会搜索**所有 Glue 数据库**，带分页，找 `LOCATION` 覆盖解析出的 S3 日志路径的表。

### 检测成功的条件

- 从 WAF 日志配置解析出的 S3 路径，就是你的表的 `LOCATION`，或者在它之下。比较按路径边界做，所以 `s3://b/waf-logs` 上的表不会去认领 `s3://b/waf-logs-prod`
- 撑起每条查询的三列都在，类型也用得上：`timestamp` 是整型的 epoch 毫秒，`action` 是字符串，`httprequest` 是 struct 并且带 `clientip` 和 `uri` 两个字段。列名按小写精确匹配
- `webaclid` 是字符串，但**只在**表的位置盖着多个 WebACL 时才要。那种表上每条查询都要加一道 `webaclid` 过滤，把别的 WebACL 的行挡在外面。位置里已经写明某一个 WebACL 的表，查询根本不提这一列，也就不要求它
- 其余的 WAF 日志列都是可选的。缺一个丢的是一项功能，不是整张表，下一节说会怎么告诉你
- 表**只有一个**分区列，用 `date` 类型的 partition projection。列名随意
- 该列的 `projection.<col>.format` 是 `yyyy/MM/dd`、`yyyy/MM/dd/HH` 或 `yyyy/MM/dd/HH/mm`，分隔符随便
- 该列的 `projection.<col>.range` 上界是 `NOW` 或者一个将来的日期

### 老版本的日志 schema 照用，但会提示你

WAF 日志里多数列只服务一项功能，不是每条查询都要，缺了就不拒表。`terminatingruleid`、`labels`、`nonterminatingmatchingrules`、`rulegrouplist`、`ja4fingerprint`、`challengeresponse`、`captcharesponse` 缺哪个，表照用，查询输出里多一行，把每个缺的列和它本来能回答什么写在一起。类型声明错了、或者少了查询要读的字段，报法一样，因为丢的查询是同一批。

AWS WAF 这些年一直在往日志里加列。`labels`、`ja4fingerprint` 还不存在的年代建的 Glue 表，今天照样读得动当前的日志，JSON SerDe 会忽略表里没声明的字段。这种表拒掉，你亏得比看一行提示多得多：在它上面 bypass 扫描的 JA4 聚合会失败，扫描其余部分照样出结果。把缺的列补进表里，下次选 WebACL 时 Agent 就认了。

### 多张表都合格时选哪张

合格的表可能不止一张。Agent 优先选**你自己维护的表**，把它自己那张临时表排在最后；同一组之内再比谁的位置更具体。

光比具体程度是不行的：Agent 自己那张表就建在解析出的路径上，位置永远最具体，那样你的表永远轮不到。

两张同样具体、分处不同数据库的表打平时，按字母序定。选中哪张一定会写在查询输出里，所以这种歧义是看得见的，不会闷着。

### 检测可能失败的场景

| 场景 | 失败原因 | 应对 |
|---|---|---|
| Firehose 前缀全是动态表达式 | 解析出的路径只是桶根，跟位置更具体的用户表对不上 | Agent 自己那张临时表会自愈（在解析出的路径上删掉重建）；位置更深的*用户表*仍然匹配不上 |
| 三个必需列的列名不一样 | `timestamp`、`action`、`httprequest` 叫了别的名字（如 `http_request`、`event_time`） | 改回来，Agent 的 SQL 就是按这些名字写的。*可选*列改了名不致命，只是丢掉那一列的功能 |
| 必需的列类型不对 | `timestamp` 声明成 `string`，没法跟 epoch 毫秒比大小；`httprequest` 被拍平成一堆标量列，就没有 `clientip` 字段可读 | 改列的声明。拒绝信息里写清了是哪一列、你给的什么类型、谁要读它 |
| integer 或 enum 类型的 partition projection | 分区裁剪是把分区值跟渲染出的时间戳比，只有 `date` 类型能这么比 | 把该列重建成 `projection.<col>.type=date` |
| 非投影的 Hive 分区 | Agent 从不执行 `ALTER TABLE ADD PARTITION`，看不到这类分区 | 把表改成 partition projection |
| 分区键超过一个 | 查询只按单个时间列做裁剪 | 只用一个投影的时间列 |
| 声明的分区比 S3 上实际的更细 | 声明成 `yyyy/MM/dd/HH/mm` 而目录只到小时，投影出来的路径根本不存在，Athena 把这种情况报成 0 行 | 把声明的格式改成跟数据一致。声明得比数据**粗**没问题：Athena 会往目录下面递归扫 |

## 按投递方式解析 S3 路径

### S3 直接投递（Vended Logs）

- WAF 配置里的 ARN：`arn:aws:s3:::aws-waf-logs-{bucket}`
- 解析出的路径：`s3://{bucket}/AWSLogs/{account}/WAFLogs/{region}/{webacl}/`
- 分区格式：固定 `yyyy/MM/dd/HH/mm`，5 分钟间隔，由 AWS 管理

### Firehose 投递

- WAF 配置里的 ARN：`arn:aws:firehose:{region}:{account}:deliverystream/aws-waf-logs-{name}`
- 解析出的路径：调 `DescribeDeliveryStream`，取出 S3 桶加静态前缀（`!{timestamp:...}` 这类动态表达式会被剥掉）
- 分区格式：从 S3 目录结构探测，小时级（`yyyy/MM/dd/HH`）或分钟级（`yyyy/MM/dd/HH/mm`）

**注意：** 如果你的 Firehose 用的是小时级分区（默认就是），Agent 会拒绝日志明细查询，因为在生产流量上会超时。发生时 Agent 会从知识库取出修复步骤，当场向你解释成因和那一次性的 Firehose 改动。同样的步骤见 [Firehose 优化指南](firehose-minute-partitioning_zh.md)。

## 分区路径的时区

分区**目录名**编码的是一个墙上时间（如 `.../2026/07/27/12/16`），Agent 必须知道那个时钟属于哪个时区，才能裁剪到正确的目录。记录自身的 `timestamp` 字段永远是 UTC epoch，并且总是被精确过滤，所以时区只影响**Athena 扫哪些目录**。

- **AWS vended logs（S3 直接投递）** 一律按 **UTC** 分区。不用做什么，这就是默认假设。
- **Firehose** 按它的 **`CustomTimeZone`** 设置来求值 `!{timestamp:...}` 前缀，默认 UTC。Agent 会从 `DescribeDeliveryStream` 读出 `CustomTimeZone`，自动按那个时区裁剪。
- **自建 ETL** 写出本地时间目录的情况探测不到，因为没有 Firehose 配置可读。把 Agent 运行时的 `WAF_AGENT_PARTITION_TZ` 环境变量设成 IANA 名称（`America/New_York`，识别夏令时）或固定偏移（`-04:00`）。
- **运维覆盖：** `WAF_AGENT_PARTITION_TZ` 也高于 Firehose 探测结果，所以探测出的时区不对时它同样是逃生口。

优先级：`WAF_AGENT_PARTITION_TZ` 环境变量 → 探测到的 Firehose `CustomTimeZone` → UTC。

**时区不对的症状：** 日志查询返回 **0 行，而 CloudWatch 指标显示有流量**。如果你的路径是本地时间而 Agent 按 UTC 算，它就会去找错那个小时的目录。设好 `WAF_AGENT_PARTITION_TZ` 然后重新部署。

## Agent 创建的表

- 数据库：`waf_analysis_tmp`，不存在则自动创建
- 表名：`waf_logs_{webacl_name}`，特殊字符替换成下划线
- 分区列：`log_time`，string 类型，partition projection
- 这些表是**永久的**，跨会话复用，没有重建开销。只有在位置失效时才会重建，见上面的"自动自愈"
- 它们是只读的 external 表，指向你已有的 S3 日志数据，不复制数据
- 可以安全删除：`DROP TABLE waf_analysis_tmp.waf_logs_xxx` 或 `DROP DATABASE waf_analysis_tmp CASCADE`

> **说明：** 只有在你的表一张都不合格时，Agent 才会自己建。真发生了，查询输出会说是哪一项检查没过。两张表指向同一份 S3 数据，不重复也不冲突；查完之后你可以两张都留着，也可以把 Agent 那张删掉。

## 已知限制

1. **没法在对话里指定表。** 你不能跟 Agent 说"用我的 X 表、在 Y 库里"。它从你的日志配置解析表，所以想让它用哪张，办法是让那张表符合条件。
2. **小时级及更粗的分区，日志明细查询仍然被拒。** 检测这一步接受它们，然后查询在扫描成本上被拦下。今天只有分钟级的表能跑明细查询。
3. **换过格式的桶，切换之前的日志读不到。** Agent 读分钟级那段，并且告诉你它从哪天开始。要读小时级那段，得你自己建一张表，因为小时级的明细查询还被拒着，Agent 就不会去建小时级的表。

4. **Vended Logs 上的自定义 S3 前缀是看不见的。** 如果你是通过 API（不是控制台）配的自定义 key 前缀，Agent 可能解析不出正确路径，因为 `GetLoggingConfiguration` 不返回这个前缀。

5. **schema 校验看的是你的声明，不是你的数据。** 它拿 Glue 目录里的列名和类型跟查询需要的比。声明得没毛病、底下的对象跟声明不一致，这种表照样过得了绑定，到查询时才失败。不真读一个对象出来，这两种情况分不出来。
