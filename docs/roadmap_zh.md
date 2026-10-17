# 路线图

[English](roadmap.md) | 中文

从现在起我们计划支持什么、修复什么。agent 现在能做什么、边界在哪，见[能力说明](capabilities_zh.md)和[已知局限](limitations_zh.md)。

每组里大致按我们打算动手的顺序排列，顺序可能会变。

## 支持范围：哪种 WebACL，哪个账号

还不完全支持的三种情况。REGIONAL WebACL 一选就被拒绝、并说明原因；跨账号日志桶、以及你放在 JSON 日志旁边前缀里的 Parquet 表，都失败得不够利索，所以[已知局限](limitations_zh.md#还不支持)逐条写明，README 也在你部署之前先提醒。

- REGIONAL WebACL（ALB、API Gateway、AppSync）分析得和 CloudFront 一样完整；如今一选就被拒绝，因为它标签、攻击、Bot、国家、Anti-DDoS 相关的段落会全部读成 0
- 读取投递到另一个 AWS 账号 S3 桶里的 WAF 日志，不再要求 WebACL、指标、日志都在同一个账号
- 读取你放在 JSON 日志旁边前缀里的 Parquet 副本；如今只有直接投到日志目的地本身的 Parquet 能读，因为 agent 按日志路径匹配表，旁边那份副本在路径之下，又没有按名字或路径指定表的办法

## 长时间查询

- 停止按钮真正取消 Athena 查询，而不只是断开浏览器请求

## 分析能力

- 网络（ASN）集中度作为分析维度，与已经支持的国家、referer 维度并列
- 巡检报告里跨 WebACL 的汇总
- 敏感文件探测单独做成一项调查：按文件名请求 `.env`、`.git/config` 或备份文件的流量。注入调查现在不再把它算进去，而且有好几种常见文件根本没有托管规则能匹配
- bypass 调查和 token 复用调查读 Bot Control 的 token 来源标签（`token_provenance:ip_category_mismatch:<level>`，targeted 级别，7.0 版起）。token 在数据中心 IP 上拿到、拿到住宅 IP 上用，正是这两项调查要找的
- Bot Control 的设备 ID 标签（`device_id:<id>`）等打这个标签的 Android SDK 发布后用来分组，并定下这个 ID 交给模型、写进报告之前要不要脱敏

## 安全与隐私

- 针对提示注入的自动化测试
