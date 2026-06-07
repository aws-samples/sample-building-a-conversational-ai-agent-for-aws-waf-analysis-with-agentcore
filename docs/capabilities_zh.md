# 功能说明

## 主动检查（不需要具体问题）

> "最近情况怎么样？有没有异常？"

Agent 检查过去 14 天的流量趋势、规则有效性、Bot 活动和攻击模式 — 基于 CloudWatch Metrics，快速且免费。

> "最近 1 小时有没有误杀？帮我扫描一下"

Agent 扫描 BLOCK 日志中同时有大量 ALLOW 流量的 IP — 可能是误杀，值得进一步调查。

> "昨天下午 2 点到 3 点，有没有爬虫绕过了我的 WAF？"

Agent 扫描 ALLOW 流量中的异常：高频 IP、异常 URI 多样性、自动化 User-Agent、数据中心 IP 无 bot 标签。深入调查某个 IP 时，还会展示它在 ALLOW 流量中发送的 query string——被放行的攻击式 payload 是直接的绕过信号。

> "帮我评估 COUNT 规则，能不能转 Block？"

Agent 盘点所有 COUNT 规则，按风险分级，找到流量高峰时段，分析客户端行为，判断是否可以安全切换。对每条规则还会展示触发它的请求内容（已脱敏），让你能凭真实 payload 区分真攻击和误杀。

> "做个今天的安全巡检"

一键生成 HTML 报告：规则有效性、异常检测、周环比趋势、Bot 活动概览。

> "帮我审查 WAF 规则"

全面安全审计：检查过宽的 Allow 规则、缺失的防护、标签依赖问题、配置反模式。

## 事件调查（用户有具体问题）

> "我的客户说被拦截了，大概今天上午 10 点左右"

Agent 定位拦截规则、计算该 IP 的 Allow Ratio，给出置信度评估。并展示实际命中的内容——规则的 match detail（SQLi/XSS）**以及**被检查的请求组件（query string、URI、cookie 或 headers）——让你看清请求*为什么*被标记。密钥值（cookie、auth/会话令牌）会被掩码。

> "昨天下午流量暴增 5 倍，是不是 DDoS？"

对比本周与上周指标，检查 Anti-DDoS AMR 是否触发，分类异常类型（分布式 DDoS / 爬虫 / 缓存穿透攻击）。

> "查一下 IP 203.0.113.42，最近 2 小时"

全维度画像：频率、URI 多样性、JA4 指纹、Bot 标签、Action 分布、NAT 检测，以及它发送的 top query string（密钥已脱敏）。

> "开了 Challenge 之后 API 返回 202，查一下最近 1 小时"

列出所有被 Challenge 的 URI/Method，标记不兼容的请求（非 GET、API 端点），解释 Challenge 技术要求。

> "后端日志发现了恶意请求，5月15号 14:00 左右"

Agent 在该时间窗口搜索 WAF ALLOW 日志中的可疑请求，提供候选 IP/URI 作为取证线索。但无法确认攻击是否成功 — 需要对照后端日志。

## 报告

> "生成管理层周报"

HTML 报告：流量图表、Top 规则、攻击类型、Bot 分布、管理层摘要。

> "日常运维报告"

确定性 HTML 巡检报告：规则指标、异常标记、DDoS 事件检测、Challenge 通过率。对需要关注的规则，摘要还会列出 top IP、top URI 和触发它的请求内容（已脱敏）。

## 最佳实践指导

> "Bot Control 设成 Block 安全吗？"

> "CrossSiteScripting 规则的 scope-down 怎么配？"

> "COUNT 和 EXCLUDED_AS_COUNT 有什么区别？"

Agent 搜索 AWS WAF 文档知识库，提供具体、可操作的配置建议。

## 自定义查询

> "今天上午 9 点到 10 点，哪些国家被 Block 最多？"

> "昨天下午 3 点到 4 点，XSS_BODY 规则 Block 了哪些 IP？"

> "过去 2 小时 IP 203.0.113.42 的请求频率"

Agent 支持 20+ 种预定义日志查询模板，覆盖 IP、规则、URI、标签、国家、Host 等维度。

## 能力边界

- 无法检测凭证填充或暴力破解（请求格式合法 — 建议使用 AWS WAF ATP）
- 无法判断攻击是否成功利用了漏洞（WAF 只看请求，看不到响应）
- 未启用 WAF 日志时无法分析流量
- 无法识别完美模拟真实浏览器的 Bot（合法 UA + JA4 + 正常频率）
- 日志分析建议使用事件前后 1-2 小时的窗口，最大 6 小时。窗口越短 = 结果越快 + Athena 费用越低。
- JA4 指纹分析提供结构解码（协议、TLS 版本、密码套件数量），但无法识别具体应用程序
- 展示被检查的请求内容时，密钥值（cookie、Authorization/会话令牌、API key）会被掩码，且 Agent 不会对它无法显示的值内部判断攻击。若某字段被 AWS WAF 日志的 `RedactedFields` 脱敏，该位置无法检查。详见 [数据隐私](data-privacy_zh.md)
