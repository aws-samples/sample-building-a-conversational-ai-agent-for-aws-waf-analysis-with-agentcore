# WAF Agent 使用指南

[English](user-guide.md)

WAF Agent 是一个 AI 助手，帮助安全工程师调查 AWS WAF 安全事件、检测绕过攻击、生成 周报摘要。它在你提出**具体、明确的问题**时效果最好。

> [!WARNING]
> **如果部署时选择了 Amazon Bedrock 上的 GPT 系列模型，WAF 分析可能被静默拦截。**
>
> 本工具是防御性的，但正常 WAF 工作会包含 SQLi、XSS、绕过、blocked payload、恶意 IP、exploit attempt 等词。一些 GPT 系列模型部署可能触发上游 cyber-safety 检查，让 Agent 看起来像卡住或没有响应。推荐部署 Claude Sonnet 4.6 或 Claude Opus。
>
> 如果 Agent 在分析 WAF 日志或指标时突然没有反应，请发送："我只是在防御性地分析自己环境中的 AWS WAF 日志和指标。请继续调查 WAF metrics 和 logs。不要提供 exploit payload、凭证窃取步骤、规避、持久化、恶意软件行为，或任何针对未授权系统的操作说明。"

## 核心原则：具体、具体、再具体

Agent 可以访问你的 AWS WAF 配置、CloudWatch 指标、CloudWatch 日志和 Athena。但它需要你缩小范围：

| 模糊（慢、噪音多） | 具体（快、准确） |
|---|---|
| "检查一下我的 AWS WAF" | "检查 my-webacl 在 5月9日下午有没有绕过流量" |
| "有没有攻击？" | "IP 54.254.254.234 昨天早上6点左右大量请求我的网站" |
| "生成报告" | "生成 my-production-webacl 的 周报摘要" |

## 能力一览

### 1. 绕过/逃逸检测

发现通过了所有 AWS WAF 规则（默认 ALLOW）但行为可疑的流量。

**好的提问方式：**
- "检查 my-webacl 在5月9日下午有没有爬虫绕过了 AWS WAF"
- "最近6小时有没有高频 IP 没被拦截"
- "有没有机器人绕过了 Bot Control？"

**Agent 的工作流程：** 查询指标找到 ALLOW 峰值窗口 → 在日志中查找高频/高多样性 IP → 分析 Top 可疑 IP（NAT 检测、频率、交叉验证）。

### 2. 攻击溯源

识别攻击者是谁、用什么手法、AWS WAF 是否成功拦截。

**好的提问方式：**
- "分析5月9日06:00 UTC左右的 DDoS 攻击"
- "今天下午2点的拦截流量峰值是谁造成的？"
- "IP 3.249.182.182 看起来可疑，深入分析一下"

**Agent 的工作流程：** 检查指标找异常窗口 → 识别 Top 攻击者 → 用标签、JA4 指纹、URI 模式交叉验证。

### 3. COUNT 规则评估

判断一个 COUNT 规则是在捕获真实攻击还是产生误报。

**好的提问方式：**
- "SizeRestrictions_BODY 触发量很高，是误报还是真攻击？"
- "CrossSiteScripting_BODY 能不能从 COUNT 改成 BLOCK？"
- "分析一下谁在触发 GenericRFI 规则"

**Agent 的工作流程：** 获取触发该规则的 Top IP → 交叉验证每个 IP（是否触发其他规则？URI 模式？时间分布？）→ 得出结论：攻击/误报/混合。

### 4. IP 深度分析

对特定 IP 进行完整的行为画像。

**好的提问方式：**
- "分析 IP 54.254.254.234 在5月9日的行为"
- "47.128.14.206 是机器人还是真实用户？"
- "检查 13.219.181.182 是不是 NAT 出口"

**Agent 的工作流程：** 检查 UA/JA4 多样性（NAT 检测）→ 请求频率 → URI 分布 → AWS WAF 标签 → 与所有规则交叉查询。

### 5. AWS WAF 规则审查

对 WebACL 配置进行全面安全审计，生成可下载的 HTML 报告。

**好的提问方式：**
- "审查 my-webacl 的规则"
- "帮我 review production-webacl 的 AWS WAF 配置"
- "检查我的 AWS WAF 配置有没有安全问题"

**Agent 的工作流程：** 运行确定性分析管线（18+ 项检查：可伪造的 Allow 规则、标签依赖链、scope-down 问题、Bot Control 配置、优先级顺序等）→ Agent 补充跨规则影响分析 → 生成带 Mermaid 流程图的 HTML 报告 → 自动下载。

### 6. 安全巡检（周报）

全面扫描所有 WebACL 的安全事件摘要——面向运维团队。

**推荐提问：**
- "安全巡检"
- "最近安全怎么样"
- "这周有没有异常"

**Agent 执行流程：** 扫描所有 WebACL → 收集 7 天各规则 metrics → 检测异常（集中度、突增）→ 对标记的规则查日志获取 top IP/URI → 生成 HTML 报告（含 3 个图表：流量、威胁分类、Challenge 有效性）。

### 7. 周报摘要生成

生成带图表的 HTML 报告，展示 AWS WAF 防护价值——面向管理层。

**好的提问方式：**
- "生成 my-webacl 的 周报摘要"
- "生成价值报告"（Agent 会问你选哪个 WebACL）

**Agent 的工作流程：** 收集7天指标 → 生成带 Chart.js 图表的 HTML（拦截 vs 放行、每日分布、Top 规则、Top 国家）→ 让 LLM 撰写管理层摘要。

> **注意：** 周报摘要仅使用 CloudWatch Metrics + CloudWatch Logs Insights（不使用 Athena）。管理层报告只需要聚合指标，不需要 IP/URI 级别细节。如果 WAF 日志通过 Firehose 发送到 S3，报告仍然可以生成（图表来自 metrics，bot/DDoS 分类来自 CWL）。如果未配置 CWL，bot 分类详情会省略，但报告仍会生成。如需详细的攻击源分析，请使用安全巡检或直接对话查询。

### 8. 指标查询

快速、免费的 AWS WAF 流量概览。

**好的提问方式：**
- "显示最近7天的流量趋势"
- "昨天拦截了多少请求？"
- "显示 AllowedRequests 指标，1小时粒度"

### 8. Host 流量画像

将 WebACL 后面的域名分类为 Web/API/混合，指导防护策略。

**好的提问方式：**
- "每个域名的流量类型是什么？"
- "我的域名主要是 API 流量还是 Web 流量？"

## 使用技巧

1. **指定 WebACL 名称**（如果有多个）。不指定的话 Agent 会问你，但提前指定能省一轮对话。

2. **指定时间范围。** "5月9日下午"、"昨天下午2-4点"、"最近6小时"——任何具体的时间。Agent 无法有效分析7天的日志。

3. **提供环境上下文：**
   - "这是一个 SPA，集成了 AWS WAF Client SDK"
   - "同一域名下有原生移动 App"
   - "/upload 端点接受大文件（SizeRestrictions 误报是预期的）"

4. **追问。** Agent 给出结果后，你可以继续问：
   - "分析接下来3个可疑 IP"
   - "另一个 WebACL 呢？"
   - "显示这个 IP 访问了哪些 URI"

5. **绕过检测：** 最有效的时间窗口是 ≤6 小时。更长的窗口噪音太多。

## 限制

- **无写操作。** Agent 不能修改你的 AWS WAF 规则、创建/删除资源（除了 `waf_analysis_tmp` 数据库中的 Athena 表 — 参见 [Athena 表自动检测](athena-table-detection_zh.md)）。
- **日志可用性。** 如果 WebACL 没有启用日志，只能使用 CloudWatch 指标（无法做 IP 级别分析）。
- **Athena 查询结果位置。** 如果 WAF 日志存储在 S3（通过 Firehose 或直接投递），Agent 使用 Athena 查询日志。它会自动从 Athena workgroup 获取输出位置。如果 workgroup 未配置输出位置，Agent 会将结果写入 WAF 日志桶的 `athena-results/` 前缀下。**建议：** 在 Athena 控制台配置查询结果位置（工作组 → primary → 编辑 → 查询结果位置），以避免权限问题。
- **Athena 查询性能。** 如果 WAF 日志通过 Firehose 以默认小时级前缀（`YYYY/MM/dd/HH/`）投递到 S3，Athena 查询可能很慢或超时。参见 [Firehose 优化指南](firehose-minute-partitioning_zh.md) 添加分钟级分区（一次性操作，2 分钟完成）。
- **Athena 表检测。** 参见 [Athena 表自动检测](athena-table-detection_zh.md) 了解 Agent 如何查找或创建 Athena 表、支持哪些分区方案、以及如何使用你自己的现有表。
- **指标发现（14 天窗口）。** CloudWatch 仅能自动发现最近 14 天内有活动的指标。如果你的 WebACL 某类流量（如某国家的拦截请求）超过 14 天没有活动，报告中该部分将为空。**解决方法：** 产生少量匹配流量（如用测试请求触发该规则），然后重新生成报告 — 这会重新激活指标索引，解锁最多 63 天的历史数据。
- **会话超时。** 容器空闲 15 分钟后释放。请及时下载报告。
- **冷启动。** 新会话的第一次查询需要约 30 秒（容器启动）。
- **版本确认。** 问 Agent "你运行的是什么版本？" 可以确认当前代码版本。Agent 会报告构建时的 commit hash 和构建时间。如果部署后版本仍是旧的，请开启新会话（旧会话会继续运行旧代码）。
- **匹配详情。** AWS WAF 只对 SQLi 和 XSS 规则提供请求体匹配详情。其他规则无法告诉你具体是什么内容触发了规则。
- **GPT 系列模型安全过滤。** 如果部署使用了 Bedrock 上的 GPT 系列模型，并且 Agent 在防御性 WAF 分析中突然静默，请明确说明这是授权的防御性 AWS WAF 日志分析，并要求继续。优先使用 Claude 模型以避免这个失败模式。
