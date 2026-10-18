# 为什么需要 WAF Analyst？

AWS DevOps Agent 自己就能调查 AWS WAF：WebACL 配置、指标、日志它都读得到，查询也基本写得对。WAF Analyst 只做 AWS WAF 这一件事。两者回答同样的 WAF 问题时，WAF Analyst 更常得出证据撑得住的结论。差别在怎么读、怎么掂量证据，不在能不能拿到数据，详见下文「DevOps Agent 与 WAF Analyst」。

## 能力差距分析

符号只表示有没有这项能力。DevOps Agent 和 WAF Analyst 调查得好不好，见下文「DevOps Agent 与 WAF Analyst」。

- **✓** 支持
- **❌** 不支持

| 客户需求 | Security Agent | DevOps Agent | WAF Analyst |
|---------|:---:|:---:|:---:|
| WAF 日志调查：误报、确认攻击、绕过、COUNT → BLOCK、DDoS、IP 画像 | ❌ | ✓ | ✓ |
| REGIONAL WebACL（ALB、API Gateway）调查 | ❌ | ✓ | ❌ |
| 每周安全巡检报告 | ❌ | ❌ | ✓ |
| 面向管理层的周报摘要 | ❌ | ❌ | ✓ |

## 其他服务的定位差异

### AWS Security Agent

- **定位**：应用安全——渗透测试、SAST、代码漏洞扫描
- **不能做**：读取 AWS WAF 日志、分析请求模式、理解 WAF 规则逻辑
- **差距**：无法回答"这个 IP 是否恶意？"或"这条规则是否应该从 COUNT 升级到 BLOCK？"

### AWS DevOps Agent

- **定位**：生产事件响应——部署失败、基础设施问题、运维指标
- **WAF 方面**：能读 WebACL 配置、CloudWatch 指标和 WAF 日志，一次 WAF 调查能自己做完。证据读得准不准，见下文「DevOps Agent 与 WAF Analyst」。
- **不做**：定期巡检报告和周报。

## DevOps Agent 与 WAF Analyst

**DevOps Agent。** 数据拿得对，读数据弱一些。它容易把话说得比 WAF 日志能证明的更满：可能的误报说成已经定了，可能是爬虫说成肯定是。有时会读错流量本身，比如到底是几台主机发的。偶尔还会主动提出替你改 WebACL。另外，要用 Athena 查 S3 里的 WAF 日志，得给它配一个开了托管查询结果的 workgroup，因为它的会话策略去掉了 `s3:PutObject`。

**WAF Analyst。** 计数和匹配交给专用工具（`analyze_ip`、`lookup_ja4`、`detect_bypass`、`check_challenge_compatibility`、`get_waf_overview`）用代码算，模型只管判断。同样的问题，它更常得出证据撑得住的结论。合作方的集成请求看着像 SSRF 和 SQL 注入，它认得出不是攻击。别人给的解释和日志对不上时，它会提出质疑。撞库分散在几台主机上、逐个 IP 限速拦不住，它能说清为什么，并把这几台主机当成同一次攻击。它能解释限速规则生效之前放过去的那批请求，误报还需要业务确认时也会直说。也有一些问题两者答得差不多，个别问题上 DevOps Agent 答得更好。

它的局限：只支持 CloudFront scope 的 WebACL；要在你的账号里作为独立 agent 用 AgentCore 部署。时间范围太长时，它会请你缩小窗口，不会整段扫完，所以查一个 IP 几周来的行为，要再追问一轮。

**怎么选。** 已经在用 DevOps Agent 的话，临时的 WAF 问题可以交给它，但结论要对照日志实际证明了什么来看，它最容易在这里说过头。要紧的判断，比如放行的流量是不是攻击、被拦的客户是不是误报，用 WAF Analyst。REGIONAL WebACL 用 DevOps Agent，WAF Analyst 不支持。

## WAF Analyst 的核心能力

### 1. 交互式安全调查

通过对话式交互，逐步深入调查安全事件：

- **误报调查**：5 步方法论——确认规则 → 查看匹配详情 → 分析 IP 行为 → 判断 NAT/代理 → 给出建议
- **绕过检测**：识别高频 ALLOW 流量中的异常模式（爬虫伪装、重复器、Token 复用）
- **攻击源分析**：IP 行为画像（JA4 指纹、URI 多样性、请求频率、Bot Control 标签）
- **DDoS 事件分析**：理解 Anti-DDoS AMR 行为，区分正常 Challenge 与异常

### 2. 自动化报告

| 报告类型 | 受众 | 内容 |
|---------|------|------|
| 安全巡检报告 | 运维工程师 | 7 天全量扫描、异常检测、15 分钟粒度图表、攻击源 Top 5 |
| 周报摘要 | 管理层 | 拦截量、趋势对比、Bot 分类、国家分布、投资回报可视化 |

### 3. 领域知识

内置 AWS WAF 专业知识，不依赖通用 LLM 知识：

- 托管规则组行为（Bot Control Common/Targeted、Anti-DDoS AMR、CRS、IP Reputation）
- 标签语义和规则交互模式
- Challenge/CAPTCHA 的适用场景和限制
- Rate-based 规则的延迟特性
- Dynamic Label Interpolation
- 知识库检索（12 篇专题文档）

### 4. 日志分析能力

20+ 预置查询模板，覆盖：

| 类别 | 查询能力 |
|------|---------|
| COUNT 规则评估 | Top IP、Top URI、Top UA（按规则） |
| IP 深度分析 | 行为画像、JA4 指纹、URI 分布、请求频率、NAT 检测 |
| 绕过检测 | 高频 ALLOW 爬虫、重复器、Token 复用 |
| 攻击概览 | Top 被拦 IP、Top 规则、Top 国家、时间线 |
| Host 画像 | 流量分布、方法分布、URI 模式（区分前端/API） |
| 标签分析 | 按标签查 Top IP（Bot Control、Anti-DDoS 等） |

### 5. 无日志降级

当 WebACL 未配置日志时，明确告知能力边界：
- ✅ 可用：CloudWatch 聚合指标（按规则/标签/国家）
- ❌ 不可用：IP 级分析、绕过检测、URI 模式分析、误报调查

不会编造数据，不会给出无法验证的结论。

### 6. 一次一个 WebACL，账号内全量发现

CloudFront WebACL 是全局的，所以一次调用就能列出账号里的 CLOUDFRONT scope WebACL。每个会话只对一个 WebACL 生效，切换到另一个会重置会话状态（日志目的地、能力、发现记录），结果不会跨 WebACL 混在一起。REGIONAL scope（ALB、API Gateway、AppSync）不支持。

## 技术架构优势

- **专用 Tools 而非通用 MCP**：每个 tool 内置分析逻辑（异常检测、NAT 判断、阈值评估），不是简单的 API wrapper
- **确定性 + LLM 混合**：数值计算和模式匹配用 Python，自然语言理解和判断用 LLM
- **会话记忆**：跨轮次保持调查上下文，支持渐进式深入
- **实时流式输出**：AG-UI 协议，用户实时看到 tool 调用进度
