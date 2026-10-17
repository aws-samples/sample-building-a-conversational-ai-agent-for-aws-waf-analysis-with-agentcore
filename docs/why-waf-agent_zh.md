# 为什么需要 WAF Analyst？

截至 2026 年 10 月，把 AI agent 接到 AWS WAF 日志上有三条路，深浅不同。DevOps Agent 自己能拿到数据，但没有 WAF 方法。开源的 `aws-waf-log-investigation` skill（[aws/tools-for-devops-agent#142](https://github.com/aws/tools-for-devops-agent/pull/142)）把方法教给 DevOps Agent，覆盖调查类场景。WAF Analyst 最深，有专用工具和直连数据，还覆盖 skill 不做的报告。三者在同一组留出题上的实测对比，见下文「原生 / skill / WAF Analyst」。

## 能力差距分析

DevOps Agent 一列拆成两列：`原生`是不带 skill 的 agent，`+Skill`是加载了 #142 的 agent。符号分的是质量，不只是能不能跑：

- **❌** 不支持
- **△** 能取到数据，但结论不可靠（有数据没方法）
- **✓** 方法可靠，结论可靠
- **◎** 最深：专用工具、验证过的方法、守在证据边界内

| 客户需求 | Security Agent | DevOps(原生) | DevOps +Skill [#142] | Security IR | WAF Analyst |
|---------|:---:|:---:|:---:|:---:|:---:|
| 判断 COUNT 规则是否误杀 | ❌ | △ | ✓ | ❌ | ◎ |
| 确认流量是否为真实攻击 | ❌ | △ | ✓ | ❌ | ◎ |
| COUNT → BLOCK 升级决策支持 | ❌ | ❌ | ✓ | ❌ | ◎ |
| 攻击源排查（IP 行为分析） | ❌ | △ | ✓ | ❌ | ◎ |
| 区分 bot 与正常用户（事后分析） | ❌ | ❌ | △ | ❌ | ◎ |
| 误报调查（"客户被拦了"） | ❌ | △ | ✓ | ❌ | ◎ |
| 绕过/逃逸检测 | ❌ | ❌ | ✓ | ❌ | ◎ |
| DDoS 事件调查 | ❌ | △ | ✓ | ❌ | ◎ |
| REGIONAL WebACL（ALB、API Gateway）调查 | ❌ | △ | ✓ | ❌ | ❌ |
| 每周安全巡检报告 | ❌ | ❌ | ❌ | ❌ | ◎ |
| 面向管理层的 周报摘要 | ❌ | ❌ | ❌ | ❌ | ◎ |
| WAF 最佳实践知识库 | ❌ | ❌ | ❌ | ❌ | ◎ |

调查类那几行从左往右读，正是这张表的重点：`原生`有数据但结论下错（△），skill 补上方法、结论变可靠（✓），WAF Analyst 用专用工具挖得更深（◎）。✓ 和 ◎ 在实践中的差别：同样的问题，WAF Analyst 会跨 IP 读 JA4 指纹、抓出一个 token 被多个 IP 重放、检查 challenge 兼容性、把自定义限速规则和 Anti-DDoS AMR 的事件检测分开，这些 skill 只能把通用 agent 往这个方向引导，做不到这么深。skill 赢的两处是它自己的列：REGIONAL WebACL（WAF Analyst 只支持 CloudFront），以及跑在客户已有的 DevOps Agent 里、不用单独部署。

## 其他服务的定位差异

### AWS Security Agent

- **定位**：应用安全——渗透测试、SAST、代码漏洞扫描
- **不能做**：读取 AWS WAF 日志、分析请求模式、理解 WAF 规则逻辑
- **差距**：无法回答"这个 IP 是否恶意？"或"这条规则是否应该从 COUNT 升级到 BLOCK？"

### AWS DevOps Agent

- **定位**：生产事件响应——部署失败、基础设施问题、运维指标
- **原生**：能读 WebACL 配置、CloudWatch 指标和 WAF 日志，查询也基本正确。缺的是 WAF 方法：会把被拦的正常用户算进攻击里，漏掉被放行的绕过流量，只看攻击那段时间就决定 COUNT 转 BLOCK。
- **加上 skill（#142）**：`aws-waf-log-investigation` skill 补上方法，agent 就能处理上面这些调查。见下文「原生 / skill / WAF Analyst」。
- **加了 skill 仍缺**：巡检、周报这些报告，以及 WAF Analyst 专用工具的分析深度。

### AWS Security Incident Response

- **定位**：IAM 泄露、EC2 实例入侵、数据外泄事件
- **不能做**：调查 WAF 层事件、分析 HTTP 请求模式、评估规则有效性
- **差距**：工作在基础设施/身份层，不在应用/WAF 层

## 原生 / skill / WAF Analyst

在同一组留出题上实测（误报、注入、绕过、COUNT→BLOCK、DDoS、token 重放、IP 画像），覆盖 CloudFront 和 REGIONAL（ALB）两种 WebACL。

**DevOps Agent 原生。** 数据拿得到，查询也基本正确，但没有 WAF 方法就会把结论下错：把被拦的正常用户算进攻击里，漏掉被放行的绕过流量，只看攻击那段时间就决定 COUNT 转 BLOCK。还有个 IAM 的坑：DevOps Agent 的会话策略砍掉了 `s3:PutObject`，拿 Athena 查 S3 里的 WAF 日志会失败，必须给它配一个用 managed query results 的 workgroup。

**DevOps Agent 加 skill（#142）。** skill 把方法带到这个通用 agent 上：该问什么、怎么读答案、结论能下到哪。覆盖误报、注入和绕过、COUNT→BLOCK、DDoS、IP 画像，Athena 和 CloudWatch Logs 都支持，CloudFront 和 REGIONAL 两种 WebACL 也都支持。客户用自己已有的 DevOps Agent 就能跑，不用额外部署，在没有 AgentCore 权限的 CDN/WAF 账号里也能用。它不做巡检、周报这些报告。

**WAF Analyst。** 专用工具（`analyze_ip`、`lookup_ja4`、`detect_bypass`、`check_challenge_compatibility`、`get_waf_overview`）、直连数据、验证过的方法，让它在能跑的地方分析最深：跨 IP 读 JA4 指纹、发现一个 token 被多个 IP 重放、检查 challenge 兼容性、把自定义限速规则和 Anti-DDoS AMR 的事件检测区分开。它也守在证据边界内，日志证不了意图时就说证不了，不猜。它的限制在于能跑在哪、怎么部署，不在分析质量：只支持 CloudFront scope，不支持 REGIONAL，而且要作为独立 agent 部署在有 AgentCore 权限的账号里。

**怎么选。** CloudFront WebACL 上要最深的分析、或者要巡检/周报报告，用 WAF Analyst。想在已有的 DevOps Agent 里做 WAF 调查、或者 WebACL 是 REGIONAL、或者账号没有 AgentCore 权限，用 skill。光靠原生 agent 不够做 WAF 的活。

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
