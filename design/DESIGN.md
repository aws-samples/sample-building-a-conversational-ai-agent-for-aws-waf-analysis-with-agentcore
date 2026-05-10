# WAF Investigation Engine — Design Document (v2)

## Problem Statement

客户在 WAF 运维中面临两个核心痛点：

1. **COUNT 规则评估**：把规则设为 COUNT 后，不知道如何判断命中的请求是真攻击还是误杀
2. **攻击源排查**：服务受影响时，不知道如何从日志中定位攻击源并制定针对性的 WAF 规则

当前工具（waf-analysis-report）是固定报告生成器——跑 25 个预定义 query，输出固定格式的 top talker 报告。真正的 insight 很少，因为 WAF 日志分析本质上是**探索性调查**，不是固定报告能解决的。

## Design Goal

构建一个**自动化调查引擎**：用户描述症状，Agent 主动收集上下文、找到调查锚点、执行 pivot chain、输出调查结论 + 证据链 + 可执行的 WAF 规则建议。

---

## Intake Protocol（主动提问）

**绝大多数用户描述不清楚自己的需求。** Agent 不应该直接开始调查，而是先通过结构化提问 + 自动信息收集来建立调查上下文。

### Agent 自动收集（不需要问用户）

通过 API 调用直接获取：

| 信息 | API | 用途 |
|------|-----|------|
| WebACL 完整配置 | `wafv2:GetWebACL` | 了解规则组成、优先级、action |
| 规则命中趋势 | `cloudwatch:GetMetricData` | 发现异常时间窗口 |
| Action 分布趋势 | `cloudwatch:GetMetricData` | 判断整体态势 |

### Agent 必须问用户的问题

根据用户初始描述的模糊程度，**选择性**提问。如果用户描述已经足够具体（包含时间、规则名、症状），跳过提问直接开始。只在信息不足时才问，且一次最多问 2 个问题。

| 问题 | 为什么需要 |
|------|-----------|
| 受影响的是浏览器流量还是 API/native app？ | 决定 Challenge 是否可用作为缓解手段 |
| 什么时候开始的？持续多久？ | 缩小日志查询范围，降低成本 |
| 症状是什么？（5xx 增加？延迟？用户投诉？metrics 异常？） | 区分"WAF 没挡住攻击"vs"WAF 误杀了正常流量" |
| 你怀疑是什么问题？（DDoS？bot？误杀？） | 选择调查策略 |

### 提问后的自动判断

Agent 拿到 WebACL 配置后，自动评估：
- 有没有 Anti-DDoS AMR？→ 如果没有且用户说 DDoS，Agent 需要在没有 AMR labels 的情况下从日志中识别攻击模式
- 有没有 Bot Control？Common 还是 Targeted？→ 决定 bot 检测能力的上限
- 有没有 rate-based rules？阈值和评估窗口是多少？→ 理解 kick-in delay
- 有没有 always-on Challenge？→ 判断是否有前置防护

---

## Anchor Discovery（找到第一个锚点）

**Pivot chain 最关键的一步是找到第一个锚点。** 锚点 = 第一个值得深入调查的异常值。

### 锚点发现策略

#### 场景 A: "我被 DDoS 了"

```
Step 1: Metrics 全景
  - AllowedRequests + BlockedRequests 时间序列 → 找异常时间窗口
  - 对比：BLOCK 暴增？还是 ALLOW 也暴增？

Step 2: 根据 WAF 配置分支

  [有 Anti-DDoS AMR]
    → 查 labels 中是否有 event-detected
    → 有 → AMR 检测到了，看 ddos-request label 的 IP 分布
    → 没有 → AMR 没检测到（可能是高度分布式攻击，volumetric-index 未超阈值）
      → 需要从 ALLOW 请求中找异常模式（UA 集中？JA4 集中？URI 集中？）

  [只有 rate-based rule]
    → 理解 kick-in delay（20-30s）
    → 锚点 = rate-based rule 生效前的 ALLOW 请求中的 top IP
    → 这些 IP 后来被 BLOCK 了吗？（确认 rate-based 最终生效）
    → 如果始终没被 BLOCK → 阈值设太高或评估窗口太长

  [什么防护都没有]
    → 所有攻击流量都是 ALLOW
    → 锚点 = ALLOW 请求中的 top IP（按请求量排序）
    → 交叉验证：这些 IP 的 UA、URI、请求频率是否异常
```

#### 场景 B: "COUNT 规则是否误杀"

```
Step 1: 锚点 = 该 COUNT 规则本身
  → 查 nonTerminatingMatchingRules 中该规则的命中记录
  → 按 IP 聚合

Step 2: 判断模式
  - 少数 IP 贡献大部分命中（集中）→ 可能是攻击
  - 大量分散 IP 命中（分散）→ 可能是误杀
  - 混合 → 需要进一步 pivot

Step 3: 对 top IP 做交叉查询
  - 该 IP 是否也有正常 ALLOW 流量？（混合流量 = 可能误杀）
  - 该 IP 的 UA / JA4 → 自动化工具？
  - 该 IP 命中了哪些其他规则？→ 多规则命中 = 更可能是攻击
```

#### 场景 C: "服务受影响了，不知道怎么回事"

```
Step 1: Metrics 全景 → 找异常维度
  - 哪个规则的 BlockedRequests 突增？→ 可能是误杀
  - AllowedRequests 突增？→ 可能是攻击穿透
  - 两者都没变？→ 可能不是 WAF 问题

Step 2: 如果 BlockedRequests 突增
  → 锚点 = 该规则
  → 查被 BLOCK 的请求详情 → 是正常流量还是攻击？

Step 3: 如果 AllowedRequests 突增
  → 锚点 = ALLOW 请求中的异常流量
  → 按 IP/URI/UA 聚合找 top talker
```

---

## Pivot Chain

找到锚点后，执行迭代 pivot：

```
锚点（第一个异常值）
  → 交叉查询（该值在其他维度的表现）
  → 识别新异常
  → pivot 到新维度
  → ...（重复直到收敛）
  → 结论 + 证据链 + 规则建议
```

### Pivot 维度

| 维度 | 字段 | 适合作为锚点 | 适合作为 pivot 目标 |
|------|------|-------------|-------------------|
| Client IP | `httpRequest.clientIp` | rate-based 触发、top talker | 从 rule/URI 发现的 top IP |
| URI path | `httpRequest.uri` | 特定接口受影响 | 从 IP 发现其攻击目标 |
| Rule / Label | `terminatingRuleId`, `labels` | COUNT 规则评估 | 从 IP 发现其触发的规则 |
| Country | `httpRequest.country` | 地理异常 | 从 IP 确认地理分布 |
| User-Agent | headers 中提取 | bot 识别 | 从 IP 确认自动化特征 |
| JA4 fingerprint | `ja4Fingerprint` | 高级 bot 识别 | 从 IP 确认 TLS 指纹 |
| Action | `action` | 规则模式切换后评估 | 从 IP 计算 block rate |
| Time | `timestamp` | 突发事件 | 确认攻击时间窗口 |
| Host | headers 中提取 | 多域名 WebACL | 确认攻击目标域名 |

### 异常检测逻辑

| 模式 | 判断条件 | 含义 |
|------|---------|------|
| 垄断 | 单一值占比 >50% | 该值是主要贡献者，值得深入 |
| 集中 | Top 3 占比 >80% | 少数来源主导，可能是定向攻击 |
| 分散 | Top 10 占比 <30% | 大量来源，可能是分布式攻击或正常流量 |
| 突增 | 当前值 / 基线 >3x | 时间维度异常 |
| 纯恶意 | Block rate = 100% | 该维度值完全是攻击流量 |
| 混合 | Block rate 10-90% | 需要进一步区分 |

### 收敛条件

1. **时间硬限制**：300 秒 timeout
2. **迭代软限制**：7 次 pivot（system prompt 引导）
3. **信息增益递减**：新 query 结果没有提供新的异常值
4. **结论可达**：已经收集到足够证据做出判断

---

## WAF Domain Knowledge（Agent 内置知识）

Agent 必须理解以下 WAF 行为，否则会做出错误判断：

### Rate-based Rule 的 kick-in delay

- 评估窗口 60s/120s/300s/600s，从阈值突破到规则生效有 **20-30 秒延迟**
- 日志中会看到：某 IP 在被 BLOCK 之前有几百个 ALLOW 请求
- **这是正常行为，不是 WAF 失效**
- Agent 看到这种模式时不应该报告为"WAF 没有保护"

### Anti-DDoS AMR 的行为和局限

- 新版 AMR 是 `AWSManagedRulesAntiDDoSRuleSet`（managed rule group），旧版 ShieldMitigationRuleGroup 已淘汰
- 检测机制：**资源级别基线偏差**（不是 per-IP rate-based），持续监控流量并与历史基线对比
- 典型 DDoS 需要 **5-10 秒 kick-in**

**3 个规则**（按优先级）：
1. `ChallengeAllDuringEvent` — 事件期间 Challenge 所有 challengeable 请求（GET + text/html）。默认 Challenge。
2. `ChallengeDDoSRequests` — 只在 #1 设为 Count 时生效，按 suspicion level Challenge。更精准。
3. `DDoSRequests` — 按 suspicion level **Block**。默认 sensitivity=LOW（只 Block high-suspicion）。**不要求 challengeable**，API 也能拦。

**关键能力**：
- `DDoSRequests` 能拦截**任何高频 IP**（包括能执行 JS 的 Playwright/Puppeteer），只要 per-IP 请求量偏离基线足够大 → 被标记为 high-suspicion → Block
- 浏览器自动化能否执行 JS **不影响** `DDoSRequests` 的拦截能力（它是 Block，不是 Challenge）

**真正的局限**（只有这种情况需要 Targeted Bot Control）：
- **高度分布式攻击**：几万个 IP，每个 IP 请求量不大（与基线差距不够显著）→ 不会被标记为 high-suspicion → `DDoSRequests` 在 LOW sensitivity 下不拦截
- 解决方案：提高 `SensitivityToBlock` 到 MEDIUM/HIGH，或部署 Targeted Bot Control（`TGT_ML_CoordinatedActivity` 检测分布式协同行为）

**Anti-DDoS AMR 不是万能的**，但它的盲区是"分布式低频"，不是"浏览器自动化"。

**AMR Labels（已从真实日志验证）**：
- `awswaf:managed:aws:anti-ddos:event-detected` — 事件正在发生（所有请求都有此 label）
- `awswaf:managed:aws:anti-ddos:ddos-request` — 被判定为 DDoS 请求
- `awswaf:managed:aws:anti-ddos:high-suspicion-ddos-request` — 高可疑
- `awswaf:managed:aws:anti-ddos:medium-suspicion-ddos-request` — 中可疑
- `awswaf:managed:aws:anti-ddos:low-suspicion-ddos-request` — 低可疑
- `awswaf:managed:aws:anti-ddos:ChallengeAllDuringEvent` — 被 ChallengeAll 命中
- `awswaf:managed:aws:anti-ddos:challengeable-request` — 可以被 Challenge 的请求

**event-detected vs ddos-request 的区别**：
- `event-detected` 作用于事件期间的**所有请求**（包括合法流量）
- `ddos-request` 只作用于被 AMR 判定为 DDoS 的请求
- 如果用户禁用了 ChallengeAllDuringEvent，report 可以看到：AMR 识别了多少 ddos-request（被 Block），放行了多少非 ddos-request（合法流量）

### Bot Control Common Level 的局限

- **只检测自报身份的 bot**（通过 User-Agent）
- 如果 bot 用正常浏览器 UA → Common level **完全检测不到**
- 不做行为分析、不做浏览器指纹、不做 ML 检测
- Agent 不能依赖 Bot Control labels 的缺失来判断"不是 bot"
- 能识别约 700 种 bot（v5.0+），但都是基于 UA 声明

**Common Bot Control 的三种处理路径**：
1. `bot:verified`（通过反向 DNS 验证的真实 bot，如真正的 Googlebot from ASN 15169）→ **放行**，不应用 rule action，也不进入 Targeted 检查
2. `bot:unverified`（自声明是某种 bot 但无法通过反向 DNS 验证）→ **应用 rule action**（通常 Block）。这是 Common level 的核心价值
3. 既不是 verified 也不是 unverified（伪装 bot UA 但不匹配任何 Category 规则，或用正常浏览器 UA）→ 落入 `SignalNonBrowserUserAgent`（如果 UA 不像浏览器）或完全不被检测（如果 UA 像浏览器）

**客户常见误解**：以为 Common Bot Control 能拦截所有 bot。实际上它只拦截"自声明是 bot 但无法验证身份的请求"。用浏览器 UA 伪装的高级 bot 需要 Targeted level（行为分析 + ML）。

**Bot Verification 在 CloudWatch Metrics 中的查询方式**：
- `LabelNamespace=awswaf:managed:aws:bot-control:bot` + `LabelName=verified` → verified bot 总量
- `LabelNamespace=awswaf:managed:aws:bot-control:bot` + `LabelName=unverified` → unverified bot 总量
- 注意：**不能**用 `awswaf:managed:aws:bot-control:bot:verified` 作为 LabelNamespace（这是 terminal label，没有子 label）
- CloudWatch Metrics **无法**关联 bot:name 和 verified/unverified（它们是独立的 time series）
- 唯一能关联的方式是 **CWL 查询**（同一条日志里同时有两个 label）：
  ```
  filter @message like "bot-control:bot:name:"
  | filter @message like "bot:verified" or @message like "bot:unverified"
  | parse @message /bot:name:(?<botName>[a-z0-9_]+)/
  | parse @message /bot:(?<verificationStatus>verified|unverified)/
  | stats count(*) as cnt by botName, verificationStatus
  ```

### Bot Control Targeted Level

- 包含 Common level 所有功能 + 行为分析 + 浏览器指纹 + ML
- 自动跳过 bot:verified 的请求
- TGT_TokenAbsent: 默认 action 是 **Count**（这是正确的设计）
  - 单个 token-absent 请求不是可靠的 bot 信号（首次访问、API 客户端、native app 都没有 token）
  - 真正的 bot 信号由 `TGT_VolumetricIpTokenAbsent`（默认 Challenge）处理：同一 IP 5 分钟内 5+ 次 token-absent
  - 只有 override 到 **Allow** 才是问题（会抑制 label）
- 价格：$10/million requests（Common 的 10 倍）
- 实际部署建议：只保护前端域名（浏览器流量），后端 API 不适合用 Bot Control

### Challenge/CAPTCHA 的适用范围

- **只能对浏览器 GET text/html 请求生效**
- POST、API、native app、非 GET → Challenge = 等同于 Block
- Agent 在建议"加 Challenge"时必须确认流量类型

### WAF Token

- 不可伪造（AWS 加密签名）
- 可以作为"已验证用户"的可靠标识
- `token:absent/accepted/rejected` 是共享 label（Bot Control、ATP、ACFP、Anti-DDoS AMR 都会产生）

### Match Detail 的现实限制

- **只有 SQLi_Body 和 XSS_Body 两个规则提供 terminatingRuleMatchDetails**
- 其他所有规则都不提供 match detail
- 只能从规则名称后缀（`_Cookie`、`_Header`、`_Body`、`_QueryArguments`）推断命中位置
- **Agent 无法告诉用户"是什么内容触发了规则"**（除了 SQLi/XSS）
- 排除条件只能基于外部维度：URI、IP、UA — 不能基于 payload 内容
- Agent 应该诚实告知用户这个限制，建议在 WAF console → Sampled Requests 中查看

---

## Frontend vs Backend Architecture（前后端分离）

### 背景

真实客户的网站通常是前后端分离的：
- **前端域名**（如 `www.example.com`）：浏览器 GET 请求、HTML 页面、可以完成 Challenge
- **后端/API 域名**（如 `api.example.com`）：POST/PUT/DELETE、JSON、native app SDK（okhttp 等）— 无法完成 Challenge

一个 WebACL 可能同时保护前端和后端域名（通过同一个 CloudFront distribution 的多个 behavior，或多个 distribution 关联同一个 WebACL）。

### 对 WAF 规则的影响

| 规则/功能 | 前端（浏览器） | 后端（API/native app） |
|-----------|--------------|---------------------|
| Challenge action | ✅ 有效 | ❌ 等同于 Block |
| Bot Control Targeted | ✅ 完整功能 | ⚠️ TGT_TokenAbsent 会命中所有请求 |
| Anti-DDoS AMR ChallengeAllDuringEvent | ✅ 有效 | ❌ 等同于 Block |
| Always-on Challenge | ✅ 有效 | ❌ 不适用 |
| Rate-based + Challenge | ✅ 有效 | ❌ 应改用 Block |

### 实际情况

- **几乎所有客户拒绝集成 AWS WAF Client SDK**（增加开发工作量、SDK 版本维护）
- 没有 SDK → native app 永远没有 WAF token → `TGT_TokenAbsent` 永远命中
- 实际做法：**只用 Bot Control 保护前端域名**，后端域名用 rate-based + IP reputation
- Anti-DDoS AMR：前端启用 ChallengeAllDuringEvent，后端禁用 Challenge 并提高 Block sensitivity

### Agent 如何检测

1. **`host_traffic_profile` query**：按 Host header 统计请求方法分布
   - 高 POST/PUT/DELETE 比例 (>30%) = 后端/API
   - 主要 GET (<5% writes) = 前端
   - 混合 = 建议拆分 WebACL 或用 scope-down 区分
2. **`get_waf_config` capabilities**：检测是否有 Bot Control、Challenge 规则
3. **Rule review**：如果 Challenge 规则没有 scope-down 排除 API 路径 → 标记为 Medium issue

### 建议策略

| 场景 | 建议 |
|------|------|
| 单 WebACL 保护前端+后端 | Bot Control scope-down 只匹配前端 Host；AMR 用 dual instance |
| 前后端分离的 WebACL | 前端 WebACL 启用全部功能；后端 WebACL 禁用 Challenge 类规则 |
| 客户拒绝集成 SDK | 只在前端域名使用 Bot Control；后端用 rate-based + IP reputation |

---

## Rule Recommendation（规则建议输出）

调查结论不只是"是攻击/误杀"，还要给出具体的规则修改建议：

| 调查发现 | 建议 |
|---------|------|
| DDoS 但没有 Anti-DDoS AMR | 建议部署 AMR，说明其局限性 |
| 高度分布式攻击，AMR 检测不到 | 建议 Targeted Bot Control |
| Bot 但只有 Common level | 建议 always-on Challenge（如果是浏览器流量）或升级 Targeted |
| Rate-based kick-in 太慢 | 建议降低评估窗口（60s）或降低阈值 |
| COUNT 规则确实误杀 | 给出排除条件（基于 URI/IP/UA 等外部维度的 label match + NOT → BLOCK） |
| COUNT 规则确实是攻击 | 建议转 BLOCK |
| Allow 规则基于可伪造条件（UA/cookie） | 建议改用不可伪造条件（IP set/WAF token/ASN） |
| 没有 always-on Challenge | 建议部署（两规则模式：Count+Label → Challenge，排除 crawler） |

**限制**：除 SQLi/XSS 外，Agent 无法提供基于 payload 的精确排除条件。只能建议基于 URI/IP/UA 的粗粒度排除，并建议用户通过 Sampled Requests 确认具体触发内容。

---

## Data Sources

三层数据源，从宏观到微观：

### Layer 1: CloudWatch Metrics（宏观信号，秒级粒度，零日志成本）

WAF 自动发布丰富的 metrics 到 CloudWatch，维度远比文档描述的多。通过 `list-metrics` 动态发现，或用 `SEARCH` 表达式批量查询。

**Metric Names（8 种）**：

| MetricName | 含义 |
|---|---|
| `AllowedRequests` | 被 ALLOW 的请求 |
| `BlockedRequests` | 被 BLOCK 的请求 |
| `ChallengeRequests` | 被 Challenge 的请求 |
| `CountedRequests` | 被 COUNT 的请求 |
| `BlockRuleMatch` | 规则匹配触发 Block（带 label 维度） |
| `ChallengeRuleMatch` | 规则匹配触发 Challenge（带 label 维度） |
| `CountRuleMatch` | 规则匹配触发 Count（带 label 维度） |
| `Sample*Request` | Bot Control dashboard 专用（带完整 bot 分类维度） |

**Dimension 组合（9 种模式）**：

| 模式 | Dimensions | 用途 |
|---|---|---|
| 全局 | `Rule=ALL` | WebACL 总请求量 |
| Per-rule | `Rule={name}` | 每条规则的命中统计 |
| Per-country | `Country` | 按国家分布（不需要查日志！） |
| Per-device | `Device` | Desktop/Mobile 分布 |
| Per-label | `LabelName` + `LabelNamespace` | 按 WAF label 统计（bot category、token status、anti-ddos labels） |
| Per-label-with-context | `Context` + `LabelName` + `LabelNamespace` | 区分同一 label 在不同 rule group 中的命中 |
| Per-managed-rule | `ManagedRuleGroup` [+ `ManagedRuleGroupRule`] | managed rule group 内部规则粒度 |
| Per-vulnerability | `VulnerabilityCategory` | IP reputation 分类（HostingProviderIPList 等） |
| Bot 分类 | `BotName` + `BotCategory` + `Intent` + `Organization` + `VerificationStatus` | Bot Control 完整分类（Sample*Request metrics） |
| Signal | `Signal` | Bot Control signal（known_bot_data_center 等） |

**关键能力**：
- **`SEARCH` 表达式**：动态发现所有 label metrics，不需要预先知道有哪些 label
  ```
  SEARCH('{AWS/WAFV2,LabelName,LabelNamespace,WebACL} WebACL="xxx"', 'Sum', 3600)
  ```
- **`list-metrics`**：发现 WebACL 的所有可用维度组合
- **Weekly Report 可以几乎完全基于 Metrics 生成**——Bot 分类、Anti-DDoS 事件、国家分布、token 状态全部有 metric，零日志查询成本
- **Investigation Engine 的 Anchor Discovery 也优先用 Metrics**——先发现异常维度，再查日志看具体请求

**CloudFront WAF 注意事项**：global scope 的 metrics 没有 Region dimension，只发布到 us-east-1。

### Layer 2: WAF Logs（微观证据，per-request 粒度）

通过 CloudWatch Logs Insights 或 Athena 查询。只在需要看具体请求细节时使用（Metrics 无法提供 IP 级别信息）。

### Layer 3: WAF Configuration（上下文）

通过 `wafv2:GetWebACL` 获取当前规则配置。

### 三层联动

```
Metrics（发现异常 + 聚合统计 + 估算日志量）→ Logs（定位具体请求，仅在需要时）→ Config（理解规则意图）→ 结论
```

**设计原则**：能用 Metrics 解决的不查 Logs。Metrics 免费（CloudWatch 基础 metrics）、快（秒级）、维度丰富。Logs 有成本（CWL $5-7.6/GB，Athena $5/TB）且慢。

**查询引擎选择**（根据 GetLoggingConfiguration 自动判断）：

| 日志位置 | 查询引擎 | 说明 |
|---------|---------|------|
| CloudWatch Logs | CWL Insights（`run_logs_query`） | 服务端聚合，无需下载数据 |
| S3 | Athena 临时表（`run_athena_query`） | 自动建表 → 查询 → 清理 |

不使用 DuckDB——CWL Insights 服务端聚合 + Athena 覆盖所有场景。

**日志量估算**（用 Metrics 计算，决定时间窗口大小）：
- 每条 WAF 日志 1.5-3 KB（未压缩，取决于 rule 数量和 count action 数量）
- 根据**要查的 action 类型**选择对应 metric 估算：

| 调查场景 | 估算用的 Metric | 原因 |
|---------|----------------|------|
| 漏杀排查 | AllowedRequests | 查 ALLOW 日志，量最大 |
| 攻击源排查 | BlockedRequests + ChallengeRequests | DDoS 期间 BLOCK 量大 |
| 误杀排查 (COUNT) | 该规则的 CountRuleMatch | COUNT 命中通常比总量少，但大客户仍可能很多 |
| Weekly Report | 不需要动态窗口 | 用 Metrics 聚合 + 少量轻量 log query（stats by bin） |

- `get_waf_metrics(metric, period=900)` → 每 15 分钟的请求数 → 计算 rps
- 根据请求速率自动选择查询窗口：
  - < 100 rps → 6 小时
  - 100-1000 rps → 30-60 分钟
  - 1000-10000 rps → 5-15 分钟
  - > 10000 rps → 5 分钟

**CWL 并发限制**：
- StartQuery: 10 TPS（不可调）
- 并发 query: ~30 per account
- waf-agent 内部 semaphore: max 8 concurrent queries（留 headroom）

### WAF 日志字段访问方式（CWL vs Athena）

WAF 日志是嵌套 JSON。部分字段可以直接用点号访问，部分需要 parse @message 正则提取。

**CWL Insights 可直接访问的字段**：
```
action                          → "ALLOW" / "BLOCK" / "CHALLENGE"
terminatingRuleId               → 终止规则名
httpRequest.clientIp            → 客户端 IP
httpRequest.country             → 国家代码
httpRequest.uri                 → URI path
httpRequest.httpMethod          → GET/POST/...
httpRequest.requestId           → 请求 ID
ja4Fingerprint                  → JA4 TLS 指纹（顶层字段）
timestamp                       → 时间戳（毫秒）
```

**CWL Insights 需要 parse @message 正则提取的字段**：
```python
# User-Agent（headers 是数组，不能用索引访问）
'parse @message /(?i)\\{"name":"user-agent","value":"(?<userAgent>.*?)"\\}/'

# Host header
'parse @message /\\{"name":"(H|h)ost","value":"(?<Host>.*?)"\\}/'

# Labels（整个数组）
"parse @message '\"labels\":[*]' as Labels"

# nonTerminatingMatchingRules（COUNT 规则命中）
"parse @message '\"nonTerminatingMatchingRules\":[{*}]' as nonTerminatingMatchingRules"

# excludedRules
"parse @message '\"excludedRules\":[{*}]' as excludedRules"

# matchedData（SQLi/XSS 的匹配内容）
"parse @message '\"matchedData\":[*]' as matchedData"

# URI path prefix（第一段路径）
"parse httpRequest.uri /^(?<pathPrefix>\\/[^\\/\\?]*)/"

# 特定 label 存在性检查
'filter @message like "bot:verified"'
'@message not like "bot:verified"'  # 注意：不是 'not @message like'
```

**CWL 不支持的操作**：
- `not @message like "X"` → 报错。正确写法：`@message not like "X"`
- `httpRequest.headers[0].value` → 不支持数组索引
- `filter(array, lambda)` → 不支持（Athena 支持）

**Athena 的字段访问方式**（SQL，支持 Lambda）：
```sql
-- User-Agent
element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value

-- Host
element_at(filter(httprequest.headers, h -> lower(h.name) = 'host'), 1).value

-- URI prefix
regexp_extract(httprequest.uri, '^(/[^/?]*)')

-- 直接字段
httprequest.clientip, httprequest.country, httprequest.httpmethod, httprequest.uri
action, terminatingruleid, ja4fingerprint
```

**日志未开启的 fallback**：如果 `GetLoggingConfiguration` 返回 WAF 没有开启日志，Agent 应该：
1. 告知用户"WAF 日志未开启，无法进行详细调查"
2. 仍然用 Metrics 做有限分析（Weekly Report 大部分内容仍可生成）
3. 建议用户开启日志

---

## Athena Tool (`run_athena_query`)

### 触发条件

当 `get_waf_config` 发现 log destination 是 S3（ARN 包含 `:s3:::` 或 `:firehose:`），自动切换到 Athena 引擎。LLM 不需要知道底层引擎差异——`run_athena_query` 的接口和 `run_logs_query` 保持一致（query_type + params）。

### Log Destination 的两种情况

`GetLoggingConfiguration` 返回的 `LogDestinationConfigs` 可能是：
1. **S3 直接投递**：`arn:aws:s3:::aws-waf-logs-*` — WAF 直接写 S3
2. **Firehose 投递**：`arn:aws:firehose:region:account:deliverystream/aws-waf-logs-*` — 经 Firehose 写 S3

两种情况下，tool 都需要找到**实际的 S3 路径**：
- S3 直接投递：bucket name 直接从 ARN 提取，但**完整路径需要 walk 发现**（WAF 会自动加 `AWSLogs/{account}/WAFLogs/{region|cloudfront}/{webacl}/` 前缀）
- Firehose 投递：需要调用 `firehose:DescribeDeliveryStream` 获取 S3 destination 的 BucketARN + Prefix

**重要**：同一个 S3 bucket 可能同时包含两种投递方式的数据（旧 Firehose + 新直接投递）。分区检测必须找到正确的子路径，不能从 bucket 根目录盲目开始。

**S3 直接投递的路径解析策略**：
- `GetLoggingConfiguration` 只返回 bucket ARN（如 `arn:aws:s3:::aws-waf-logs-xxx`），不包含完整路径
- WAF 直接投递的标准路径是 `s3://bucket/AWSLogs/{account}/WAFLogs/{cloudfront|region}/{webacl-name}/`
- 因此可以**构造预期路径**：`s3://{bucket}/AWSLogs/{account}/WAFLogs/cloudfront/{webacl_name}/`（CloudFront scope）或 `s3://{bucket}/AWSLogs/{account}/WAFLogs/{region}/{webacl_name}/`（Regional scope）
- 先尝试构造路径是否存在（`s3 ls` 验证），如果存在直接用；如果不存在再 fallback 到 walk 发现

**Firehose 投递的路径解析策略**：
- `GetLoggingConfiguration` 返回 Firehose ARN（如 `arn:aws:firehose:us-east-1:123:deliverystream/aws-waf-logs-xxx`）
- 调用 `firehose:DescribeDeliveryStream` → `Destinations[0].S3DestinationDescription` 或 `ExtendedS3DestinationDescription`
- 获取 `BucketARN` + `Prefix`（Prefix 可能为空）
- S3 path = `s3://{bucket}/{prefix}`
- 然后从这个路径开始 walk 发现分区结构

### 自动发现流程

```
get_waf_config()
  → GetLoggingConfiguration
  → log_destination ARN
  → session_state.log_destination = ARN
  → session_state.log_engine = "athena" (if S3 or Firehose)

run_athena_query() 首次调用时（lazy init）：
  → _resolve_s3_path(log_destination_arn, webacl_name, scope, account_id)
    Case 1: S3 ARN (arn:aws:s3:::bucket-name)
      → bucket = arn.split(":::")[1]
      → 构造预期路径: s3://{bucket}/AWSLogs/{account}/WAFLogs/{cloudfront|region}/{webacl_name}/
      → s3.list_objects_v2(Bucket, Prefix, Delimiter='/') 验证路径存在
      → 存在 → 用这个路径
      → 不存在 → fallback: walk from s3://{bucket}/ 发现分区
    Case 2: Firehose ARN (arn:aws:firehose:region:account:deliverystream/name)
      → firehose.describe_delivery_stream(DeliveryStreamName)
      → S3DestinationDescription.BucketARN + Prefix
      → s3_path = s3://{bucket}/{prefix}
      → walk from s3_path 发现分区
  → _find_existing_table(s3_path)
    → Glue: get_tables() → 找 LOCATION 匹配的表 → 直接使用
    → 没找到 → _detect_and_create_table(s3_path)
  → session_state.athena_table = "database.table_name"
  → session_state.athena_partition_format = detected format
```

### 表发现

**Step 1: 检查现有表**

```python
# 搜索 Glue catalog 中所有 database 的表
# 优先检查 "default" 和 "waf_analysis_tmp"
for db in ["waf_analysis_tmp", "default"]:
    tables = glue.get_tables(DatabaseName=db)
    for table in tables:
        location = table.StorageDescriptor.Location
        if s3_path in location or location in s3_path:
            # 找到匹配的表 → 验证 schema 兼容性（有 httprequest, action, labels 列）
            return f"{db}.{table.Name}"
# 没找到 → 进入 Step 2
```

### 分区结构检测（核心逻辑，从 waf-runner-athena.py 移植）

**真实用户的 S3 路径千差万别**。不能假设任何固定结构。必须 walk 发现。

两种常见投递方式产生的路径：
- **WAF 直接投递**：`s3://bucket/AWSLogs/{account}/WAFLogs/{region|cloudfront}/{webacl-name}/YYYY/MM/dd/HH/mm/`
- **Firehose 投递**：`s3://bucket/{prefix}/YYYY/MM/dd/HH/` （Firehose 默认按小时分区，无分钟级）

检测算法（从 `waf-runner-athena.py` 的 `detect_partitions()` 移植）：
```python
def _detect_partitions(s3_path):
    """Walk S3 directories to find year-based partition structure.
    Returns (storage_template, partition_format, partition_unit)."""
    current = s3_path.rstrip("/") + "/"
    
    for depth in range(10):  # 最多走 10 层
        dirs = s3_list_dirs(current)  # boto3 list_objects_v2 with delimiter
        
        # 找到年份目录（20XX）？
        year_dirs = [d for d in dirs if re.match(r"^20[2-3]\d$", d)]
        if year_dirs:
            # 从最新年份向下探测深度
            year = year_dirs[-1]
            levels = _walk_down(current + year + "/")
            # levels = ["2026", "05", "10", "12", "00"] → 5 层 = minutes
            # levels = ["2026", "05", "10", "12"] → 4 层 = hours
            if len(levels) >= 5:
                partition_format = "yyyy/MM/dd/HH/mm"
                partition_unit = "minutes"
            else:
                partition_format = "yyyy/MM/dd/HH"
                partition_unit = "hours"
            storage_template = current + "${log_time}"
            return storage_template, partition_format, partition_unit
        
        # 没找到年份 → 选择最可能的子目录继续向下
        # 优先 "AWSLogs"，其次检查哪个子目录下有年份
        chosen = _pick_best_subdir(current, dirs)
        current = current + chosen + "/"
    
    raise RuntimeError(f"Cannot detect partition structure under {s3_path}")
```

**关键**：`_pick_best_subdir` 的逻辑：
1. 如果有 `AWSLogs` → 选它（WAF 直接投递的标准前缀）
2. 否则逐个检查子目录，找到包含年份子目录的那个
3. 都没有 → 选第一个（fallback）

### WAF 日志格式验证

创建表之前，必须验证 S3 里确实是 WAF 日志（不是 CloudFront access log 或其他）：

```python
def _validate_waf_log(s3_path):
    """Download one .gz file, decompress, verify WAF log schema."""
    # Walk to deepest level, find first .gz file
    gz_key = _find_first_gz(s3_path)
    # Download + gunzip + parse first line as JSON
    record = json.loads(first_line)
    required_fields = {"webaclId", "action", "httpRequest"}
    return required_fields.issubset(record.keys())
```

### 创建临时表（Partition Projection）

```sql
CREATE EXTERNAL TABLE IF NOT EXISTS `waf_analysis_tmp`.`waf_logs_{timestamp}` (
  `timestamp` bigint,
  `formatversion` int,
  `webaclid` string,
  `terminatingruleid` string,
  `action` string,
  `httprequest` struct<clientip:string,country:string,headers:array<struct<name:string,value:string>>,uri:string,httpmethod:string,requestid:string,host:string>,
  `labels` array<struct<name:string>>,
  `ja4fingerprint` string,
  `nonterminatingmatchingrules` array<struct<ruleid:string,action:string,overriddenaction:string>>,
  `ratebasedrulelist` array<struct<ratebasedruleid:string,ratebasedrulename:string,limitkey:string,maxrateallowed:int>>,
  `captcharesponse` struct<responsecode:string,solvetimestamp:string,failurereason:string>,
  `challengeresponse` struct<responsecode:string,solvetimestamp:string,failurereason:string>,
  `requestbodysize` int
  -- 完整 schema 见 waf-runner-athena.py DDL_TEMPLATE
)
PARTITIONED BY (`log_time` string)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
WITH SERDEPROPERTIES ('ignore.malformed.json' = 'true')
STORED AS INPUTFORMAT 'org.apache.hadoop.mapred.TextInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION '{s3_path}'
TBLPROPERTIES (
  'projection.enabled' = 'true',
  'projection.log_time.format' = '{YYYY/MM/dd/HH 或 YYYY/MM/dd/HH/mm}',
  'projection.log_time.interval' = '1',
  'projection.log_time.interval.unit' = '{hours 或 minutes}',
  'projection.log_time.range' = '2020/01/01/00,NOW',
  'projection.log_time.type' = 'date',
  'storage.location.template' = '{s3://bucket/prefix/${log_time}}'
)
```

**关键设计决策**：使用 Partition Projection 而不是 `MSCK REPAIR TABLE`。
- Partition Projection：零延迟，不需要扫描 S3 发现分区，Athena 根据 range 自动推断
- `MSCK REPAIR TABLE`：需要扫描所有 S3 prefix，大客户可能有几十万个分区，耗时 10+ 分钟

### 查询模板（Athena SQL）

Athena 查询模板和 CWL 模板一一对应，但语法不同：

| CWL 语法 | Athena 等价 |
|---------|------------|
| `filter httpRequest.clientIp = '{ip}'` | `WHERE httprequest.clientip = '{ip}'` |
| `stats count(*) by X` | `GROUP BY X ORDER BY count DESC` |
| `parse @message /regex/` | `element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value` |
| `@message like 'bot:verified'` | `EXISTS(SELECT 1 FROM UNNEST(labels) t(l) WHERE l.name LIKE '%bot:verified%')` |
| `@message not like 'bot:verified'` | `NOT EXISTS(...)` |
| `count_distinct(X)` | `count(DISTINCT X)` |
| `bin(1m)` | `date_format(from_unixtime("timestamp"/1000), '%Y-%m-%d %H:%i:00')` |

**Header 访问**（CWL 需要 parse regex，Athena 用 lambda）：
```sql
-- User-Agent
element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value AS ua

-- Host
element_at(filter(httprequest.headers, h -> lower(h.name) = 'host'), 1).value AS host
```

**Labels 访问**（CWL 用 `@message like`，Athena 用 UNNEST）：
```sql
-- 检查是否有某个 label
WHERE EXISTS(SELECT 1 FROM UNNEST(labels) t(l) WHERE l.name LIKE '%bot:verified%')

-- 提取所有 labels 为 JSON string（和 CWL 的 Labels 字段等价）
json_format(cast(labels as json)) AS Labels
```

**时间过滤**（必须同时过滤 timestamp + log_time 以利用 partition pruning）：
```sql
WHERE "timestamp" BETWEEN {start_ms} AND {end_ms}
  AND log_time >= '{start_partition}' AND log_time <= '{end_partition}'
```

### 并发与成本控制

- Athena 并发限制：20 DML queries per account（默认），可通过 Service Quotas 提高
- waf-agent 内部限制：串行执行（一次一个 query），不需要 semaphore
- 成本：$5/TB scanned。Partition projection + 时间过滤确保只扫描必要的分区
- Workgroup：使用 `primary`（默认）或用户指定。从 workgroup 配置获取 output location
- Result reuse：启用 `ResultReuseByAgeConfiguration`（60 分钟内相同查询复用结果）

### 清理策略

- 临时表：session 结束时 `DROP TABLE`（通过 Python `atexit` 或 `finally`）
- Query results：每次查询完成后删除 S3 上的 .csv + .csv.metadata 文件
- 如果 session 异常终止（timeout），临时表会残留。表名包含时间戳（`waf_logs_20260510_153000`），可以定期清理 `waf_analysis_tmp` database 中超过 24 小时的表

### 接口设计

```python
@tool
def run_athena_query(
    query_type: str,       # 和 run_logs_query 相同的 query_type
    rule_name: str = "",
    ip: str = "",
    label: str = "",
    action: str = "",
    host: str = "",
    hours_ago: int = 168,  # 默认 7 天（Athena 适合长时间范围）
    limit: int = 25,
) -> str:
    """Run a WAF log query via Athena (for S3-stored logs).
    Interface identical to run_logs_query — same query_types, same output format.
    """
```

LLM 不需要区分 CWL 和 Athena——system prompt 中引导：
- 如果 `session_state.log_engine == "cwl"` → 用 `run_logs_query`
- 如果 `session_state.log_engine == "athena"` → 用 `run_athena_query`
- 如果 `session_state.log_engine == "none"` → 告知用户日志未开启

### 从 waf-runner-athena.py 借鉴的经验

1. **S3 throttling**：批量查询时 S3 prefix 需要时间 scale up。waf-runner 用 batch=4 + 间隔 0.5s。waf-agent 串行执行不需要 batching。
2. **Partition format 检测**：必须实际 walk S3 目录到年份目录才能确定深度。不能假设。
3. **WAF 日志验证**：下载一个 .gz 验证格式，防止用户给错 S3 path。
4. **DDL 完整 schema**：WAF 日志 schema 很复杂（嵌套 struct + array）。必须用完整 DDL，不能省略字段（否则 Athena 解析失败）。
5. **`ignore.malformed.json`**：必须设置，因为 WAF 日志偶尔有格式异常的行。
6. **Partition projection range start**：用 `2020/01/01/00`（足够早），不需要精确匹配实际数据起始时间。
7. **Result reuse**：60 分钟内相同查询直接返回缓存结果，节省成本。
8. **Field name 大小写**：Athena 默认 lowercase 所有列名。`httprequest.clientip`（不是 `httpRequest.clientIp`）。
9. **Output location**：必须有。优先从 workgroup 配置获取，fallback 到用户指定。
10. **同一 bucket 多种数据**：真实用户的 bucket 可能同时有 Firehose 旧数据（根目录 `YYYY/`）和直接投递新数据（`AWSLogs/`）。S3 直接投递时应优先构造标准路径（`AWSLogs/{account}/WAFLogs/...`）而不是从根目录 walk（会误匹配 Firehose 数据）。
11. **Firehose prefix 可能为空**：`DescribeDeliveryStream` 返回的 Prefix 可能是 `""`，此时日志直接写在 bucket 根目录。

### IAM 权限要求（deploy/backend.yaml 需要补充）

```yaml
- Sid: Firehose
  Effect: Allow
  Action:
    - firehose:DescribeDeliveryStream
  Resource: '*'
```

---

## Investigation Scenarios

### Scenario 1: COUNT Rule Evaluation

**入口**：用户提供 rule name 或 label

**调查链**：见 Anchor Discovery 场景 B

**输出**：
- 结论：攻击 / 误杀 / 混合
- 证据链
- 如果是攻击 → 建议转 BLOCK
- 如果是误杀 → 给出基于 URI/IP 的排除条件（说明 match detail 限制）
- 如果是混合 → 建议加 scope-down 缩小范围

### Scenario 2: Attack Source Investigation

**入口**：用户描述症状（时间窗口 + 受影响的服务）

**调查链**：见 Anchor Discovery 场景 A 或 C

**输出**：
- 攻击画像：来源（IP/CIDR）、目标（URI）、手法（UA/JA4）、规模
- 时间线：攻击开始/结束/峰值
- WAF 规则建议（根据 Rule Recommendation 表）

### Scenario 3: Bypass/Evasion Detection（漏杀）

**入口**：用户怀疑有流量绕过 WAF（所有规则都没命中，走到 default ALLOW）

**核心洞察**：高级爬虫/自动化工具在单个请求层面看起来完全正常（真实浏览器 UA、有效 cookie、能执行 JS、有 GA 埋点）。唯一可靠的信号是**频率和行为模式**。

**真实案例**：某电商客户发现来自美国住宅 IP 的流量，Edge 浏览器 UA、有 GA 埋点、有 session 状态、通过 Google 广告进入。LLM 初始判断为"正常用户"。但实际上该 IP 在 1 小时内浏览了 656 个商品页（18,954 次请求），平均每 4 秒打开一个新商品页——这是不可能的人类行为。Bot Control 完全没有检测到（因为是真实浏览器自动化，能执行 JS）。

**教训**：
- LLM 会被"看起来正常"的请求内容欺骗
- 必须**先计算频率**（脚本做），再让 LLM 分析
- JA4 fingerprint 可以被伪造（curl-impersonate、Scrapling、Playwright）
- 只有 WAF token 不可伪造

**调查策略（防止超时）**：

关键原则：**绝不盲目查日志**。必须先收窄时间范围。

```
Step 0: 收集上下文（必须）
  - 如果用户没给时间范围 → ask_user() 询问
  - 如果用户说"不确定" → 进入 Step 1（metrics 定位）
  - 如果用户给了 ≤6 小时的范围 → 跳到 Step 2

Step 1: Metrics 定位峰值窗口（零日志成本）
  - get_waf_metrics(AllowedRequests, period=900) → 每 15 分钟的请求量
  - 找 ALLOW 流量最高的时间段
  - 根据请求速率自动选择窗口大小：
    < 100 rps → 6 小时窗口
    100-1000 rps → 30-60 分钟窗口
    1000-10000 rps → 5-15 分钟窗口
    > 10000 rps → 5 分钟窗口（CWL 聚合仍可工作）

Step 1.5: 用两个互补 query 一次性找出可疑 IP
  - top_allowed_crawlers：按 unique_uris desc 排序——广度爬虫（内容抓取、SEO 爬虫）
    - 过滤 unique_uris > 50 的 IP
  - top_allowed_repeaters：按 total desc 排序——深度刷单（抢票、抢券、量化交易）
    - 过滤 total > 200 AND unique_uris < 10 的 IP
  - 两个 query 排除 verified bot + 静态资源
  - 返回 top 25，包含 total/unique_uris/first_seen/last_seen

  CWL query (crawlers):
  ```
  filter action = 'ALLOW'
    and httpRequest.uri not like /\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)/
    and @message not like 'bot:verified'
  | stats count(*) as total,
          count_distinct(httpRequest.uri) as unique_uris,
          min(@timestamp) as first_seen,
          max(@timestamp) as last_seen
    by httpRequest.clientIp
  | filter unique_uris > 50
  | sort unique_uris desc
  | limit 25
  ```

  CWL query (repeaters):
  ```
  filter action = 'ALLOW'
    and httpRequest.uri not like /\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)/
    and @message not like 'bot:verified'
  | stats count(*) as total,
          count_distinct(httpRequest.uri) as unique_uris,
          min(@timestamp) as first_seen,
          max(@timestamp) as last_seen
    by httpRequest.clientIp
  | filter total > 200 and unique_uris < 10
  | sort total desc
  | limit 25
  ```

  注意 CWL 语法：`@message not like "X"`（不是 `not @message like "X"`，后者报错）

Step 2: analyze_ip 复合 tool（1 次 tool call = 两阶段查询）
  - 阶段 1：先单独跑 ip_diversity（~5-10s）
    - 多 UA + 多 JA4 (>3) = NAT → 直接返回 "NAT/shared IP, skipping"
  - 阶段 2（仅非 NAT）：并行跑 ip_cross_query + ip_request_rate + ip_ja4_fingerprints
  - 总超时 600s，每个子 query 超时 300s
  - 并发限制：module-level semaphore (max 8 concurrent CWL queries)

Step 3: 深入最可疑的 1 个 IP（如果 Step 2 发现异常）
  - ip_unique_uris + ip_uri_breakdown
  - 人类阈值：>200 unique 非静态 URIs/hour = 自动化

Step 4: 结论 + 问用户是否继续
  - 找到漏杀 → record_finding() + 展示证据
  - 没找到 → 告知用户 + 问是否查其他时间段
```

**性能预期**：
- 当前（18 tool calls × 25s）= 7.5 分钟
- 优化后（4 tool calls × 15s model + 15s parallel queries）= ~75 秒

**约束**：
- 每次日志查询窗口根据请求速率自动调整（不硬编码 6 小时）
- 每轮最多分析 3 个 IP（analyze_ip 内部并行）
- CWL 并发限制：semaphore max 8（留 headroom 给账号其他用途）
- 扩大范围前必须问用户

**深度调研（用户追问时）**：

当用户对某个 IP 或事件追问时，利用 managed rule labels 做深度分析：

```
ip_labels query → 返回该 IP 被 WAF 打的所有 labels
  - Bot Control labels: bot:name:*, bot:verified/unverified, bot:category:*, signal:*, TGT_*
  - Anti-DDoS labels: event-detected, ddos-request, high/medium/low-suspicion
  - Token labels: token:absent/accepted/rejected
  - Custom labels: 用户自定义的 Count+Label 规则

label_top_ips query → 给定 label，找哪些 IP 被打了这个标签
  - 例：label="ddos-request" → 找出所有被 AMR 标记为 DDoS 的 IP
  - 例：label="bot:name:googlebot" → 找出所有声称是 Googlebot 的 IP
```

关键分析逻辑：
- IP 有 bot labels 但没有 ddos labels → 纯 bot 行为
- IP 有 ddos labels 但没有 bot labels → 非 bot 的 volumetric 攻击（或 Bot Control 未启用）
- IP 同时有 bot + ddos labels → bot-driven DDoS
- IP 有 TGT_VolumetricIpTokenAbsent → Targeted 已检测到高频无 token 行为
- IP 有 signal:cloud_service_provider → 来自云基础设施（可能是被滥用的 EC2/Lambda）

**判断标准**：
- 单 UA + 单 JA4 + 高频 + 多样 URI = 浏览器自动化（Selenium/Playwright）
- 多 UA + 多 JA4 + 高频 = NAT gateway（不是 bot）
- 多 UA + 单 JA4 + 高频 = UA spoofing（同一工具）
- 多 IP + 相同行为模式 + 各自中等频率 = 住宅代理/IP 轮换

**输出**：
- 攻击类型（浏览器自动化 / 住宅代理 / token replay）
- 建议（Targeted Bot Control / TGT_VolumetricSession→CAPTCHA / TGT_TokenReuseIP→BLOCK）

### Scenario 4 (reserved): Rule Effectiveness Review (TBD)

---

## Competitive Landscape

截至 2026 年 5 月，AWS 没有任何原生服务能解决客户的 WAF 日志调查需求。

| 客户需求 | Security Agent | DevOps Agent | Security IR | Bot Control | 本工具 |
|---------|:---:|:---:|:---:|:---:|:---:|
| COUNT 规则是否误杀 | ❌ | ❌ | ❌ | ❌ | ✅ |
| 是否是真攻击 | ❌ | ❌ | ❌ | ❌ | ✅ |
| COUNT→BLOCK 决策 | ❌ | ❌ | ❌ | ❌ | ✅ |
| 攻击源排查 | ❌ | △ | ❌ | ❌ | ✅ |
| IP 是 bot 还是正常 | ❌ | ❌ | ❌ | △ (实时标签，无事后分析) | ✅ |

- **AWS Security Agent**: AppSec（pentest/SAST），不看 WAF 日志
- **AWS DevOps Agent**: 生产事件响应，无 WAF 领域知识
- **AWS Security Incident Response**: 调查 IAM/EC2 事件，不看 WAF 日志

---

## AgentCore Architecture

> **详细架构图见 `design/ARCHITECTURE.md`**

### Why AgentCore + Strands

- **Strands Agents SDK** 是 AWS 推荐的 agentic AI 框架，原生支持 AG-UI 协议
- **AgentCore Runtime** 提供 serverless microVM，session 隔离，最长 8 小时
- 迭代调查循环直接映射到 Strands 的原生 agentic loop
- **AG-UI 协议**：SSE streaming，用户实时看到 tool 调用进度

### Architecture

```
Browser (React SPA + AG-UI client)
    │
    │  SSE streaming (Bearer JWT from Cognito)
    ▼
AgentCore Runtime Endpoint (POST /runtimes/{arn}/invocations)
    │
    │  Session-isolated microVM (2 vCPU / 8 GB)
    ▼
Strands Agent (WAF Investigator)
    │  Claude Sonnet 4.6 (cross-region inference profile)
    │
    ├── @tool: get_waf_config()          → wafv2:GetWebACL
    ├── @tool: get_waf_metrics()         → cloudwatch:GetMetricData
    ├── @tool: run_logs_query()          → logs:StartQuery (max 7 days, 10-min timeout)
    ├── @tool: run_athena_query()        → athena:StartQueryExecution (for S3 logs, >7 days)
    ├── @tool: lookup_ja4()              → JA4 fingerprint → known client identification
    ├── @tool: record_finding()          → session state accumulator
    ├── @tool: generate_weekly_report()  → HTML report with charts
    ├── @tool: set_report_summary()      → inject LLM-generated summary into report
    └── @tool: review_waf_rules()        → 13 deterministic checks
```

### Key Technical Details

| 维度 | 方案 |
|------|------|
| Framework | Strands Agents SDK |
| Compute | AgentCore Runtime (microVM, session-isolated) |
| Model | `us.anthropic.claude-sonnet-4-6` (cross-region inference profile) |
| Max session | 8 hours |
| Streaming timeout | 60 minutes per invocation |
| IAM | AgentCore Execution Role 直接读取本账号 WAF 资源 |
| 认证 | Cognito JWT → AgentCore 原生验证（不需要 API Gateway） |
| 前端 | React SPA + AG-UI client（SSE streaming） |
| 前端托管 | CloudFront + S3 或 Amplify Hosting |
| Tool output | 每个 tool 最多返回 25 行（防止 context overflow） |
| Log query | MAX_POLL=600s, MAX_HOURS=168 (7 days, 超过用 Athena) |
| Health check | 使用内置 /ping |

### 部署架构（客户自部署 — Single-tenant）

```
客户 AWS 账号
├── CloudFront + S3（React SPA 前端）
│   └── AG-UI chat interface
├── Cognito User Pool（员工认证）
│   └── App Client → JWT token（前端直接用于调 AgentCore）
├── AgentCore Runtime（不需要 API Gateway 做代理）
│   ├── JWT Authorizer（Cognito token 验证，AgentCore 内置）
│   ├── SSE Streaming（AG-UI 协议，60 分钟 timeout）
│   ├── Execution Role（本账号权限）
│   │   ├── wafv2:GetWebACL, wafv2:ListWebACLs, wafv2:GetLoggingConfiguration
│   │   ├── logs:StartQuery, logs:GetQueryResults, logs:DescribeLogGroups
│   │   ├── cloudwatch:GetMetricData, cloudwatch:ListMetrics
│   │   ├── athena:StartQueryExecution, athena:GetQueryExecution, athena:GetQueryResults
│   │   ├── s3:GetObject, s3:ListBucket (Athena results + WAF logs)
│   │   ├── glue:GetTable, glue:GetDatabase (Athena catalog)
│   │   └── bedrock:InvokeModel, bedrock:InvokeModelWithResponseStream
│   └── Docker Image (ECR Public)
└── (可选) Cross-account role — 多 AWS 账号场景
```

**交付方式**：
- 代码开源到 `github.com/aws-samples/`
- Docker image 发布到 ECR Public（`public.ecr.aws`）
- CloudFormation/CDK template 一键部署：Cognito + AgentCore + S3/CloudFront + IAM
- 前端选项：CopilotKit（快速）或自定义 AG-UI client（灵活）

**与旧设计的区别**：
- ~~API Gateway HTTP API~~ → 不需要（AgentCore 原生支持 JWT auth + streaming）
- ~~Lambda bridge~~ → 不需要（前端直连 AgentCore endpoint）
- ~~29 秒 timeout~~ → 60 分钟 streaming timeout
- ~~同步 request/response~~ → AG-UI 实时事件流（用户看到每一步 tool 调用）

### Pricing Estimate

| 项目 | 估算 |
|------|------|
| Runtime（~5 min active CPU, 70% I/O wait）| ~$0.01-0.02 |
| Bedrock model（~56K input + ~14K output tokens）| ~$0.38 |
| CW Logs / Athena query 费用 | ~$0.01-0.05 |
| **总计** | **~$0.40-0.45 / 次调查** |

Model 调用费是主要成本（~85%）。

---

## Query Template System

LLM 不构造 query——只选择 `query_type` 并提供参数。脚本内部用模板生成 CWL query。

**已实现的 query types**（`tools/waf_logs.py`）：

| query_type | 用途 | 需要的参数 |
|---|---|---|
| `count_rule_top_ips` | COUNT 规则的 top IP | rule_name |
| `count_rule_top_uris` | COUNT 规则的 top URI | rule_name |
| `count_rule_top_uas` | COUNT 规则的 top UA | rule_name |
| `ip_cross_query` | 某 IP 的所有 action/rule | ip |
| `ip_uri_breakdown` | 某 IP 的 URI 分布 | ip |
| `ip_ja4_fingerprints` | 某 IP 的 JA4 指纹 | ip |
| `top_blocked_ips` | 被 BLOCK 最多的 IP | (无) |
| `top_blocked_rules` | BLOCK 最多的规则 | (无) |
| `top_allowed_ips` | ALLOW 最多的 IP | (无) |
| `top_countries_blocked` | 被 BLOCK 最多的国家 | (无) |
| `label_top_ips` | 某 label 的 top IP | label |
| `action_timeline` | 某 action 的时间线 | action |

**安全措施**：
- 参数值经过 sanitize（移除 `'"|;\`` 等字符）
- IP 用 `ipaddress` 模块校验（支持 IPv4 + IPv6）
- log_group 从 session_state 自动获取（不依赖 LLM 传入）

---

## Implementation Plan

### Phase 1: AgentCore MVP

- Strands Agent + AgentCore Runtime 部署
- 核心 tools：list_webacls、get_waf_config（含 capabilities 检测）、get_waf_metrics、run_logs_query（模板化）、lookup_ja4、generate_weekly_report
- Auto-discovery：ListWebACLs → GetLoggingConfiguration → 自动判断数据源
- Session state：region/scope/capabilities 自动传递，LLM 不需要记忆
- Scenario 4（Weekly Report）先交付
- Scenario 1（COUNT 规则评估）+ Scenario 2（漏杀/bypass 检测）
- Model/Region 可配置（环境变量）

### Phase 2: Full Investigation + Deployment

- run_athena_query（S3 日志支持）
- record_finding / ask_user tools
- AgentCore 部署 + Lambda bridge + Cognito 认证
- 端到端测试（EC2 打流量）

### Phase 3: Productization

- CloudFormation 一键部署（Cognito + API GW + Lambda + AgentCore + IAM）
- 发布到 github.com/aws-samples/ + ECR Public
- Weekly Report 丰富化（Bot Control 分类、Anti-DDoS 事件、成本效益）
- 多 WebACL / 多账号支持

### Testing Strategy

**核心问题**：自己的 AWS 账号有 WAF 但日志量不够，无法模拟真实攻击场景。

| 方案 | 适用场景 | 优缺点 |
|------|---------|--------|
| 自生成攻击流量 | 功能验证 | 对自己的 CloudFront/ALB 跑攻击工具（nikto、sqlmap、gobuster）。快速可控，但模式单一 |
| 客户真实环境 | 端到端验证 | 用客户的 role 访问真实日志。最真实，但需要客户配合 |
| 历史日志快照 | 离线开发 | 客户导出 S3 日志到我们的账号。可以反复测试同一份数据 |
| Mock 数据生成器 | 单元测试 + CI | 脚本生成符合 WAF log schema 的 JSON，推到 CW Logs。可模拟各种场景 |

**建议组合**：
1. 开发阶段：自生成攻击流量（验证 tool 能跑通）+ Mock 数据（验证 Agent 推理逻辑）
2. 验收阶段：客户真实环境（验证实际效果）

---

## Scenario 4: WAF Weekly Report（周报 — 价值证明）

### 背景

客户部署了 Anti-DDoS AMR 和 Bot Control（都有额外费用），需要向管理层证明这笔钱花得值。需求是一个自动化/半自动化的周报，汇总攻击拦截数据和 Bot 控制情况。

### 与 Investigation Engine 的关系

| | Investigation Engine | Weekly Report |
|---|---|---|
| 触发 | 出了问题时，人工触发 | 定期自动生成（每周） |
| 目标 | 找到根因、给出修复建议 | 证明 WAF 的价值、展示防护效果 |
| 受众 | 安全工程师 | 管理层 / 非技术决策者 |
| 输出 | 调查报告 + 规则建议 | 数据摘要 + 图表 + 趋势对比 |
| 深度 | 深（pivot chain） | 浅（聚合统计） |
| 共享基础设施 | ✅ 相同的 query 能力 | ✅ 相同的 query 能力 |

### 周报内容

**面向管理层的关键指标**：

#### 1. Executive Summary（由 Agent/Sonnet 4.6 生成，不是模板）

**生成流程**：`generate_weekly_report` tool 收集数据并生成 HTML（summary 留空）→ Agent 根据数据写 Markdown summary → `set_report_summary` 用 markdown lib 转 HTML 注入。

**Summary 必须包含 5 个段落**：
1. **概览** — 流量趋势变化、是否有异常事件
2. **DDoS/攻击** — 具体攻击事件、持续时间（分钟）、拦截数量
3. **Bot 流量**（必须单独一段）— verified bot（合法）、unverified bot（被拦截或因 override 被放行）、配置风险
4. **风险/建议** — 新出现的攻击来源、配置问题
5. **ROI 结论** — 钱花得值不值

**Domain knowledge 注入**（防止 LLM 犯错）：
- Anti-DDoS AMR 能拦截任何高频 IP（包括 JS-capable 浏览器自动化），只有高度分布式低频攻击才需要 Bot Control
- 如果 bot 规则被 override 到 Count，不能说"正确处置"

**语言**：与用户 prompt 语言一致。

**长度**：根据数据丰富程度自然决定，不设硬性限制。

**风格**：
- 用具体数字，不用模糊描述（"拦截了 1,283 次攻击"而不是"拦截了大量攻击"）
- 突出变化和异常（"与上周相比流量增长 400%，主要来自新加坡和爱尔兰"）
- 如果有风险/建议，放在最后一句（"建议关注来自 NL 的持续扫描活动"）
- 可以用 HTML `<span class='highlight'>` 强调关键数字

**Agent 收到的数据**（由 tool 返回）：
- 总请求量 + WoW 变化
- Threats mitigated（blocked + challenged）
- Bot/suspicious 请求数 + 占比
- Top 攻击来源国家
- Top blocking 规则 + 命中数
- Challenge issued 数量
- Daily trend（哪天有 spike）

#### 2. 攻击拦截概览
| 指标 | 本周 | 上周 | 变化 |
|------|------|------|------|
| 总请求量 | | | ↑/↓ % |
| 拦截请求量（BLOCK） | | | |
| 拦截率 | | | |
| DDoS 事件次数 | | | |
| DDoS 拦截请求量 | | | |

#### 3. Bot Control 效果
| 指标 | 本周 | 上周 | 变化 |
|------|------|------|------|
| Bot 请求总量 | | | |
| 已验证 bot（搜索引擎等） | | | |
| 恶意 bot 拦截量 | | | |
| Bot 占总流量比例 | | | |
| Token 验证成功率 | | | |

#### 4. Anti-DDoS AMR 效果
| 指标 | 本周 | 上周 | 变化 |
|------|------|------|------|
| DDoS 事件检测次数 | | | |
| 事件持续时间（平均/最长） | | | |
| Challenge 成功拦截量 | | | |
| Block 拦截量 | | | |
| 可疑 IP 数量 | | | |

#### 5. Top 攻击来源（国家/IP 段）
- 前 5 个攻击来源国家
- 前 5 个被拦截最多的 IP 段

#### 6. 成本效益（可选）
| 项目 | 金额 |
|------|------|
| Bot Control 月费 | $X |
| Anti-DDoS AMR 月费 | $X |
| 本周拦截的恶意请求量 | Y 万 |
| 如果这些请求到达源站的估算成本 | $Z（按 origin compute 估算）|

### 数据来源

周报所需数据全部来自 CloudWatch Metrics + WAF Logs，不需要新的数据源：

| 指标 | 数据源 | 查询方式 |
|------|--------|---------|
| 总请求/拦截量 | CW Metrics: AllowedRequests, BlockedRequests | GetMetricData (7 天 sum) |
| DDoS 事件 | WAF Logs: label `event-detected` | CWL Insights / Athena |
| Bot 分类统计 | WAF Logs: labels `bot:verified`, `bot:unverified`, `signal:non_browser_user_agent` | CWL Insights / Athena |
| Token 状态 | CW Metrics: RequestsWithValidChallengeToken | GetMetricData |
| Top 攻击来源 | WAF Logs: filter action=BLOCK, stats by country/IP | CWL Insights / Athena |
| 上周数据（对比） | 同上，时间范围改为上周 | 同上 |

### 输出格式

- **Markdown**：结构化文本，可以直接贴到邮件/Slack
- **HTML**：带 Chart.js 图表（复用现有 waf-analysis-report 的 HTML 模板）
- 图表：拦截量趋势（日粒度折线图）、Bot 分类饼图、攻击来源国家柱状图

### 实现方式

**Phase 1（CLI skill）**：
- 新增一个 `--weekly-report` 模式到现有 waf-runner.py
- 跑固定的 7-8 个聚合 query（不需要 pivot chain）
- LLM 生成 executive summary 文本
- 输出 Markdown + HTML

**Phase 2（AgentCore）**：
- 定时触发（EventBridge Scheduler → AgentCore invoke）
- 自动发送到 Slack/邮件
- 与上周数据对比（AgentCore Memory 存历史）

### 与 Investigation Engine 的代码复用

| 组件 | Investigation | Weekly Report | 复用 |
|------|--------------|---------------|------|
| CW Metrics 查询 | ✅ | ✅ | 共享 tool |
| CWL Insights 查询 | ✅ | ✅ | 共享 tool |
| WebACL 配置获取 | ✅ | ✅ | 共享 tool |
| HTML 报告生成 | ❌ | ✅ | 复用现有 waf-enrich.py html |
| Pivot chain | ✅ | ❌ | 不复用 |
| LLM 分析 | 深度推理 | 简单摘要 | 不同 prompt |

---

## Open Questions

1. **MVP 优先级**：Weekly Report 先交付（客户已明确需求，实现简单），Investigation Engine 紧随其后。
2. **Query 成本控制**：用 Cedar policy 限制单次调查的 query 次数？还是只靠 timeout？
3. **基线数据**：用 Metrics 7 天历史的 p95 作为基线？还是用 AgentCore Memory 存历史？
4. **Model 选择**：是否需要 Extended Thinking？调查逻辑需要强推理。
5. **客户 onboarding**：CloudFormation template 一键部署全套（Cognito + API Gateway + AgentCore + IAM Role）。客户只需运行 template，然后把员工加入 Cognito User Pool。
6. **ask_user tool**：Agent 提问后如何等待用户回复？AgentCore 的 session 模型支持吗？
7. **Weekly Report 定制化**：不同客户关注的指标不同（有的只有 Bot Control，有的只有 Anti-DDoS）。模板是固定的还是根据 WebACL 配置自动调整？
8. **Weekly Report 语言**：客户管理层可能需要中文/日文报告。LLM 生成 executive summary 时用什么语言？

---

## References

- [aws-waf-rules-reviewer](~/Documents/github/aws-waf-rules-reviewer/) — WAF 规则审查工具 + 完整的 WAF 行为参考文档
- [cloudwatch-log-insights-query-samples-for-waf](~/Documents/github/cloudwatch-log-insights-query-samples-for-waf/) — 经过验证的 CWL query 语法
- [aws-samples/waf-log-sample-athena-queries](https://github.com/aws-samples/waf-log-sample-athena-queries) — AWS 官方 Athena query 模板
- [AWS Security Services Best Practices: WAF](https://aws.github.io/aws-security-services-best-practices/guides/waf/) — 官方最佳实践
