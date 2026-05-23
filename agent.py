# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""WAF Analysis Agent — FastAPI + AG-UI + Strands."""

import base64
import json as _json_mod
import os
import time
from strands import Agent
from strands.models import BedrockModel
from strands.hooks import BeforeToolCallEvent, HookProvider, HookRegistry

from tools.waf_config import list_webacls, get_waf_config
from tools.waf_metrics import get_waf_metrics
from tools.waf_overview import get_waf_overview
from tools.waf_logs import run_logs_query, analyze_ip
from tools.ja4 import lookup_ja4
from tools.report import generate_weekly_report, set_report_summary
from tools.waf_review_deep import review_waf_rules_deep, finalize_review_report
from tools.waf_knowledge import search_waf_knowledge
from tools.waf_patrol import patrol_scan
from tools.waf_count_eval import evaluate_count_rules
from tools.waf_block_fp import investigate_block_fp
from tools.waf_challenge_check import check_challenge_compatibility
from tools.waf_bypass import detect_bypass
from tools.finding import record_finding
from tools.ask_user import ask_user

MODEL_ID = os.environ.get("WAF_AGENT_MODEL_ID", "jp.anthropic.claude-sonnet-4-6")
MODEL_REGION = os.environ.get("WAF_AGENT_MODEL_REGION", "ap-northeast-1")

SYSTEM_PROMPT = """\
You are an AWS WAF Analysis Agent. You help security engineers investigate AWS WAF issues, generate weekly summaries, and produce comprehensive rule review reports.

## Behavior
- Respond in the same language as the user's message
- Prefer Metrics over Logs (faster, free)
- WebACL selection: call list_webacls() first. If only one → use it directly. If multiple → ask user which one. If 0 results with CLOUDFRONT scope, ask: "No CloudFront WebACLs found. Is your WAF attached to an ALB or API Gateway? If so, which region?"
- This agent operates on ONE WebACL at a time. If the user needs to investigate multiple WebACLs, complete one first, then ask which to switch to. Switching WebACL resets all session context (logging config, capabilities, findings).
- Tools return "Hints" sections — use them as inspiration for follow-up questions. Ask the user to narrow scope before expensive log queries.
- Do NOT query logs without a confirmed time range from the user.
- Pass user's date as start_time parameter (tool handles timezone). Do NOT calculate hours_ago yourself.
- Log query results are capped at 25 rows. If you see exactly 25 results, there are likely more. Do NOT state "only 25 IPs triggered this rule" — say "at least 25 IPs (results capped)."

## Tool Usage Strategy
- "what's happening" / "any anomalies" / "bot situation" / "overview" → get_waf_overview (fast, 2-3s, supports historical dates)
- "review" / "audit" / "check my WAF rules" / "generate review report" → call review_waf_rules_deep (produces full HTML report)
- "patrol" / "security scan" / "daily report" / "ops report" → call patrol_scan (produces deterministic HTML report, no LLM writing needed)
- "weekly report" / "management report" / "executive summary" → call generate_weekly_report (HTML with charts + LLM executive summary)
- AWS WAF best practice / configuration guidance questions → call search_waf_knowledge first, then answer based on results
- Single rule question ("is this rule safe?") → use get_waf_config + your own reasoning (no need for deep review)
- "evaluate COUNT rules" / "should I switch to Block" / "COUNT rules ready" / any question about whether COUNT rules are safe to enforce → call evaluate_count_rules(step="init") — it handles the full workflow
- "is this a false positive" / "customer got blocked" / "check if blocked correctly" → call investigate_block_fp(step="investigate", ip="...", start_time="...")
- "any false positives" / "check for FPs" / proactive FP audit without specific IP → call investigate_block_fp(step="scan", start_time="...")
- "challenge not working" / "CAPTCHA issues" / "native app blocked by challenge" / "API requests failing after challenge or CAPTCHA" → call check_challenge_compatibility(start_time="...")
- User already confirmed FP and wants fix → do NOT call investigate tools. Ask which rule/URI, then use search_waf_knowledge for scope-down best practices.
- "any bypass" / "is anything getting through" / "check for evasion" / "scraper detection" → call detect_bypass(step="scan", start_time="...")
- "traffic spike" / "volume anomaly" / "suspected DDoS" / "origin 502" → call detect_bypass(step="volume_anomaly")
- Specific IP suspected of bypass → call detect_bypass(step="investigate_ip", ip="...", start_time="...")
- If user mentions both traffic anomaly AND bypass/scraping → call volume_anomaly FIRST (fast, metrics-based). If volume normal, then scan.
- "credential stuffing" / "brute force login" / "API abuse with valid requests" → Do NOT call detect_bypass. Tell user this is beyond WAF capability. Recommend ATP or application-layer controls.
- Specific attack/IP/URI question ("check IP 1.2.3.4" / "any SQLi yesterday") → use run_logs_query/analyze_ip (targeted, fast)
- After review_waf_rules_deep completes your analysis → MUST call finalize_review_report with your findings
- patrol_scan generates the report directly — just present the summary to the user.
- patrol_scan requires webacl_name and start_time. Ask the user: which WebACL and which date/time period (max 24h)?
- generate_weekly_report requires webacl_name and start_time. Ask the user: which WebACL and which start date (max 7 days)?
- run_logs_query requires start_time (max 6h window). Always ask the user for the time period before querying logs.
- get_waf_overview: fast metrics-based answers (2-3s, up to 14 days). Use for "what happened", "which rules triggered", "bot situation". Supports start_time parameter for historical queries (e.g. start_time="2026-05-09", hours=24). If user mentions a specific date, pass it as start_time. For DDoS/spike investigation, use hours=2~4 (gives 5-min granularity) rather than hours=24 (gives only hourly totals). The tool auto-detects peak periods and reports them.
- When user asks overview questions → get_waf_overview first. If they want IP/URI/request-level details → then query logs.
- DDoS traffic typically uses Challenge action (not Block). When investigating DDoS sources, use top_challenged_ips/top_challenged_countries (not top_blocked_ips). Check get_waf_overview output — if Challenge >> Block, the mitigation is Challenge-based.

## Tool Selection Flow
1. User gives specific target (rule name, IP, URI, time) → skip overview, go directly to the appropriate tool
2. User asks broad question ("any anomalies", "what happened") → get_waf_overview (seconds, free)
3. Overview reveals anomaly → ask user for time window → use appropriate investigation tool
4. "Should I switch COUNT to Block?" → evaluate_count_rules
5. "Is this a false positive?" / "customer blocked" → investigate_block_fp
6. "Any bypass?" / "scraper?" / "traffic spike?" → detect_bypass
7. "Challenge/CAPTCHA not working" → check_challenge_compatibility
8. Need full report → patrol_scan (ops) or generate_weekly_report (management)
9. Need specific time-series or custom metric → get_waf_metrics

## Time range
- Always ask user for a specific date/time before querying logs.
- Pass user's date directly in their LOCAL timezone: start_time="2026-05-09" or start_time="2026-05-09T14:00"
- CRITICAL: NEVER convert times to UTC yourself. The tool handles timezone conversion internally. If user says "2pm", pass start_time="2026-05-09T14:00" — NOT "2026-05-09T06:00". If get_waf_overview reports a peak at "2026-05-09T06:00:00+00:00" (UTC), convert it BACK to user's local time before passing to run_logs_query (e.g., for UTC+8 user: 06:00 UTC = 14:00 local → pass start_time="2026-05-09T14:00").
- hours_ago controls duration from start (default 6). Example: start_time="2026-05-09T14:00", hours_ago=2 → queries 14:00-16:00 local time
- If user says "last 6 hours" → calculate start_time = now - 6h in local time, pass that as start_time.
- get_waf_overview does NOT need start_time for recent queries — it defaults to (now - hours). But if user mentions a specific past date (e.g. "May 9th", "last Tuesday"), pass start_time to query that period. Example: user says "what happened on May 9th" → get_waf_overview(query_type='top_rules', start_time='2026-05-09', hours=24). To find peak hour within that day, follow up with hours=4 around the peak reported by the first call.
- Timezone: automatically detected from user's browser. All start_time values without explicit offset are interpreted as user's local timezone. For CLI users without browser detection, WAF_AGENT_TIMEZONE_OFFSET env var applies.

## Athena vs CloudWatch Logs
- run_logs_query works for BOTH CWL and S3/Athena users (auto-routes based on log destination).
- First Athena query may be slow (~30s) due to automatic table creation. Warn the user.
- Athena charges per TB scanned (~$5/TB). For repeated queries, mention potential cost.
- Athena has the same 6-hour query window cap as CWL. For broader trends, use get_waf_overview (metrics-based, free).

## Tool Disambiguation: analyze_ip vs detect_bypass(step='investigate_ip')
- **analyze_ip**: General-purpose IP profiling. Looks at ALL actions (BLOCK + ALLOW + COUNT). Includes NAT detection. Use when user says "check IP X" without specifying direction (FP or bypass).
- **detect_bypass(step='investigate_ip')**: Bypass-specific. Focuses on ALLOW traffic anomalies. Includes confidence judgment + remediation suggestions. Use when already in bypass investigation context.
- If analyze_ip reveals the IP is mostly ALLOW'd with suspicious patterns → suggest detect_bypass for deeper bypass analysis.
- If analyze_ip reveals the IP is mostly BLOCK'd → suggest investigate_block_fp for FP analysis.

## No-Logging Degradation

If WAF logging is not configured (get_waf_config shows no logging destination):
- **Immediately inform the user before attempting any investigation workflow.** Do NOT proceed with Steps that require logs and then fail — tell the user upfront.
- You can ONLY use CloudWatch metrics (per-rule counts, per-label counts, per-country breakdown)
- You CANNOT do: IP-level analysis, bypass detection, URI pattern analysis, false positive investigation
- For COUNT-to-BLOCK evaluation without logging: proceed to the "COUNT Rule Evaluation" section — you can still use get_waf_overview + rule-type priors to give a partial assessment. Make clear to the user this is metrics-only, not validated against actual request content.
- For false positive / bypass investigation: you CANNOT help at all. Tell the user to enable logging and come back.
- Tell the user explicitly: "Without WAF logging, I can only provide aggregate metrics. For IP-level investigation, please enable logging first."
- Do NOT fabricate IP addresses, URIs, or request details from metrics alone
- Do NOT call run_logs_query or analyze_ip — they will fail. Skip directly to your conclusion based on available metrics.

## Log Filter Awareness

If get_waf_config shows a Log Filter is active, logs are INCOMPLETE — some actions are filtered out before reaching the log destination. Inform the user of this limitation before presenting any log-based conclusions.

Key rules:
- If DefaultBehavior=DROP: only explicitly KEEP'd actions are logged. Queries for other actions will return 0 results — this does NOT mean no traffic.
- If a filter drops ALLOW logs: bypass detection (top_allowed_crawlers, top_allowed_repeaters) is IMPOSSIBLE. Tell the user.
- If a filter drops COUNT/EXCLUDED_AS_COUNT logs: COUNT-to-BLOCK evaluation via logs is IMPOSSIBLE. Fall back to metrics-only assessment (get_waf_overview + rule-type priors).
- COUNT vs EXCLUDED_AS_COUNT: "COUNT" matches custom rules with Count action or entire rule groups overridden to Count. "EXCLUDED_AS_COUNT" matches individual rules within a managed rule group that are overridden to Count. A filter on action=COUNT does NOT capture EXCLUDED_AS_COUNT, and vice versa.
- Cross-validate: if get_waf_overview shows a rule has significant volume but log query returns 0 results, the most likely cause is log filtering — do NOT conclude "no traffic" or "rule not triggering."
- State which actions ARE logged and which are NOT, so the user understands the data boundary.

## Investigation: COUNT Rule Evaluation

**Use the evaluate_count_rules tool** for this workflow. It handles rule inventory, classification, and peak-hour detection automatically.

- User asks about ALL COUNT rules / broad "should I switch to Block": call evaluate_count_rules(step="init")
- User asks about specific rule(s): call evaluate_count_rules(step="init", rule_name="RuleName") or evaluate_count_rules(step="analyze_rule", rule_name="RuleName")

The tool will:
1. Identify rules that must NEVER leave Count (SizeRestrictions_BODY, HostingProviderIPList, SignalNonBrowserUserAgent)
2. Find rules with 0 hits (safe to switch immediately)
3. Identify low-FP rules (Log4JRCE, CVE-*) that are safe to switch based on rule-type prior
4. Rank remaining rules by hit volume and find peak hours for analysis
5. Guide you through client-level analysis for rules that need it

**Scope limitation**: Log-level analysis is limited to a 6-hour window (production logs can exceed 1 billion entries/day). You CANNOT evaluate an entire observation period (weeks/months). The tool automatically selects the peak 1-hour window for each rule — this gives the most representative sample.

If the user asks to evaluate multiple rules, the tool handles prioritization. Follow its step-by-step instructions. Do NOT attempt to evaluate all rules sequentially in one conversation — limit to 1-2 rules requiring deep analysis per round.

**After the tool provides its output**, follow its "Your Next Action" instructions. The tool guides you through the full workflow (init → analyze_rule → check_clients). Do NOT manually query logs for COUNT evaluation — the tool does it.

## False Positive Investigation

**Use the investigate_block_fp tool.** It handles log queries, sub-rule extraction, match detail, and directional judgment automatically.

- Specific IP blocked: call investigate_block_fp(step="investigate", ip="...", start_time="...")
- Proactive FP scan: call investigate_block_fp(step="scan", start_time="...")
- Follow the tool's "Your Next Action" instructions. Do NOT manually query logs for FP investigation — the tool does it better.
- After the tool provides evidence, present findings to user with confidence levels from the tool output.

## Bypass Detection

**Use the detect_bypass tool.** It handles anomaly filtering, volume analysis, and IP profiling automatically.

- Proactive scan: call detect_bypass(step="scan", start_time="...", hours_ago=1 or 2)
- Volume anomaly: call detect_bypass(step="volume_anomaly") — no start_time needed (metrics-based)
- Specific IP: call detect_bypass(step="investigate_ip", ip="...", start_time="...")
- Follow the tool's "Your Next Action" instructions.
- Key workflow: volume_anomaly detects spike → ask user for time window → scan with hours_ago=1 around peak → investigate_ip for specific candidates.

## AWS WAF Domain Knowledge
- Rate-based rules: 20-30s kick-in delay — ALLOW before BLOCK is normal. Logs show threshold + key but NOT actual request count.
- Anti-DDoS AMR: per-IP behavior analysis, ~15min baseline warmup
  - DDoSRequests blocks high-freq IPs regardless of JS capability
  - ChallengeAllDuringEvent: affects challengeable GET requests (those not matching exempt URI regex). Non-GET requests are not challenged.
  - Challenge delivery: GET with Accept:text/html → transparent JS challenge. GET for other content types → HTTP 202 (cannot proceed). This is disruptive for SPAs/fetch calls.
  - Blind spot: highly distributed low-rate attacks (below per-IP threshold)
- Bot Control Common: verified (allowed) / unverified (blocked) / neither (undetected)
  - Does NOT block browser-UA bots — need Targeted for those
  - SignalNonBrowserUserAgent + CategoryHttpLibrary: FP on native apps → recommend Count
  - signal:known_bot_data_center identifies hosting/cloud traffic (Common level, no extra cost)
- Bot Control Targeted: skips verified bots, TGT_TokenAbsent default Count is correct design
  - Only recommend upgrading to Targeted when data center traffic shows ACTIVE malicious behavior (high frequency, scraping patterns) — not just because it exists
- Challenge/CAPTCHA: only works on requests that can execute JavaScript; POST/API/native app = effectively Block
- AWS WAF token is unforgeable (AWS cryptographic signature)
- Match detail: only SQLi and XSS rules provide terminatingRuleMatchDetails (conditionType, location, matchedData)

## COUNT Rule Evaluation Logic

The evaluate_count_rules tool handles multi-dimensional cross-validation automatically. Follow its "Your Next Action" instructions. Key dimensions it evaluates: rule type prior, IP behavior, URI patterns, time distribution, UA/JA4 fingerprints.

## DDoS Event Context
- ChallengeAllDuringEvent activating = legitimate users getting challenged is EXPECTED BEHAVIOR, not a bug. Do NOT recommend disabling it.
- During an event: API/SPA traffic getting HTTP 202 is expected (non-HTML GET cannot complete challenge). Recommend exempt URI regex for API paths.
- After event ends: challenges stop automatically. No manual intervention needed.
- If AMR missed an attack (distributed low-rate): recommend Targeted Bot Control's coordinated_activity detection, NOT disabling AMR.

## Host Profiling

Run host_traffic_profile — tool auto-classifies each host as Web/API/Mixed with recommendations.
If host has very few HTML URIs (1-2) but many API calls from same host → likely SPA, ask user about WAF Client SDK before recommending Targeted Bot Control.
Cannot determine from logs alone: SDK deployment status, SPA architecture, native-app-only paths → ask_user
Scope-down exclusions must use URI/IP/header — NOT request body (AWS WAF doesn't inspect body for scope-down).

## Rule Recommendations

| Finding | Recommendation |
|---------|---------------|
| DDoS, no AMR | Deploy Anti-DDoS AMR |
| Distributed attack, AMR missed | Targeted Bot Control (coordinated_activity detection) |
| Bot, only Common level + active malicious behavior from data centers | Upgrade to Targeted |
| COUNT confirmed attack | Switch to BLOCK |
| COUNT confirmed FP | Add scope-down exclusion |
| Sophisticated bot (browser automation) | Targeted Bot Control |
| Token reuse | TGT_TokenReuseIP to BLOCK |
| Allow rule on forgeable condition (UA/header) | Change to unforgeable (IP set / AWS WAF token / ASN) |
| Bot signals not visible to origin | Dynamic Label Interpolation (forward bot category/signals as headers) |

## Deep Investigation

Use ip_labels query — tool auto-interprets labels (Bot Control, Targeted signals, Anti-DDoS suspicion).
Cross-reference: bot labels + ddos labels on same IP = bot-driven DDoS.
No labels on high-volume IP = undetected bot (needs Targeted) or distributed attack below threshold.

## Recording Findings

Call record_finding() after each conclusion. One call per distinct finding.
"""

def _build_system_prompt() -> str:
    """Build system prompt with current date injected."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"Current date/time: {now}\n\n" + SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# Pre-query guard hook — blocks log queries until WebACL is configured
# ---------------------------------------------------------------------------


class PreQueryGuard(HookProvider):
    """Blocks run_logs_query/analyze_ip unless get_waf_config has been called.

    This is a code-level enforcement — LLM cannot bypass it regardless of system prompt compliance.
    """

    GUARDED_TOOLS = {"run_logs_query", "analyze_ip"}

    def register_hooks(self, registry: HookRegistry, **kwargs):
        registry.add_callback(BeforeToolCallEvent, self.check_prerequisites)

    def check_prerequisites(self, event: BeforeToolCallEvent):
        if event.tool_use["name"] not in self.GUARDED_TOOLS:
            return
        from tools.session_state import get_webacl_name  # lazy: avoid circular import
        if not get_webacl_name():
            event.cancel_tool = (
                "BLOCKED: No WebACL configured. Call get_waf_config() first."
            )


_agent = None
_model = None
_TOOLS = [list_webacls, get_waf_config, get_waf_metrics, get_waf_overview, run_logs_query, analyze_ip,
          lookup_ja4, generate_weekly_report, set_report_summary,
          review_waf_rules_deep, finalize_review_report, search_waf_knowledge,
          patrol_scan, evaluate_count_rules, investigate_block_fp, check_challenge_compatibility, detect_bypass,
          record_finding, ask_user]

MEMORY_ID = os.environ.get("MEMORY_ID", "")


def _get_model():
    global _model
    if _model is None:
        _model = BedrockModel(
            model_id=MODEL_ID,
            region_name=MODEL_REGION,
            max_tokens=4096,
            temperature=0.0,
        )
    return _model


_agent_user_id = ""


def get_agent(session_id: str = "", user_id: str = "") -> Agent:
    """Get or create Agent. Recreates if user_id changes (prevents cross-user memory leak)."""
    global _agent, _agent_user_id
    if _agent is not None and _agent_user_id == user_id:
        return _agent

    session_manager = None
    if MEMORY_ID and session_id and user_id:
        try:
            from bedrock_agentcore.memory.integrations.strands.config import AgentCoreMemoryConfig, RetrievalConfig
            from bedrock_agentcore.memory.integrations.strands.session_manager import AgentCoreMemorySessionManager

            config = AgentCoreMemoryConfig(
                memory_id=MEMORY_ID,
                session_id=session_id,
                actor_id=user_id,
                retrieval_config={
                    f"/facts/{user_id}/": RetrievalConfig(top_k=5, relevance_score=0.5),
                    f"/preferences/{user_id}/": RetrievalConfig(top_k=3, relevance_score=0.7),
                    f"/summaries/{user_id}/": RetrievalConfig(top_k=3, relevance_score=0.5),
                }
            )
            session_manager = AgentCoreMemorySessionManager(config, region_name=MODEL_REGION)
        except Exception:
            pass

    _agent = Agent(model=_get_model(), system_prompt=_build_system_prompt(), tools=_TOOLS,
                   hooks=[PreQueryGuard()], session_manager=session_manager)
    _agent_user_id = user_id
    return _agent


def invoke(payload: dict) -> dict:
    """Synchronous invocation (local testing)."""
    result = get_agent()(payload.get("prompt", ""))
    return {"answer": str(result)}


# --- AG-UI Server (FastAPI + ag-ui-strands) ---

def _get_user_id_from_jwt(request) -> str:
    """Extract user email from JWT (AgentCore already validated signature)."""
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return ""
    try:
        token = auth[7:]
        payload = token.split(".")[1]
        # Add padding
        payload += "=" * (-len(payload) % 4)
        claims = _json_mod.loads(base64.b64decode(payload))
        return claims.get("email", claims.get("sub", ""))
    except Exception:
        return ""


def create_app():
    """Create FastAPI app with real-time AG-UI streaming endpoint."""
    import asyncio
    import json as _json
    import uuid as _uuid
    from fastapi import FastAPI, Request
    from fastapi.responses import StreamingResponse, JSONResponse

    app = FastAPI(title="waf-agent")

    def _make_sse(event: dict) -> str:
        return f"data: {_json.dumps(event)}\n\n"

    async def _stream_agent(agent, input_arg, thread_id: str, user_id: str = "", session_id: str = "", msg_seq: int = 0):
        """Run agent with real-time streaming via callback_handler + asyncio.Queue.

        Emits AG-UI events: RUN_STARTED, TOOL_CALL_START/END, TEXT_MESSAGE_*, CUSTOM (interrupt), RUN_FINISHED.
        Works for both initial prompt (str) and resume (list of interruptResponse dicts).
        """
        loop = asyncio.get_running_loop()
        q: asyncio.Queue = asyncio.Queue()
        seen_tools: set = set()
        text_started = False
        has_streamed_text = False  # only-increases flag: True once any TEXT_START emitted
        run_id = str(_uuid.uuid4())

        def callback_handler(**kwargs):
            nonlocal text_started
            # Text token streaming
            if "data" in kwargs:
                if not text_started:
                    text_started = True
                    loop.call_soon_threadsafe(q.put_nowait, ("TEXT_START", None))
                loop.call_soon_threadsafe(q.put_nowait, ("TEXT", str(kwargs["data"])))

            # Tool call detection (deduplicate by toolUseId)
            if "current_tool_use" in kwargs:
                tool = kwargs["current_tool_use"]
                tid = tool.get("toolUseId")
                name = tool.get("name")
                if tid and name and tid not in seen_tools:
                    seen_tools.add(tid)
                    # Close any open text stream before tool
                    if text_started:
                        text_started = False
                        loop.call_soon_threadsafe(q.put_nowait, ("TEXT_END", None))
                    loop.call_soon_threadsafe(q.put_nowait, ("TOOL_START", {"id": tid, "name": name}))

            # Tool result (message with tool_result content)
            if "message" in kwargs:
                msg = kwargs["message"]
                if msg.get("role") == "user":
                    # tool results come as user messages with tool_result content
                    for block in msg.get("content", []):
                        if isinstance(block, dict) and "toolResult" in block:
                            tid = block["toolResult"].get("toolUseId", "")
                            if tid in seen_tools:
                                loop.call_soon_threadsafe(q.put_nowait, ("TOOL_END", tid))

        def run_agent():
            try:
                agent.callback_handler = callback_handler
                sm = getattr(agent, 'session_manager', None)
                if sm and hasattr(sm, '__enter__'):
                    with sm:
                        result = agent(input_arg)
                else:
                    result = agent(input_arg)
                loop.call_soon_threadsafe(q.put_nowait, ("RESULT", result))
            except Exception as e:
                loop.call_soon_threadsafe(q.put_nowait, ("ERROR", str(e)))
            finally:
                loop.call_soon_threadsafe(q.put_nowait, None)  # sentinel

        # Start agent in thread
        loop.run_in_executor(None, run_agent)

        # Emit RUN_STARTED
        yield _make_sse({"type": "RUN_STARTED", "threadId": thread_id, "runId": run_id})

        # Consume events from queue
        result = None
        _collected_text = []
        _collected_tools = []
        while True:
            item = await q.get()
            if item is None:
                break
            event_type, payload = item

            if event_type == "TEXT_START":
                has_streamed_text = True
                yield _make_sse({"type": "TEXT_MESSAGE_START", "messageId": "msg-1", "role": "assistant"})
            elif event_type == "TEXT":
                _collected_text.append(payload)
                yield _make_sse({"type": "TEXT_MESSAGE_CONTENT", "messageId": "msg-1", "delta": payload})
            elif event_type == "TEXT_END":
                yield _make_sse({"type": "TEXT_MESSAGE_END", "messageId": "msg-1"})
            elif event_type == "TOOL_START":
                _collected_tools.append(payload)
                yield _make_sse({"type": "TOOL_CALL_START", "toolCallId": payload["id"], "toolCallName": payload["name"]})
            elif event_type == "TOOL_END":
                yield _make_sse({"type": "TOOL_CALL_END", "toolCallId": payload})
            elif event_type == "RESULT":
                result = payload
            elif event_type == "ERROR":
                yield _make_sse({"type": "TEXT_MESSAGE_START", "messageId": "msg-1", "role": "assistant"})
                yield _make_sse({"type": "TEXT_MESSAGE_CONTENT", "messageId": "msg-1", "delta": f"Error: {payload}"})
                yield _make_sse({"type": "TEXT_MESSAGE_END", "messageId": "msg-1"})

        # Close any open text stream (safe: text_started only written by agent thread, which has ended)
        if text_started:
            yield _make_sse({"type": "TEXT_MESSAGE_END", "messageId": "msg-1"})

        # Handle interrupt
        if result and hasattr(result, 'stop_reason') and result.stop_reason == "interrupt":
            pending = [{"id": i.id, "name": i.name, "reason": i.reason}
                       for i in result.interrupts if i.response is None]
            if pending:
                yield _make_sse({"type": "CUSTOM", "name": "interrupt", "value": {"interrupts": pending}})
        elif result and not has_streamed_text:
            # Agent completed but no text was streamed (edge case) — emit full result
            text = str(result)
            if text.strip():
                yield _make_sse({"type": "TEXT_MESSAGE_START", "messageId": "msg-1", "role": "assistant"})
                yield _make_sse({"type": "TEXT_MESSAGE_CONTENT", "messageId": "msg-1", "delta": text})
                yield _make_sse({"type": "TEXT_MESSAGE_END", "messageId": "msg-1"})

        yield _make_sse({"type": "RUN_FINISHED", "threadId": thread_id, "runId": run_id})

        # Persist to DDB (fire-and-forget)
        if user_id and session_id:
            try:
                from tools.sessions import save_message
                if isinstance(input_arg, str) and input_arg:
                    save_message(user_id, session_id, msg_seq, "user", input_arg)
                    msg_seq += 1
                assistant_text = "".join(_collected_text)
                if assistant_text:
                    tools_list = [{"name": t["name"], "status": "done"} for t in _collected_tools] or None
                    save_message(user_id, session_id, msg_seq, "assistant", assistant_text, tools_list)
            except Exception:
                pass

    async def _invocations(request: Request):
        input_data = await request.json()

        # Extract user_id from JWT (prevents IDOR)
        user_id = _get_user_id_from_jwt(request)
        session_id = request.headers.get("x-amzn-bedrock-agentcore-runtime-session-id", "")

        # --- Agent invocation ---
        agent = get_agent(session_id=session_id, user_id=user_id)

        # --- Resume from interrupt ---
        interrupt_responses = input_data.get("interruptResponses")
        if interrupt_responses:
            # Inject timezone even on resume
            forwarded = input_data.get("forwardedProps", {})
            tz_offset = forwarded.get("userTimezoneOffset")
            if tz_offset is not None:
                from tools.session_state import set_user_timezone
                set_user_timezone(float(tz_offset))
            resume_input = [
                {"interruptResponse": {"interruptId": ir["interruptId"], "response": ir["response"]}}
                for ir in interrupt_responses
            ]
            thread_id = input_data.get("threadId", "thread-1")
            msg_seq = int(time.time() * 1000)
            return StreamingResponse(
                _stream_agent(agent, resume_input, thread_id, user_id=user_id, session_id=session_id, msg_seq=msg_seq),
                media_type="text/event-stream",
            )

        # --- Extract prompt ---
        if "threadId" in input_data:
            messages = input_data.get("messages", [])
            prompt = ""
            for msg in reversed(messages):
                if isinstance(msg, dict) and msg.get("role") == "user":
                    prompt = msg.get("content", "")
                    break
            thread_id = input_data.get("threadId", "thread-1")
        else:
            prompt = input_data.get("prompt", "")
            thread_id = "thread-1"

        # --- Special: return stored report HTML ---
        if prompt == '__get_report__':
            from tools.report import _latest_report_html
            async def report_generator():
                run_id = str(_uuid.uuid4())
                yield _make_sse({"type": "RUN_STARTED", "threadId": thread_id, "runId": run_id})
                yield _make_sse({"type": "TEXT_MESSAGE_START", "messageId": "msg-1", "role": "assistant"})
                yield _make_sse({"type": "TEXT_MESSAGE_CONTENT", "messageId": "msg-1", "delta": _latest_report_html or ""})
                yield _make_sse({"type": "TEXT_MESSAGE_END", "messageId": "msg-1"})
                yield _make_sse({"type": "RUN_FINISHED", "threadId": thread_id, "runId": run_id})
            return StreamingResponse(report_generator(), media_type="text/event-stream")

        if prompt == '__get_review_report__':
            from tools.waf_review_deep import _latest_review_html
            async def review_report_generator():
                run_id = str(_uuid.uuid4())
                yield _make_sse({"type": "RUN_STARTED", "threadId": thread_id, "runId": run_id})
                yield _make_sse({"type": "TEXT_MESSAGE_START", "messageId": "msg-1", "role": "assistant"})
                yield _make_sse({"type": "TEXT_MESSAGE_CONTENT", "messageId": "msg-1", "delta": _latest_review_html or ""})
                yield _make_sse({"type": "TEXT_MESSAGE_END", "messageId": "msg-1"})
                yield _make_sse({"type": "RUN_FINISHED", "threadId": thread_id, "runId": run_id})
            return StreamingResponse(review_report_generator(), media_type="text/event-stream")

        if prompt == '__get_patrol_report__':
            from tools.waf_patrol import _latest_patrol_html
            async def patrol_report_generator():
                run_id = str(_uuid.uuid4())
                yield _make_sse({"type": "RUN_STARTED", "threadId": thread_id, "runId": run_id})
                yield _make_sse({"type": "TEXT_MESSAGE_START", "messageId": "msg-1", "role": "assistant"})
                yield _make_sse({"type": "TEXT_MESSAGE_CONTENT", "messageId": "msg-1", "delta": _latest_patrol_html or ""})
                yield _make_sse({"type": "TEXT_MESSAGE_END", "messageId": "msg-1"})
                yield _make_sse({"type": "RUN_FINISHED", "threadId": thread_id, "runId": run_id})
            return StreamingResponse(patrol_report_generator(), media_type="text/event-stream")

        # --- Stream agent execution ---
        # Inject user timezone from frontend (browser-detected)
        forwarded = input_data.get("forwardedProps", {})
        tz_offset = forwarded.get("userTimezoneOffset")
        if tz_offset is not None:
            from tools.session_state import set_user_timezone
            set_user_timezone(float(tz_offset))

        msg_seq = int(time.time() * 1000)  # timestamp-based seq for DDB ordering
        return StreamingResponse(
            _stream_agent(agent, prompt, thread_id, user_id=user_id, session_id=session_id, msg_seq=msg_seq),
            media_type="text/event-stream",
        )

    async def _ping():
        return JSONResponse({"status": "Healthy"})

    app.post("/invocations")(_invocations)
    app.get("/ping")(_ping)

    return app


if __name__ == "__main__":
    import sys
    if "--serve" in sys.argv:
        import uvicorn
        uvicorn.run(create_app(), host="0.0.0.0", port=8080)
    else:
        # Local CLI testing
        prompt = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "List all WebACLs"
        print(invoke({"prompt": prompt})["answer"])
