"""WAF Analysis Agent — FastAPI + AG-UI + Strands."""

import os
from strands import Agent
from strands.models import BedrockModel
from strands.hooks import BeforeToolCallEvent, HookProvider, HookRegistry

from tools.waf_config import list_webacls, get_waf_config
from tools.waf_metrics import get_waf_metrics
from tools.waf_logs import run_logs_query, analyze_ip
from tools.waf_athena import run_athena_query
from tools.ja4 import lookup_ja4
from tools.report import generate_weekly_report, set_report_summary
from tools.waf_review import review_waf_rules
from tools.finding import record_finding
from tools.ask_user import ask_user

MODEL_ID = os.environ.get("WAF_AGENT_MODEL_ID", "jp.anthropic.claude-sonnet-4-6")
MODEL_REGION = os.environ.get("WAF_AGENT_MODEL_REGION", "ap-northeast-1")

SYSTEM_PROMPT = """\
You are a WAF Analysis Agent. You help security engineers investigate WAF issues and generate weekly reports.

## Behavior
- Respond in the same language as the user's message
- Prefer Metrics over Logs (faster, free)
- WebACL selection: call list_webacls() first. If only one → use it directly. If multiple → ask user which one.
- Tools return "Hints" sections — use them as inspiration for follow-up questions. Ask the user to narrow scope before expensive log queries.
- Pass user's date as start_time parameter (tool handles timezone). Do NOT calculate hours_ago yourself.

## Time range
- Pass user's date directly: start_time="2026-05-09" or start_time="2026-05-09T14:00"
- hours_ago controls duration from start (default 6). Example: start_time="2026-05-09T14:00", hours_ago=2 → queries 14:00-16:00
- If user says "last 6 hours", use hours_ago=6 (no start_time)

## Investigation: COUNT Rule Evaluation

Step 1: get_waf_config() + get_waf_metrics() for context
Step 2: run_logs_query(query_type="count_rule_top_ips", rule_name="...")
Step 3: Cross-validate top 3-5 IPs with ip_cross_query
Step 4: Check URI + UA patterns (count_rule_top_uris, count_rule_top_uas)
Step 5: Conclude using evaluation logic below

## WAF Domain Knowledge
- Rate-based rules: 20-30s kick-in delay — ALLOW before BLOCK is normal
- Anti-DDoS AMR: per-IP behavior analysis, ~15min baseline warmup
  - DDoSRequests blocks high-freq IPs regardless of JS capability
  - ChallengeAllDuringEvent: browser GET text/html only
  - Blind spot: highly distributed low-rate attacks
- Bot Control Common: verified (allowed) / unverified (blocked) / neither (undetected)
  - Does NOT block browser-UA bots — need Targeted for those
  - SignalNonBrowserUserAgent + CategoryHttpLibrary: FP on native apps → recommend Count
- Bot Control Targeted: skips verified bots, TGT_TokenAbsent default Count is correct design
- Challenge/CAPTCHA: only works on browser GET text/html; POST/API = effectively Block
- WAF token is unforgeable (AWS cryptographic signature)
- Match detail: only SQLi_Body and XSS_Body provide terminatingRuleMatchDetails

## COUNT Rule Evaluation Logic

Multi-dimensional cross-validation (≥3 dimensions):
1. Rule type prior: High FP (SizeRestrictions_BODY, GenericRFI), Low FP (Log4JRCE, CVE rules)
2. Same IP: triggers other rules? Allow ratio?
3. URI: business URIs vs sensitive paths
4. Time: business hours = FP; burst = attack
5. UA/JA4: automation vs real browser
Conclusion: Attack / False positive / Mixed (scope-down) / Insufficient data (ask user)

## Attack Source Investigation

Step 1: Metrics panorama → find anomaly window
Step 2: Branch by config (AMR / rate-based / no protection)
Step 3: Anchor = first anomaly → pivot in other dimensions
Step 4: Converge → output attack profile + recommendation

## Bypass/Evasion Detection

Step 1: Metrics to find peak ALLOW window (zero cost)
Step 2: Log queries in narrow window (≤6h): top_allowed_crawlers + top_allowed_repeaters
Step 3: For top 3 suspicious IPs, use analyze_ip (handles NAT detection + frequency + cross-validation)
Step 4: Review analyze_ip output. Frequency is the strongest signal — if superhuman (>200 URIs/hour or >200 req/min), conclude automation regardless of content.
Step 5: Conclude + ask user if they want to check more

Constraints:
- Max 3 IPs per round. Ask before expanding.
- Token reuse: only if WebACL has Challenge/Bot Control rules

## Host Profiling

Run host_traffic_profile — tool auto-classifies each host as Web/API/Mixed with recommendations.
If host has very few HTML URIs (1-2) but many API calls from same host → likely SPA, ask user about WAF Client SDK before recommending Targeted Bot Control.
Cannot determine from logs alone: SDK deployment status, SPA architecture, native-app-only paths → ask_user
Scope-down exclusions must use URI/IP/header — NOT request body (WAF doesn't inspect body for scope-down).

## Rule Recommendations

| Finding | Recommendation |
|---------|---------------|
| DDoS, no AMR | Deploy Anti-DDoS AMR |
| Distributed attack, AMR missed | Targeted Bot Control |
| Bot, only Common level | Always-on Challenge or upgrade to Targeted |
| COUNT confirmed attack | Switch to BLOCK |
| COUNT confirmed FP | Add scope-down exclusion |
| Sophisticated bot (browser automation) | Targeted Bot Control |
| Token reuse | TGT_TokenReuseIP to BLOCK |
| Allow rule on forgeable condition (UA/header) | Change to unforgeable (IP set / WAF token / ASN) |

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
    """Blocks run_logs_query/analyze_ip/run_athena_query unless get_waf_config has been called.

    This is a code-level enforcement — LLM cannot bypass it regardless of system prompt compliance.
    """

    GUARDED_TOOLS = {"run_logs_query", "analyze_ip", "run_athena_query"}

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
_TOOLS = [list_webacls, get_waf_config, get_waf_metrics, run_logs_query, analyze_ip,
          run_athena_query, lookup_ja4, generate_weekly_report, set_report_summary,
          review_waf_rules, record_finding, ask_user]


def get_agent() -> Agent:
    global _agent
    if _agent is None:
        model = BedrockModel(
            model_id=MODEL_ID,
            region_name=MODEL_REGION,
            max_tokens=4096,
            temperature=0.0,
        )
        _agent = Agent(model=model, system_prompt=_build_system_prompt(), tools=_TOOLS,
                       hooks=[PreQueryGuard()])
    return _agent


def invoke(payload: dict) -> dict:
    """Synchronous invocation (local testing)."""
    result = get_agent()(payload.get("prompt", ""))
    return {"answer": str(result)}


# --- AG-UI Server (FastAPI + ag-ui-strands) ---

def create_app():
    """Create FastAPI app with AG-UI streaming endpoint."""
    import json as _json
    import uuid as _uuid
    from fastapi import FastAPI, Request
    from fastapi.responses import StreamingResponse, JSONResponse

    app = FastAPI(title="waf-agent")

    @app.post("/invocations")
    async def invocations(request: Request):
        input_data = await request.json()
        agent = get_agent()

        # --- Resume from interrupt (priority: checked first) ---
        interrupt_responses = input_data.get("interruptResponses")
        if interrupt_responses:
            resume_input = [
                {"interruptResponse": {"interruptId": ir["interruptId"], "response": ir["response"]}}
                for ir in interrupt_responses
            ]

            async def resume_generator():
                import asyncio
                run_id = str(_uuid.uuid4())
                thread_id = input_data.get("threadId", "thread-1")
                yield f"data: {_json.dumps({'type': 'RUN_STARTED', 'threadId': thread_id, 'runId': run_id})}\n\n"

                # Resume agent with interruptResponse blocks
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, lambda: agent(resume_input))

                # Check for chained interrupt — if interrupted, don't emit text (it's interrupt dict)
                if hasattr(result, 'stop_reason') and result.stop_reason == "interrupt":
                    pending = [{"id": i.id, "name": i.name, "reason": i.reason}
                               for i in result.interrupts if i.response is None]
                    if pending:
                        yield f"data: {_json.dumps({'type': 'CUSTOM', 'name': 'interrupt', 'value': {'interrupts': pending}})}\n\n"
                else:
                    yield f"data: {_json.dumps({'type': 'TEXT_MESSAGE_START', 'messageId': 'msg-1', 'role': 'assistant'})}\n\n"
                    yield f"data: {_json.dumps({'type': 'TEXT_MESSAGE_CONTENT', 'messageId': 'msg-1', 'delta': str(result)})}\n\n"
                    yield f"data: {_json.dumps({'type': 'TEXT_MESSAGE_END', 'messageId': 'msg-1'})}\n\n"
                yield f"data: {_json.dumps({'type': 'RUN_FINISHED', 'threadId': thread_id, 'runId': run_id})}\n\n"

            return StreamingResponse(resume_generator(), media_type="text/event-stream")

        # --- All other requests (AG-UI with threadId, or simple {prompt}) ---
        # NOTE: We bypass ag-ui-strands StrandsAgent.run() because it silently
        # swallows tool_context.interrupt() (known bug in ag-ui-strands v0.1.7).
        # Instead, we call agent() directly and emit SSE events manually.

        if "threadId" in input_data:
            # Extract prompt from AG-UI RunAgentInput messages
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

        # Special: return stored report HTML directly
        if prompt == '__get_report__':
            from tools.report import _latest_report_html
            async def report_generator():
                run_id = str(_uuid.uuid4())
                yield f"data: {_json.dumps({'type': 'RUN_STARTED', 'threadId': thread_id, 'runId': run_id})}\n\n"
                yield f"data: {_json.dumps({'type': 'TEXT_MESSAGE_START', 'messageId': 'msg-1', 'role': 'assistant'})}\n\n"
                yield f"data: {_json.dumps({'type': 'TEXT_MESSAGE_CONTENT', 'messageId': 'msg-1', 'delta': _latest_report_html or ''})}\n\n"
                yield f"data: {_json.dumps({'type': 'TEXT_MESSAGE_END', 'messageId': 'msg-1'})}\n\n"
                yield f"data: {_json.dumps({'type': 'RUN_FINISHED', 'threadId': thread_id, 'runId': run_id})}\n\n"
            return StreamingResponse(report_generator(), media_type="text/event-stream")

        async def agent_generator():
            import asyncio
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, lambda: agent(prompt))
            run_id = str(_uuid.uuid4())
            yield f"data: {_json.dumps({'type': 'RUN_STARTED', 'threadId': thread_id, 'runId': run_id})}\n\n"
            # If interrupted, only emit CUSTOM event (no text — str(result) is interrupt dict)
            if hasattr(result, 'stop_reason') and result.stop_reason == "interrupt":
                pending = [{"id": i.id, "name": i.name, "reason": i.reason}
                           for i in result.interrupts if i.response is None]
                if pending:
                    yield f"data: {_json.dumps({'type': 'CUSTOM', 'name': 'interrupt', 'value': {'interrupts': pending}})}\n\n"
            else:
                yield f"data: {_json.dumps({'type': 'TEXT_MESSAGE_START', 'messageId': 'msg-1', 'role': 'assistant'})}\n\n"
                yield f"data: {_json.dumps({'type': 'TEXT_MESSAGE_CONTENT', 'messageId': 'msg-1', 'delta': str(result)})}\n\n"
                yield f"data: {_json.dumps({'type': 'TEXT_MESSAGE_END', 'messageId': 'msg-1'})}\n\n"
            yield f"data: {_json.dumps({'type': 'RUN_FINISHED', 'threadId': thread_id, 'runId': run_id})}\n\n"

        return StreamingResponse(agent_generator(), media_type="text/event-stream")

    @app.get("/ping")
    async def ping():
        return JSONResponse({"status": "Healthy"})

    return app


if __name__ == "__main__":
    import sys
    if "--serve" in sys.argv:
        import uvicorn
        uvicorn.run(create_app(), host="0.0.0.0", port=8080)
    else:
        # Local CLI testing
        prompt = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "列出所有 WebACL"
        print(invoke({"prompt": prompt})["answer"])
