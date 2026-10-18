# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""COUNT-to-BLOCK evaluation workflow tool — guided skill for LLM."""

import json
import re
import sys
import time
from strands import tool
from tools.aws_session import get_client
from tools.session_state import get_webacl_name, get_scope, resolve_region, is_log_filter_active
from tools.waf_query import query_logs, log_query_error, get_log_type
from tools.waf_aggregate import _LABELS_ARRAY

# Rules that should NEVER be recommended to switch from Count.
# These have known high false-positive rates in production environments.
PERMANENT_COUNT_RULES = {
    # CRS Body Size Restriction — triggers on legitimate large uploads (file uploads, rich text editors)
    "SizeRestrictions_BODY",
    # Anonymous IP — blocks hosting/cloud provider IPs that include legitimate services (VPNs, corporate proxies)
    "HostingProviderIPList",
    # Bot Control Common — blocks non-browser UAs which include legitimate native apps, SDKs, health checks
    "SignalNonBrowserUserAgent",
}

# Rules with known low false-positive rates — safe to recommend Block without deep log analysis
LOW_FP_RULES = {
    "Log4JRCE", "Log4JRCE_HEADER", "Log4JRCE_QUERYSTRING", "Log4JRCE_BODY", "Log4JRCE_URI",
    "JavaDeserializationRCE_HEADER", "JavaDeserializationRCE_BODY", "JavaDeserializationRCE_QUERYSTRING", "JavaDeserializationRCE_URI",
}


class LogQueryFailed(Exception):
    """A log query did not return its rows. The message is the engine's own reason.

    Named for what happens rather than for one hypothetical cause. It was
    `QueryCapError`, "raised when Athena query window cap is hit", and there has never
    been a window cap to hit: the only producers of an `_error` row are a CloudWatch poll
    timeout and a CloudWatch engine failure, so the name described a cause the code cannot
    produce and sent the reader looking for a limit that is not there."""


def _run_log_query(query_cwl: str, query_athena: str, start_epoch: int, end_epoch: int, limit: int = 25) -> list[dict]:
    """Execute a log query via the unified layer. Raises LogQueryFailed if it did not run.

    The `except Exception: return []` this replaces was **engine-asymmetric**, and that is
    the defect rather than the untidiness. CloudWatch failures arrive as an `_error` row and
    were reported; Athena failures arrive as a raised `RuntimeError` carrying
    `poll_timeout_message`, and swallowing those to `[]` meant a cancelled or failed Athena
    query reached the user as "this rule has no low-volume clients", which is a statement
    about their traffic. Same class as the patrol and weekly-report fix in 0.17.0, in a file
    that sweep did not reach.

    `None` still returns `[]`: that is the no-logging-configured case, which `_has_logging`
    checks before any caller gets here.
    """
    try:
        results = query_logs(query_cwl, query_athena, start_epoch, end_epoch, limit)
    except Exception as exc:
        raise LogQueryFailed(f"{type(exc).__name__}: {exc}") from exc
    if results is None:
        return []
    reason = log_query_error(results)
    if reason:
        raise LogQueryFailed(reason)
    return results


def _has_logging() -> bool:
    """Check if any logging (CWL or S3) is configured."""
    return get_log_type() != "none"


@tool
def evaluate_count_rules(step: str = "init", rule_name: str = "", start_time: str = "", duration_minutes: int = 60) -> str:
    """Guided workflow for evaluating whether COUNT rules are ready to switch to BLOCK.

    This is a multi-step skill. Call with step="init" for bulk evaluation (all COUNT rules),
    or jump directly to step="analyze_rule" for a single specific rule.

    Prerequisite: call get_waf_config first (after selecting the WebACL). This tool
    reads session state populated there; without it it errors out.

    Steps:
    - "init": Inventory all COUNT rules, classify them, find peak hour. Returns full assessment plan.
    - "analyze_rule": Deep-dive a specific rule — finds peak hour and hit count. Does NOT auto-query logs. Requires rule_name.
    - "check_low_volume_clients": Check low-volume clients for a rule (FP signal). Requires rule_name + start_time. Also surfaces the triggering request content (redacted) so you can judge attack vs FP from the real payload.

    Args:
        step: Workflow step to execute.
        rule_name: Rule name (required for analyze_rule and check_low_volume_clients).
        start_time: Start time for log queries (required for check_low_volume_clients).
        duration_minutes: Duration in minutes (default 60, max 360, both engines).
    """
    if not get_webacl_name():
        return ("Error: No WebACL selected. Call get_waf_config(webacl_name='...') first, "
                "or call list_webacls() to see available WebACLs.")

    # Normalised and validated at the dispatch so every step is covered by one check, and so the
    # steps below interpolate the name this decided on rather than re-deriving it.
    # `_step_check_clients` interpolated it into six Athena literals and three CWL filters with no
    # guard at all.
    #
    # **`checked_rule_name` is the only thing that normalises, deliberately.** The first fix also
    # stripped `rule_name` here, which made the returned name's assignment dead: the perturbation
    # dropping it stayed green, because the padding was already gone. Two mechanisms where one
    # belongs, and the redundant one is the weaker duplicate this file has been bitten by twice.
    # `init` needs no normalisation of its own either -- it takes a comma-separated list, which
    # the guard would refuse, and `_step_init` strips each part when it splits.
    from tools.waf_query import checked_rule_name

    if step == "init":
        return _step_init(rule_name=rule_name)
    elif step == "analyze_rule":
        if not rule_name:
            return "Error: rule_name is required for step='analyze_rule'."
        rule_name, bad = checked_rule_name(rule_name)
        if bad:
            return bad
        return _step_analyze_rule(rule_name)
    elif step == "check_low_volume_clients":
        if not rule_name or not start_time:
            return "Error: rule_name and start_time are required for step='check_low_volume_clients'."
        rule_name, bad = checked_rule_name(rule_name)
        if bad:
            return bad
        return _step_check_clients(rule_name, start_time, duration_minutes)
    else:
        return f"Error: unknown step '{step}'. Available: init, analyze_rule, check_low_volume_clients"


def _step_init(rule_name: str = "") -> str:
    """Step 0+1+2: Inventory COUNT rules, classify, find peak hours.
    If rule_name is provided, only evaluate that specific rule (or comma-separated list)."""

    # If user specified specific rules, filter to just those
    target_rules = set()
    if rule_name:
        target_rules = {r.strip() for r in rule_name.split(",") if r.strip()}

    # Get all COUNT rules from WebACL config
    webacl_name = get_webacl_name()
    scope = get_scope()
    region = resolve_region(scope)
    webacl_rules = _get_webacl_rules(region, scope)
    all_count_rules = _get_all_count_rules(region, scope, webacl_rules)
    prefix = label_prefix()

    # Filter to target rules if specified
    if target_rules:
        all_count_rules = [r for r in all_count_rules if r in target_rules]
        if not all_count_rules:
            return f"Error: specified rule(s) {target_rules} not found in COUNT mode. Available COUNT rules: use step='init' without rule_name to see all."

    if not all_count_rules:
        return "No COUNT rules found in this WebACL."

    # Get hit counts from CloudWatch Metrics (accurate, works for both CWL and S3 users)
    from datetime import datetime as dt, timedelta, timezone as tz
    from tools.waf_patrol import _get_all_rules_metrics_search
    cw = get_client("cloudwatch", region_name=region)
    end_dt = dt.now(tz.utc)
    start_dt = end_dt - timedelta(days=14)
    metrics = _get_all_rules_metrics_search(cw, webacl_name, start_dt, end_dt, period=14 * 86400, scope=scope, region=region, rules=webacl_rules)

    # Build hit count map from metrics. A rule SEARCH did not count is confirmed with an explicit
    # MetricStat before it may be called zero: WAF publishes only non-zero values and SEARCH only
    # discovers series with data in the last 14 days, so absent there is "matched nothing",
    # "metrics off" or "the lookup did not answer", and only the first is safe to switch.
    from tools.waf_metrics import rule_blocked_per_metrics
    start_epoch, end_epoch = int(start_dt.timestamp()), int(end_dt.timestamp())
    found_rules = {}
    no_metric = {}
    for rule_id in all_count_rules:
        counted = sum(metrics.get(rule_id, {}).get("counted", []))
        if not counted:
            counted, reason = rule_blocked_per_metrics(webacl_name, rule_id, webacl_rules, start_epoch,
                                                       end_epoch, metric_name="CountedRequests")
            if counted is None:
                no_metric[rule_id] = reason
                continue
        found_rules[rule_id] = counted

    # Classify rules. A Count rule a later rule reads the label of is kept whatever its hits say.
    designed = {r: by_design(webacl_rules, r, prefix) for r in all_count_rules}
    designed = {r: readers for r, readers in designed.items() if readers}
    # A custom rule's labels sit in the WebACL's own namespace, where no `awswaf:managed:` key reaches, and
    # `by_design` already decides them, so only managed sub-rules and groups are read here.
    managed_readers = {r: [(n, p, k) for n, p, sc, k in label_readers(webacl_rules, r) if k.startswith("awswaf:managed:")]
                       for r in all_count_rules if r not in designed and not _is_custom(webacl_rules, r)}
    managed_readers = {r: v for r, v in managed_readers.items() if v}
    permanent_count = []
    zero_hit = []
    low_fp_nonzero = []
    needs_analysis = []

    for rule_id in all_count_rules:
        if rule_id in no_metric or rule_id in designed:
            continue
        hits = found_rules[rule_id]
        if rule_id in PERMANENT_COUNT_RULES:
            permanent_count.append((rule_id, hits))
        elif rule_id in managed_readers and (hits == 0 or rule_id in LOW_FP_RULES
                                             or rule_id.startswith(("CVE_", "CVE-"))):
            # Not safe to switch on its hits or its type: a later rule may read its label, which only the
            # logs can tell. Listed with the later rules instead.
            continue
        elif hits == 0:
            zero_hit.append(rule_id)
        elif rule_id in LOW_FP_RULES or any(rule_id.startswith(p) for p in ("CVE_", "CVE-")):
            low_fp_nonzero.append((rule_id, hits))
        else:
            needs_analysis.append((rule_id, hits))
    # Ranked, which the heading below and the "highest volume" recommendation always claimed; the
    # list stayed in WebACL order, and the peak hour is computed for element 0 only.
    needs_analysis.sort(key=lambda rh: rh[1], reverse=True)

    # For top rule needing analysis, find peak hour via CloudWatch Metrics (works for all log types)
    peak_info = ""
    if needs_analysis:
        top_rule = needs_analysis[0][0]
        # Re-query with hourly granularity to find peak hour
        peak_metrics = _get_all_rules_metrics_search(cw, webacl_name, start_dt, end_dt, period=3600, scope=scope, region=region)
        rule_data = peak_metrics.get(top_rule, {})
        counted_series = rule_data.get("counted", [])
        timestamps = rule_data.get("timestamps", [])
        if counted_series and timestamps and len(counted_series) == len(timestamps):
            peak_idx = counted_series.index(max(counted_series))
            peak_info = timestamps[peak_idx][:16].replace(" ", "T")  # YYYY-MM-DDTHH:MM

    from tools.waf_metrics import summed_sub_rules
    summed, repeated = summed_sub_rules(cw, webacl_name, webacl_rules, scope, region)
    mark = lambda r: f"{r}*" if r in summed else r

    # Build response
    lines = [
        "## COUNT Rule Evaluation — Inventory Complete",
        f"Analyzed 14 days of CloudWatch Metrics. Found {len(all_count_rules)} COUNT rules total.",
        "",
        "### Step 0: Permanent COUNT (never switch — known high FP)",
    ]
    if permanent_count:
        for r, h in permanent_count:
            lines.append(f"  - {mark(r)} ({h:,} hits) — KEEP as Count permanently")
    else:
        lines.append("  (none found)")

    if designed:
        lines.append("")
        lines.append("### Keep in Count by design (a later rule reads its label)")
        for r, readers in designed.items():
            named = "; ".join(f"{n} (priority {p}, key {k})" for n, p, k in readers)
            lines.append(f"  - {r} — read by {named}. Switching it to Block stops those requests here, so the "
                         f"later rule never sees them; that is usually a scope-down. Keep it in Count.")

    lines.append("")
    lines.append("### Step 1: Zero Hits (safe to switch to default action)")
    if zero_hit:
        for r in zero_hit:
            lines.append(f"  - {r} — 0 hits in 14 days, safe to switch")
    else:
        lines.append("  (all COUNT rules had at least 1 hit)")

    if no_metric:
        lines.append("")
        lines.append("### No metric to judge from (NOT safe to switch on this evidence)")
        for r, why in no_metric.items():
            lines.append(f"  - {r} — {why}")
        lines.append("  Judge these from the logs instead: evaluate_count_rules(step='analyze_rule', rule_name=...).")

    lines.append("")
    lines.append("### Step 2: Low-FP Rules with Hits (safe to switch based on rule-type prior)")
    if low_fp_nonzero:
        for r, h in low_fp_nonzero:
            lines.append(f"  - {mark(r)} ({h:,} hits) — known low-FP, safe to switch")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("### Step 3: Rules Requiring Log Analysis (ranked by hit volume)")
    if needs_analysis:
        for r, h in needs_analysis:
            lines.append(f"  - {mark(r)} ({h:,} hits)")
    else:
        lines.append("  (none — all rules classified above)")
    if any(r in summed for r, _ in permanent_count + low_fp_nonzero + needs_analysis):
        lines.append("")
        lines.append(repeated)
    if managed_readers:
        lines.append("")
        lines.append("### Later rules that read managed labels (check before switching these)")
        for r, readers in managed_readers.items():
            named = "; ".join(f"{n} (priority {p}, key {k})" for n, p, k in readers)
            hits = f"{found_rules[r]:,} hits" if r in found_rules else "hits unknown"
            lines.append(f"  - {mark(r)} ({hits}): {named}. A managed sub-rule's label is not in the configuration, "
                         f"so check_low_volume_clients counts how many of the requests {r} counted carry it. Not "
                         f"safe to switch on its hits alone.")

    lines.append("")
    lines.append("---")
    lines.append("## Your Next Action")
    lines.append("")
    lines.append("Present the above classification to the user. Then:")
    lines.append("")

    if not needs_analysis:
        lines.append("All rules are classified. No further log analysis needed.")
        lines.append("Summarize recommendations and call record_finding() for each.")
    else:
        lines.append(f"Recommend starting with **{needs_analysis[0][0]}** ({needs_analysis[0][1]:,} hits — highest volume).")
        lines.append("")
        lines.append("**IMPORTANT: Analyze ONE rule at a time.** Do NOT call analyze_rule for multiple rules in parallel.")
        lines.append("After completing one rule, ask the user if they want to continue with the next.")
        if peak_info:
            lines.append(f"\nPeak hour identified: {peak_info}")
            lines.append("")
            lines.append(f"Ask the user: \"I recommend analyzing {needs_analysis[0][0]} during its peak hour ({peak_info}). Proceed?\"")
            lines.append("")
            lines.append(f"When confirmed, call: evaluate_count_rules(step='analyze_rule', rule_name='{needs_analysis[0][0]}')")
        else:
            lines.append("\nCould not determine peak hour. Ask the user for a time window.")
            lines.append(f"When confirmed, call: evaluate_count_rules(step='analyze_rule', rule_name='{needs_analysis[0][0]}')")

    return "\n".join(lines)


def _count_rule_matches(rule_name: str, start_epoch: int, end_epoch: int) -> int | None:
    """How many requests this rule COUNTed in this window, ungrouped. `None` when it could not answer.

    **Ungrouped on purpose, and that is the whole reason this exists.** The two queries above are
    `stats count(*) as hits by httpRequest.clientIp | limit 5`, so neither their row count nor the sum
    of their `hits` column is the number of requests: the first is a count of distinct IPs and the
    second is a lower bound truncated at five of them. A cross-check built on either would report a gap
    on a window with six busy clients and stay silent on a window with six hundred, which inverts what
    the check is for.

    The filter is the same one both queries use, including the two places a `RuleActionOverride` COUNT
    entry can appear: the top-level `nonTerminatingMatchingRules` and the per-rule-group one.

    `None` rather than 0 when the query failed, because 0 is a claim about the traffic and a failure is
    not. `_run_log_query` already returns an `_error` row on every give-up path.
    """
    from tools.waf_query import log_query_error
    # Adjacent keys on purpose. WAF writes a rule entry as {"ruleId":..,"action":..,
    # "overriddenAction":..}, and the two keys searched separately pair one entry's ruleId with another
    # entry's COUNT: measured 2026-10-16 on test-webacl-cwl over 14 days, LFI_URIPATH, which only
    # blocks, matched 34 records that way and none in this form.
    cwl = (f"filter @message like '\"ruleId\":\"{rule_name}\",\"action\":\"COUNT\"'"
           " | stats count(*) as cnt")
    athena = (f"SELECT count(*) as cnt FROM {{TABLE}}"
              f" WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
              f" AND (any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}'"
              f"        AND r.action = 'COUNT')"
              f"   OR any_match(rulegrouplist, rg -> any_match(rg.nonterminatingmatchingrules,"
              f"        r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT')))")
    rows = _run_log_query(cwl, athena, start_epoch, end_epoch, limit=1)
    if not rows:
        return 0
    if log_query_error(rows):
        return None
    if "cnt" not in rows[0]:
        return None
    return int(rows[0]["cnt"])


_MATCH_SAMPLE = 50


def _detail_text(d: dict) -> str:
    data = d.get("matchedData")
    return (f"{d.get('conditionType') or '?'} at {d.get('location') or '?'}: "
            f"{' '.join(data) if data else 'matched data not recorded'}")


def _count_match_details(rule_name: str, start_epoch: int, end_epoch: int) -> tuple[list, int | None]:
    """What the rule matched in the requests it counted: `[(detail, requests)]`, busiest first, and how
    many requests CloudWatch's list came from (None on Athena, which counts the whole window). Raises
    LogQueryFailed when the read did not run.

    The details are on the Count entry itself, top-level or inside its group, and
    `terminatingRuleMatchDetails` stays empty. WAF fills them for SQLi and XSS statements, with the
    matched tokens, and for some others with the location only. Measured 2026-09-08 on
    `test-webacl-s3`: 160 of 160 `CrossSiteScripting_QUERYARGUMENTS` Count records carried them.
    Counted once per request, because a group deployed twice logs its sub-rule's entry twice.

    CloudWatch has no array accessor that holds up, so it reads up to `_MATCH_SAMPLE` raw records and
    parses them here; Athena flattens both levels in the query."""
    if get_log_type() == "cwl":
        cwl = (f"filter @message like '\"ruleId\":\"{rule_name}\",\"action\":\"COUNT\",\"ruleMatchDetails\":[{{'"
               f" | fields @message | limit {_MATCH_SAMPLE}")
        rows = _run_log_query(cwl, "", start_epoch, end_epoch, limit=_MATCH_SAMPLE)
        counts: dict[str, int] = {}
        for r in rows:
            try:
                rec = json.loads(r.get("@message", ""))
            except ValueError:
                continue
            entries = list(rec.get("nonTerminatingMatchingRules") or [])
            for g in rec.get("ruleGroupList") or []:
                entries += g.get("nonTerminatingMatchingRules") or []
            for text in {_detail_text(d) for e in entries
                         if e.get("ruleId") == rule_name and e.get("action") == "COUNT"
                         for d in e.get("ruleMatchDetails") or []}:
                counts[text] = counts.get(text, 0) + 1
        return sorted(counts.items(), key=lambda x: -x[1])[:8], len(rows)
    pick = f"r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT'"
    details = (f"concat(flatten(transform(filter(coalesce(nonterminatingmatchingrules, ARRAY[]), {pick}),"
               f" r -> coalesce(r.rulematchdetails, ARRAY[]))),"
               f" flatten(transform(coalesce(rulegrouplist, ARRAY[]), rg -> flatten(transform(filter("
               f"coalesce(rg.nonterminatingmatchingrules, ARRAY[]), {pick}), r -> coalesce(r.rulematchdetails, ARRAY[]))))))")
    athena = (f"SELECT coalesce(d.conditiontype, '?') || ' at ' || coalesce(d.location, '?') || ': ' ||"
              f" coalesce(array_join(d.matcheddata, ' '), 'matched data not recorded') as md,"
              f" count(DISTINCT httprequest.requestid) as hits"
              f" FROM {{TABLE}} CROSS JOIN UNNEST({details}) AS u(d)"
              f" WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
              f" GROUP BY 1 ORDER BY hits DESC LIMIT {{LIMIT}}")
    rows = _run_log_query("", athena, start_epoch, end_epoch, limit=8)
    return [(r.get("md", "?"), int(r.get("hits") or 0)) for r in rows], None


def _step_analyze_rule(rule_name: str) -> str:
    """Step 4-5: Find peak hour for this rule, then get client distribution.

    `rule_name` arrives normalised and validated from `evaluate_count_rules`, the only caller, so
    nothing here touches it. This used to run `re.sub` over it and then compare the rewritten
    result against `PERMANENT_COUNT_RULES` two lines down, which could change whether the
    permanent-Count GATE fires rather than only what the header echoes. It then briefly kept a
    `.strip()` of its own, which was the weaker-duplicate mistake `analyze_ip`'s dead `re.sub`
    was: a second normalisation implies the value arrives untrusted and sends the next reader
    hunting for a check that already happened."""
    # Step 0 gate: check if this rule should never leave Count
    if rule_name in PERMANENT_COUNT_RULES:
        return (
            f"## Rule: {rule_name} — PERMANENT COUNT\n\n"
            f"This rule is in the permanent-Count list due to known high false-positive rates:\n"
            f"- SizeRestrictions_BODY: triggers on legitimate large uploads (file uploads, rich text)\n"
            f"- HostingProviderIPList: blocks hosting/cloud IPs that include legitimate services\n"
            f"- SignalNonBrowserUserAgent: blocks non-browser UAs including legitimate native apps/SDKs\n\n"
            f"**Recommendation**: Keep as Count. Do NOT switch to Block.\n\n"
            f"---\n## Your Next Action\n"
            f"Tell the user this rule should remain in Count mode and explain why. "
            f"Call record_finding(title='{rule_name} should remain Count', severity='info', "
            f"conclusion='Permanent Count — known high FP rate', evidence='Rule-type prior', "
            f"recommendation='Keep as Count permanently')."
        )

    # Check if it's a known low-FP rule
    if rule_name in LOW_FP_RULES or any(rule_name.startswith(p) for p in ("CVE_", "CVE-")):
        return (
            f"## Rule: {rule_name} — LOW FALSE-POSITIVE\n\n"
            f"This rule has a known low false-positive rate. It targets specific vulnerability signatures "
            f"that legitimate traffic should never match.\n\n"
            f"**Recommendation**: Safe to switch to Block without deep log analysis.\n\n"
            f"---\n## Your Next Action\n"
            f"Tell the user this rule is safe to switch. "
            f"Call record_finding(title='{rule_name} safe to Block', severity='info', "
            f"conclusion='Low-FP rule type — safe to switch', evidence='Rule-type prior', "
            f"recommendation='Switch to Block')."
        )

    if not _has_logging():
        # Give what we can without logs: rule-type prior assessment
        prior = _get_rule_type_prior(rule_name)
        return (
            f"## Rule: {rule_name} — No Logging Available\n\n"
            f"⚠️  Cannot perform log-level analysis (no logging configured).\n\n"
            f"**Rule-type assessment**: {prior}\n\n"
            f"**What I can still check**: Use get_waf_overview(query_type='top_rules') to see this rule's "
            f"hit volume and week-over-week trend. Stable low volume with no spikes suggests low risk.\n\n"
            f"**What I cannot determine without logs**: Whether hits are from legitimate users or attackers, "
            f"IP patterns, URI patterns, false positive signals.\n\n"
            f"## Your Next Action\n"
            f"Tell the user: to make a confident decision on this rule, enable WAF logging. "
            f"In the meantime, here is the best assessment based on available data."
        )

    # Check if log filter might drop COUNT logs
    if is_log_filter_active():
        return (
            f"## Rule: {rule_name} — Log Filter Warning\n\n"
            f"⚠️  A Log Filter is active on this WebACL. COUNT logs may be filtered out.\n"
            f"Log-level analysis for this rule may return 0 results even if the rule has hits.\n\n"
            f"**Attempting query anyway** — if results are empty, this confirms the filter is dropping COUNT logs.\n\n"
            f"## Your Next Action\n"
            f"Cross-validate with get_waf_overview(query_type='top_rules'). If overview shows hits but logs show 0,\n"
            f"tell the user: COUNT logs are being filtered. Cannot perform client-level analysis.\n"
            f"Fall back to rule-type prior assessment only.\n\n"
            f"If you still want to attempt the log query, call:\n"
            f"evaluate_count_rules(step='check_low_volume_clients', rule_name='{rule_name}', start_time='<peak_time>')"
        )

    end_epoch = int(time.time())
    start_epoch = end_epoch - (14 * 86400)

    # Find peak hour via CloudWatch Metrics (avoids Athena cap issue)
    from datetime import datetime as dt, timedelta, timezone as tz
    from tools.waf_patrol import _get_all_rules_metrics_search
    scope = get_scope() or "CLOUDFRONT"
    region = resolve_region(scope)
    cw = get_client("cloudwatch", region_name=region)
    end_dt = dt.now(tz.utc)
    start_dt = end_dt - timedelta(days=14)
    peak_metrics = _get_all_rules_metrics_search(cw, get_webacl_name(), start_dt, end_dt, period=3600, scope=scope, region=region)
    rule_data = peak_metrics.get(rule_name, {})
    counted_series = rule_data.get("counted", [])
    timestamps = rule_data.get("timestamps", [])
    peak_hour_str = ""
    if counted_series and timestamps and len(counted_series) == len(timestamps):
        peak_idx = counted_series.index(max(counted_series))
        peak_hour_str = timestamps[peak_idx][:16].replace(" ", "T")
    if not peak_hour_str:
        return (f"Could not find peak hour for rule '{rule_name}'. "
                "The rule may have very sparse hits. Ask the user for a specific time window, "
                "then call evaluate_count_rules(step='check_low_volume_clients', "
                f"rule_name='{rule_name}', start_time='...').")

    # Parse peak hour to epoch
    from tools.waf_logs import _parse_start_time
    peak_epoch = _parse_start_time(peak_hour_str)
    if peak_epoch is None:
        return f"Error parsing peak hour '{peak_hour_str}'."

    peak_hits = int(max(counted_series))
    # Suggest duration based on hit volume
    if peak_hits < 1000:
        suggested_minutes = 60
    elif peak_hits < 10000:
        suggested_minutes = 15
    else:
        suggested_minutes = 5

    lines = [
        f"## Rule Analysis: {rule_name}",
        f"**Peak hour**: {peak_hour_str}",
        f"**Hits in peak hour**: {peak_hits:,}",
        "",
        "---",
        "## Your Next Action",
        "",
        f"Based on hit volume ({peak_hits:,}/hour ≈ {peak_hits // 60}/min), recommend duration_minutes={suggested_minutes}.",
        "",
        f"Call: evaluate_count_rules(step='check_low_volume_clients', rule_name='{rule_name}', "
        f"start_time='{peak_hour_str}', duration_minutes={suggested_minutes})",
    ]

    return "\n".join(lines)


def _step_check_clients(rule_name: str, start_time: str, duration_minutes: int) -> str:
    """Step 6: Detailed client check for a specific time window."""
    if not _has_logging():
        return "Error: No logging configured. Cannot perform log-level analysis."
    from tools.waf_query import check_coarse_partition_block
    coarse_err = check_coarse_partition_block()
    if coarse_err:
        return coarse_err

    from tools.waf_logs import _parse_start_time
    start_epoch = _parse_start_time(start_time)
    if start_epoch is None:
        return f"Error: cannot parse start_time '{start_time}'."

    end_epoch = start_epoch + duration_minutes * 60

    # Get both ends of client distribution
    # Note: RuleActionOverride COUNT entries appear in ruleGroupList[].nonTerminatingMatchingRules,
    # not in the top-level nonTerminatingMatchingRules. Check both locations.
    # The clients are read on the matches that ended ALLOW, which are the only ones a switch to Block
    # changes; a match another rule blocked or challenged ends the same way after the switch.
    cwl_bottom = (
        f"filter @message like '\"ruleId\":\"{rule_name}\",\"action\":\"COUNT\"' and action = 'ALLOW'"
        " | stats count(*) as hits by httpRequest.clientIp"
        " | sort hits asc | limit 5"
    )
    athena_bottom = (
        f"SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as hits"
        f" FROM {{TABLE}}"
        f" WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND action = 'ALLOW'"
        f" AND (any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT')"
        f"   OR any_match(rulegrouplist, rg -> any_match(rg.nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT')))"
        f" GROUP BY httprequest.clientip ORDER BY hits ASC LIMIT {{LIMIT}}"
    )
    cwl_top = (
        f"filter @message like '\"ruleId\":\"{rule_name}\",\"action\":\"COUNT\"' and action = 'ALLOW'"
        " | stats count(*) as hits by httpRequest.clientIp"
        " | sort hits desc | limit 5"
    )
    athena_top = (
        f"SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as hits"
        f" FROM {{TABLE}}"
        f" WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND action = 'ALLOW'"
        f" AND (any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT')"
        f"   OR any_match(rulegrouplist, rg -> any_match(rg.nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT')))"
        f" GROUP BY httprequest.clientip ORDER BY hits DESC LIMIT {{LIMIT}}"
    )

    # One read of the WebACL for the two sections that need it. Both are additive, so a failure here is
    # theirs to report, never the answer's.
    try:
        acl_rules, acl_error = _get_webacl_rules(resolve_region(get_scope() or "CLOUDFRONT"), get_scope() or "CLOUDFRONT"), ""
    except Exception as exc:                              # noqa: BLE001
        acl_rules, acl_error = None, f"{type(exc).__name__}: {exc}"

    cwl_outcomes = (f"filter @message like '\"ruleId\":\"{rule_name}\",\"action\":\"COUNT\"'"
                    " | stats count(*) as n by action")
    athena_outcomes = (f"SELECT action, count(*) as n FROM {{TABLE}}"
                       f" WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
                       f" AND (any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT')"
                       f"   OR any_match(rulegrouplist, rg -> any_match(rg.nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT')))"
                       f" GROUP BY action")
    try:
        outcomes = {r.get("action", "?"): int(float(r.get("n") or 0))
                    for r in _run_log_query(cwl_outcomes, athena_outcomes, start_epoch, end_epoch, limit=10)}
        bottom = _run_log_query(cwl_bottom, athena_bottom, start_epoch, end_epoch, limit=5)
        top = _run_log_query(cwl_top, athena_top, start_epoch, end_epoch, limit=5)
    except LogQueryFailed as exc:
        # Return the engine's reason rather than an empty client table. Both queries feed
        # the same recommendation, so one failing makes the whole step unanswerable.
        return (f"## Client Distribution: {rule_name}\n\n"
                f"The log query did not run, so this says nothing about {rule_name}'s "
                f"clients.\n{exc}")

    allowed = outcomes.get("ALLOW", 0)
    stopped = {a: n for a, n in sorted(outcomes.items()) if a != "ALLOW" and n}
    lines = [
        f"## Client Distribution: {rule_name}",
        f"**Window**: {start_time} + {duration_minutes}min",
        "",
        f"**What a switch to Block changes**: {sum(outcomes.values()):,} requests counted, {allowed:,} of them "
        f"allowed in the end. Only those change outcome."
        + (f" The other {sum(stopped.values()):,} were already stopped by later rules ("
           + ", ".join(f"{a} {n:,}" for a, n in stopped.items()) + ") and end the same way." if stopped else ""),
        "",
        "### Low-Volume Clients, allowed matches (check these for FP first)",
    ]
    if bottom:
        for r in bottom:
            lines.append(f"  {r.get('httpRequest.clientIp', '?'):>15}  {r.get('hits', '?'):>6} hits")
    elif outcomes and not allowed:
        lines.append("  (none: every request it counted was already stopped by another rule)")
    else:
        lines.append("  (no results — check if Log Filter drops COUNT logs)")

    lines.append("")
    lines += _reader_lines(rule_name, acl_rules, acl_error, start_epoch, end_epoch)
    lines.append("")
    lines.append("### High-Volume Clients, allowed matches (double-confirm)")
    if top:
        for r in top:
            lines.append(f"  {r.get('httpRequest.clientIp', '?'):>15}  {r.get('hits', '?'):>6} hits")
    elif outcomes and not allowed:
        lines.append("  (none: every request it counted was already stopped by another rule)")
    else:
        lines.append("  (no results)")

    # ROADMAP 7.7. `outcomes` holds every COUNT match by final action, so all of it empty means the
    # logs report no COUNT match for this rule in this window. `CountedRequests` for the
    # same rule is recorded upstream of every log-side failure, and it is the one witness whose
    # subject is this question. **This is the tool whose output the user executes against
    # production**, by switching the rule from Count to Block, so a zero here that is really a
    # missed query is the most expensive absence on the list.
    # **Widened 2026-09-15 to the case where the logs DO hold rows**, which is the more common shape
    # and was unreported. `bottom` and `top` cannot supply the number: they hold allowed matches only, and are
    # `stats count(*) as hits by httpRequest.clientIp | limit 5`, so their row count is a number of
    # distinct IPs capped at five, and summing their `hits` column would give a lower bound that goes
    # silent exactly on windows with many clients, which are the busy ones. One ungrouped count with
    # the same filter is immune to that by construction rather than corrected for it, at one extra
    # query per rule.
    _matched = _count_rule_matches(rule_name, start_epoch, end_epoch)
    if _matched is not None:
        from tools.waf_metrics import missed_data_warning
        scope = get_scope() or "CLOUDFRONT"
        # **The cross-check is additive, so nothing in it may break the answer it annotates.**
        # Resolving the metric dimension needs the WebACL, which is two more wafv2 calls in a branch
        # that previously touched no AWS at all, and they can fail on their own: no credentials,
        # throttling, a missing `wafv2:GetWebACL`. Found by CI rather than by review, where
        # `test_a_padded_rule_name_reaches_the_query_without_its_padding` drives this branch with no
        # credentials and the unguarded read turned a passing test into `NoCredentialsError`. That
        # test failing was the cheap version of a user losing a working answer.
        rules = acl_rules
        if rules is None:
            print(f"[waf_count_eval] no metric cross-check for {rule_name}: {acl_error}",
                  file=sys.stderr, flush=True)
        if rules is not None:
            warning = missed_data_warning(get_webacl_name(), rule_name, rules, start_epoch,
                                          end_epoch, log_rows=_matched,
                                          metric_name="CountedRequests")
            if warning:
                lines.append(warning)

    # Triggering content at the rule's inspection location. AWS WAF does not
    # record matchedData for most managed rules, but the rule name tells us
    # which request component it inspected — surface that component so the
    # analyst can judge attack vs FP from the actual content.
    from tools.waf_query import sample_inspection_content, PRIVACY_MASK_HINT, REDACTION_POSSIBLE_HINT
    cwl_filter = (
        f"filter @message like '\"ruleId\":\"{rule_name}\",\"action\":\"COUNT\"'"
    )
    athena_where = (
        f"(any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT')"
        f"   OR any_match(rulegrouplist, rg -> any_match(rg.nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT')))"
    )
    try:
        label, samples, masked = sample_inspection_content(rule_name, cwl_filter, athena_where, start_epoch, end_epoch, limit=8)
    except Exception:
        label, samples, masked = (None, None, False)
    if label:
        lines.append("")
        lines.append(f"### Triggering Content — inspected location: {label}")
        lines.append("(raw, as logged; query strings/URIs are URL-encoded — show to user, do NOT interpret/verdict)")
        if samples:
            for s in samples:
                lines.append(f"  [{s['hits']:>4} hits] {s['content'][:200]}")
            if masked:
                lines.append(f"  HINT: {PRIVACY_MASK_HINT}")
        elif samples is None:
            lines.append(f"  ⚠️  Could not retrieve {label} content on this log backend — state this; do not guess.")
        else:
            lines.append(f"  HINT: {REDACTION_POSSIBLE_HINT}")

    lines.append("")
    lines.append("### What the rule matched (its Count entries' ruleMatchDetails)")
    lines.append("(raw, as logged — show to user, do NOT interpret/verdict)")
    try:
        details, sampled = _count_match_details(rule_name, start_epoch, end_epoch)
    except LogQueryFailed as exc:
        lines.append(f"  UNKNOWN, the query for this section failed: {exc}")
    else:
        for text, hits in details:
            lines.append(f"  [{hits:>4} requests] {text[:200]}")
        if not details:
            lines.append("  (none logged; WAF records them for SQLi and XSS statements, and the location "
                         "only for some others)")
        if sampled is not None:
            lines.append(f"  (from {sampled} sampled requests; CloudWatch reads raw records, at most "
                         f"{_MATCH_SAMPLE})")

    lines.append("")
    lines.append("---")
    lines.append("## Your Next Action")
    lines.append("")
    lines.append("For each low-volume client, call run_logs_query(query_type='ip_cross_query', ip='<IP>', start_time='...') to cross-validate.")
    lines.append("Then apply the conclusion criteria from the previous step.")

    return "\n".join(lines)


def _reader_lines(rule_name: str, rules, acl_error: str, start_epoch: int, end_epoch: int) -> list:
    """The section naming each later rule that reads a label the requests this rule counted carry.
    Read off the logs, so it holds for a managed sub-rule whose label the configuration does not name."""
    head = ["### Later rules that read labels these requests carry"]
    if rules is None:
        return head + [f"  UNKNOWN: the WebACL's rules could not be read ({acl_error}), so whether a later "
                       f"rule depends on this one is unknown. Do not recommend Block until it is."]
    readers = label_readers(rules, rule_name)
    unplaced = _rule_of(rules, rule_name) is None
    if not readers:
        return head + ["  (none: no rule in the WebACL matches on a label)" if unplaced else
                       "  (none: no rule after this one matches on a label)"]
    if unplaced:
        head.append(f"  {rule_name} is not named in the WebACL's configuration (a managed sub-rule that counts by "
                    f"default has no override), so where it runs is unknown and every rule that matches on a label "
                    f"is listed. One evaluated before its rule group never sees the label.")
    prefix = label_prefix()
    pattern = lambda sc, k: _label_pattern(sc, k, prefix)
    cwl = (f"filter @message like '\"ruleId\":\"{rule_name}\",\"action\":\"COUNT\"' | {_LABELS_ARRAY}"
           " | stats count(*) as total, " + ", ".join(
               f"sum(if(lbls like /\"name\":\"{pattern(sc, k)[1:].rstrip('$')}{chr(34) if sc == 'LABEL' else ''}/, 1, 0)) as l{i}"
               for i, (_, _, sc, k) in enumerate(readers)))
    athena = (f"SELECT count(*) as total, " + ", ".join(
                  f"count_if(any_match(labels, l -> regexp_like(l.name, '{pattern(sc, k)}'))) as l{i}"
                  for i, (_, _, sc, k) in enumerate(readers))
              + f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
              f" AND (any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT')"
              f"   OR any_match(rulegrouplist, rg -> any_match(rg.nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT')))")
    try:
        rows = _run_log_query(cwl, athena, start_epoch, end_epoch, limit=1)
    except LogQueryFailed as exc:
        return head + [f"  UNKNOWN, the query for this section failed: {exc}. Do not recommend Block until it answers."]
    row = rows[0] if rows else {}
    total = int(float(row.get("total") or 0))
    out = []
    for i, (name, pri, sc, key) in enumerate(readers):
        n = int(float(row.get(f"l{i}") or 0))
        out.append(f"  - {name} (priority {pri}, {sc} {key}): {n:,} of the {total:,} requests counted here carry it")
    if any(int(float(row.get(f"l{i}") or 0)) for i in range(len(readers))):
        out.append("  ⚠️  Switching this rule to Block stops these requests here, so those rules never see them. "
                   "Where a rule matches on this rule's own label, the Count is a scope-down design: keep it.")
    return head + out


# Known rule-type priors for no-logging fallback
_RULE_PRIORS = {
    "CrossSiteScripting_BODY": "Medium-high FP rate. Rich text editors and HTML form submissions commonly trigger this. Recommend enabling logging before switching.",
    "CrossSiteScripting_QUERYARGUMENTS": "Medium FP rate. Some web apps pass HTML fragments in query strings. Recommend logging verification.",
    "CrossSiteScripting_COOKIE": "Low-medium FP rate. Less common in legitimate traffic.",
    "SQLi_BODY": "Medium FP rate. JSON payloads with SQL-like syntax can trigger. Recommend logging verification.",
    "SQLi_QUERYARGUMENTS": "Medium FP rate. Search queries and filter parameters can trigger.",
    "SQLi_COOKIE": "Low FP rate. Rarely triggered by legitimate traffic.",
    "GenericLFI_QUERYARGUMENTS": "Medium-high FP rate. File path parameters in legitimate apps trigger this.",
    "GenericLFI_BODY": "Medium FP rate. File upload forms may trigger.",
    "GenericRFI_QUERYARGUMENTS": "Medium-high FP rate. URLs in query parameters trigger this.",
    "GenericRFI_BODY": "Medium FP rate. URLs in POST bodies trigger this.",
    "RestrictedExtensions_QUERYARGUMENTS": "Low-medium FP rate. Depends on application file handling.",
    "EC2MetaDataSSRF_BODY": "Low FP rate. Legitimate traffic rarely contains EC2 metadata paths.",
    "EC2MetaDataSSRF_QUERYARGUMENTS": "Low FP rate. Same as above.",
    "NoUserAgent_HEADER": "Medium FP rate. Health checks, internal services, and some mobile apps omit User-Agent.",
}


def _get_rule_type_prior(rule_name: str) -> str:
    """Return a rule-type prior assessment string."""
    if rule_name in PERMANENT_COUNT_RULES:
        return "Known high-FP rule. Should remain in Count permanently."
    if rule_name in LOW_FP_RULES or any(rule_name.startswith(p) for p in ("CVE_", "CVE-")):
        return "Known low-FP rule. Safe to switch to Block without log analysis."
    if rule_name in _RULE_PRIORS:
        return _RULE_PRIORS[rule_name]
    return "No specific prior available for this rule. Log analysis recommended before switching."


def _get_webacl_rules(waf_region: str, scope: str) -> list[dict]:
    """The current WebACL's `Rules` list, or `[]` when it cannot be read.

    Extracted from `_get_all_count_rules` rather than written beside it, because the metric
    cross-check needs the same list for a different reason: it reads each rule's
    `VisibilityConfig` to get the metric name and to refuse a rule that publishes nothing. Two
    readers of one WebACL in one file is the duplication this repository keeps paying for, so
    there is one.
    """
    webacl_name = get_webacl_name()
    if not webacl_name:
        return []

    waf = get_client("wafv2", region_name=waf_region)
    acls = waf.list_web_acls(Scope=scope).get("WebACLs", [])
    match = next((a for a in acls if a["Name"].lower() == webacl_name.lower()), None)
    if not match:
        return []

    resp = waf.get_web_acl(Name=webacl_name, Scope=scope, Id=match["Id"])
    return resp["WebACL"].get("Rules", [])


# --- the labels a later rule reads -----------------------------------------------------------------
#
# A Count rule whose label a later rule matches is part of a design, often a scope-down: the sub-rule
# counts and labels, and a later rule blocks on the label outside an excluded slice. Switching it to
# Block ends evaluation there, so the later rule, and every rate-based rule after it, never sees those
# requests. How a `LabelMatchStatement` key matches, from AWS documentation read 2026-10-18 (label
# match, label match examples, label requirements): a key starting `awswaf:` is fully qualified, and
# for LABEL matches that label exactly; any other key is resolved in the rule's own context,
# `awswaf:<account>:webacl:<name>:`, so it never reaches a managed group's `awswaf:managed:...` label;
# a short LABEL key is the end of the label, with any namespaces between the prefix and it; NAMESPACE
# matches from the prefix on. Matching is case-sensitive. The documentation does not say whether a
# short NAMESPACE key may match a run in the middle, so that counts as a match: an extra reader
# reported is a question for the user, a missed one is a design broken in production.
_LABEL_CHARS = r"[0-9A-Za-z_\-:]+"


def label_prefix() -> str:
    """`awswaf:<account>:webacl:<name>:`, the context a short key and a custom rule's label live in, for
    the WebACL `get_waf_config` selected."""
    from tools.session_state import get_webacl_arn
    arn = get_webacl_arn() or ""
    return f"awswaf:{arn.split(':')[4] if arn.count(':') >= 5 else ''}:webacl:{get_webacl_name() or ''}:"


def _label_pattern(scope: str, key: str, prefix: str) -> str:
    """The regex a label must match to be read by `(scope, key)`, anchored at both ends for LABEL. Not
    escaped: a key and the prefix hold only `[0-9A-Za-z_:-]`, none of it special outside a class, so the
    one pattern reads the same in Python, CloudWatch and Athena."""
    if not re.fullmatch(_LABEL_CHARS, key) or not re.fullmatch(_LABEL_CHARS, prefix):
        raise ValueError(f"outside WAF's label charset: {key!r}, {prefix!r}")
    head = key if key.startswith("awswaf:") else prefix + "([0-9A-Za-z_-]+:)*" + key
    return "^" + head + ("$" if scope == "LABEL" else "")


def label_key_matches(label: str, scope: str, key: str, prefix: str) -> bool:
    return re.search(_label_pattern(scope, key, prefix), label) is not None


def _label_matches(stmt) -> list:
    """Every `(scope, key)` a statement tree matches on, including under Not and in scope-downs."""
    if not isinstance(stmt, dict):
        return []
    found = []
    if "LabelMatchStatement" in stmt:
        lm = stmt["LabelMatchStatement"]
        found.append((lm.get("Scope", "LABEL"), lm.get("Key", "")))
    for key in ("AndStatement", "OrStatement"):
        for sub in (stmt.get(key) or {}).get("Statements", []):
            found += _label_matches(sub)
    if "NotStatement" in stmt:
        found += _label_matches(stmt["NotStatement"].get("Statement", {}))
    for key in ("RateBasedStatement", "ManagedRuleGroupStatement"):
        if key in stmt:
            found += _label_matches(stmt[key].get("ScopeDownStatement", {}))
    return found


def _rule_of(rules: list, count_rule: str):
    """The WebACL rule a Count rule runs in: itself, or the managed group a sub-rule override sits in."""
    for r in rules:
        group = (r.get("Statement") or {}).get("ManagedRuleGroupStatement") or {}
        if r.get("Name") == count_rule or any(o.get("Name") == count_rule for o in group.get("RuleActionOverrides", [])):
            return r
    return None


def label_readers(rules: list, count_rule: str) -> list:
    """`[(rule name, priority, scope, key)]` for each label match in a rule evaluated after `count_rule`.
    When the configuration does not name `count_rule`, every label match: a managed sub-rule that counts
    by default, `TGT_TokenAbsent` say, has no override, so its position is unknown, and a later rule
    reading its label is common. The log check counts which of them its requests carry."""
    own = _rule_of(rules, count_rule)
    return [(r.get("Name", ""), r.get("Priority"), scope, key)
            for r in sorted(rules, key=lambda r: r.get("Priority", 0))
            if own is None or r.get("Priority", 0) > own.get("Priority", 0)
            for scope, key in _label_matches(r.get("Statement", {}))
            if re.fullmatch(_LABEL_CHARS, key)]


def _is_custom(rules: list, count_rule: str) -> bool:
    """Whether `count_rule` is a WebACL rule of its own rather than a managed sub-rule or group."""
    own = _rule_of(rules, count_rule)
    return own is not None and own.get("Name") == count_rule and "ManagedRuleGroupStatement" not in (own.get("Statement") or {})


def by_design(rules: list, count_rule: str, prefix: str) -> list:
    """The later rules that read a label this Count rule adds, from the configuration alone: exact for
    a custom rule's `RuleLabels`. A managed sub-rule's label is not in the configuration, so for those
    the log check in check_low_volume_clients is the evidence."""
    own = _rule_of(rules, count_rule)
    if own is None or own.get("Name") != count_rule:
        return []
    labels = [prefix + l.get("Name", "") for l in own.get("RuleLabels", [])]
    return [(name, pri, key) for name, pri, scope, key in label_readers(rules, count_rule)
            if any(label_key_matches(l, scope, key, prefix) for l in labels)]


def _get_all_count_rules(waf_region: str, scope: str, rules: list | None = None) -> list[str]:
    """Get all rule IDs that are in COUNT mode from the WebACL config."""
    rules = _get_webacl_rules(waf_region, scope) if rules is None else rules

    count_rules = []
    for r in rules:
        # Custom rules with Count action
        action = r.get("Action", {})
        if "Count" in action:
            count_rules.append(r["Name"])

        # Managed rule groups — check for RuleActionOverrides to Count
        stmt = r.get("Statement", {})
        mgr = stmt.get("ManagedRuleGroupStatement", {})
        if mgr:
            # Entire group overridden to Count
            override_action = r.get("OverrideAction", {})
            if "Count" in override_action:
                count_rules.append(r["Name"])
            # Individual rule overrides within the group
            for rao in mgr.get("RuleActionOverrides", []):
                if "Count" in rao.get("ActionToUse", {}):
                    count_rules.append(rao["Name"])

    return list(dict.fromkeys(count_rules))  # a group deployed twice names its overrides twice



