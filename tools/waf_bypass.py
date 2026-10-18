# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Bypass/evasion detection tool — find malicious traffic that WAF is allowing through."""

import re
import sys
import time
from datetime import datetime, timedelta, timezone
from strands import tool
from tools.aws_session import get_client
from tools.session_state import (get_webacl_name, get_scope, resolve_region, is_log_filter_active,
                                 note_window_capped)
from tools.waf_query import (query_logs, log_query_error, get_log_type, run_concurrently, truncation_summary,
                             CWL_QUERY_MAX)
from tools.query_limits import MAX_MINUTES
from tools.static_assets import ATHENA_EXCLUDE_STATIC, ATHENA_ONLY_STATIC, CWL_EXCLUDE_STATIC, CWL_ONLY_STATIC

# Every label test on CloudWatch reads the parsed `labels` array, never the raw record. A bare
# `@message not like 'bot:verified'` also dropped any request carrying that text in its URI or
# User-Agent: measured 2026-10-15, three probe requests with no such label but the words in the
# path and UA were excluded from every section, and kept once the test read `lbls`. Evidence for the
# `not ispresent(lbls)` branch: 46,040 of 46,040 WAF records on `aws-waf-logs-test` carried a labels
# key (the Anti-DDoS AMR labels every request), so a record without one is unmeasured here. It keeps
# such a record rather than dropping it, which is right whichever way an unlabelled record is shaped.
from tools.waf_aggregate import _LABELS_ARRAY


def _safe_query(cwl: str, athena: str, start: int, end: int, limit: int = 10, *,
                failures: dict | None = None, label: str = "",
                notes: dict | None = None) -> list[dict]:
    """Run a log query, return its rows, and record why if there are none.

    Still never raises, which is what a report assembled from many independent queries
    needs. What it no longer does is destroy the reason: a query that failed and a query
    that matched nothing both arrived as `[]`, and this file renders `[]` as
    `(none found)`, which is a claim about the traffic rather than a report of what we
    know. Measured on 2026-09-10 against a table missing `ja4fingerprint`: two of six
    queries failed with COLUMN_NOT_FOUND and the scan produced a full report asserting no
    bypass candidates, with the errors visible only on stderr.

    Both spellings of failure land here. An **exception** is the Athena path, where
    `_run_athena_select` raises on a stop or an engine failure. An **`_error` row** is the
    CloudWatch path, and passing that through as data was the worse of the two: the row is
    truthy, so a section rendered it as a table row of `?` placeholders, which is a
    fabricated finding rather than a missing one.
    """
    def _record(reason: str) -> list[dict]:
        print(f"[waf_bypass] {label or 'log query'} failed: {reason}",
              file=sys.stderr, flush=True)
        if failures is not None:
            failures[label] = reason
        return []

    try:
        rows = query_logs(cwl, athena, start, end, limit, notes=notes, label=label)
    except Exception as e:
        return _record(f"{type(e).__name__}: {e}")
    reason = log_query_error(rows)
    if reason:
        return _record(reason)
    return rows or []


def _static_traffic(static_peak, non_static, allowed, distinct, distinct_failed, ip) -> list[str]:
    """The verdict for fast ALLOW traffic that is nearly all static. It reached static files rather
    than the application, so it is abuse or cost rather than a way past the rules, and the rate is
    measured while the intent is not, so it names the shapes that fit. The distinct-URI count only
    picks the shape, so without it the verdict stands unshaped, and says why: the investigation has
    no section of its own for that count."""
    if None in (static_peak, non_static, allowed):
        return []
    if distinct is None:
        reason = (distinct_failed or "").split("\nACTION:")[0].strip()
        shape = f" How many distinct files it fetched is unknown: the all_uris query did not answer ({reason})." if reason else ""
    else:
        shape = (f" It fetched many files ({distinct} distinct URIs), which is how bulk fetching, a mirror or "
                 f"an image scraper looks. These signals cannot tell which." if distinct > 50 else
                 f" It pulled the same {distinct} file{'s' if distinct != 1 else ''} over and over, which fits a "
                 f"flood aimed at a file, a client stuck in a retry loop, or a monitoring probe. These signals "
                 f"cannot tell which." if distinct <= 2 else
                 f" It was spread over {distinct} distinct URIs.")
    return ["**LIKELY: High-rate static-asset traffic, not a bypass.**",
            f"Evidence: peak {static_peak:g} static req/min allowed, and {allowed - non_static:,} of "
            f"{allowed:,} allowed requests static. It reached static files, not the application's "
            f"endpoints, so this is an abuse or cost question rather than a way past the rules.{shape}",
            f"→ Before deciding, look at its top URIs (run_logs_query(query_type='ip_uri_breakdown', "
            f"ip='{ip}')), its User-Agent above, and its Referer (aggregate_logs(group_by='referer', "
            f"filter_by='{{\"ip\": \"{ip}\"}}'))."]


def _cwl_count_rules(ip: str, start: int, end: int, failures: dict, notes: dict) -> list[dict]:
    """The Count rules on one IP's requests, CloudWatch side: `[{"rule", "hits"}]`, busiest first.

    **CloudWatch has no array accessor that holds up**, so the names are found first and each is then
    counted with a one-entry substring, `"ruleId":"X","action":"COUNT"`, which counts it once per
    request as Athena does and which client text cannot produce. `unnest` measured wrong: filtered on
    the element's action and grouped by its rule, it answered 604 for TGT_TokenAbsent where the
    records held 1,040 entries, and other filters on unnested fields answered differently on identical
    runs. A first-match parse alone was the version before this, and since `ruleGroupList` comes before
    the top-level `nonTerminatingMatchingRules` in the record, it always took a nested entry: over 24
    hours on `test-webacl-cwl` a WebACL-level Count rule read 0 for 5 requests.

    The names are the first and the last Count entry of each record plus every Count rule the WebACL
    configures. Missed is only a rule in the middle of three or more, that the configuration does not
    name, and no such record was found in 24 hours.
    """
    import re
    base = f"filter httpRequest.clientIp = '{ip}' and @message like '\"action\":\"COUNT\"'"
    found = _safe_query(
        base + " | parse @message /\"ruleId\":\"(?<first>[^\"]+)\",\"action\":\"COUNT\"/"
        " | parse @message /.*\"ruleId\":\"(?<last>[^\"]+)\",\"action\":\"COUNT\"/"
        " | stats count(*) as n by first, last",
        "", start, end, limit=1000, failures=failures, label="count_rules", notes=notes)
    if failures.get("count_rules"):
        return []
    names = {r.get(k) for r in found for k in ("first", "last")}
    try:
        from tools.waf_count_eval import _get_all_count_rules
        scope = get_scope() or "CLOUDFRONT"
        names |= set(_get_all_count_rules(resolve_region(scope), scope))
    except Exception as e:
        # Not a failure of the section: the names from the records still stand, and only a rule found
        # in neither place can be missing. Rendered beside the list rather than instead of it.
        failures["count_rules_config"] = f"{type(e).__name__}: {e}"
    names = sorted(n for n in names if n and re.fullmatch(r"[\w-]+", n))
    if not names:
        return []
    # As many queries as the length limit needs: every Count rule the WebACL configures is counted,
    # and a WebACL tuning several managed groups in Count holds more than 140 of them.
    chunks = [[]]
    for i, n in enumerate(names):
        field = f"sum(strcontains(@message, '\"ruleId\":\"{n}\",\"action\":\"COUNT\"')) as c{i}"
        if chunks[-1] and len(base + " | stats " + ", ".join(chunks[-1] + [field])) > CWL_QUERY_MAX:
            chunks.append([])
        chunks[-1].append(field)
    row = {}
    for chunk in chunks:
        counted = _safe_query(base + " | stats " + ", ".join(chunk), "", start, end, limit=1,
                              failures=failures, label="count_rules", notes=notes)
        if failures.get("count_rules"):
            return []
        row.update(counted[0] if counted else {})
    hits = sorted(((n, int(float(row.get(f"c{i}") or 0))) for i, n in enumerate(names)), key=lambda x: -x[1])
    hits = [{"rule": n, "hits": str(h)} for n, h in hits if h > 0]
    if len(hits) > 5:
        notes["count_rules"] = 5  # what the Athena side records at its row limit of five
    return hits[:5]


def _empty_reason(failures: dict, label: str, none_text: str = "  (none found)") -> str:
    """The line an empty section shows, which depends on why it is empty.

    Every `none_text` in this file is a statement about the traffic: "(none found)",
    "(not available)", "(no query strings on ALLOW traffic)". A failed query supports no
    statement about the traffic at all, so the two must not read alike.

    **The retry choreography is stripped, and that is the point of the transform.**
    `poll_timeout_message` ends in an `ACTION:` block telling the reader to retry once with a
    quarter of the window, which is written for whoever *chose* the window. Nobody chose this
    one: the tool issues these queries itself with the scan's window. Rendering that advice into
    a section note asks the model to act on a decision it did not make, and on two adjacent slow
    queries in one scan the second message reads "that is 2 timeouts in a row, so narrowing is
    not working", which is a statement about the user's window that the user never set.

    The counter behind that count is shared session state and is still incremented by a chain
    query, so a slow scan can still change what the next user-driven question is told. That half
    needs the poller to know who chose the window, which is ROADMAP 2.1's remaining piece."""
    reason = failures.get(label)
    if reason:
        first = reason.split("\nACTION:")[0].strip()
        return f"  UNKNOWN, the query for this section failed: {first}"
    return none_text

# Automation User-Agents, one list for the scan and the investigation. They were two lists, and the
# investigation's lacked libwww-perl, so an IP the scan surfaced for it was not an automation UA once
# investigated; the scan's said python-requests, so Python-urllib and httpx were never surfaced.
AUTOMATION_UA_TOKENS = ("curl", "python", "wget", "httpie", "go-http", "java/", "okhttp", "libwww-perl")
AUTOMATION_UA_CWL = "ua like /(?i)(" + "|".join(t.replace("/", "\\/") for t in AUTOMATION_UA_TOKENS) + ")/"
AUTOMATION_UA_ATHENA = "'(?i)(" + "|".join(AUTOMATION_UA_TOKENS) + ")'"

CONFIDENCE_RULES = """\
## Confidence Rules
- HIGH: automation UA + ALLOW, data-center IP + high freq + no bot labels → state directly
- LIKELY: high URI diversity + no bot labels, regular intervals → "probable bot, needs confirmation"
- CANNOT DETERMINE: browser UA + browser JA4 + moderate frequency → ask user
- PRESENT-ONLY: volume trends, IP distribution → show data, user decides if expected
"""

# The endpoint signal: many sources on one path and method, against the same window a week earlier.
# Measured 2026-10-18 with this exact condition (allowed, non-static, bot:verified left out) over 8 days
# of hourly windows on the two low-traffic test WebACLs: it marked two events and no ordinary traffic,
# a 6-IP credential-stuffing run on POST /login (816 requests, none a week earlier), which every per-IP
# signal here missed with each IP under 200 requests, and a 10-source flood on GET / (37,771 allowed).
# Loosened to 3 IPs and 50 requests it adds one endpoint per WebACL, both false-positive test traffic.
ENDPOINT_MIN_IPS = 5
ENDPOINT_MIN_REQUESTS = 200
ENDPOINT_IP_GROWTH = 3
_ENDPOINTS = 20
_SAFE_URI = re.compile(r"[A-Za-z0-9/._~%!$&()*+,=:@-]+")

# Anomaly thresholds (hardcoded, not LLM judgment)
WOW_ANOMALY_MODERATE = 2.0
WOW_ANOMALY_SIGNIFICANT = 3.0
UNIQUE_IP_ANOMALY = 2.0


@tool
def detect_bypass(step: str = "scan", ip: str = "", start_time: str = "",
                  duration_minutes: int = 180, ja4: str = "") -> str:
    """Detect potential WAF bypass — find malicious traffic in ALLOW logs.

    This tool provides evidence for human judgment. It does NOT make definitive
    bypass verdicts without quantifiable signal support. For ALLOW traffic it also
    surfaces the top query strings (redacted) as a bypass signal.

    Prerequisite: call get_waf_config first (after selecting the WebACL). This tool
    reads session state populated there; without it scan/investigate_ip error out.

    Steps:
    - "scan": Proactive check — run anomaly filters on ALLOW traffic to find suspicious IPs.
    - "ja4_ips": The IPs behind one JA4 fingerprint from the scan's JA4 tables. Requires ja4.
    - "investigate_ip": Deep-dive a specific IP's behavior in ALLOW logs.
    - "volume_anomaly": Check a window for traffic volume anomalies (DDoS/scraping indicators): the
      window given, or else the busiest hour of the last 7 days, against the same window a week earlier.

    Args:
        step: "scan", "ja4_ips", "investigate_ip", or "volume_anomaly".
        ip: Client IP (required for investigate_ip).
        ja4: JA4 fingerprint (required for ja4_ips), copied from the scan's JA4 table.
        start_time: Start time for log queries (required for scan and investigate_ip). Optional for
            volume_anomaly, which otherwise picks the busiest hour of ALLOW traffic in the last 7 days.
        duration_minutes: Duration in minutes (default 180, max 360, both engines).
    """
    from tools.waf_logs import _parse_start_time

    if step == "volume_anomaly":
        if not start_time:
            return _step_volume_anomaly()
        start_epoch = _parse_start_time(start_time)
        if start_epoch is None:
            return f"Error: cannot parse start_time '{start_time}'."
        return _step_volume_anomaly(start_epoch, start_epoch + duration_minutes * 60)

    # Ensure session state is populated
    if not get_webacl_name():
        return ("Error: No WebACL selected. Call get_waf_config(webacl_name='...') first, "
                "or call list_webacls() to see available WebACLs.")

    # scan and investigate_ip require logging
    if get_log_type() == "none":
        return ("Error: No logging configured for this WebACL. Cannot analyze ALLOW traffic without logs.\n"
                "Enable WAF logging (S3 or CloudWatch Logs) first.\n"
                "For a metrics-only volume check, call detect_bypass(step='volume_anomaly').")
    from tools.waf_query import check_coarse_partition_block
    coarse_err = check_coarse_partition_block()
    if coarse_err:
        return coarse_err

    if is_log_filter_active():
        # Check if ALLOW logs are available
        test_cwl = "filter action = 'ALLOW' | stats count(*) as cnt"
        test_athena = "SELECT count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND action = 'ALLOW'"
        if start_time:
            start_epoch = _parse_start_time(start_time)
            if start_epoch:
                end_epoch = start_epoch + min(duration_minutes, 60) * 60
                # The one `_safe_query` call in this file that recorded nothing, and the only place
                # in the repository where a failed query was reported as a *named cause* rather
                # than as absence. Without a `failures` dict a failure returns `[]`, `not results`
                # is true, and the tool answered "Log Filter is active and ALLOW logs appear
                # filtered out", then told the user to change their WAF logging configuration and
                # refused the whole scan. A poll timeout produced a diagnosis of their filter.
                probe: dict[str, str] = {}
                results = _safe_query(test_cwl, test_athena, start_epoch, end_epoch, limit=1,
                                      failures=probe, label="allow_probe")
                if probe:
                    return ("## Cannot Proceed — the ALLOW-log probe did not run\n\n"
                            f"{_empty_reason(probe, 'allow_probe')}\n\n"
                            "A Log Filter is active on this WebACL, so the scan checks first whether "
                            "ALLOW rows reach the log destination. That check failed, which says "
                            "nothing about the filter. Do NOT tell the user their filter is dropping "
                            "ALLOW logs, and do NOT suggest they change it. Re-run "
                            "detect_bypass(step='scan') once the reason above is addressed.")
                if not results or int(results[0].get("cnt", 0)) == 0:
                    return ("## Cannot Proceed — ALLOW Logs Unavailable\n\n"
                            "⚠️  Log Filter is active and ALLOW logs appear filtered out.\n"
                            "Bypass detection requires ALLOW logs. Remove the filter or add ALLOW to KEEP filters.\n"
                            "For a metrics-only volume check, call detect_bypass(step='volume_anomaly').")

    if not start_time:
        return "Error: start_time is required. Ask the user which time period to analyze."

    start_epoch = _parse_start_time(start_time)
    if start_epoch is None:
        return f"Error: cannot parse start_time '{start_time}'."

    _duration = min(duration_minutes, MAX_MINUTES)
    note_window_capped(duration_minutes, _duration)
    end_epoch = min(start_epoch + _duration * 60, int(time.time()))

    if step == "scan":
        return _step_scan(start_epoch, end_epoch)
    elif step == "ja4_ips":
        if not ja4:
            return ("Error: ja4 is required for step='ja4_ips'. Copy a fingerprint from the "
                    "JA4 table in the scan output.")
        return _step_ja4_ips(ja4, start_epoch, end_epoch)
    elif step == "investigate_ip":
        if not ip:
            return "Error: ip is required for step='investigate_ip'. Ask the user which IP to check."
        import ipaddress as _ipa
        try:
            _ipa.ip_address(ip)
        except ValueError:
            return f"Error: invalid IP address '{ip}'"
        return _step_investigate_ip(ip, start_epoch, end_epoch)
    else:
        return (f"Error: unknown step '{step}'. Available: scan, ja4_ips, investigate_ip, "
                f"volume_anomaly")


def _step_ja4_ips(ja4: str, start_epoch: int, end_epoch: int) -> str:
    """The IPs behind one JA4 fingerprint. One query, for one fingerprint the user chose.

    This is the drill-down that used to run eagerly for every candidate the scan found, up to
    ten extra serial queries on top of the scan's six. The measurement that mattered is that
    chain length dominates cost, so the lever is not making each query cheaper but issuing
    fewer of them, and the user almost never wants all ten.

    Splitting it out also fixed a reporting bug the loop had: every iteration recorded its
    failures under the single label `distributed_ips`, so if two fingerprints failed the report
    kept one reason and silently dropped the other."""
    failures: dict[str, str] = {}
    # Which sections were cut off at their limit, keyed the same way as `failures` so a
    # renderer looks in one place for both and cannot surface one while forgetting the other.
    notes: dict[str, int] = {}
    # Reject, do not substitute. `re.sub` of the disallowed characters is injection-safe, since
    # the quotes go, but it then queries a DIFFERENT fingerprint: paste `t13d…h2 ` with a stray
    # character and the report's own header names a fingerprint the user never typed, which
    # reads as authoritative. The two comparable places in this repo already do it this way,
    # `waf_query.py:504` and `waf_patrol.py:593`, both fullmatch-or-refuse before a
    # user-derived string reaches SQL. A legitimate JA4 is alphanumeric with underscores, so
    # this costs a real one nothing.
    # `.strip()` and nothing more. Surrounding whitespace is a paste artifact carrying no
    # information, so removing it recovers the fingerprint the user meant. An INTERIOR
    # stray character changes which fingerprint is named, and that is the case refused.
    safe_ja4 = ja4.strip()
    if not re.fullmatch(r"[0-9a-zA-Z_]+", safe_ja4):
        return (f"Error: '{ja4}' is not a JA4 fingerprint. They are letters, digits and "
                f"underscores only. Copy one from the scan's JA4 table without editing it.")

    cwl = (
        _LABELS_ARRAY + " | " f"filter action = 'ALLOW' and ja4Fingerprint = '{safe_ja4}'"
        f"{CWL_EXCLUDE_STATIC}"
        " and (not ispresent(lbls) or not (lbls like 'bot:verified'))"
        " | stats count(*) as hits by httpRequest.clientIp"
        " | sort hits desc | limit 10"
    )
    athena = (
        f"SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as hits"
        f" FROM {{TABLE}}"
        f" WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND action = 'ALLOW' AND ja4fingerprint = '{safe_ja4}'"
        f"{ATHENA_EXCLUDE_STATIC}"
        f" AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:verified%') )"
        f" GROUP BY httprequest.clientip ORDER BY hits DESC LIMIT {{LIMIT}}"
    )
    rows = _safe_query(cwl, athena, start_epoch, end_epoch, limit=10,
                       failures=failures, label="ja4_ips", notes=notes)

    lines = [f"## IPs behind JA4 {safe_ja4}", ""]
    if failures:
        lines.append(_empty_reason(failures, "ja4_ips"))
        return "\n".join(lines)
    if not rows:
        lines.append("  (no ALLOW traffic from this fingerprint in this window)")
        lines.append("  The fingerprint came from the scan's window; if you widened or moved the "
                     "window since, use the scan's window here.")
        return "\n".join(lines)

    lines.append(f"| {'IP':<15} | {'Requests':>8} |")
    lines.append(f"| {'-'*15} | {'-'*8} |")
    for r in rows:
        lines.append(f"| {r.get('httpRequest.clientIp', '?'):<15} | {r.get('hits', '?'):>8} |")
    lines.append("")
    lines.append("→ Pick one and call detect_bypass(step='investigate_ip', ip='<IP>') for its "
                 "behaviour, labels and query strings.")
    _cut = truncation_summary(notes, failures)
    if _cut:
        lines.append(_cut)
    return "\n".join(lines)


# The local baseline: this many hours either side of the window, scaled to the window's length.
SURROUNDING_HOURS = 6


def _volume_reads(cw, webacl_name: str, start, end, period: int, scope: str, region: str) -> dict:
    """`{"allowed", "mitigated", "event"}` summed over [start, end) at `period`. Raises on a failed read.

    `Rule=ALL` by MetricStat, so no SEARCH discovery is involved, and `event` is the Anti-DDoS
    `event-detected` label's ChallengeRequests over the same window."""
    dims = [{"Name": "WebACL", "Value": webacl_name}, {"Name": "Rule", "Value": "ALL"}]
    label_dims = [{"Name": "WebACL", "Value": webacl_name},
                  {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:anti-ddos"},
                  {"Name": "LabelName", "Value": "event-detected"}]
    if scope == "REGIONAL" and region:
        dims.append({"Name": "Region", "Value": region})
        label_dims.append({"Name": "Region", "Value": region})
    metrics = {"allowed": ("AllowedRequests", dims), "blocked": ("BlockedRequests", dims),
               "challenge": ("ChallengeRequests", dims), "captcha": ("CaptchaRequests", dims),
               "event": ("ChallengeRequests", label_dims)}
    resp = cw.get_metric_data(MetricDataQueries=[
        {"Id": key, "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": name, "Dimensions": d},
                                   "Period": period, "Stat": "Sum"}}
        for key, (name, d) in metrics.items()], StartTime=start, EndTime=end)
    sums = {r["Id"]: sum(r.get("Values", [])) for r in resp.get("MetricDataResults", [])}
    return {"allowed": sums.get("allowed", 0),
            "mitigated": sums.get("blocked", 0) + sums.get("challenge", 0) + sums.get("captcha", 0),
            "event": sums.get("event", 0)}


def _peak_hour(cw, webacl_name: str, scope: str, region: str, end):
    """`(start, ALLOW count)` of the busiest hour of ALLOW traffic in the seven days before `end`, or None
    if there was none."""
    dims = [{"Name": "WebACL", "Value": webacl_name}, {"Name": "Rule", "Value": "ALL"}]
    if scope == "REGIONAL" and region:
        dims.append({"Name": "Region", "Value": region})
    start = (end - timedelta(days=7)).replace(minute=0, second=0, microsecond=0)
    resp = cw.get_metric_data(MetricDataQueries=[{"Id": "a", "MetricStat": {"Metric": {
        "Namespace": "AWS/WAFV2", "MetricName": "AllowedRequests", "Dimensions": dims},
        "Period": 3600, "Stat": "Sum"}}], StartTime=start, EndTime=end)
    points = [(v, t) for r in resp.get("MetricDataResults", [])
              for v, t in zip(r.get("Values", []), r.get("Timestamps", [])) if v]
    if not points:
        return None
    v, t = max(points, key=lambda p: p[0])
    return t.astimezone(timezone.utc), v


def _comparison_window(start, end, now):
    """`(start, end, period, has_week)` for reading a window against the same window a week earlier, or
    None when CloudWatch no longer holds it: whole points from the resolution the older read is kept at,
    ending at the last whole point, so a point still filling does not read low against a full one."""
    from tools.waf_metrics import _period_for_window
    from tools.waf_overview import _whole_points
    week = timedelta(days=7)
    has_week = _period_for_window(int((start - week).timestamp())) is not None
    oldest = start - week if has_week else start
    period = _period_for_window(int(oldest.timestamp()))
    if period is None:
        return None
    start, end = _whole_points(start, end, period, oldest)
    last = now - timedelta(seconds=int(now.timestamp()) % period, microseconds=now.microsecond)
    return start, max(min(end, last), start + timedelta(seconds=period)), period, has_week


def _step_volume_anomaly(start_epoch: int | None = None, end_epoch: int | None = None) -> str:
    """Metrics-based volume anomaly detection for one window. No logs needed.

    **The window, not the week.** This compared seven-day totals, and an hour-long scraper or flood
    barely moves a week's ALLOW count, so the likely reading of a real anomaly was "within normal
    range". Now the window is the one asked for, or else the busiest hour of ALLOW traffic in the last
    seven days, and it is set against the same window a week earlier and against the hours around it.
    The week-earlier ratio decides, because it carries the weekly cycle; the surrounding hours decide
    only when the week earlier had no ALLOW traffic at all. A busiest hour picked out of 168 sits above
    its own hour a week earlier by selection alone, so a picked hour is set against the busiest hour of
    the week before instead."""
    webacl_name = get_webacl_name()
    if not webacl_name:
        return "Error: No WebACL configured. Call get_waf_config first."

    from tools.waf_overview import _window_note
    from tools.waf_logs import naive_time_tz
    scope = get_scope()
    region = resolve_region(scope)
    cw = get_client("cloudwatch", region_name=region)
    now = datetime.now(timezone.utc)

    week = timedelta(days=7)
    try:
        prev_peak = None
        if start_epoch is None:
            peak = _peak_hour(cw, webacl_name, scope, region, now)
            if peak is None:
                return (f"## Volume Anomaly Analysis\n\nNo ALLOW traffic was recorded for {webacl_name} in the "
                        f"last 7 days, so there is no busiest hour to compare. Give a start_time to check a "
                        f"specific window.")
            start, peak_allowed = peak
            prev_peak = _peak_hour(cw, webacl_name, scope, region, now - week)
            end, chosen = min(start + timedelta(hours=1), now), "the busiest hour of ALLOW traffic in the last 7 days"
        else:
            start = datetime.fromtimestamp(start_epoch, timezone.utc)
            end, chosen = min(datetime.fromtimestamp(end_epoch, timezone.utc), now), "the window asked for"
        asked_start, asked_end = start, end
        window = _comparison_window(start, end, now)
        if window is None:
            return (f"No metrics for {webacl_name} in this window: CloudWatch keeps WAF metrics for 455 days, "
                    f"and this window starts before that.")
        start, end, period, has_week = window
        last = now - timedelta(seconds=int(now.timestamp()) % period, microseconds=now.microsecond)
        span = end - start
        this = _volume_reads(cw, webacl_name, start, end, period, scope, region)
        prev = _volume_reads(cw, webacl_name, start - week, end - week, period, scope, region) if has_week else None
        around = timedelta(hours=SURROUNDING_HOURS)
        after_end = min(end + around, last)
        before = _volume_reads(cw, webacl_name, start - around, start, period, scope, region)
        after = (_volume_reads(cw, webacl_name, end, after_end, period, scope, region)
                 if after_end > end else {"allowed": 0, "mitigated": 0, "event": 0})
    except Exception as e:                                # noqa: BLE001
        return (f"## Volume Anomaly Analysis\n\nThe CloudWatch metric read failed ({type(e).__name__}: {e}), so "
                f"nothing here says whether traffic was normal. Retry, or query the logs for the window.")

    around_span = around + max(after_end - end, timedelta(0))
    scale = span / around_span
    near = {k: (before[k] + after[k]) * scale for k in ("allowed", "mitigated")}
    ratio = lambda k, base: this[k] / base[k] if base and base[k] else None
    week_allowed, near_allowed = ratio("allowed", prev), ratio("allowed", near)
    if prev_peak is not None:
        allowed_x, base = peak_allowed / prev_peak[1], prev
        basis = f"the busiest hour of the week before ({prev_peak[0].astimezone(naive_time_tz()).strftime('%Y-%m-%d %H:%M')})"
    elif week_allowed is not None:
        allowed_x, base, basis = week_allowed, prev, "the same window a week earlier"
    else:
        allowed_x, base, basis = near_allowed, near, f"the {SURROUNDING_HOURS} hours either side"
    # A rise from nothing has no ratio, and it is still a rise: the first live run read 562,445
    # mitigated against 0 a week earlier as "did NOT rise".
    mitigated_x = ratio("mitigated", base)
    mitigated_rose = this["mitigated"] > 0 and (mitigated_x is None or mitigated_x > WOW_ANOMALY_SIGNIFICANT)
    mitigated_desc = (f"{mitigated_x:.1f}x" if mitigated_x is not None
                      else f"{this['mitigated']:,.0f} against none" if this["mitigated"] else "none in either")

    tz = naive_time_tz()
    fmt = lambda t: t.astimezone(tz).strftime("%Y-%m-%d %H:%M")
    show = lambda x: "n/a" if x is None else f"{x:.1f}x"
    week_cell = lambda k: "no data (older than 455 days)" if prev is None else f"{prev[k]:,.0f}"
    lines = [
        "## Volume Anomaly Analysis",
        f"**Window**: {fmt(start)} to {fmt(end)}, {chosen}",
        f"**WebACL**: {webacl_name}",
        "",
        "### Traffic Comparison",
        f"| Metric | This window | Same window a week earlier | {SURROUNDING_HOURS} hours either side, scaled to this window |",
        "| ------ | ----------- | -------------------------- | ------------------------------------- |",
        f"| ALLOW | {this['allowed']:,.0f} | {week_cell('allowed')} | {near['allowed']:,.0f} |",
        f"| Mitigated (Block+Challenge+Captcha) | {this['mitigated']:,.0f} | {week_cell('mitigated')} | {near['mitigated']:,.0f} |",
        f"| ALLOW ratio | | {show(week_allowed)} | {show(near_allowed)} |",
        "",
    ]
    if this["event"]:
        lines += ["⚠️  **The Anti-DDoS event-detected label appeared in this window**: AMR declared a DDoS event.", ""]

    scan_minutes = max(60, min(int(span.total_seconds() // 60), 120))
    scan_call = (f"detect_bypass(step='scan', start_time='{start.astimezone(tz).strftime('%Y-%m-%dT%H:%M')}', "
                 f"duration_minutes={scan_minutes})")
    if allowed_x is None:
        lines += ["### Assessment: No Baseline",
                  f"Neither the same window a week earlier nor the {SURROUNDING_HOURS} hours either side had ALLOW "
                  f"traffic, so a ratio would mean nothing. Show the numbers and ask the user whether this "
                  f"volume is expected."]
    elif allowed_x < WOW_ANOMALY_MODERATE:
        lines += ["### Assessment: No Significant Volume Anomaly",
                  f"ALLOW traffic is {allowed_x:.1f}x {basis}. A scan can still find abuse that does not move "
                  f"the volume."]
    elif allowed_x < WOW_ANOMALY_SIGNIFICANT:
        lines += ["### Assessment: Moderate Increase",
                  f"ALLOW traffic is {allowed_x:.1f}x {basis}. Could be legitimate growth or an early-stage "
                  f"attack; until someone says what explains it, treat it as unexplained."]
    else:
        lines += ["### Assessment: Significant Anomaly",
                  f"⚠️  ALLOW traffic is **{allowed_x:.1f}x** {basis}.", "",
                  "**Preliminary classification (from metrics only):**"]
        if this["event"]:
            lines.append("- Anti-DDoS event detected → DDoS attack confirmed by AMR")
        if mitigated_rose:
            lines.append(f"- Mitigated traffic also rose ({mitigated_desc}) → WAF IS catching some of it")
        else:
            lines.append(f"- Mitigated traffic did NOT rise as much ({mitigated_desc}) → the extra traffic is "
                         f"being allowed")
        lines += ["", "The scan determines IP distribution and URI patterns, which distinguish:",
                  "- IP distribution FLAT + URI concentrated → Classic distributed DDoS",
                  "  → Recommend: Anti-DDoS AMR, rate-based rules",
                  "- IP distribution FLAT + URI diversity HIGH (random paths) → Cache-bypass DDoS",
                  "  → Recommend: Cache 403/404 in CloudFront, rate-based rule, Anti-DDoS AMR",
                  "- IP distribution CONCENTRATED + URI diversity HIGH → Scraper/crawler",
                  "  → Recommend: Bot Control (Targeted), custom rate-based rule"]

    lines += ["", "## Your Next Action", "",
              "Always ask: \"Is this expected traffic (marketing campaign, product launch, seasonal event)?\"",
              f"If unexpected → call {scan_call} to find the clients behind it."]
    lines += ["", CONFIDENCE_RULES]
    return "\n".join(lines) + (_window_note(asked_start, asked_end, start, end, period) if chosen == "the window asked for" else "")


def _step_scan(start_epoch: int, end_epoch: int) -> str:
    """Proactive scan: find suspicious IPs in ALLOW traffic."""

    # Why a section is empty, keyed by the section. Six sections render an empty
    # list as "(none found)", which is a claim about the traffic, so a failed query
    # has to be told apart from a query that matched nothing.
    failures: dict[str, str] = {}
    # Which sections were cut off at their limit, keyed the same way as `failures` so a
    # renderer looks in one place for both and cannot surface one while forgetting the other.
    notes: dict[str, int] = {}

    # ROADMAP 4.6. The six anomaly filters are independent: none reads another's output, so
    # the serial chain's wall time was the sum for no reason. Each is registered here as a
    # thunk and they all start together below.
    #
    # Deferred in place rather than by hoisting the six query strings to the top. Moving them
    # would be a hundred-line diff whose review burden is entirely in the movement, and the
    # queries read better next to the comment explaining what each one looks for.
    jobs: dict[str, object] = {}

    def later(label: str, cwl: str, athena: str, limit: int = 10):
        """Queue one independent query. Nothing runs until `run_concurrently` below.

        `_safe_query` is what makes the fan-out safe to write this way: it never raises, and
        it records its own reason under `label`, so six threads write six distinct keys of
        `failures`. Distinct-key dict assignment is atomic under the GIL, so no lock is
        needed here; a job that MUTATED a shared value would need one."""
        jobs[label] = lambda: _safe_query(cwl, athena, start_epoch, end_epoch, limit=limit,
                                          failures=failures, label=label, notes=notes)

    # 0. Quick coverage check (config-based) + WoW volume check
    coverage_gaps = _check_coverage_gaps()

    # This window against the same window a week earlier. It compared seven-day totals, which an
    # anomaly inside this window barely moves. Advisory only, so a failed read is a stderr line.
    wow_note = ""
    try:
        scope = get_scope()
        region = resolve_region(scope)
        cw = get_client("cloudwatch", region_name=region)
        window = _comparison_window(datetime.fromtimestamp(start_epoch, timezone.utc),
                                    datetime.fromtimestamp(end_epoch, timezone.utc), datetime.now(timezone.utc))
        week = timedelta(days=7)
        if window and window[3]:
            start_dt, end_dt, period, _ = window
            tw_a = _volume_reads(cw, get_webacl_name(), start_dt, end_dt, period, scope, region)["allowed"]
            lw_a = _volume_reads(cw, get_webacl_name(), start_dt - week, end_dt - week, period, scope, region)["allowed"]
            if lw_a and tw_a / lw_a >= WOW_ANOMALY_SIGNIFICANT:
                wow_note = (f"⚠️  ALLOW traffic in this window is {tw_a / lw_a:.1f}x the same window a week "
                            f"earlier (significant spike). Consider calling detect_bypass(step='volume_anomaly', "
                            f"start_time='...') for aggregate analysis first.")
    except Exception as e:                                # noqa: BLE001
        print(f"[waf_bypass] no volume comparison for the scan: {type(e).__name__}: {e}",
              file=sys.stderr, flush=True)

    # 1. Run anomaly filters (exclusions built into queries)
    crawlers_cwl = (
        _LABELS_ARRAY + " | " "filter action = 'ALLOW'"
        f"{CWL_EXCLUDE_STATIC}"
        " and (not ispresent(lbls) or not (lbls like 'bot:verified'))"
        " | stats count(*) as total, count_distinct(httpRequest.uri) as unique_uris by httpRequest.clientIp"
        " | filter unique_uris > 50"
        " | sort unique_uris desc | limit 10"
    )
    crawlers_athena = (
        "SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as total,"
        " count(DISTINCT httprequest.uri) as unique_uris"
        " FROM {TABLE}"
        " WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER}"
        " AND action = 'ALLOW'"
        f"{ATHENA_EXCLUDE_STATIC}"
        " AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:verified%') )"
        " GROUP BY httprequest.clientip"
        " HAVING count(DISTINCT httprequest.uri) > 50"
        " ORDER BY unique_uris DESC LIMIT {LIMIT}"
    )

    repeaters_cwl = (
        _LABELS_ARRAY + " | " "filter action = 'ALLOW'"
        f"{CWL_EXCLUDE_STATIC}"
        " and (not ispresent(lbls) or not (lbls like 'bot:verified'))"
        " | stats count(*) as total, count_distinct(httpRequest.uri) as unique_uris by httpRequest.clientIp"
        " | filter total > 200 and unique_uris < 10"
        " | sort total desc | limit 10"
    )
    repeaters_athena = (
        "SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as total,"
        " count(DISTINCT httprequest.uri) as unique_uris"
        " FROM {TABLE}"
        " WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER}"
        " AND action = 'ALLOW'"
        f"{ATHENA_EXCLUDE_STATIC}"
        " AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:verified%') )"
        " GROUP BY httprequest.clientip"
        " HAVING count(*) > 200 AND count(DISTINCT httprequest.uri) < 10"
        " ORDER BY total DESC LIMIT {LIMIT}"
    )

    # Data-center and cloud-provider IPs not caught by Bot Control. The provider signal is the one a
    # fleet on rented instances carries: measured 2026-09-08 on `test-webacl-s3`, 12 scraper
    # hosts sent 1,080 allowed requests, all labelled `signal:cloud_service_provider:aws` and none
    # `known_bot_data_center`.
    datacenter_cwl = (
        _LABELS_ARRAY + " | " "filter action = 'ALLOW' and (lbls like 'known_bot_data_center'"
        " or lbls like 'signal:cloud_service_provider:')"
        " and not (lbls like 'bot:verified') and not (lbls like 'bot:unverified')"
        " | parse lbls /signal:cloud_service_provider:(?<csp>[a-z_]+)/"
        " | stats count(*) as total, sum(strcontains(lbls, 'known_bot_data_center')) as data_center,"
        " latest(csp) as provider by httpRequest.clientIp"
        " | filter total > 50"
        " | sort total desc | limit 10"
    )
    datacenter_athena = (
        "SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as total,"
        " count_if(any_match(labels, l -> l.name LIKE '%known_bot_data_center%')) as data_center,"
        " max(regexp_extract(array_join(transform(labels, l -> l.name), ','),"
        " 'signal:cloud_service_provider:([a-z_]+)', 1)) as provider"
        " FROM {TABLE}"
        " WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER}"
        " AND action = 'ALLOW'"
        " AND (any_match(labels, l -> l.name LIKE '%known_bot_data_center%')"
        " OR any_match(labels, l -> l.name LIKE '%signal:cloud_service_provider:%'))"
        " AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:verified%') )"
        " AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:unverified%') )"
        " GROUP BY httprequest.clientip HAVING count(*) > 50"
        " ORDER BY total DESC LIMIT {LIMIT}"
    )

    later("crawlers", crawlers_cwl, crawlers_athena)
    later("repeaters", repeaters_cwl, repeaters_athena)
    later("datacenter", datacenter_cwl, datacenter_athena)

    # Automation UA filter (curl, python-requests, wget, etc. that are ALLOW'd)
    auto_ua_cwl = (
        "filter action = 'ALLOW'"
        " | parse @message /(?i)\\{\"name\":\"user-agent\",\"value\":\"(?<ua>.*?)\"\\}/"
        " | filter " + AUTOMATION_UA_CWL +
        " | stats count(*) as total by httpRequest.clientIp, ua"
        " | filter total > 10"
        " | sort total desc | limit 10"
    )
    auto_ua_athena = (
        "SELECT httprequest.clientip as \"httpRequest.clientIp\","
        " element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value as ua,"
        " count(*) as total"
        " FROM {TABLE}"
        " WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER}"
        " AND action = 'ALLOW'"
        " AND regexp_like(element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value,"
        " " + AUTOMATION_UA_ATHENA + ")"
        " GROUP BY httprequest.clientip,"
        " element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value"
        " HAVING count(*) > 10"
        " ORDER BY total DESC LIMIT {LIMIT}"
    )
    later("auto_ua", auto_ua_cwl, auto_ua_athena)

    # Single tool distributed across many IPs (JA4 aggregation)
    # Require high URI diversity per JA4 to filter out normal browser traffic sharing common fingerprints
    distributed_cwl = (
        _LABELS_ARRAY + " | " "filter action = 'ALLOW' and ispresent(ja4Fingerprint) and ja4Fingerprint != ''"
        f"{CWL_EXCLUDE_STATIC}"
        " and (not ispresent(lbls) or not (lbls like 'bot:verified'))"
        " | stats count(*) as total, count_distinct(httpRequest.clientIp) as unique_ips,"
        " count_distinct(httpRequest.uri) as unique_uris by ja4Fingerprint"
        " | filter unique_ips > 10 and total > 500 and unique_uris > 50"
        " | sort total desc | limit 10"
    )
    distributed_athena = (
        "SELECT ja4fingerprint as \"ja4Fingerprint\", count(*) as total,"
        " count(DISTINCT httprequest.clientip) as unique_ips,"
        " count(DISTINCT httprequest.uri) as unique_uris"
        " FROM {TABLE}"
        " WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER}"
        " AND action = 'ALLOW'"
        " AND ja4fingerprint IS NOT NULL AND ja4fingerprint != ''"
        f"{ATHENA_EXCLUDE_STATIC}"
        " AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:verified%') )"
        " GROUP BY ja4fingerprint"
        " HAVING count(DISTINCT httprequest.clientip) > 10 AND count(*) > 500"
        " AND count(DISTINCT httprequest.uri) > 50"
        " ORDER BY total DESC LIMIT {LIMIT}"
    )
    later("distributed", distributed_cwl, distributed_athena)

    # The per-JA4 drill-down loop used to live here: one extra query per candidate, capped
    # at 10, so a scan issued up to 16 serial Athena queries. The full-chain measurement found
    # the dominant cost is the NUMBER of queries run back to back rather than the partition
    # layout, and this loop was the unbounded part of it, firing hardest at production volume
    # where diverse fingerprints actually qualify. It is now `step="ja4_ips"`, one query for one
    # fingerprint the user picked, which bounds the chain by construction instead of by a cap.
    # UA rotation candidates: one TLS fingerprint (JA4) behind many different User-Agents from few
    # IPs. A JA4 names a TLS stack rather than a client, so an office on one browser build behind one
    # egress looks the same, and the section says so rather than calling it spoofing. Few IPs keeps
    # large NAT and CDN egress points out.
    ua_rotation_cwl = (
        _LABELS_ARRAY + " | " "filter action = 'ALLOW' and ispresent(ja4Fingerprint) and ja4Fingerprint != ''"
        " and (not ispresent(lbls) or not (lbls like 'bot:verified'))"
        " | parse @message /(?i)\\{\"name\":\"user-agent\",\"value\":\"(?<ua>.*?)\"\\}/"
        " | stats count(*) as total, count_distinct(ua) as unique_uas,"
        " count_distinct(httpRequest.clientIp) as unique_ips by ja4Fingerprint"
        " | filter unique_uas > 5 and unique_ips < 5"
        " | sort unique_uas desc | limit 10"
    )
    ua_rotation_athena = (
        "SELECT ja4fingerprint as \"ja4Fingerprint\", count(*) as total,"
        " count(DISTINCT element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value) as unique_uas,"
        " count(DISTINCT httprequest.clientip) as unique_ips"
        " FROM {TABLE}"
        " WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER}"
        " AND action = 'ALLOW'"
        " AND ja4fingerprint IS NOT NULL AND ja4fingerprint != ''"
        " AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:verified%') )"
        " GROUP BY ja4fingerprint"
        " HAVING count(DISTINCT element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value) > 5"
        " AND count(DISTINCT httprequest.clientip) < 5"
        " ORDER BY unique_uas DESC LIMIT {LIMIT}"
    )
    later("ua_rotation", ua_rotation_cwl, ua_rotation_athena)

    # Many sources on one endpoint, which every per-IP signal above is blind to by construction: a
    # spread credential-stuffing run keeps each IP under them, and one endpoint fails the JA4 table's
    # URI-breadth test. Compared with the same window a week earlier below. Both floors are in the query
    # and the list is ordered by requests per IP: ordered by IPs, a real site's popular pages fill it
    # and a quiet login endpoint taken by six IPs never reaches the comparison.
    endpoints_cwl = (
        _LABELS_ARRAY + " | " "filter action = 'ALLOW'"
        f"{CWL_EXCLUDE_STATIC}"
        " and (not ispresent(lbls) or not (lbls like 'bot:verified'))"
        " | stats count(*) as total, count_distinct(httpRequest.clientIp) as unique_ips"
        " by httpRequest.uri, httpRequest.httpMethod"
        f" | filter unique_ips >= {ENDPOINT_MIN_IPS} and total >= {ENDPOINT_MIN_REQUESTS}"
        " | fields total / unique_ips as per_ip"
        f" | sort per_ip desc | limit {_ENDPOINTS}"
    )
    endpoints_athena = (
        "SELECT httprequest.uri as \"httpRequest.uri\", httprequest.httpmethod as \"httpRequest.httpMethod\","
        " count(*) as total, count(DISTINCT httprequest.clientip) as unique_ips"
        " FROM {TABLE}"
        " WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER}"
        " AND action = 'ALLOW'"
        f"{ATHENA_EXCLUDE_STATIC}"
        " AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:verified%') )"
        " GROUP BY httprequest.uri, httprequest.httpmethod"
        f" HAVING count(DISTINCT httprequest.clientip) >= {ENDPOINT_MIN_IPS} AND count(*) >= {ENDPOINT_MIN_REQUESTS}"
        " ORDER BY count(*) * 1.0 / count(DISTINCT httprequest.clientip) DESC LIMIT {LIMIT}"
    )
    later("endpoints", endpoints_cwl, endpoints_athena, _ENDPOINTS)

    # All six at once. `reasons` carries the labels that never answered inside the batch
    # budget, which is a THIRD way to have no rows alongside "failed" and "matched
    # nothing", and it has to reach the section note or a batch timeout renders as
    # "(none found)", the exact wrong answer 0.17.0 removed from the other two paths.
    results, reasons = run_concurrently(jobs)
    failures.update(reasons)
    crawlers = results.get("crawlers") or []
    repeaters = results.get("repeaters") or []
    datacenter = results.get("datacenter") or []
    auto_ua = results.get("auto_ua") or []
    distributed = results.get("distributed") or []
    ua_rotation = results.get("ua_rotation") or []
    endpoints = results.get("endpoints") or []
    endpoint_lines, endpoints_marked = _endpoint_section(endpoints, start_epoch, end_epoch, failures, notes)

    # Build output
    lines = ["## Bypass Scan Results", ""]

    if wow_note:
        lines.append(wow_note)
        lines.append("")

    if coverage_gaps:
        lines.append("### Coverage Gaps Detected")
        for gap in coverage_gaps:
            lines.append(f"  - {gap}")
        lines.append("")

    lines.append("### High URI Diversity (probable scrapers/crawlers)")
    if crawlers:
        lines.append(f"| {'IP':<15} | {'Requests':>8} | {'Unique URIs':>11} |")
        lines.append(f"| {'-'*15} | {'-'*8} | {'-'*11} |")
        for r in crawlers:
            lines.append(f"| {r.get('httpRequest.clientIp', '?'):<15} | {r.get('total', '?'):>8} | {r.get('unique_uris', '?'):>11} |")
    else:
        lines.append(_empty_reason(failures, "crawlers"))

    lines.append("")
    lines.append("### High Frequency + Low URI Diversity (endpoint hammering)")
    if repeaters:
        lines.append(f"| {'IP':<15} | {'Requests':>8} | {'Unique URIs':>11} |")
        lines.append(f"| {'-'*15} | {'-'*8} | {'-'*11} |")
        for r in repeaters:
            lines.append(f"| {r.get('httpRequest.clientIp', '?'):<15} | {r.get('total', '?'):>8} | {r.get('unique_uris', '?'):>11} |")
    else:
        lines.append(_empty_reason(failures, "repeaters"))

    lines.append("")
    lines.append("### Data-Center and Cloud-Provider IPs Not Caught by Bot Control")
    if datacenter:
        lines.append(f"| {'IP':<15} | {'Requests':>8} | {'Signal':<20} |")
        lines.append(f"| {'-'*15} | {'-'*8} | {'-'*20} |")
        for r in datacenter:
            signal = ("data center" if str(r.get("data_center", "0")) not in ("0", "") else
                      f"cloud provider: {r.get('provider') or '?'}")
            lines.append(f"| {r.get('httpRequest.clientIp', '?'):<15} | {r.get('total', '?'):>8} | {signal:<20} |")
        lines.append("  (signal:known_bot_data_center or signal:cloud_service_provider:* present, but not "
                     "classified as a bot. Partners and SaaS tools run on cloud providers too, so a "
                     "cloud-provider row needs the user to say whether the IP is expected. A provider "
                     "that is a CDN or proxy service makes the IP its egress for many clients.)")
    else:
        lines.append(_empty_reason(failures, "datacenter"))

    lines.append("")
    lines.append("### Automation User-Agents Allowed Through")
    if auto_ua:
        lines.append(f"| {'IP':<15} | {'UA':<30} | {'Requests':>8} |")
        lines.append(f"| {'-'*15} | {'-'*30} | {'-'*8} |")
        for r in auto_ua:
            lines.append(f"| {r.get('httpRequest.clientIp', '?'):<15} | {str(r.get('ua', '?'))[:30]:<30} | {r.get('total', '?'):>8} |")
    else:
        lines.append(_empty_reason(failures, "auto_ua"))

    lines.append("")
    lines.append("### Single Tool Distributed Across Many IPs (JA4 aggregation)")
    if distributed:
        lines.append(f"| {'JA4 Fingerprint':<34} | {'Requests':>8} | {'Unique IPs':>10} | {'Unique URIs':>11} |")
        lines.append(f"| {'-'*34} | {'-'*8} | {'-'*10} | {'-'*11} |")
        for r in distributed:
            lines.append(f"| {r.get('ja4Fingerprint', '?'):<34} | {r.get('total', '?'):>8} | {r.get('unique_ips', '?'):>10} | {r.get('unique_uris', '?'):>11} |")
        lines.append("  ⚠️  Candidate signal: single TLS fingerprint + high URI diversity across many IPs. Needs IP-level investigation to confirm.")
        lines.append("  → Ask the user which fingerprint to look at, then call "
                     "detect_bypass(step='ja4_ips', ja4='<fingerprint>') for the IPs behind it, "
                     "then investigate_ip on one of those. Do NOT walk the whole table: each "
                     "fingerprint costs a query and the user rarely wants all of them.")
    else:
        lines.append(_empty_reason(failures, "distributed"))

    lines.append("")
    lines.append("### UA Rotation Candidates — Single JA4 Behind Many User-Agents")
    if ua_rotation:
        lines.append(f"| {'JA4 Fingerprint':<34} | {'Requests':>8} | {'Unique UAs':>10} | {'Unique IPs':>10} |")
        lines.append(f"| {'-'*34} | {'-'*8} | {'-'*10} | {'-'*10} |")
        for r in ua_rotation:
            lines.append(f"| {r.get('ja4Fingerprint', '?'):<34} | {r.get('total', '?'):>8} | {r.get('unique_uas', '?'):>10} | {r.get('unique_ips', '?'):>10} |")
        lines.append("  ⚠️  Candidate signal: one TLS fingerprint behind many User-Agents from few IPs. That fits one "
                     "client rotating its User-Agent, and also an office on one browser build behind one egress, "
                     "so it is not spoofing until an IP-level investigation says so.")
        lines.append("  → This section has no IPs in it, so do not invent one: call "
                     "detect_bypass(step='ja4_ips', ja4='<fingerprint>') first, then "
                     "investigate_ip on one of the IPs it returns.")
    else:
        lines.append(_empty_reason(failures, "ua_rotation"))

    lines.append("")
    lines += endpoint_lines

    # One expression, read twice, because the two readings disagreed. This condition and the
    # action block below were written separately as De Morgan twins, and only this one learned
    # about `failures`: with every query failed the report said "Cannot Say Whether Bypass
    # Candidates Exist ... do NOT report it as clean" and then, six lines later, "Tell user: no
    # obvious bypass detected in this window". `## Your Next Action` is the heading the step
    # machines instruct the model to follow, so the refusal was overridden by the section that
    # decides what happens next. Naming the condition once is half the fix; the other half is
    # that both readings now branch on `failures`.
    found_any = bool(crawlers or repeaters or datacenter or auto_ua or distributed or ua_rotation or endpoints_marked)

    if not found_any:
        lines.append("")
        if failures:
            # The emptiness guard, and it is the whole point of recording the reasons.
            # Every section came back empty and at least one query failed, so this scan
            # supports no verdict at all. Reporting it as clean is the wrong answer that
            # was shipping: on 2026-09-10 two failed queries produced exactly this block.
            lines.append("### Cannot Say Whether Bypass Candidates Exist")
            lines.append(f"Every section is empty and {len(failures)} of this scan's log "
                         f"queries failed ({', '.join(sorted(failures))}), so there is no "
                         f"evidence either way.")
            lines.append("Tell the user the scan did not complete and do NOT report it as clean.")
        else:
            lines.append("### No Obvious Bypass Candidates Found")
            lines.append("No IPs matched the anomaly filters in this time window.")
            lines.append("⚠️  This does NOT guarantee no bypass exists — only that no IP exceeded the detection thresholds.")
            # ROADMAP 7.7 item 1, group B, and once for the whole scan rather than once per section.
            # The six sections share one witness, the log path in this window, so six copies of the same
            # sentence would be six statements about one fact. This branch is the right place: every
            # section is empty AND no query failed, which is exactly when "the path returned nothing for
            # anyone" is the reading nothing here can rule out. The subject is ALLOW, which is the traffic
            # every one of the six sections looks at.
            from tools.waf_metrics import log_path_warning
            _warning = log_path_warning(get_webacl_name(), "ALLOW", start_epoch, end_epoch, narrow_rows=0)
            if _warning:
                lines.append(_warning.strip())

    lines.append("")
    lines.append("---")
    lines.append(CONFIDENCE_RULES)
    lines.append("")
    lines.append("## Your Next Action")
    lines.append("")
    if found_any:
        lines.append("Present candidates to user. For each:")
        lines.append("- HIGH CONFIDENCE candidates (automation UA, data-center IP) → call record_finding")
        lines.append("- LIKELY/CANNOT DETERMINE → ask user: \"Do you recognize this IP? Is this expected traffic?\"")
        lines.append("- For deeper analysis → call detect_bypass(step='investigate_ip', ip='...', start_time='...')")
        if endpoints_marked:
            lines.append("- A marked endpoint → ask whether it is new or expected to draw many sources. If not, the "
                         "sources are spread on purpose: aggregate_logs(group_by='clientIp', filter_by='{\"uri\": "
                         "\"<path>\", \"action\": \"ALLOW\"}') lists them, a rate-based rule scoped to the path and keyed "
                         "on something other than the IP limits them, and for a login path ATP is the AWS answer.")
        if failures:
            lines.append(f"- Say the scan was partial: {len(failures)} of its queries failed "
                         f"({', '.join(sorted(failures))}), so these candidates are a floor and "
                         f"not the whole picture.")
    elif failures:
        lines.append("Tell user the scan did not complete, and name the sections that failed.")
        lines.append("Do NOT say no bypass was detected. That is a claim about their traffic, and "
                     "a query that did not run is no evidence for it.")
        lines.append("Then re-run detect_bypass(step='scan') once the reason above is addressed.")
    else:
        lines.append("Tell user: no obvious bypass detected in this window.")
        lines.append("If user still suspects bypass, try a shorter/different time window (1-2h around the suspected incident).")
        lines.append("Tip: use get_waf_overview or volume_anomaly to identify peak traffic hours first.")

    _cut = truncation_summary(notes, failures)
    if _cut:
        lines.append(_cut)
    return "\n".join(lines)


def _endpoint_section(rows: list, start_epoch: int, end_epoch: int, failures: dict, notes: dict) -> tuple[list, bool]:
    """The endpoint section's lines, and whether it marked anything.

    Marked: at least ENDPOINT_MIN_IPS distinct IPs and ENDPOINT_MIN_REQUESTS requests on one path and
    method, with ENDPOINT_IP_GROWTH times the distinct IPs of the same window a week earlier, or none
    then. Two queries read the week earlier: the listed endpoints, and whether that window holds any log
    at all, because a log group kept for less than a week or a table that does not reach back reads as
    "no traffic a week earlier" on every endpoint and would mark them all."""
    head = ["### Many Sources on One Endpoint (distributed low-rate abuse)"]
    rule = (f"Marked when one path and method has at least {ENDPOINT_MIN_IPS} IPs and {ENDPOINT_MIN_REQUESTS} "
            f"allowed requests, and {ENDPOINT_IP_GROWTH} times the distinct IPs of the same window a week "
            f"earlier, or none then. These numbers were measured only on low-traffic test WebACLs.")
    if failures.get("endpoints"):
        return head + [_empty_reason(failures, "endpoints"), rule], False
    if not rows:
        return head + [f"  (no endpoint drew {ENDPOINT_MIN_IPS} or more IPs and {ENDPOINT_MIN_REQUESTS} or more "
                       f"allowed requests in this window)", rule], False

    week = 7 * 86400
    keyed = [(r.get("httpRequest.uri", ""), r.get("httpRequest.httpMethod", ""), r) for r in rows]
    safe = [(u, m) for u, m, _ in keyed if _SAFE_URI.fullmatch(u) and re.fullmatch(r"[A-Z]+", m)]
    uris = sorted({u for u, _ in safe})
    prev_cwl = (_LABELS_ARRAY + " | " "filter action = 'ALLOW'"
                f" and httpRequest.uri in [{', '.join(repr(u) for u in uris)}]"
                " and (not ispresent(lbls) or not (lbls like 'bot:verified'))"
                " | stats count_distinct(httpRequest.clientIp) as unique_ips by httpRequest.uri, httpRequest.httpMethod"
                f" | limit {_ENDPOINTS * 10}")
    prev_athena = ("SELECT httprequest.uri as \"httpRequest.uri\", httprequest.httpmethod as \"httpRequest.httpMethod\","
                   " count(DISTINCT httprequest.clientip) as unique_ips FROM {TABLE}"
                   " WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND action = 'ALLOW'"
                   f" AND httprequest.uri IN ({', '.join(repr(u) for u in uris)})"
                   " AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:verified%') )"
                   " GROUP BY 1, 2 LIMIT {LIMIT}")
    any_cwl = "stats count(*) as n"
    any_athena = "SELECT count(*) as n FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER}"
    jobs = {"endpoints_logged": lambda: _safe_query(any_cwl, any_athena, start_epoch - week, end_epoch - week, limit=1,
                                                    failures=failures, label="endpoints_logged", notes=notes)}
    if uris:
        jobs["endpoints_before"] = lambda: _safe_query(prev_cwl, prev_athena, start_epoch - week, end_epoch - week,
                                                       limit=_ENDPOINTS * 10, failures=failures,
                                                       label="endpoints_before", notes=notes)
    got, reasons = run_concurrently(jobs)
    failures.update(reasons)
    logged = got.get("endpoints_logged") or []
    logged_n = int(float(logged[0].get("n") or 0)) if logged else 0
    before = {(r.get("httpRequest.uri", ""), r.get("httpRequest.httpMethod", "")): int(float(r.get("unique_ips") or 0))
              for r in got.get("endpoints_before") or []}
    baseline = None
    if failures.get("endpoints_before"):
        baseline = _empty_reason(failures, "endpoints_before")
    elif failures.get("endpoints_logged"):
        baseline = _empty_reason(failures, "endpoints_logged")
    elif not logged_n:
        baseline = ("  No request is logged in the same window a week earlier, so the comparison cannot run: the "
                    "log destination may keep less than a week. Nothing is marked; the endpoints are listed.")

    lines = head + [f"| {'Method':<6} | {'URI':<40} | {'Requests':>8} | {'IPs':>5} | {'Req/IP':>6} | {'IPs a week earlier':>18} | Marked |",
                    f"| {'-'*6} | {'-'*40} | {'-'*8} | {'-'*5} | {'-'*6} | {'-'*18} | ------ |"]
    marked, new_marked, busy = False, False, False
    for uri, method, r in keyed:
        total, ips = int(float(r.get("total") or 0)), int(float(r.get("unique_ips") or 0))
        # The week-earlier query answered and that window holds logs, so an endpoint absent from it had
        # no allowed request then: zero, not unknown. Unknown is only an endpoint not compared.
        prior = before.get((uri, method), 0) if (uri, method) in safe and baseline is None else None
        hit = prior is not None and ips >= ENDPOINT_MIN_IPS and total >= ENDPOINT_MIN_REQUESTS and (
            prior == 0 or ips >= ENDPOINT_IP_GROWTH * prior)
        marked, new_marked = marked or hit, new_marked or (hit and prior == 0)
        busy = busy or (prior is not None and prior >= ENDPOINT_MIN_IPS and not hit)
        shown = "n/a" if prior is None else f"{prior:,}"
        lines.append(f"| {method:<6} | {uri[:40]:<40} | {total:>8,} | {ips:>5,} | {total // max(ips, 1):>6,} | "
                     f"{shown:>18} | {'yes' if hit else '':<6} |")
    if baseline:
        lines.append(baseline)
    if len(safe) < len(keyed):
        lines.append(f"  ({len(keyed) - len(safe)} endpoint(s) not compared: their path holds characters this does "
                     f"not put in a query)")
    if notes.get("endpoints"):
        lines.append(f"  The list stopped at {len(rows)} endpoints, taken by requests per IP, so an endpoint with "
                     f"fewer requests per IP that would be marked may be outside it.")
    lines.append(rule)
    if new_marked:
        lines.append("  A marked endpoint with no IPs a week earlier is either new or newly attacked; ask the user which.")
    if busy:
        lines.append("  An endpoint that already draws many sources is not marked by a few more, so an unmarked "
                     "endpoint here does not rule out distributed abuse on it.")
    return lines, marked


def _step_investigate_ip(ip: str, start_epoch: int, end_epoch: int) -> str:
    """Deep-dive a specific IP's behavior in ALLOW logs."""

    # Same channel as _step_scan. It matters more here: the verdict block at the
    # bottom reads `not has_bot_label`, and a failed `labels` query makes that True,
    # so a swallowed error pushed the conclusion TOWARD declaring a bypass with HIGH
    # CONFIDENCE. Absence of evidence was being read as evidence of absence, in the
    # direction that produces a false alarm.
    failures: dict[str, str] = {}
    # Which sections were cut off at their limit, keyed the same way as `failures` so a
    # renderer looks in one place for both and cannot surface one while forgetting the other.
    notes: dict[str, int] = {}

    # 1. Frequency (ALLOW only — bypass context)
    freq_cwl = (
        f"filter httpRequest.clientIp = '{ip}' and action = 'ALLOW'"
        " | stats count(*) as hits by bin(1m)"
        " | stats max(hits) as peak_rpm, avg(hits) as avg_rpm, count(*) as active_minutes"
    )
    freq_athena = (
        f"SELECT max(cnt) as peak_rpm, avg(cnt) as avg_rpm, count(*) as active_minutes FROM ("
        f"  SELECT date_format(from_unixtime(\"timestamp\"/1000), '%Y-%m-%d %H:%i') as minute, count(*) as cnt"
        f"  FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f"  AND httprequest.clientip = '{ip}' AND action = 'ALLOW'"
        f"  GROUP BY date_format(from_unixtime(\"timestamp\"/1000), '%Y-%m-%d %H:%i')"
        f")"
    )
    freq = _safe_query(freq_cwl, freq_athena, start_epoch, end_epoch, limit=1, failures=failures, label="frequency", notes=notes)
    # No rows from a query that answered is a zero: on CloudWatch a `stats` with no group-by over no
    # records answers none, where Athena answers one row, with "" for a `max` or `avg` over nothing.
    # "?" is kept for a failure.
    peak_rpm = (freq[0].get("peak_rpm", "?") or 0) if freq else ("?" if failures.get("frequency") else 0)
    avg_rpm = (freq[0].get("avg_rpm", "?") or 0) if freq else ("?" if failures.get("frequency") else 0)

    # 2. URI diversity (ALLOW only)
    uri_cwl = (
        f"filter httpRequest.clientIp = '{ip}' and action = 'ALLOW'"
        f"{CWL_EXCLUDE_STATIC}"
        " | stats count_distinct(httpRequest.uri) as unique_uris, count(*) as total"
    )
    uri_athena = (
        f"SELECT count(DISTINCT httprequest.uri) as unique_uris, count(*) as total"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{ip}' AND action = 'ALLOW'"
        f"{ATHENA_EXCLUDE_STATIC}"
    )
    uri_data = _safe_query(uri_cwl, uri_athena, start_epoch, end_epoch, limit=1, failures=failures, label="uri_diversity", notes=notes)
    unique_uris = (uri_data[0].get("unique_uris", "?") or 0) if uri_data else ("?" if failures.get("uri_diversity") else 0)
    total_reqs = (uri_data[0].get("total", "?") or 0) if uri_data else ("?" if failures.get("uri_diversity") else 0)

    # 2a. The ALLOW rate over the same non-static requests the URI count reads, and every distinct
    # ALLOW URI, static ones included. The scraper and hammering rungs set a rate against the
    # non-static URI count, and the rate was over every request, so an IP pulling only static files
    # had 0 URIs at 300/min and read as hammering.
    dyn_cwl = (
        f"filter httpRequest.clientIp = '{ip}' and action = 'ALLOW'"
        f"{CWL_EXCLUDE_STATIC}"
        " | stats count(*) as hits by bin(1m)"
        " | stats max(hits) as peak_rpm"
    )
    dyn_athena = (
        f"SELECT max(cnt) as peak_rpm FROM ("
        f"  SELECT date_format(from_unixtime(\"timestamp\"/1000), '%Y-%m-%d %H:%i') as minute, count(*) as cnt"
        f"  FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f"  AND httprequest.clientip = '{ip}' AND action = 'ALLOW'"
        f"{ATHENA_EXCLUDE_STATIC}"
        f"  GROUP BY date_format(from_unixtime(\"timestamp\"/1000), '%Y-%m-%d %H:%i')"
        f")"
    )
    dyn = _safe_query(dyn_cwl, dyn_athena, start_epoch, end_epoch, limit=1, failures=failures,
                      label="frequency_dynamic", notes=notes)
    dyn_peak = (dyn[0].get("peak_rpm", "?") or 0) if dyn else ("?" if failures.get("frequency_dynamic") else 0)
    # The ALLOW rate over static requests alone, for the static rung. The overall peak less the
    # non-static one is only a floor on the static requests in the busiest minute: an API burst in
    # another minute lowers it, and an IP pulling 250 static files a minute read as mixed.
    static_cwl = (
        f"filter httpRequest.clientIp = '{ip}' and action = 'ALLOW'"
        f"{CWL_ONLY_STATIC}"
        " | stats count(*) as hits by bin(1m)"
        " | stats max(hits) as peak_rpm"
    )
    static_athena = (
        f"SELECT max(cnt) as peak_rpm FROM ("
        f"  SELECT date_format(from_unixtime(\"timestamp\"/1000), '%Y-%m-%d %H:%i') as minute, count(*) as cnt"
        f"  FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f"  AND httprequest.clientip = '{ip}' AND action = 'ALLOW'"
        f"{ATHENA_ONLY_STATIC}"
        f"  GROUP BY date_format(from_unixtime(\"timestamp\"/1000), '%Y-%m-%d %H:%i')"
        f")"
    )
    static_data = _safe_query(static_cwl, static_athena, start_epoch, end_epoch, limit=1, failures=failures,
                              label="frequency_static", notes=notes)
    static_peak = ((static_data[0].get("peak_rpm", "?") or 0) if static_data else
                   ("?" if failures.get("frequency_static") else 0))
    all_cwl = (
        f"filter httpRequest.clientIp = '{ip}' and action = 'ALLOW'"
        " | stats count_distinct(httpRequest.uri) as unique_uris_all"
    )
    all_athena = (
        f"SELECT count(DISTINCT httprequest.uri) as unique_uris_all"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{ip}' AND action = 'ALLOW'"
    )
    all_data = _safe_query(all_cwl, all_athena, start_epoch, end_epoch, limit=1, failures=failures,
                           label="all_uris", notes=notes)
    all_uris = (all_data[0].get("unique_uris_all", "?") or 0) if all_data else ("?" if failures.get("all_uris") else 0)

    # 2b. Query strings on ALLOW traffic — attack-like payloads that were NOT
    # blocked are a direct bypass signal. Sensitive params redacted below.
    qs_cwl = (
        f"filter httpRequest.clientIp = '{ip}' and action = 'ALLOW'"
        " and ispresent(httpRequest.args) and httpRequest.args != ''"
        " | stats count(*) as hits by httpRequest.args | sort hits desc | limit 8"
    )
    qs_athena = (
        f"SELECT httprequest.args as args, count(*) as hits"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{ip}' AND action = 'ALLOW' AND httprequest.args <> ''"
        f" GROUP BY httprequest.args ORDER BY hits DESC LIMIT {{LIMIT}}"
    )
    qs_data = _safe_query(qs_cwl, qs_athena, start_epoch, end_epoch, limit=8, failures=failures, label="query_strings", notes=notes)

    # 3. Action breakdown
    action_cwl = (
        f"filter httpRequest.clientIp = '{ip}'"
        " | stats count(*) as hits by action"
    )
    action_athena = (
        f"SELECT action, count(*) as hits"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{ip}'"
        f" GROUP BY action"
    )
    actions = _safe_query(action_cwl, action_athena, start_epoch, end_epoch, limit=10, failures=failures, label="actions", notes=notes)
    action_map = {r.get("action", ""): int(r.get("hits", 0)) for r in actions}

    # 4. Labels (bot detection)
    labels_cwl = (
        f"filter httpRequest.clientIp = '{ip}' and @message like '\"labels\":['"
        " | parse @message '\"labels\":[*]' as Labels"
        " | filter ispresent(Labels)"
        " | stats count(*) as cnt by Labels"
        " | sort cnt desc | limit 5"
    )
    labels_athena = (
        f"SELECT json_format(cast(labels as json)) as Labels, count(*) as cnt"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{ip}'"
        f" AND labels IS NOT NULL AND cardinality(labels) > 0"
        f" GROUP BY json_format(cast(labels as json)) ORDER BY cnt DESC LIMIT {{LIMIT}}"
    )
    labels = _safe_query(labels_cwl, labels_athena, start_epoch, end_epoch, limit=5, failures=failures, label="labels", notes=notes)

    # 5. Country
    country_cwl = (
        f"filter httpRequest.clientIp = '{ip}'"
        " | stats count(*) as hits by httpRequest.country"
        " | limit 1"
    )
    country_athena = (
        f"SELECT httprequest.country as \"httpRequest.country\", count(*) as hits"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{ip}'"
        f" GROUP BY httprequest.country LIMIT {{LIMIT}}"
    )
    country_data = _safe_query(country_cwl, country_athena, start_epoch, end_epoch, limit=1, failures=failures, label="country", notes=notes)
    country = country_data[0].get("httpRequest.country", "?") if country_data else "?"

    # 6. User-Agent
    ua_cwl = (
        f"filter httpRequest.clientIp = '{ip}'"
        " | parse @message /(?i)\\{\"name\":\"user-agent\",\"value\":\"(?<ua>.*?)\"\\}/"
        " | stats count(*) as hits by ua"
        " | sort hits desc | limit 3"
    )
    ua_athena = (
        f"SELECT element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value as ua,"
        f" count(*) as hits"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{ip}'"
        f" GROUP BY element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value"
        f" ORDER BY hits DESC LIMIT {{LIMIT}}"
    )
    ua_data = _safe_query(ua_cwl, ua_athena, start_epoch, end_epoch, limit=3, failures=failures, label="user_agent", notes=notes)

    # 7. JA4 fingerprint
    ja4_cwl = (
        f"filter httpRequest.clientIp = '{ip}'"
        " | stats count(*) as hits by ja4Fingerprint"
        " | sort hits desc | limit 3"
    )
    ja4_athena = (
        f"SELECT ja4fingerprint as \"ja4Fingerprint\", count(*) as hits"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{ip}'"
        f" GROUP BY ja4fingerprint ORDER BY hits DESC LIMIT {{LIMIT}}"
    )
    ja4_data = _safe_query(ja4_cwl, ja4_athena, start_epoch, end_epoch, limit=3, failures=failures, label="ja4", notes=notes)

    # 8. COUNT rules triggered, one hit per request. A managed sub-rule's Count is nested in
    # `ruleGroupList`, and it is the common one: measured 2026-10-16 on `test-webacl-s3`,
    # 2026-10-01 to 10-16, 5 top-level COUNT entries against 2,142 nested. Athena reads both levels
    # and counts each rule once per request, since a group deployed twice logs its sub-rules twice.
    count_rules_athena = (
        "SELECT t.rule as rule, count(*) as hits FROM (SELECT array_distinct(concat("
        "coalesce(transform(filter(nonterminatingmatchingrules, r -> r.action = 'COUNT'), r -> r.ruleid), ARRAY[]),"
        " coalesce(flatten(transform(rulegrouplist, rg -> coalesce(transform(filter("
        "rg.nonterminatingmatchingrules, r -> r.action = 'COUNT'), r -> r.ruleid), ARRAY[]))), ARRAY[]))) as rules"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{ip}') CROSS JOIN UNNEST(rules) AS t(rule)"
        f" GROUP BY t.rule ORDER BY hits DESC LIMIT {{LIMIT}}"
    )
    if get_log_type() == "cwl":
        count_rules = _cwl_count_rules(ip, start_epoch, end_epoch, failures, notes)
    else:
        count_rules = _safe_query("", count_rules_athena, start_epoch, end_epoch, limit=5, failures=failures,
                                  label="count_rules", notes=notes)

    # Build output
    lines = [
        f"## Bypass Investigation: {ip}",
        f"**Country**: {country}",
        f"**Total ALLOW requests (non-static)**: {total_reqs}",
        f"**Unique URIs**: {unique_uris}",
        f"**Peak frequency**: {peak_rpm} req/min (avg {avg_rpm})",
        "",
        "### Action Breakdown",
    ]
    allow_count = action_map.get("ALLOW", 0)
    non_allow_count = sum(v for k, v in action_map.items() if k != "ALLOW")
    for action, count in sorted(action_map.items(), key=lambda x: x[1], reverse=True):
        lines.append(f"  {action}: {count:,}")
    # Gated on an allowed request: any count is more than five times 0, and with none allowed the
    # verdict below is NO BYPASS.
    if allow_count and non_allow_count > allow_count * 5:
        lines.append(f"\n  ⚠️ This IP has {non_allow_count:,} non-ALLOW requests vs {allow_count:,} ALLOW — primarily an attacker being mitigated, with partial bypass.")

    lines.append("")
    lines.append("### User-Agent")
    is_automation_ua = False
    if ua_data:
        for r in ua_data:
            ua = r.get("ua", "?")
            lines.append(f"  {ua} ({r.get('hits', '?')} requests)")
            if any(t in ua.lower() for t in AUTOMATION_UA_TOKENS):
                is_automation_ua = True
    else:
        lines.append(_empty_reason(failures, "user_agent", "  (not available)"))

    lines.append("")
    lines.append("### JA4 Fingerprint")
    if ja4_data:
        for r in ja4_data:
            lines.append(f"  {r.get('ja4Fingerprint', r.get('ja4fingerprint', '?'))} ({r.get('hits', '?')} requests)")
    else:
        lines.append(_empty_reason(failures, "ja4", "  (not available)"))

    lines.append("")
    lines.append("### COUNT Rules Triggered (matched but not blocked)")
    if count_rules:
        for r in count_rules:
            lines.append(f"  {r.get('rule', '?')} ({r.get('hits', '?')} hits)")
    else:
        lines.append(_empty_reason(failures, "count_rules", "  (none, no COUNT rule matches for this IP)"))
    if failures.get("count_rules_config"):
        lines.append(f"  (The WebACL's Count rules could not be read ({failures['count_rules_config']}), so a "
                     f"Count rule that is neither the first nor the last on a request may be missing.)")

    lines.append("")
    lines.append("### Bot Control Labels")
    bot_categories = set()
    bot_names = set()
    if labels:
        has_bot_labels = False
        for r in labels:
            label_str = r.get("Labels", "")
            if "bot:" in label_str or "signal:" in label_str:
                has_bot_labels = True
            # Extract bot category and name
            import re
            for cat in re.findall(r'bot:category:([^"}\s,]+)', label_str):
                bot_categories.add(cat)
            for name in re.findall(r'bot:name:([^"}\s,]+)', label_str):
                bot_names.add(name)
            lines.append(f"  {label_str} ({r.get('cnt', '?')} requests)")
        if bot_categories or bot_names:
            lines.append(f"\n  **Bot classification**: category={', '.join(bot_categories) or 'unknown'}, name={', '.join(bot_names) or 'unknown'}")
        if not has_bot_labels:
            lines.append("  ⚠️  No bot detection labels — Bot Control did not classify this IP")
    else:
        lines.append(_empty_reason(failures, "labels", "  (no labels found, Bot Control may not be deployed or IP has no label matches)"))

    # Directional judgment
    lines.append("")
    lines.append("### Query Strings on ALLOW Traffic (bypass signal if attack-like)")
    if qs_data:
        from tools.waf_query import _redact, PRIVACY_MASK_HINT
        _qs_masked = False
        for r in qs_data[:8]:
            red, m = _redact("args", r.get("args", ""))
            _qs_masked = _qs_masked or m
            if red:
                lines.append(f"  [{r.get('hits', '?')} hits] {red[:200]}")
        if _qs_masked:
            lines.append(f"  HINT: {PRIVACY_MASK_HINT}")
    else:
        lines.append(_empty_reason(failures, "query_strings", "  (no query strings on ALLOW traffic)"))

    lines.append("")
    lines.append("---")
    lines.append("## Directional Judgment")
    lines.append("")

    def _num(text, cast):
        """The value, or None when it does not parse. A failed query arrives as "?", so this one
        test covers both; None used to be 0, and every rung read a failed query as a quiet IP."""
        try:
            return cast(text)
        except (ValueError, TypeError):
            return None

    peak_val = _num(peak_rpm, float)
    dyn_val = _num(dyn_peak, float)
    uri_val = _num(unique_uris, int)
    non_static = _num(total_reqs, int)
    all_val = _num(all_uris, int)
    static_val = _num(static_peak, float)
    allowed = None if failures.get("actions") else allow_count
    ua_known = not failures.get("user_agent")

    # `any()` over an empty list is False, and `labels` is empty both when Bot Control
    # applied no labels and when the label query failed. Every branch below that reads
    # `not has_bot_label` treats False as "Bot Control did not classify this IP", so on a
    # failed query the verdict moved TOWARD declaring a bypass at HIGH CONFIDENCE. Refuse
    # to conclude instead: a security verdict must not be built on an unread input.
    labels_unknown = "labels" in failures
    has_bot_label = any("bot:" in r.get("Labels", "") for r in labels)
    has_datacenter = any("known_bot_data_center" in r.get("Labels", "") for r in labels)
    providers = sorted({p for r in labels for p in re.findall(r"signal:cloud_service_provider:([a-z_]+)", r.get("Labels", ""))})
    has_verified = any("bot:verified" in r.get("Labels", "") for r in labels)

    if not failures.get("actions") and allow_count == 0:
        # Before every rung, which all read ALLOW traffic: with none, each fell through to "mixed or
        # insufficient" on CloudWatch, and on Athena stopped on a peak that was not a number.
        lines.append("**NO BYPASS: no request from this IP was allowed in this window.**")
        lines.append("Every request it sent ended blocked, challenged or at a CAPTCHA, so nothing it "
                     "sent here reached the origin." if action_map else
                     "The logs hold no request from it in this window at all.")
    elif labels_unknown:
        lines.append("**CANNOT DETERMINE: the Bot Control label query failed.**")
        lines.append(f"Reason: {failures['labels']}")
        lines.append("Every confidence rule here turns on whether Bot Control labelled this "
                     "IP, and that is exactly what could not be read. An unlabelled IP and an "
                     "unread label set look identical from here, and reading the second as the "
                     "first is what produces a false bypass call.")
        lines.append("→ Re-run this investigation once the query succeeds. Do NOT report a "
                     "verdict from this run.")
    elif has_verified:
        # Before every volume rung, which read no label: a verified search crawler at crawl volume
        # was "HIGH CONFIDENCE: Automated scraper". The prompt treats bot:verified as ground truth.
        lines.append(f"**VERIFIED BOT: {', '.join(sorted(bot_names)) or 'name not labelled'}.**")
        lines.append("Bot Control verified this client's identity, so its traffic is not a bypass. "
                     "Whether to allow, rate-limit or block it is a business decision, not a finding.")
    else:
        # Each rung is True (fires), False (cannot fire) or None (cannot tell). The first True wins;
        # the first None stops the ladder, because a rung that might have fired makes every rung
        # after it answer the wrong question. A rung its known inputs already rule out is False,
        # so an unread input it does not need cannot block it.
        def _gt(v, n):
            return None if v is None else v > n

        def _lt(v, n):
            return None if v is None else v < n

        def _all(*xs):
            return False if any(x is False for x in xs) else (None if any(x is None for x in xs) else True)

        rungs = [
            (("frequency",), _all(has_datacenter, not has_bot_label, _gt(peak_val, 50)), [
                "**HIGH CONFIDENCE: Undetected bot from data center.**",
                "Evidence: data-center IP (signal:known_bot_data_center) + high frequency + no bot classification.",
                "→ Bot Control is not catching this IP."]),
            (("user_agent",), _all(not has_bot_label, is_automation_ua if ua_known else None), [
                "**HIGH CONFIDENCE: Bot Control bypass — automation UA allowed through.**",
                "Evidence: known automation User-Agent but no bot detection label applied.",
                "→ Bot Control may not be deployed, or SignalNonBrowserUserAgent is set to Count."]),
            (("frequency_dynamic", "uri_diversity"), _all(_gt(dyn_val, 200), _gt(uri_val, 50)), [
                "**HIGH CONFIDENCE: Automated scraper/crawler.**",
                f"Evidence: {dyn_peak} non-static req/min + {unique_uris} unique URIs — far exceeds human behavior."]),
            (("frequency_dynamic", "uri_diversity"), _all(_gt(dyn_val, 200), _lt(uri_val, 10)), [
                "**HIGH CONFIDENCE: Endpoint hammering (possible DDoS participant or brute-force).**",
                f"Evidence: {dyn_peak} non-static req/min concentrated on few URIs."]),
            # The static peak, not the overall one: an API burst in a mostly static window made the
            # overall peak minute, and the static share alone is over the whole window.
            (("frequency_static", "uri_diversity", "actions"),
             _all(_gt(static_val, 200), None if non_static is None or allowed is None else non_static < 0.1 * allowed),
             _static_traffic(static_val, non_static, allowed, all_val, failures.get("all_uris"), ip)),
            # Below the rate rungs and the data-center one: a cloud provider's addresses carry partners',
            # SaaS tools' and offices' traffic too, so the signal alone is LIKELY, and a rung that measured
            # more speaks first. The probable-scraper rung's URI bar, not a rate: the fleet that motivated
            # this ran at 11-14 a minute to 79-86 URIs per host, and an Amazon office egress labelled
            # `cloud_service_provider:aws` carried real browsers. This names the provider that rung omits.
            (("uri_diversity",), _all(bool(providers), not has_datacenter, not has_bot_label, _gt(uri_val, 50)), [
                f"**LIKELY: Undetected automation from a cloud provider ({', '.join(providers)})** "
                f"(needs user confirmation).",
                f"Evidence: signal:cloud_service_provider:{', '.join(providers)} + {unique_uris} unique URIs at "
                f"a {dyn_peak} non-static req/min peak + no bot classification. A fleet on rented instances "
                f"looks like this, and so do a partner's integration and an office or VPN egress on the "
                f"provider's addresses.",
                "→ Ask user whether this IP is a known partner or service. If not, Bot Control at "
                "Targeted, or a rate-based rule, is what would catch it."]),
            (("uri_diversity",), _all(not has_bot_label, _gt(uri_val, 50)), [
                "**LIKELY: Probable scraper** (needs user confirmation).",
                f"Evidence: {unique_uris} unique URIs, no bot labels, at a peak of {dyn_peak} non-static req/min.",
                "→ Ask user if this IP is a known partner/crawler."]),
        ]
        verdict = None
        for needs, fires, text in rungs:
            if fires is None:
                unread = [n for n in needs if failures.get(n)]
                verdict = ([f"**CANNOT DETERMINE** — the {', '.join(unread)} input did not answer, so "
                            f"the rungs that read it cannot be evaluated.",
                            *(f"Reason ({n}): {failures[n]}" for n in unread),
                            "→ Re-run this investigation once the query succeeds."] if unread else
                           [f"**CANNOT DETERMINE** — the {', '.join(needs)} input answered with a value "
                            f"that is not a number, so the rungs that read it cannot be evaluated."])
                break
            if fires:
                verdict = text
                break
        lines.extend(verdict or [
            "**CANNOT DETERMINE** — signals are mixed or insufficient.",
            f"Evidence: {peak_rpm} req/min, {unique_uris} URIs, country={country}.",
            "→ Ask user: is this IP expected? Is this a known service/partner?"])
        # After whichever rung spoke, since every rung reads this IP as one client. The provider is
        # named rather than classified here: which providers are CDNs or proxies is the model's to say.
        if providers:
            lines.append(f"Provider signal: signal:cloud_service_provider:{', '.join(providers)}. If that is a CDN "
                         f"or proxy service rather than a host for rented instances, this IP is its egress for "
                         f"many clients and every reading above is about all of them together: say so, and look "
                         f"for the client address it forwards before naming one actor.")

    lines.append("")
    lines.append(CONFIDENCE_RULES)
    lines.append("")
    lines.append("## Your Next Action")
    lines.append("")
    lines.append("Present findings to user.")
    lines.append("If HIGH CONFIDENCE → call record_finding, then suggest remediation:")
    lines.append("  - Bot Control not deployed → 'Deploy Bot Control'")
    lines.append("  - Bot Control deployed but missed → 'Upgrade to Targeted level'")
    lines.append("  - High frequency → 'Add rate-based rule'")
    lines.append("")
    lines.append("If this IP has high URI diversity but moderate frequency:")
    lines.append("  → 'This IP may be part of a distributed scraping operation.")
    lines.append("     Want me to scan for more IPs with similar patterns?'")
    lines.append("  → If yes, call detect_bypass(step='scan', start_time='...')")

    _cut = truncation_summary(notes, failures)
    if _cut:
        lines.append(_cut)
    return "\n".join(lines)


def _check_coverage_gaps() -> list[str]:
    """Quick config check for missing protection layers."""
    gaps = []
    webacl_name = get_webacl_name()
    scope = get_scope()
    if not webacl_name:
        return gaps

    region = resolve_region(scope)
    waf = get_client("wafv2", region_name=region)

    try:
        acls = waf.list_web_acls(Scope=scope).get("WebACLs", [])
        match = next((a for a in acls if a["Name"].lower() == webacl_name.lower()), None)
        if not match:
            return gaps
        resp = waf.get_web_acl(Name=webacl_name, Scope=scope, Id=match["Id"])
        rules = resp["WebACL"].get("Rules", [])

        has_bot_control = False
        has_rate_based = False
        has_antiddos = False
        for r in rules:
            stmt = r.get("Statement", {})
            mgr = stmt.get("ManagedRuleGroupStatement", {})
            if mgr.get("Name") == "AWSManagedRulesBotControlRuleSet":
                has_bot_control = True
            if mgr.get("Name") == "AWSManagedRulesAntiDDoSRuleSet":
                has_antiddos = True
            if "RateBasedStatement" in stmt:
                has_rate_based = True

        if not has_bot_control:
            gaps.append("Bot Control not deployed — automated traffic may not be detected")
        if not has_rate_based:
            gaps.append("No rate-based rules — high-frequency IPs are not throttled")
        if not has_antiddos:
            gaps.append("Anti-DDoS AMR not deployed — DDoS attacks may not be mitigated")
    except Exception:
        pass
    return gaps


def _label_dim_set() -> str:
    """Return correct dimension set for label metrics (no Region needed)."""
    return "{AWS/WAFV2,LabelName,LabelNamespace,WebACL}"
