# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A CloudWatch Logs query answered from another WebACL's records, and signed with the session's.

**Demonstrated through the tool on the deployment account, 2026-09-15.** Session context on
`shield-sample-webacl`, whose destination is the log group `aws-waf-logs-group`:

    run_logs_query(query_type="top_blocked_ips", start_time="2024-05-10T06:00", duration_minutes=360)
    → | httpRequest.clientIp | cnt |  ... six rows ...  and "Next: use analyze_ip"
    → SOURCE: shield-sample-webacl via CloudWatch Logs Insights.

Every one of those rows belongs to `test2`, a WebACL that used to log to that group. Counted the same
window directly: 7 BLOCK records, all `test2`, none `shield-sample-webacl`. **The provenance channel
cannot see this**, because the record's subject comes from session state and the rows come from the log
group, and nothing bound them together.

Each link measured, none assumed: several WebACLs sharing one destination is supported and documented and
AWS ships centralized WAF logging built on it; this group already holds streams from six WAF sources; its
retention is unset and it stores 19.8 GB so 2024 records are still scannable; and `MAX_MINUTES` bounds a
window's span rather than its age, so a 2024 `start_time` is a legal call.

**Recent windows are clean, measured exhaustively rather than sampled**, which matters because the
log-versus-metric cross-check behind ROADMAP 7.12 rests on it. Across 2026-05-01 to 2026-09-01:
14,893,856 records, 7,446,843 `shield-sample-webacl`, 7,447,003 CloudFront access logs sharing the group
with no `webaclId` at all, and zero from another WebACL. Every stream that is not this WebACL's ends on or
before 2025-10-14.

Full write-up in `design/audit-patrol-report-queries.md`.
"""

import ast
import pathlib

import pytest

from tools import report as R
from tools import session_state as S
from tools import waf_patrol as P
from tools import waf_query as Q

ROOT = pathlib.Path(__file__).resolve().parents[1]


class FakeCwl:
    """Captures the query string that reached the engine and answers Complete with no rows."""

    def __init__(self):
        self.queries = []

    def start_query(self, **kwargs):
        self.queries.append(kwargs["queryString"])
        return {"queryId": "q"}

    def get_query_results(self, queryId):
        return {"status": "Complete", "results": [], "statistics": {}}

    def stop_query(self, **kwargs):
        return {}


def test_the_filter_names_the_webacl_as_a_path_segment():
    """The same shape as the Athena side's `webaclid LIKE '%/name/%'`, because `webaclId` is the full ARN
    in WAFv2 and the name is one path segment of it.

    Verified against real records: `filter webaclId like '/test2/'` returned 7 in the window above and
    `'/shield-sample-webacl/'` returned nothing. The substring form is used rather than the regex form
    `like /\\/name\\//`, which also works and needs escaping this one does not."""
    scoped = Q.scope_cwl_query("filter x | stats count(*) as c", "shield-sample-webacl")
    assert scoped == "filter webaclId like '/shield-sample-webacl/' | filter x | stats count(*) as c"


def test_a_missing_or_malformed_name_refuses_instead_of_querying_unscoped():
    """**Refusal rather than a degraded mode**, because the degraded mode is the defect. An unscoped
    query on a shared group is the wrong answer this exists to prevent, so there is nothing better to
    fall back to.

    A name outside `[A-Za-z0-9_-]` cannot come from AWS, which restricts WebACL names to exactly those,
    but it is refused rather than interpolated: the filter is built by string interpolation, so a quote
    in the name would rewrite the query. The Athena side drops its filter silently in the same case,
    which is one absence standing in for two reasons and is noted in the audit."""
    for bad in (None, "", "acl'; --", "acl name"):
        with pytest.raises(RuntimeError, match="cannot scope"):
            Q.scope_cwl_query("filter x", bad)


def test_a_log_query_is_scoped_to_the_session_webacl(monkeypatch):
    """The path the ten log tools take. `query_logs` reads the destination out of session state, so the
    WebACL whose destination it is is the one to scope to."""
    monkeypatch.setattr(Q, "get_log_destination", lambda: "arn:aws:logs:r:1:log-group:lg")
    monkeypatch.setattr(Q, "get_webacl_name", lambda: "shield-sample-webacl")
    monkeypatch.setattr(Q, "get_user_timezone", lambda: 0.0)
    monkeypatch.setattr(Q, "get_logs_region", lambda: "us-east-1")
    fake = FakeCwl()
    monkeypatch.setattr(Q, "get_client", lambda *a, **k: fake)

    Q.query_logs("filter action = 'BLOCK' | stats count(*) as cnt | limit 5", "SELECT 1", 0, 60, 5)
    # Driven down to the client rather than to `_run_cwl`, because the executor is where the scoping
    # now happens and a stub for it would capture the query before the prefix exists.
    assert fake.queries[0].startswith("filter webaclId like '/shield-sample-webacl/' | "), fake.queries[0]
    assert "| limit 6" in fake.queries[0], (
        "the limit+1 rewrite has to survive the prefix; truncation detection depends on it")


def test_patrol_scopes_to_the_webacl_it_was_asked_about_not_the_session_one():
    """**Patrol never writes session state**, which is the whole of ROADMAP 7.11, so reading
    `get_webacl_name()` inside it would name whatever the conversation last loaded. It passes its own
    parameter instead, and this drives the disagreement directly: session state says one thing and the
    argument says another, and the argument wins."""
    S.set_webacl_context("session-acl", "arn:x", "CLOUDFRONT", "us-east-1",
                         log_destination="arn:aws:logs:r:1:log-group:lg")
    fake = FakeCwl()
    P._poll_log_query(fake, "lg", 0, 60, "filter terminatingRuleId = 'r' | limit 5", "patrolled-acl")
    assert fake.queries[0].startswith("filter webaclId like '/patrolled-acl/' | "), fake.queries[0]
    assert "session-acl" not in fake.queries[0]


def test_the_report_scopes_the_same_way():
    """`generate_weekly_report` also takes its own `webacl_name` and never writes session state, so its
    three Anti-DDoS queries have the same exposure and the same fix. ROADMAP 7.12 replaces those queries
    with label metrics, and until it does they are scoped."""
    S.set_webacl_context("session-acl", "arn:x", "CLOUDFRONT", "us-east-1",
                         log_destination="arn:aws:logs:r:1:log-group:lg")
    fake = FakeCwl()
    R._poll_log_query(fake, "lg", 0, 60, "filter @message like 'anti-ddos:event-detected'",
                      "reported-acl")
    assert fake.queries[0].startswith("filter webaclId like '/reported-acl/' | "), fake.queries[0]


def _start_query_sites() -> dict[str, str]:
    """`module: enclosing function` for every `start_query(` call under `tools/`."""
    out = {}
    for path in sorted(ROOT.glob("tools/*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for sub in ast.walk(node):
                if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                        and sub.func.attr == "start_query"):
                    out[f"{path.name}::{node.name}"] = path.name
    return out


# Every CloudWatch Logs Insights query this project can send, and what scopes it. A new one fails the
# test below rather than shipping unscoped, which is the failure this whole file exists for: the
# defect was not that one query lacked a filter, it was that no query had ever had one.
SCOPED = {
    "waf_query.py::_run_cwl",            # the executor the ten log tools reach
    "waf_patrol.py::_poll_log_query",    # patrol's three detail queries, one executor
    "report.py::_poll_log_query",        # the report's three Anti-DDoS queries
}
UNSCOPED_ON_PURPOSE = {
    # The caller named a log group, so the session WebACL is not the subject of the answer and
    # filtering by it would answer a question nobody asked. This is the same distinction the
    # provenance record carries as `subject_explicit`, and that path already sets it.
    "waf_logs.py::run_logs_query",
}
DEAD = {
    # No callers. Left in place because it predates this change, and asserted below to have none, so
    # calling it goes red rather than shipping an unscoped query.
    "waf_logs.py::_execute_query_internal",
}


def test_every_cloudwatch_logs_query_site_is_accounted_for():
    """The inventory, because the defect was a class rather than an instance."""
    sites = set(_start_query_sites())
    assert len(sites) >= 4, f"extraction found only {sorted(sites)}, so this proves nothing"
    assert sites == SCOPED | UNSCOPED_ON_PURPOSE | DEAD, (
        f"the set of CloudWatch Logs query sites has changed. New: {sorted(sites - (SCOPED | UNSCOPED_ON_PURPOSE | DEAD))}. "
        f"Gone: {sorted((SCOPED | UNSCOPED_ON_PURPOSE | DEAD) - sites)}. A new site must scope to a "
        f"WebACL or be declared here with the reason it does not.")


def test_the_dead_query_site_still_has_no_callers():
    """`_execute_query_internal` is unreferenced and would send an unscoped query if it were called.
    Asserted rather than deleted, because it predates this change; the assertion is what turns calling
    it into a red test instead of a silent regression."""
    src = (ROOT / "tools").glob("*.py")
    callers = [p.name for p in src if "_execute_query_internal(" in p.read_text().replace(
        "def _execute_query_internal(", "")]
    assert not callers, f"_execute_query_internal now has callers in {callers}; scope it or delete it"


def test_each_scoped_site_reaches_the_shared_builder():
    """Structural, and it is what stops a site from growing its own filter. Three modules scope, and a
    second spelling of the same filter is what drifts: the Athena side already has one, and this file's
    first draft nearly added a third inside patrol's builders rather than its executor."""
    for site in SCOPED:
        module, func = site.split("::")
        tree = ast.parse((ROOT / "tools" / module).read_text())
        node = next(n for n in ast.walk(tree)
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == func)
        names = {s.func.id for s in ast.walk(node)
                 if isinstance(s, ast.Call) and isinstance(s.func, ast.Name)}
        assert "scope_cwl_query" in names, (
            f"{site} sends a CloudWatch Logs query without calling scope_cwl_query")
