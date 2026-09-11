# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ROADMAP 4.2: the rule-level hit rate, and the invariant 4.1 could not be tested for yet.

**4.2 is two paths, not the thin layer over `metric="ratio"` the roadmap predicted.** Reading
`_top_rules` settled it: the per-rule numerators come from a metric SEARCH and the exact
`Rule=ALL` denominator from a MetricStat, both already fetched in one function, so the rule-level
rate is arithmetic on data in hand. Free, unaffected by a Log Filter, and 14 days instead of the
log window. Only the endpoint-level rate needs logs, because CloudWatch has no URI dimension, and
it is the only half a Log Filter disclosure attaches to.

The two things worth testing here are the two that produce a plausible wrong number rather than
an error:

1. **A small nonzero rate must not print as `0.00%`.** That is a false zero, the same shape as
   every other one in this project: the output a genuine zero would produce. Measured live, the
   IP-reputation list ran at 10/45513 = 0.022%, and a rule an order of magnitude quieter rounds
   to `0.00%` under plain formatting.
2. **A denominator that came from the fallback must not be used.** `_top_rules` swallows the
   MetricStat failure with `except: pass` and falls back to the SEARCH-derived total, which is
   subject to the very 14-day expiry the MetricStat call exists to dodge. A rate on that could be
   wrong with nothing saying so, so the column is omitted and given a reason.
"""

import ast
import pathlib
import re

import pytest

import agent
from tools import waf_overview as O

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"


def _series(*vals):
    return list(vals)


def _fixture(rules: dict, all_totals: dict) -> dict:
    """A `_get_all_rules_metrics_search` result: `{rule: {metric: [values]}}` plus `ALL`."""
    out = {name: {k: _series(v) for k, v in metrics.items()} for name, metrics in rules.items()}
    out["ALL"] = {k: _series(v) for k, v in all_totals.items()}
    return out


@pytest.fixture
def rendered(monkeypatch):
    """`_top_rules` with both metric calls faked, returning the rendered table.

    Both are faked rather than one, because the denominator has two sources and the test's whole
    subject is which one was used. `denom_exact` is decided by whether the MetricStat call raises,
    so the fake `get_metric_data` is what selects the branch."""
    def run(rules, all_totals, metricstat_ok=True, prev=None):
        class FakeCW:
            def get_metric_data(self, **kw):
                if not metricstat_ok:
                    raise RuntimeError("MetricStat unavailable")
                out = []
                for q in kw["MetricDataQueries"]:
                    if q["Id"].startswith("ms_"):
                        key = {"ms_a": "allowed", "ms_b": "blocked",
                               "ms_c": "challenge", "ms_p": "captcha"}[q["Id"]]
                        out.append({"Id": q["Id"], "Values": [all_totals.get(key, 0)],
                                    "Timestamps": []})
                return {"MetricDataResults": out}

        monkeypatch.setattr(O, "_calc_period", lambda m: 3600, raising=False)
        import tools.waf_patrol as P
        monkeypatch.setattr(
            P, "_get_all_rules_metrics_search",
            lambda cw, name, s, e, period=86400, scope="CLOUDFRONT", region="":
                _fixture(rules, all_totals) if s == "now" else _fixture(prev or {}, all_totals))
        return O._top_rules(FakeCW(), "acl", "now", "end", "prev", 1440)
    return run


TOTALS = {"allowed": 45494, "blocked": 19, "challenge": 0, "captcha": 0}  # denom 45513, live


def test_a_small_nonzero_rate_is_not_printed_as_zero(rendered):
    """The false-zero guard, swept across the magnitudes where plain formatting breaks.

    `0.0066%` formats to `0.01%` under `.2f`, which is fine. The break is below that: a rule at
    1 match in 45513 is `0.0022%`, which `.2f` prints as `0.00%` -- indistinguishable from a rule
    that matched nothing, which is the one thing the column must never say by accident."""
    out = rendered({"Tiny": {"blocked": 1}, "Small": {"blocked": 3},
                    "Real": {"blocked": 10}}, TOTALS)
    rates = dict(re.findall(r"^(\w+)\s.*?(\S+%)\s*$", out, re.M))
    assert rates.get("Tiny") == "<0.01%", f"1/45513 printed as {rates.get('Tiny')}"
    assert rates.get("Small") == "<0.01%", f"3/45513 printed as {rates.get('Small')}"
    assert rates.get("Real") == "0.02%", f"10/45513 printed as {rates.get('Real')}"
    assert "0.00%" not in out, "a match was rounded down to a printed zero"


def test_the_rate_uses_the_verified_denominator_and_says_what_it_is(rendered):
    """The denominator is printed so the arithmetic can be checked instead of trusted."""
    out = rendered({"R": {"blocked": 10}}, TOTALS)
    assert "45,513 evaluated requests" in out, out
    # 10/45513 = 0.0220%, so the printed rate pins the denominator too.
    assert "0.02%" in out


def test_the_denominator_never_requests_counted_requests():
    """**`CountedRequests` is excluded upstream of the arithmetic, and asserting the arithmetic
    missed that.** The first version of this test added a large `counted` value to the `ALL`
    fixture and required it not to appear in the total. It passed with `counted` deliberately
    summed INTO the denominator, because the MetricStat response that overwrites `ALL` has no
    `counted` key at all -- so there was nothing for the summation to add and the perturbation
    could not bite.

    The property therefore lives in WHICH metrics the MetricStat call asks for, not in how they are
    added up. Read off the source, because the four query ids are constructed inline.

    Why it matters: a counted request is non-terminal, so it also ends in Allowed or Blocked and is
    already in the denominator once. Adding it again inflates the total and understates every
    rate."""
    src = (TOOLS / "waf_overview.py").read_text()
    block = src.split("denom_exact = False", 1)[1].split("denom_exact = True", 1)[0]
    requested = set(re.findall(r'"MetricName": "(\w+)"', block))
    assert requested == {"AllowedRequests", "BlockedRequests", "ChallengeRequests",
                         "CaptchaRequests"}, (
        f"the Rule=ALL denominator query requests {sorted(requested)}. It must be exactly the four "
        f"mutually exclusive terminal outcomes: CountedRequests is non-terminal and double-counts, "
        f"and PassedRequests is per-rule-group and reads 0 here.")


def test_a_counted_only_rule_still_gets_a_rate(rendered):
    """A pure-Count rule has zero mitigated traffic, and its hit rate is the number a
    COUNT-to-Block decision turns on. Numerator includes `counted` even though the denominator
    excludes it, which is the asymmetry the output explains rather than hides."""
    out = rendered({"CountOnly": {"counted": 455}}, TOTALS)
    assert re.search(r"CountOnly\s.*\s1\.00%", out), out


def test_no_rate_column_when_the_denominator_came_from_the_fallback(rendered):
    """The degradation, and it degrades the COLUMN rather than the section.

    `_top_rules` falls back to the SEARCH-derived `ALL` when the MetricStat call fails, and that
    source is subject to the 14-day index expiry the MetricStat exists to avoid. So the per-rule
    counts stay, since they were never in doubt, and only the rate goes -- with a reason, because
    a silently missing column is indistinguishable from a rule having no rate."""
    out = rendered({"R": {"blocked": 10}}, TOTALS, metricstat_ok=False)
    assert "Hit rate" not in out.split("Hit rate omitted")[0], \
        "a rate was computed on the fallback denominator"
    assert "Hit rate omitted" in out
    assert "14-day" in out, "the omission does not say why"
    assert "10" in out, "the per-rule counts were dropped along with the rate"


def test_a_zero_denominator_yields_no_rate_rather_than_a_crash(rendered):
    """No traffic at all is a real state, and dividing by it turns an empty window into a 500.

    **The first version of this assertion was hollow**: `"%" not in ... or "-" in out` is satisfied
    by the table's own separator dashes, so it passed whatever `_rate` returned. Asserted on the
    rule's own rate CELL instead, which is the only thing that distinguishes "no denominator" from
    a rate that happened to render.

    Reachable because a Count rule survives the zero-mitigated filter, which is the only way to get
    a row at all when nothing terminal happened."""
    out = rendered({"R": {"counted": 5}},
                   {"allowed": 0, "blocked": 0, "challenge": 0, "captcha": 0})
    row = next(l for l in out.splitlines() if l.startswith("R "))
    assert row.split()[-1] == "-", f"expected no rate, got {row.split()[-1]!r} in {row!r}"
    assert "%" not in row, row


# --- the invariant 4.1 deferred until there was something to route -------------


def _calls_in_own_scope(fn, name: str) -> list:
    """Calls to `name` made by `fn` itself, not by a function nested inside it.

    Same helper as `test_window_cap.py`, and for the same reason: `ast.walk` descends into nested
    `FunctionDef`s, so a wrapper defined inside the function it serves gets credited twice."""
    lines, stack = [], list(fn.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == name:
            lines.append(node.lineno)
        stack.extend(ast.iter_child_nodes(node))
    return sorted(lines)


def test_no_new_log_query_path_was_added_beside_the_primitive():
    """**ROADMAP 4.1 decision 4, finally writable.** It deferred this test with a stated reason:
    the property that stops `aggregate_logs` becoming a fourth parallel query path is that later
    items route THROUGH it, and there was nothing to route until 4.2 existed.

    4.2 turned out not to need it at all, which is the stronger outcome: the rule-level rate is
    metrics-only and the endpoint-level rate is `aggregate_logs` as it already ships, so 4.2 added
    no query template and no `query_logs` call anywhere. What this asserts is that it stays that
    way -- `waf_overview` reaches CloudWatch and never the log layer, and `waf_logs.TEMPLATES` did
    not grow a hand-written per-URI ratio beside the primitive.

    Phrased as "no new path" rather than "4.2 calls aggregate_logs", because a test demanding a
    call would push toward a wrapper existing only to satisfy it, which is the manufactured
    consumer 4.1 decision 4 rejected.

    **Both halves carry a floor, for the reason the anchoring sweep in `test_aggregate_logs.py`
    needed one.** Each half is an absence claim, and `for fn in ast.walk(tree)` is satisfied by a
    module with no functions while the comprehension below is satisfied by an empty `TEMPLATES`. A
    narrowed search space needs a floor exactly as a widened one needs a scope, and named subjects
    rather than counts, since a count passes on the wrong set."""
    tree = ast.parse((TOOLS / "waf_overview.py").read_text())
    functions = {fn.name for fn in ast.walk(tree)
                 if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))}
    assert {"_top_rules", "get_waf_overview"} <= functions, sorted(functions)
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            assert not _calls_in_own_scope(fn, "query_logs"), (
                f"waf_overview.{fn.name} queries logs. The rule-level hit rate is metrics-only on "
                f"purpose: free, unaffected by a Log Filter, and 14 days deep.")
    from tools.waf_logs import TEMPLATES
    assert {"top_blocked_ips", "ip_cross_query"} <= set(TEMPLATES), sorted(TEMPLATES)
    # Every template carries a non-empty `athena`, verified over all 37, so the sweep sees the whole
    # set rather than defaulting past part of it.
    missing_athena = [k for k, v in TEMPLATES.items() if not v.get("athena")]
    assert not missing_athena, (
        f"these templates have no Athena variant, so the ratio sweep below cannot see them: "
        f"{missing_athena}")
    ratio_like = [k for k, v in TEMPLATES.items()
                  if "count_if" in v["athena"] or "hit_rate" in v["athena"]]
    assert not ratio_like, (
        f"a ratio was hand-written as a template instead of routing through "
        f"aggregate_logs(metric='ratio'): {ratio_like}")


def test_the_prompt_sends_each_hit_rate_question_to_the_right_level():
    """The two levels have different denominators and different exposure, so routing them to one
    tool is the failure. Asserted on the prompt because the split is only real if the model sees
    it: the code cannot stop a per-rule question going to the log path."""
    prompt = agent._build_system_prompt(9)
    assert "Hit rate: two levels" in prompt, "the prompt does not distinguish the two levels"
    rule_line = next(l for l in prompt.splitlines() if l.startswith('- "hit rate of rule X"'))
    assert "top_rules" in rule_line and "aggregate_logs" not in rule_line, rule_line
    uri_line = next(l for l in prompt.splitlines() if "hit rate per URL" in l)
    assert "aggregate_logs" in uri_line, uri_line
    # The Log Filter caveat must sit on the log-only level and nowhere else, or it reads as a
    # caveat on hit rate in general and the metrics path loses its main advantage.
    section = prompt.split("## Hit rate: two levels")[1].split("\n## ")[0]
    endpoint = next(l for l in section.splitlines() if "Endpoint level" in l)
    assert "Log Filter" in endpoint, "the Log Filter caveat is not on the endpoint level"
    rule_bullet = next(l for l in section.splitlines() if "Rule level" in l)
    assert "Log Filter cannot affect it" in rule_bullet, rule_bullet


def test_the_prompt_says_a_missing_rule_is_not_a_zero():
    """Measured on the live WebACL: four of eleven configured rules had no metric of any kind over
    24 hours, because WAF publishes nothing for a rule that matched nothing. `_top_rules` drops
    those rows rather than printing 0%, which is right, but the model then sees a short table and
    could report a rule as inactive on the strength of its absence."""
    prompt = agent._build_system_prompt(9)
    section = prompt.split("## Hit rate: two levels")[1].split("\n## ")[0]
    assert "no data" in section and "never fires" in section, section


def test_the_quoted_measurement_matches_the_one_the_tests_pin():
    """One measured figure, quoted in one place, and this is why.

    `_rate`'s docstring first said `10/45515` while every assertion here says `45513`. **Both were
    real measurements** -- two live runs minutes apart, with `allowed` moving by two -- so neither
    was a mistake and the pair still disagreed. That is the defect class this project has spent the
    most machinery on: a numeric claim in prose that the code contradicts, arrived at without anyone
    writing anything false.

    The fix is not "be careful", it is that the test owns the number and the docstring has to match
    it."""
    src = (TOOLS / "waf_overview.py").read_text()
    quoted = set(re.findall(r"10/(\d{5})", src))
    assert quoted, "the measurement is no longer quoted, so nothing pins the denominator"
    denom = str(sum(TOTALS.values()))
    assert quoted == {denom}, (
        f"waf_overview quotes 10/{sorted(quoted)} while the tests pin {denom}. Both may have been "
        f"measured; they still have to agree.")
