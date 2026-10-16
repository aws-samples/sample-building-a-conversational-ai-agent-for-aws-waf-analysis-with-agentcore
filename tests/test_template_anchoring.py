# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""No CloudWatch query matches text against the raw record unanchored.

`host_top_ips` filtered `@message like '{host}'`, so the host name turning up anywhere counted.
Measured 2026-10-15 on `aws-waf-logs-group`, 24 hours, host `cf-httpecho.a.letsmakeit.link`: the
top row was 45,841 hits with no client IP at all, CloudFront access-log records sharing the log
group, which the Host-header parse excludes. `label_top_ips` had the same shape for `{label}`.
The rule is the one `test_aggregate_logs` holds the aggregate filters to: a raw-record literal must
carry a quote, which puts the value inside a JSON key/value pair, where a client's quote arrives
escaped and cannot reach.

**The package sweep found what the defect list named and five more.** The bypass scan dropped any
request with "bot:verified" in its URI or User-Agent from five sections (measured with three probe
requests that carried the words and no such label: all three excluded); `top_allowed_crawlers` and
`top_allowed_repeaters` did the same; the weekly report's Anti-DDoS event and suspicion counts could
be raised by the label text in a URI; and `token_reuse_ips` parsed its session id from the first
`awswaf:managed:token:id:` text anywhere in the record, where the request line comes before labels.

**A quote alone is not an anchor.** The first version of this sweep accepted any literal carrying
a `"`, so `'"awswaf:managed:aws:anti-ddos:event-detected'` passed: every JSON string value opens
with a quote, and a header `X-A: awswaf:managed:aws:anti-ddos:event-detected` logs as
`"value":"awswaf...`, which that literal matches. Measured 2026-10-16 on `aws-waf-logs-group` over
a day, a literal opening with a quote, `'"Mozilla'`, matched 518 of 46,159 WAF records. The anchor
is a JSON key with its colon, `"name":`, because the client's quotes around a key it writes arrive
escaped.
"""

import ast
import pathlib

import re

from tools.waf_logs import TEMPLATES

ROOT = pathlib.Path(__file__).resolve().parents[1]
# A test of the raw record: `like` or `=~` with a quoted or regex operand, or `strcontains`.
MATCH = re.compile(r"""(?:@message\s+(?:not\s+)?like|@message\s+=~)\s*('[^']*'|"[^"]*"|/(?:[^/\\]|\\.)*/)"""
                   r"""|strcontains\(@message,\s*('[^']*')""")
# An extraction from it, which reads client text on purpose and needs only a key to find its field.
PARSE = re.compile(r"""parse\s+@message\s+(/(?:[^/\\]|\\.)*/|'[^']*')""")
KEY = re.compile(r'"\w+\\?":')
# Keys only WAF writes, so their values cannot be client text. `name` is also a header's key, so it
# anchors only a value holding `:`, which a header name cannot.
WAF_KEYS = ("ruleId", "action", "exclusionType", "labels", "terminatingRule", "terminatingRuleMatchDetails",
            "rateBasedRuleName", "nonTerminatingMatchingRules", "ruleGroupList", "ruleGroupId")
WAF_KEY = re.compile(r'"(?:' + "|".join(WAF_KEYS) + r')\\?":|"name\\?":\\?"[^"\\]*:')


def anchored(lit: str) -> bool:
    """Whether a test of the raw record pins a key WAF writes. `\\?` admits the escaped quote a
    regex written in a Python string carries."""
    return lit[0] in "'/" and bool(WAF_KEY.search(lit))


def test_the_anchor_test_tells_a_waf_key_from_a_leading_quote_or_a_client_key():
    """The precondition: the criterion rejects what each earlier one let through. Measured
    2026-10-16, `'"value":"Mozilla'` matched 2,235 records in 14 days, every one a User-Agent."""
    assert not anchored("'\"awswaf:managed:aws:anti-ddos:event-detected'")
    assert not anchored("'awswaf:managed:token:accepted\"'")
    assert not anchored("'\"value\":\"Mozilla'")
    assert not anchored("'\"name\":\"user-agent\"'")
    assert not anchored('"\\"name\\":\\"awswaf:managed:x\\""'), "double-quoted like answered 0 measured"
    assert anchored("'\"name\":\"awswaf:managed:aws:anti-ddos:event-detected\"'")
    assert anchored("'\"ruleId\":\"{}\",\"action\":\"COUNT\"'")
    assert anchored('/"labels":\\[(?<lbls>[^\\]]*)\\]/')


def test_every_raw_record_match_on_a_parameter_is_anchored():
    literals = [(k, lit) for k, t in TEMPLATES.items()
                for lit in re.findall(r"@message\s+(?:not\s+)?like\s+'([^']*)'", t["query"])]
    with_param = [(k, lit) for k, lit in literals if "{" in lit]
    assert with_param, "no template matches a parameter against @message, so this sweep proves nothing"
    bad = [(k, lit) for k, lit in with_param if not anchored(f"'{lit}'")]
    assert not bad, bad


def test_the_host_and_label_templates_read_the_field_they_name():
    assert "filter host = '{host}'" in TEMPLATES["host_top_ips"]["query"]
    assert "filter lbls like '{label}'" in TEMPLATES["label_top_ips"]["query"]


def _query_strings(tree):
    """`(lineno, text)` for every string in a module, an f-string whole with each placeholder as `{}`,
    and none of its pieces again on their own. Docstrings are left out."""
    docs = {id(n.body[0].value) for n in ast.walk(tree)
            if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
    pieces = {id(v) for n in ast.walk(tree) if isinstance(n, ast.JoinedStr) for v in n.values}
    for n in ast.walk(tree):
        if isinstance(n, ast.JoinedStr):
            yield n.lineno, "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in n.values), True
        elif isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs | pieces:
            yield n.lineno, n.value, False


def test_no_query_in_the_package_matches_the_raw_record_unanchored():
    """Every string in `tools/`, f-strings included, not only the templates, and not only the ones
    carrying a parameter: a fixed label word is forgeable from a URI just the same. An f-string was
    invisible to the first two versions, so seven anchored literals were never checked."""
    tests, parses, in_fstrings, bad = [], [], 0, []
    for path in sorted((ROOT / "tools").glob("*.py")):
        for line, text, is_f in _query_strings(ast.parse(path.read_text())):
            for m in MATCH.finditer(text):
                lit = m.group(1) or m.group(2)
                tests.append(lit)
                in_fstrings += is_f
                if not anchored(lit):
                    bad.append(f"{path.name}:{line} {lit!r}")
            for m in PARSE.finditer(text):
                parses.append(m.group(1))
                if not KEY.search(m.group(1)):
                    bad.append(f"{path.name}:{line} parse {m.group(1)!r}")
    assert len(tests) >= 25 and len(parses) >= 15, (len(tests), len(parses))
    assert in_fstrings >= 7, f"only {in_fstrings} tests found inside f-strings; they are not being read"
    assert not bad, bad
