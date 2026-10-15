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
"""

import ast
import pathlib

import re

from tools.waf_logs import TEMPLATES

ROOT = pathlib.Path(__file__).resolve().parents[1]
RAW = re.compile(r"(?:@message\s+(?:not\s+)?like|strcontains\(@message,)\s*'([^']*)'")


def test_every_raw_record_match_on_a_parameter_is_anchored():
    literals = [(k, lit) for k, t in TEMPLATES.items()
                for lit in re.findall(r"@message\s+(?:not\s+)?like\s+'([^']*)'", t["query"])]
    with_param = [(k, lit) for k, lit in literals if "{" in lit]
    assert with_param, "no template matches a parameter against @message, so this sweep proves nothing"
    bad = [(k, lit) for k, lit in with_param if '"' not in lit]
    assert not bad, bad


def test_the_host_and_label_templates_read_the_field_they_name():
    assert "filter host = '{host}'" in TEMPLATES["host_top_ips"]["query"]
    assert "filter lbls like '{label}'" in TEMPLATES["label_top_ips"]["query"]


def test_no_query_in_the_package_matches_the_raw_record_unanchored():
    """Every string literal in `tools/`, not only the templates, and not only the ones carrying a
    parameter: a fixed label word is forgeable from a URI just the same."""
    found, bad = [], []
    for path in sorted((ROOT / "tools").glob("*.py")):
        tree = ast.parse(path.read_text())
        docs = {id(n.body[0].value) for n in ast.walk(tree)
                if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
        for n in ast.walk(tree):
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs:
                for lit in RAW.findall(n.value):
                    found.append(lit)
                    if '"' not in lit:
                        bad.append(f"{path.name}:{n.lineno} {lit!r}")
    assert len(found) >= 15, f"only {len(found)} raw-record matches found; the pattern broke"
    assert not bad, bad
