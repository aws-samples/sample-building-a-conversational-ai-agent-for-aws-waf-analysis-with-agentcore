# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Two CloudWatch match forms that had to pin one JSON object, and one that had to ignore case.

**A rule's Count is one rule entry, `{"ruleId":"X","action":"COUNT",...}`.** The `count_rule_top_*`
templates matched `'"ruleId":"X"'` and `'"action":"COUNT"'` as two separate substrings, so a record
where X blocked and some other rule counted matched both. Measured 2026-10-16 on
`shield-sample-webacl` over 14 days, for LFI_URIPATH, which only ever blocks: 34 records matched
the separate form, 0 the adjacent one, and 0 on the Athena twin, which compares the two fields of
one entry. So the tool reported 34 Count hits for a rule that counted nothing.

**The log keeps the client's header-name casing**, and the Host parse matched only `Host` and
`host`, while Athena compares `lower(h.name)`. Over 14 days only those two spellings occurred, so
this is the low-cost half of keeping the engines alike.
"""

import ast
import pathlib
import re

from tools.waf_logs import TEMPLATES

ROOT = pathlib.Path(__file__).resolve().parents[1]
SEPARATE_RULE = re.compile(r"""'"ruleId":"[^"']*"'""")
SEPARATE_COUNT = re.compile(r"""'"action":"COUNT"'""")


def _strings():
    for path in sorted((ROOT / "tools").glob("*.py")):
        for n in ast.walk(ast.parse(path.read_text())):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                yield path.name, n.lineno, n.value


def test_the_count_rule_templates_match_one_entry():
    for key in ("count_rule_top_ips", "count_rule_top_uris", "count_rule_top_uas"):
        assert '\'"ruleId":"{rule_name}","action":"COUNT"\'' in TEMPLATES[key]["query"], key


def test_no_query_matches_a_rule_and_a_count_as_two_substrings():
    both = [f"{f}:{line}" for f, line, s in _strings() if SEPARATE_RULE.search(s) and SEPARATE_COUNT.search(s)]
    assert not both, both


def test_the_control_the_sweep_sees_the_separate_form():
    """The precondition: the old template text is what the sweep flags."""
    old = """filter @message like '"ruleId":"{rule_name}"' and @message like '"action":"COUNT"'"""
    assert SEPARATE_RULE.search(old) and SEPARATE_COUNT.search(old)


def _host_parses():
    out = []
    for f, line, s in _strings():
        for m in re.finditer(r"parse @message /((?:[^/\\]|\\.)*)/", s):
            if "(?<host>" in m.group(1):
                out.append((f"{f}:{line}", m.group(1).replace("(?<", "(?P<")))
    return out


def test_every_host_parse_reads_any_casing():
    parses = _host_parses()
    assert len(parses) >= 4, parses
    for where, rx in parses:
        for name in ("Host", "host", "HOST"):
            m = re.search(rx, '"headers":[{"name":"%s","value":"example.com"}]' % name)
            assert m and m.group("host") == "example.com", (where, name, rx)
