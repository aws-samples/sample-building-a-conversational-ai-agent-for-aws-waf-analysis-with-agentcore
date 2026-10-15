# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A counted request is found where WAF records the Count, which for a managed sub-rule is nested.

`top_counted_ips` and `top_counted_countries` read the Count from the top level only, and
`aggregate_logs(filter_by={"action": "COUNT"})` from the top-level `action`, which never holds
COUNT. Measured 2026-10-15: 0 versus 1792 counted requests on Athena for one day, 2 versus 515 on
CloudWatch for 24 hours. The numbers and the mechanism are in `tools/counted.py`.

What this cannot check: that the engines still record the Count where `tools/counted.py` says.
That is a measurement, and the docstring there says how it was taken.
"""

import ast
import pathlib
import re

from tools import waf_aggregate as AG
from tools.counted import COUNTED_ATHENA, COUNTED_CWL
from tools.waf_logs import TEMPLATES

ROOT = pathlib.Path(__file__).resolve().parents[1]

# The two shapes that read a Count from the top level. `r.action` and `rg.` prefixes are rule
# entries and correct; the lookbehind keeps them out.
TOP_LEVEL_COUNT = [re.compile(r"nonTerminatingMatchingRules\.\d+\.action"),
                   re.compile(r"(?<![.\w])action = '(COUNT|EXCLUDED_AS_COUNT)'"),
                   re.compile(r"(?<![.\w])any_match\(nonterminatingmatchingrules, r -> r\.action = 'COUNT'\)"
                              r"(?! OR any_match\(rulegrouplist)")]


def _literals():
    """Every string constant in `tools/`, minus docstrings, which describe these shapes in prose
    (`tools/counted.py` names the bad one on purpose) and never reach an engine."""
    for path in sorted((ROOT / "tools").glob("*.py")):
        tree = ast.parse(path.read_text())
        docs = {id(n.body[0].value) for n in ast.walk(tree)
                if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docs:
                yield path.name, node.lineno, node.value


def test_no_query_in_the_package_reads_a_count_from_the_top_level():
    """Walked over every string literal in `tools/`, not over the templates this fix touched, so a
    query written next year in another module is held to it too."""
    literals = list(_literals())
    assert len(literals) > 500, f"only {len(literals)} literals; the walk is broken"
    assert any("any_match(rulegrouplist" in v for _, _, v in literals), "positive control missing"
    hits = [(f, n, p.pattern) for f, n, v in literals for p in TOP_LEVEL_COUNT if p.search(v)]
    assert not hits, f"top-level-only COUNT predicates: {hits}"


def test_the_counted_templates_use_the_shared_predicate():
    named = [k for k in TEMPLATES if "counted" in k]
    assert set(named) == {"top_counted_ips", "top_counted_countries"}, named
    for name in named:
        assert COUNTED_ATHENA in TEMPLATES[name]["athena"], name
        assert COUNTED_CWL in TEMPLATES[name]["query"], name


def test_aggregate_count_filter_finds_nested_counts():
    cwl, athena = AG._build("clientIp", "count", {"action": "COUNT"}, 5, 25)
    assert COUNTED_ATHENA in athena, athena
    assert COUNTED_CWL in cwl, cwl
    assert not TOP_LEVEL_COUNT[1].search(athena) and not TOP_LEVEL_COUNT[1].search(cwl)


def test_aggregate_terminating_actions_still_filter_on_the_top_level():
    """The control. BLOCK is a terminating action, so the top-level field is the right place."""
    cwl, athena = AG._build("clientIp", "count", {"action": "BLOCK"}, 5, 25)
    assert "action = 'BLOCK'" in athena and "action = 'BLOCK'" in cwl


def test_the_shared_predicate_names_the_nested_location_it_was_measured_at():
    assert "rg.nonterminatingmatchingrules" in COUNTED_ATHENA
    assert "'\"action\":\"COUNT\"'" in COUNTED_CWL
