# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A WebACL's log records are picked out by the `webacl/<name>/` segment of `webaclId`.

`webaclId` is the WebACL's ARN, `arn:aws:wafv2:<region>:<account>:global/webacl/<name>/<id>`, and
the filters matched `/<name>/`. A WebACL may be named `webacl`, and every ARN holds `/webacl/`:
measured 2026-10-15 on `aws-waf-logs-test`, `'/webacl/'` matched all 46,192 records of
`test-webacl-cwl`, as many as `'/webacl/test-webacl-cwl/'`.
"""

import ast
import pathlib
import re

from tools import waf_query as Q

ROOT = pathlib.Path(__file__).resolve().parents[1]
ARN = "arn:aws:wafv2:us-east-1:111122223333:global/webacl/{}/22222222-3333-4444-5555-666666666666"


def _cwl_literal(name):
    return re.match(r"filter webaclId like '([^']*)'", Q.scope_cwl_query("x", name)).group(1)


def test_a_webacl_named_webacl_does_not_match_another_webacls_records():
    assert _cwl_literal("webacl") not in ARN.format("test-webacl-cwl")
    assert _cwl_literal("webacl") in ARN.format("webacl")


def test_the_control_a_webacl_still_matches_its_own_records():
    assert _cwl_literal("test-webacl-cwl") in ARN.format("test-webacl-cwl")


def test_every_webacl_filter_in_the_package_names_the_webacl_segment():
    """The Athena filters are built inside query paths that need a table to reach, so they are swept
    from the source; each must carry `/webacl/` before the name. Only f-strings, since every filter
    interpolates a name and the docstrings quote measured literals."""
    found = []
    for p in sorted((ROOT / "tools").glob("*.py")):
        for n in ast.walk(ast.parse(p.read_text())):
            if isinstance(n, ast.JoinedStr):
                text = "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in n.values)
                found += [(p.name, m.group(1)) for m in re.finditer(r"webacl[iI]d (?:like|LIKE) '([^']*)'", text)]
    assert len(found) >= 3, f"only {found}: the sweep is not reading the filters"
    bad = [f for f in found if not re.search(r"/webacl/\{", f[1])]
    assert not bad, bad
