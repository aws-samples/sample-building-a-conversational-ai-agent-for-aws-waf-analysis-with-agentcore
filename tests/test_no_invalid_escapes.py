# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""No source file holds an invalid string escape such as `\\/` in a non-raw string.

Python warns about one today and is to reject it later. A regex written into the system prompt, which
is a plain triple-quoted string, put `\\/` there on 2026-10-16; it worked, warned once in the suite's
output, and no test failed.
"""

import pathlib
import warnings

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _invalid(source: str, name: str):
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        try:
            compile(source, name, "exec")
        except SyntaxError as e:
            return f"{name}:{e.lineno} {e.msg}"
    return None


def test_the_check_catches_an_invalid_escape():
    assert _invalid('X = """a \\/ b"""\n', "sample") is not None


def test_no_source_file_holds_an_invalid_escape():
    files = sorted([*ROOT.glob("*.py"), *(ROOT / "tools").glob("*.py"), *(ROOT / "tests").rglob("*.py")])
    assert len(files) > 50, len(files)
    bad = [r for p in files if (r := _invalid(p.read_text(), str(p.relative_to(ROOT))))]
    assert not bad, bad
