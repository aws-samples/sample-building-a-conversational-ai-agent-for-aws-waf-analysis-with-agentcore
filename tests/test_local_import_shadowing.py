"""No function in `tools/` uses a name before a local import of the same name further down.

A local import binds the name for the whole function, so the earlier use raises `UnboundLocalError`.
`waf_bypass._step_scan` did this from v0.27.0: an import of `get_webacl_name` beside the log-path
warning made the call at the top of the scan's week-over-week check raise, `except Exception: pass`
swallowed it, and the spike note never printed. Nothing failed, which is why it lasted.
"""

import ast
import pathlib

TOOLS = pathlib.Path(__file__).resolve().parent.parent / "tools"


def _shadowed(source: str) -> list[str]:
    found = []
    for fn in ast.walk(ast.parse(source)):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        local = {}
        for node in ast.walk(fn):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    local.setdefault((alias.asname or alias.name).split(".")[0], node.lineno)
        for name, line in local.items():
            early = [n.lineno for n in ast.walk(fn)
                     if isinstance(n, ast.Name) and n.id == name and n.lineno < line]
            if early:
                found.append(f"{fn.name}: {name!r} used at line {early[0]}, imported locally at line {line}")
    return found


def test_the_check_finds_the_shape_it_is_for():
    src = ("def f():\n    try:\n        x = g()\n    except Exception:\n        pass\n"
           "    from m import g\n    return g()\n")
    assert _shadowed(src) == ["f: 'g' used at line 3, imported locally at line 6"]


def test_no_function_in_tools_shadows_a_name_it_already_used():
    files = sorted(TOOLS.glob("*.py"))
    assert "waf_bypass.py" in {f.name for f in files}, files
    found = [f"{f.name}:{hit}" for f in files for hit in _shadowed(f.read_text())]
    assert not found, found
