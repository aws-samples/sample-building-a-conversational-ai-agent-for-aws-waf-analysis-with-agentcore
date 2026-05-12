# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Deep WAF review — runs deterministic pipeline + returns context for LLM analysis."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from strands import tool

from tools.aws_session import get_client

REVIEW_DIR = "/tmp/review"
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
REFERENCES_DIR = Path(__file__).resolve().parent.parent / "references"

_latest_review_html = ""

# Section → reference file mapping
SECTION_REFERENCES = {
    5: "bot-control.md",
    8: "crawler-seo.md",
    17: "common-patterns.md",
}


def _run_script(name: str, args: list[str], timeout: int = 30) -> tuple[bool, str]:
    """Run a pipeline script. Returns (success, stdout)."""
    cmd = [sys.executable, str(SCRIPTS_DIR / name)] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(SCRIPTS_DIR))
        if result.returncode == 2:  # FATAL
            return False, result.stdout + result.stderr
        return True, result.stdout
    except subprocess.TimeoutExpired:
        return False, f"Script {name} timed out after {timeout}s"


@tool
def review_waf_rules_deep(webacl_name: str, scope: str = "CLOUDFRONT", region: str = "us-east-1", lang: str = "en") -> str:
    """Run comprehensive WAF rules review pipeline. Produces a full security audit report.
    Use this when the user asks to review, audit, or optimize their WAF rules/WebACL configuration.
    NOT for simple single-rule questions — use get_waf_config + your own reasoning for those.

    Args:
        webacl_name: Exact WebACL name
        scope: CLOUDFRONT or REGIONAL
        region: AWS region (for REGIONAL scope)
        lang: Report language — 'zh' for Chinese, 'en' for English. Detect from user's message language.
    """
    # 1. Clean /tmp/review
    shutil.rmtree(REVIEW_DIR, ignore_errors=True)
    os.makedirs(REVIEW_DIR, exist_ok=True)

    # 2. Fetch WebACL JSON
    waf_region = "us-east-1" if scope == "CLOUDFRONT" else region
    waf = get_client("wafv2", region_name=waf_region)
    try:
        resp = waf.get_web_acl(Name=webacl_name, Scope=scope, Id=_get_webacl_id(waf, webacl_name, scope))
    except Exception as e:
        return f"Error fetching WebACL: {e}"

    input_file = os.path.join(REVIEW_DIR, "input.json")
    with open(input_file, "w") as f:
        json.dump(resp, f, default=str)

    # 3. Run pipeline
    steps = [
        ("waf-preprocess.py", [input_file, REVIEW_DIR]),
        ("waf-generate-mermaid.py", [REVIEW_DIR]),
        ("waf-pre-checks.py", [REVIEW_DIR, input_file]),
        ("waf-generate-findings.py", [REVIEW_DIR, "--lang", lang]),
        ("waf-generate-appendix.py", [REVIEW_DIR]),
    ]
    for script_name, args in steps:
        ok, output = _run_script(script_name, args)
        if not ok:
            return f"Pipeline failed at {script_name}:\n{output}"

    # 4. Read metadata
    metadata_path = os.path.join(REVIEW_DIR, "findings-metadata.json")
    if not os.path.exists(metadata_path):
        return "Pipeline completed but findings-metadata.json not found."
    with open(metadata_path) as f:
        metadata = json.load(f)

    llm_sections = metadata.get("llm_sections", [])
    next_issue_number = metadata.get("next_issue_number", 1)

    # 5. Build context for LLM (only rules relevant to LLM sections)
    summary_path = os.path.join(REVIEW_DIR, "waf-summary.json")
    with open(summary_path) as f:
        summary = json.load(f)

    # Extract relevant rules for LLM sections
    llm_context = metadata.get("llm_context", {})
    relevant_rules = []
    for rule in summary.get("rules", []):
        relevant_rules.append({
            "name": rule.get("name"),
            "priority": rule.get("priority"),
            "action": rule.get("action"),
            "labels_produced": rule.get("labels_produced", []),
            "labels_consumed": rule.get("labels_consumed", []),
            "summary": rule.get("statement_summary", "")[:200],
        })

    # 6. Attach reference files for LLM sections
    references_text = ""
    for section in llm_sections:
        ref_file = SECTION_REFERENCES.get(section)
        if ref_file:
            ref_path = REFERENCES_DIR / ref_file
            if ref_path.exists():
                references_text += f"\n\n--- Reference: {ref_file} ---\n{ref_path.read_text()}"

    # 7. Build return value
    result = f"""## WAF Deep Review Pipeline Complete

**WebACL**: {webacl_name} ({scope}, {waf_region})
**Rules analyzed**: {len(summary.get('rules', []))}
**Scripted findings generated**: {next_issue_number - 1} issues (deterministic, already saved)

---

## Your Task

Analyze the following sections and output findings in this exact format:

## Issue N (severity): title

**Rule**: rule_name (priority N)
**Current state**: ...

**Problem**:
- ...

**Recommendation**:
- ...

---

**Sections to analyze**: {llm_sections}
**Start numbering from**: Issue #{next_issue_number}
**After completing your analysis, call finalize_review_report(llm_analysis_md) with your findings.**

---

## Rules Summary (for your analysis)

```json
{json.dumps(relevant_rules, indent=2, ensure_ascii=False)[:8000]}
```

## Additional Context

{json.dumps(llm_context, indent=2, ensure_ascii=False)[:2000]}

{references_text}
"""
    return result


@tool
def finalize_review_report(llm_analysis_md: str) -> str:
    """Finalize the WAF review report by combining scripted findings with LLM analysis.
    MUST be called after review_waf_rules_deep with your analysis as the argument.

    Args:
        llm_analysis_md: Your analysis in Markdown format (Issue sections only).
    """
    global _latest_review_html

    # 1. Read scripted findings
    scripted_path = os.path.join(REVIEW_DIR, "scripted-findings.md")
    if not os.path.exists(scripted_path):
        return "Error: scripted-findings.md not found. Run review_waf_rules_deep first."
    scripted = Path(scripted_path).read_text()

    # 2. Combine: scripted + LLM findings
    report_path = os.path.join(REVIEW_DIR, "waf-review-report.md")
    combined = scripted.rstrip() + "\n\n" + llm_analysis_md.strip() + "\n"
    Path(report_path).write_text(combined)

    # 3. Generate report header (summary table)
    _run_script("waf-generate-report-header.py", [REVIEW_DIR])

    # 4. Build issue-rule mapping
    _run_script("waf-build-issue-map.py", [REVIEW_DIR])

    # 5. Annotate Mermaid diagram
    _run_script("waf-annotate-mermaid.py", [REVIEW_DIR])

    # 6. Read final report
    report_path = os.path.join(REVIEW_DIR, "waf-review-report.md")
    report_md = Path(report_path).read_text()

    # 7. Append Mermaid + appendix
    mermaid_path = os.path.join(REVIEW_DIR, "mermaid-annotated.md")
    appendix_path = os.path.join(REVIEW_DIR, "appendix.md")
    if os.path.exists(mermaid_path):
        report_md += "\n\n" + Path(mermaid_path).read_text()
    if os.path.exists(appendix_path):
        report_md += "\n\n" + Path(appendix_path).read_text()

    # 8. Render to HTML
    _latest_review_html = _render_html(report_md)

    # 9. Count issues for summary
    import re
    issues = re.findall(r"## Issue \d+ \((\w+)\):", report_md)
    severity_counts = {}
    for s in issues:
        severity_counts[s] = severity_counts.get(s, 0) + 1
    summary_parts = [f"{count} {sev}" for sev, count in severity_counts.items()]

    return f"Review report generated: {len(issues)} issues ({', '.join(summary_parts)}). User can download the full HTML report.\n---\nHints:\nCall ask_user() tool to ask: Would you like to download the full review report?"


def _get_webacl_id(waf, name: str, scope: str) -> str:
    """Get WebACL ID by name."""
    kwargs = {"Scope": scope, "Limit": 100}
    while True:
        resp = waf.list_web_acls(**kwargs)
        for acl in resp.get("WebACLs", []):
            if acl["Name"].lower() == name.lower():
                return acl["Id"]
        marker = resp.get("NextMarker")
        if not marker:
            break
        kwargs["NextMarker"] = marker
    raise ValueError(f"WebACL '{name}' not found")


def _render_html(md: str) -> str:
    """Render Markdown to styled HTML."""
    # Simple conversion — use basic HTML wrapping
    # Mermaid blocks rendered client-side via mermaid.js
    import html as html_mod
    import re
    lines = md.split("\n")
    html_lines = []
    in_code = False
    for line in lines:
        if line.startswith("```"):
            if in_code:
                html_lines.append("</code></pre>")
                in_code = False
            else:
                lang = line[3:].strip()
                if lang == "mermaid":
                    html_lines.append(f'<pre class="mermaid">')
                else:
                    html_lines.append(f"<pre><code>")
                in_code = True
            continue
        if in_code:
            html_lines.append(html_mod.escape(line))
            continue
        if line.startswith("# "):
            html_lines.append(f"<h1>{html_mod.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            html_lines.append(f"<h2>{html_mod.escape(line[3:])}</h2>")
        elif line.startswith("### "):
            html_lines.append(f"<h3>{html_mod.escape(line[4:])}</h3>")
        elif line.startswith("- "):
            html_lines.append(f"<li>{html_mod.escape(line[2:])}</li>")
        elif line.startswith("**") and line.endswith("**"):
            html_lines.append(f"<p><strong>{html_mod.escape(line[2:-2])}</strong></p>")
        elif line.startswith("---"):
            html_lines.append("<hr>")
        elif line.startswith("|"):
            html_lines.append(f"<p>{html_mod.escape(line)}</p>")
        elif line.strip():
            html_lines.append(f"<p>{html_mod.escape(line)}</p>")
        else:
            html_lines.append("")

    body = "\n".join(html_lines)
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>WAF Review Report</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
<script>mermaid.initialize({{startOnLoad:true}});</script>
<style>
body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;line-height:1.6;color:#1a1a1a}}
h1{{color:#1a56db;border-bottom:2px solid #1a56db;padding-bottom:0.5rem}}
h2{{color:#c53030;margin-top:2rem}}
h3{{color:#2d3748}}
hr{{border:none;border-top:1px solid #e2e8f0;margin:1.5rem 0}}
pre{{background:#f7fafc;padding:1rem;border-radius:6px;overflow-x:auto;border:1px solid #e2e8f0}}
code{{background:#f0f0f0;padding:2px 6px;border-radius:3px}}
li{{margin:0.3rem 0}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #e2e8f0;padding:8px;text-align:left}}th{{background:#f7fafc}}
.mermaid{{background:#fff;text-align:center;padding:1rem}}
</style></head><body>{body}</body></html>"""
