# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ROADMAP 4.3: injection investigation as a tool, so the sequence is code rather than advice.

Injection was the one major scenario with no scenario tool. Its method lived only as a prompt
playbook, six steps the model executed by firing the generic data tools itself, which means the
orchestration carried none of the guarantee the packaged tools do: nothing stopped the model
skipping a step, reordering one, or stopping after the first interesting result. On a security
question a skipped step is where it hurts most, and step 5 -- profiling the source IPs -- is the
one most likely to be dropped because the first four already look like an answer.

**The playbook's judgment moved too, not just its sequence.** ROADMAP 4.3 names this as the way to
lose it: delete the six steps, leave the classification matrix and the confidence language in the
prompt, and the tool ships with the orchestration and none of the reasoning. So `_classify` holds
the matrix and `CONFIDENCE` holds the boundary, both in code and both in the output.

## Which rules are injection rules, read rather than guessed

The obvious implementation is a name pattern, and it would be wrong in both directions: a custom
rule called `block-bad-stuff` doing SQLi detection matches nothing, and a rule called
`sqli-allowlist` matches when it should not. WAF has real statement types for this, so the WebACL
config answers it:

- **Custom rules: `SqliMatchStatement` or `XssMatchStatement` anywhere in the statement tree.**
  Authoritative, since that IS the rule doing injection detection. Walked recursively because the
  statement can sit under `And`/`Or`/`Not` or a scope-down, the same traversal
  `waf_block_fp._extract_transforms_from_statement` already does.
- **Managed rule groups: their injection sub-rules, by family and component.** The sub-rule names
  are AWS's (`SQLi_BODY`, `CrossSiteScripting_QUERYARGUMENTS`, `LFI_QUERYSTRING`), so a name
  pattern over them is a documented set rather than a guess at a customer's naming. The group
  itself is not a detector: CommonRuleSet also blocks on extensions and sizes, and taking it whole
  made `.bak` probing the busiest "injection detector".

A rule this cannot classify is reported as unclassifiable rather than dropped, because "no
injection rules found" and "you have injection rules I could not recognise" are different answers
and only one of them means stop looking.
"""

import json

from strands import tool

from tools.aws_session import get_client
from tools.query_limits import MAX_MINUTES
from tools.session_state import get_scope, get_webacl_name, note_window_capped, resolve_region

# Every sub-rule of the AWS managed groups that hold injection detectors, read off
# `describe-managed-rule-group` (CLOUDFRONT, default versions) on 2026-10-16. The agent's role cannot
# call it, so they are listed here; a sub-rule a later version adds is still found once it is
# overridden, and `_is_injection_sub_rule` decides which of these are detectors.
_MANAGED_SUB_RULES = {
    "AWSManagedRulesCommonRuleSet": (
        "NoUserAgent_HEADER", "UserAgent_BadBots_HEADER", "SizeRestrictions_QUERYSTRING",
        "SizeRestrictions_Cookie_HEADER", "SizeRestrictions_BODY", "SizeRestrictions_URIPATH",
        "EC2MetaDataSSRF_BODY", "EC2MetaDataSSRF_COOKIE", "EC2MetaDataSSRF_URIPATH",
        "EC2MetaDataSSRF_QUERYARGUMENTS", "GenericLFI_QUERYARGUMENTS", "GenericLFI_URIPATH",
        "GenericLFI_BODY", "RestrictedExtensions_URIPATH", "RestrictedExtensions_QUERYARGUMENTS",
        "GenericRFI_QUERYARGUMENTS", "GenericRFI_BODY", "GenericRFI_URIPATH", "CrossSiteScripting_COOKIE",
        "CrossSiteScripting_QUERYARGUMENTS", "CrossSiteScripting_BODY", "CrossSiteScripting_URIPATH"),
    "AWSManagedRulesKnownBadInputsRuleSet": (
        "JavaDeserializationRCE_BODY", "JavaDeserializationRCE_URIPATH", "JavaDeserializationRCE_QUERYSTRING",
        "JavaDeserializationRCE_HEADER", "Host_localhost_HEADER", "PROPFIND_METHOD", "ExploitablePaths_URIPATH",
        "Log4JRCE_QUERYSTRING", "Log4JRCE_BODY", "Log4JRCE_URIPATH", "Log4JRCE_HEADER", "ReactJSRCE_BODY"),
    "AWSManagedRulesSQLiRuleSet": (
        "SQLiExtendedPatterns_QUERYARGUMENTS", "SQLi_QUERYARGUMENTS", "SQLi_BODY", "SQLi_COOKIE", "SQLi_URIPATH"),
    "AWSManagedRulesLinuxRuleSet": ("LFI_URIPATH", "LFI_QUERYSTRING", "LFI_HEADER"),
    "AWSManagedRulesUnixRuleSet": (
        "UNIXShellCommandsVariables_QUERYSTRING", "UNIXShellCommandsVariables_BODY", "UNIXShellCommandsVariables_HEADER"),
    "AWSManagedRulesWindowsRuleSet": (
        "WindowsShellCommands_URIPATH_RC_COUNT", "WindowsShellCommands_BODY_RC_COUNT",
        "WindowsShellCommands_QUERYSTRING_RC_COUNT", "WindowsShellCommands_HEADER_RC_COUNT",
        "WindowsShellCommands_HEADER", "WindowsShellCommands_QUERYARGUMENTS", "WindowsShellCommands_BODY",
        "WindowsShellCommands_URIPATH", "PowerShellCommands_COOKIE", "PowerShellCommands_QUERYARGUMENTS",
        "PowerShellCommands_BODY"),
    "AWSManagedRulesPHPRuleSet": (
        "PHPHighRiskMethodsVariables_HEADER", "PHPHighRiskMethodsVariables_QUERYSTRING",
        "PHPHighRiskMethodsVariables_BODY", "PHPHighRiskMethodsVariables_URIPATH"),
}
_INJECTION_GROUPS = tuple(_MANAGED_SUB_RULES)
# Families that find a payload in a request component. `Log4JRCE` with no suffix is the name in
# KnownBadInputs Version_1.2 to 1.8 and 1.12 to 1.14.
_INJECTION_FAMILIES = ("SQLi", "CrossSiteScripting_", "GenericRFI_", "Log4JRCE", "JavaDeserializationRCE_",
                       "ReactJSRCE_", "UNIXShellCommandsVariables_", "WindowsShellCommands_",
                       "PowerShellCommands_", "PHPHighRiskMethodsVariables_", "EC2MetaDataSSRF_",
                       "GenericLFI_", "LFI_")


def _is_injection_sub_rule(name: str) -> bool:
    """Whether a managed sub-rule finds an injected payload, decided with the maintainer 2026-10-16.

    File inclusion on the URI path is file probing, a file asked for by name: the maintainer's
    2026-10-13 test of 42 paths such as `.env` and `.git/config` matched `LFI_URIPATH` and
    `GenericLFI_URIPATH` and no payload rule. The same family on a query, body or header is a
    payload. `_RC_COUNT` rules count and label for the rule beside them, so are not detectors."""
    if not name.startswith(_INJECTION_FAMILIES) or name.endswith("_RC_COUNT"):
        return False
    return not (name.startswith(("GenericLFI_", "LFI_")) and name.endswith("_URIPATH"))


def _sub_rule_groups(rules: list) -> dict:
    """Each injection sub-rule named by `_injection_rules`, mapped to its managed group's name, which
    is the `ManagedRuleGroup` dimension its blocks are counted under."""
    out = {}
    for rule in rules:
        group = rule.get("Statement", {}).get("ManagedRuleGroupStatement", {})
        name = group.get("Name", "")
        if name in _MANAGED_SUB_RULES:
            for sub in _group_sub_rules(group):
                out.setdefault(sub, name)
    return out


def _group_sub_rules(group: dict) -> list:
    """The injection sub-rules of one managed group statement: the listed ones and any override."""
    names = list(_MANAGED_SUB_RULES.get(group.get("Name", ""), ()))
    names += [o["Name"] for o in group.get("RuleActionOverrides", []) if o.get("Name")]
    return [n for n in dict.fromkeys(names) if _is_injection_sub_rule(n)]
# Statement types that ARE injection detection. Not a name pattern.
_INJECTION_STATEMENTS = ("SqliMatchStatement", "XssMatchStatement")

CONFIDENCE = (
    "CONFIDENCE BOUNDARY: WAF logs prove a request arrived, which rule matched it, what action "
    "was taken and what labels were applied. They do NOT prove a backend exploit succeeded, that "
    "a request was legitimate business traffic, or what the application returned. So this is an "
    "attack-pattern assessment, never a confirmed exploit. If you need to know whether anything "
    "got through, that requires origin logs, response codes or application errors, and you should "
    "ask for them rather than infer it here."
)


def _has_injection_statement(stmt: dict) -> bool:
    """Whether a rule's statement tree contains injection detection.

    Recursive because the statement can be nested under `AndStatement`, `OrStatement` or a
    rate-based rule's scope-down, and a top-level-only check would miss a rule that pairs SQLi
    detection with a path condition, which is exactly how a tuned rule is written.

    **`NotStatement` is deliberately NOT descended into, and it was at first.** Every other
    combinator preserves "this rule inspects for SQLi"; `Not` reverses it. Descending gave
    `Action: Allow, And[IPSet(partners), Not(SqliMatchStatement)]` a True, which is an allowlist
    classified as a detector -- the direction this module's docstring calls the dangerous one, and
    the one reading statement types instead of names does NOT fix on its own.

    **Dropping the descent costs nothing, verified rather than assumed.** The tuned case
    `And[Not(uri /upload), SqliMatchStatement]` still returns True, because the injection statement
    is a SIBLING of the `Not` rather than inside it. So this is strictly better, not a trade."""
    if not isinstance(stmt, dict):
        return False
    if any(key in stmt for key in _INJECTION_STATEMENTS):
        return True
    for key in ("AndStatement", "OrStatement"):
        if key in stmt:
            if any(_has_injection_statement(sub) for sub in stmt[key].get("Statements", [])):
                return True
    if "RateBasedStatement" in stmt:
        return _has_injection_statement(stmt["RateBasedStatement"].get("ScopeDownStatement", {}))
    return False


def _injection_rules(rules: list) -> tuple[list, list]:
    """`(injection rule names, names that could not be classified)`.

    The second half exists because dropping what it cannot classify would make "you have no
    injection rules" and "you have injection rules I did not recognise" print the same thing, and
    only one of those means stop looking. A custom rule with no injection statement and no
    recognisable name is not evidence of anything, so it is named and left to the reader."""
    found, unknown = [], []
    for rule in rules:
        name = rule.get("Name", "")
        stmt = rule.get("Statement", {})
        group = stmt.get("ManagedRuleGroupStatement", {})
        if group:
            # The sub-rules, not the group: a match is logged under the sub-rule's name, nested, and
            # the group's own name is on every block it makes, injection or not.
            if group.get("Name", "") in _MANAGED_SUB_RULES:
                found += [n for n in _group_sub_rules(group) if n not in found]
            continue
        # **An `Allow` rule is not a detector whatever its shape**, which is an independent second
        # signal to the statement type. It catches the inverted allowlist even if some future
        # combinator smuggles an injection statement back into a negated position, and it is
        # cheaper than reasoning about the tree. Count, Captcha and Challenge all stay: a
        # Count-mode injection rule in shadow mode is exactly what you would investigate.
        if "Allow" in (rule.get("Action") or {}):
            continue
        if _has_injection_statement(stmt):
            found.append(name)
        elif "RuleGroupReferenceStatement" in stmt:
            # A customer-owned rule group. Its rules are not in this response, so whether it does
            # injection detection cannot be read here without another API call per group.
            unknown.append(f"{name} (custom rule group, contents not inspected)")
    return found, unknown


def _count_mode(rules: list) -> set:
    """Detector names whose matches end as ALLOW: custom rules with a Count action, sub-rules
    overridden to Count, and groups overridden to Count as a whole."""
    out = set()
    for rule in rules:
        group = rule.get("Statement", {}).get("ManagedRuleGroupStatement", {})
        if "Count" in (rule.get("Action") or {}) or "Count" in (rule.get("OverrideAction") or {}):
            out.add(rule.get("Name", ""))
            # A group in Count as a whole counts every sub-rule's match.
            if "Count" in (rule.get("OverrideAction") or {}):
                out |= set(_group_sub_rules(group))
        out |= {o["Name"] for o in group.get("RuleActionOverrides", [])
                if "Count" in (o.get("ActionToUse") or {})}
    return out


def _outcome(table: str):
    """`(pairs, None)` for a result table, `([], None)` for a query that found nothing, and
    `(None, reason)` for one that did not run. `_extract_column` returns `[]` for the last two
    alike, which is how a failed query read as "nothing matched"."""
    if any(r.startswith("| ") for r in table.splitlines()):
        header = next(r for r in table.splitlines() if r.startswith("| "))
        return _extract_pairs(table, header.strip("| ").split(" |")[0].strip()), None
    if " returned 0 results." in table:
        return [], None
    return None, table.strip().splitlines()[0] if table.strip() else "no answer"


def _classify(ip_rows: list, ja4_rows: list) -> tuple[str, str]:
    """`(classification, recommendation)` from the prompt playbook's step-6 matrix, as code.

    Moved verbatim in substance from the prompt, because ROADMAP 4.3 names leaving it behind as the
    way to lose the judgment while shipping the orchestration.

    **The unknown branch is not in the original matrix and has to be.** The prompt gave three
    outcomes and no fourth, so a model reading it with no JA4 data had to pick one of the three.
    JA4 is absent on API Gateway and AppSync upstreams entirely, so "same JA4" and "no JA4 field"
    would otherwise classify identically as a distributed bot."""
    ips = len(ip_rows)
    ja4s = {r for r in ja4_rows if r}
    if not ip_rows:
        # **Distinct from the no-JA4 branch, and the live run is why.** With no data at all the
        # first version answered "unknown, no JA4 data", which points at a field-availability
        # problem when the truth is that nothing matched. Two different causes, two different
        # next actions.
        return ("no evidence, nothing matched this rule in this window",
                "There is nothing to classify. Widen the window, or check whether a Log Filter is "
                "dropping BLOCK records before they reach the log destination, which would make "
                "real attack traffic invisible here while the metrics still count it.")
    if not ja4s:
        return ("unknown, no JA4 data",
                "JA4 fingerprints are absent from these records, so the bot-versus-probing "
                "distinction cannot be made. API Gateway and AppSync upstreams do not send JA4 at "
                "all; on CloudFront or ALB it means the field was not populated. Judge from the "
                "URI and User-Agent evidence above instead, and say which you used.")
    if ips >= 5 and len(ja4s) == 1:
        return ("distributed bot attack, many source IPs sharing one TLS fingerprint",
                "One client stack behind many addresses. Bot Control targeted mitigation or a "
                "rate-based rule keyed on the fingerprint fits this better than blocking IPs, "
                "which will not keep up.")
    if ips <= 3:
        return ("concentrated attack, few sources at high volume",
                "Few enough to name. An IP set block or a rate-based rule on those addresses is "
                "proportionate; confirm they are not a shared NAT egress first, which the source "
                "profile above covers.")
    return ("distributed probing, diverse sources and diverse fingerprints",
            "This is the shape of untargeted scanning, and your existing rules are matching it. "
            "No new rule is indicated; keep monitoring and revisit if the volume trend rises.")


@tool
def investigate_injection(start_time: str, duration_minutes: int = 60,
                          rule_name: str = "") -> str:
    """Investigate SQL-injection / XSS / LFI attack activity. Runs the whole method in one call.

    Use this for "blocked SQLi", "injection attempts", "what attacks were blocked", or a BLOCK
    spike you suspect is an attack. It runs the full sequence in code, so the source-IP profiling
    step cannot be skipped, and it returns a classification and a recommendation rather than raw
    tables to interpret.

    Args:
        start_time: Start of the window, e.g. "2026-05-09T14:00". REQUIRED — ask the user.
        duration_minutes: Window length (default 60, max 360). Keep it tight: this issues several
            aggregations plus a source profile, so a wide window is slow and, on Athena, costly.
        rule_name: Optional. Focus one injection rule; otherwise the top blocking one is chosen
            from the WebACL's injection rules.

    Returns:
        The attack's target paths, source IPs, user agents and fingerprints, a profile of the top
        source, and a classification with a recommendation. Never a claim that an exploit
        succeeded: WAF logs cannot show that.
    """
    from tools.waf_aggregate import aggregate_logs
    from tools.waf_query import check_coarse_partition_block, checked_rule_name

    if not get_webacl_name():
        return ("Error: No WebACL selected. Call get_waf_config(webacl_name='...') first, "
                "or call list_webacls() to see available WebACLs.")
    if not start_time:
        return ("Error: start_time is required. Ask the user which time period to investigate.\n"
                "Example: investigate_injection(start_time=\"2026-05-09T14:00\", "
                "duration_minutes=60)")
    if rule_name:
        rule_name, bad = checked_rule_name(rule_name)
        if bad:
            return bad
    coarse = check_coarse_partition_block()
    if coarse:
        return coarse

    duration = min(duration_minutes, MAX_MINUTES)
    note_window_capped(duration_minutes, duration)
    scope = get_scope() or "CLOUDFRONT"
    lines = [f"## Injection Investigation: {get_webacl_name()}", "",
             f"Window: {start_time} + {duration} min", ""]

    # Step 1. Which rules do injection detection, read off the WebACL rather than guessed.
    # Held beyond the `try` because the metric cross-check below re-checks a rule name against it
    # at the line that issues the query, rather than trusting that the name came from here.
    injection, unknown, acl_rules, acl_error = [], [], [], None
    try:
        waf = get_client("wafv2", region_name=resolve_region(scope))
        acls = waf.list_web_acls(Scope=scope).get("WebACLs", [])
        match = next((a for a in acls if a["Name"].lower() == get_webacl_name().lower()), None)
        if match:
            acl = waf.get_web_acl(Name=get_webacl_name(), Scope=scope, Id=match["Id"])["WebACL"]
            acl_rules = acl.get("Rules", [])
            injection, unknown = _injection_rules(acl_rules)
    except Exception as exc:
        acl_error = f"{type(exc).__name__}: {exc}"
        lines.append(f"Could not read the WebACL's rules ({acl_error}), so the "
                     f"rule list below is whatever the logs show rather than the configured set.")
    count_mode = _count_mode(acl_rules)

    if rule_name:
        targets = [rule_name]
    elif injection:
        targets = injection
    elif acl_error:
        # Not "no injection rules": the read that would have said so did not happen. That message
        # calls the absence a finding, which is exactly wrong for a failed API call.
        lines.append("**Whether this WebACL has any injection-detection rule is unknown**, because "
                     "reading its rules failed. Re-run once get_web_acl succeeds, or pass rule_name "
                     "to investigate a rule you already know.")
        lines.append(f"\n{CONFIDENCE}")
        return "\n".join(lines)
    else:
        lines.append("**No injection-detection rule found in this WebACL.** Nothing here matches "
                     "a SQLi or XSS statement, and no AWS managed rule group that covers "
                     "injection is attached. So there is no injection coverage to investigate, "
                     "which is itself the finding: an attack would not be blocked and would not "
                     "appear in these logs as a match.")
        if unknown:
            lines.append(f"\nNot inspected, and any of these could contain injection rules: "
                         f"{', '.join(unknown)}. Ask the user what they do.")
        lines.append(f"\n{CONFIDENCE}")
        return "\n".join(lines)

    # By group, since a group contributes up to thirteen sub-rules and each is a name a user never set.
    groups = _sub_rule_groups(acl_rules)
    per_group = {}
    for t in targets:
        if t in groups:
            per_group[groups[t]] = per_group.get(groups[t], 0) + 1
    own = [t for t in targets if t not in groups]
    lines.append("Injection rules configured: " + ", ".join(
        own + [f"{n} injection sub-rules of {g}" for g, n in per_group.items()]))
    if unknown:
        lines.append(f"Not inspected: {', '.join(unknown)}")
    lines.append("")

    def _agg(**kw) -> str:
        """Every data step goes through the primitive, so redaction, partition pruning, the window
        cap and WebACL scoping stay intact rather than being re-implemented here."""
        return aggregate_logs._tool_func(start_time=start_time, duration_minutes=duration, **kw)

    # **Which injection rule to focus, ranked by what it matched, whatever the action.** Config
    # order was the first version and picked a rule that had matched nothing. BLOCK-only was the
    # second: it ranked the terminating rule, and a Count-mode detector ends as ALLOW under its
    # sub-rule's name, so the shadow-mode detectors step 1 keeps on purpose could never be the
    # focus. Counted through the rule filter's predicates, which reach a sub-rule counted inside a
    # managed group, in one query per engine: managed sub-rules are forty-odd names.
    if not rule_name:
        from tools.waf_aggregate import rule_match_counts
        counts, reason = rule_match_counts(targets, start_time, duration)
        if counts is None:
            lines.append(f"Nothing can be concluded about injection activity in this window: the query "
                         f"counting the detectors' matches did not answer ({reason}). Re-run once it "
                         f"does. Do NOT report this window as quiet.")
            lines += ["", CONFIDENCE]
            return "\n".join(lines)
        ranked = sorted(((t, m, b) for t, (m, b) in counts.items() if m), key=lambda t: t[1], reverse=True)
        if not ranked:
            # **Stopping here is the answer, not a failure to find one.** Investigating a rule with
            # no activity produces four empty sections and an assessment with nothing behind it,
            # which reads like a finished investigation.
            lines.append("**No injection rule matched anything in this window**, in Block or in "
                         "Count mode. Your injection rules are configured and matched no requests "
                         "here, so there is no attack activity to characterise.")
            lines += ["", "If you expected injection activity, widen the window or check whether a "
                          "Log Filter is dropping records before they reach the log destination."]
            # ROADMAP 7.1. This is the sentence the investigation got wrong on 2026-09-08: it said
            # zero SQLi hits on the strength of one log query, and a log query returning zero is
            # byte-identical to the attack not having happened. Metrics are the one witness immune
            # to the log side's failure modes, so before the claim goes out, ask them.
            #
            # **Per rule, never at the WebACL.** In that same window `shield-sample-webacl`'s
            # rate-limit rule blocked 566,070 requests while its SQLi series was empty, so a
            # WebACL-level comparison would fire here and be wrong. A check that is always on is
            # not a check.
            #
            # `acl_rules` comes from the `get_web_acl` above, in this function, and the helper
            # re-checks each name against it at the line that issues the query.
            import time
            from tools.waf_logs import _parse_start_time
            from tools.waf_metrics import missed_data_warning
            # Parsed here rather than passed in. An unparseable `start_time` makes every ranking
            # query an error, which stops above as unread rather than reaching this branch, so None
            # here would mean a parser the primitive disagrees with; the cross-check stands down.
            start_epoch = _parse_start_time(start_time)
            if start_epoch is not None:
                end_epoch = min(start_epoch + duration * 60, int(time.time()))
                # A managed sub-rule's blocks are counted under its group's dimensions, not `Rule`.
                groups = _sub_rule_groups(acl_rules)
                for target in targets:
                    warning = missed_data_warning(
                        get_webacl_name(), target, acl_rules, start_epoch, end_epoch, log_rows=0,
                        metric_name="CountedRequests" if target in count_mode else "BlockedRequests",
                        group="" if target in count_mode else groups.get(target, ""))
                    if warning:
                        lines.append(warning)
            lines += ["", CONFIDENCE]
            return "\n".join(lines)
        # Busiest first, by matches, read from the counts rather than any table's row order.
        targets = [name for name, _, _ in ranked]
        if len(ranked) > 1:
            others = ", ".join(f"{n} ({t:,})" for n, t, _ in ranked[1:])
            lines.append(f"Focusing **{ranked[0][0]}**, the busiest injection detector in this "
                         f"window ({ranked[0][1]:,} matches, {ranked[0][2]:,} blocked). Also "
                         f"matching: {others}. Re-run with rule_name set to look at one of those "
                         f"instead; the sections below cover the focus rule only.")
        else:
            lines.append(f"Focus rule: **{ranked[0][0]}** ({ranked[0][1]:,} matches, "
                         f"{ranked[0][2]:,} blocked).")
        lines.append("")

    # Steps 2-4. The rule filter reaches all six places a match is recorded, so a sub-rule
    # counted inside a managed group is found too. Every match, not only blocks: a Count-mode
    # focus ends as ALLOW, and a BLOCK filter here emptied all four sections for it.
    focus = targets[0]
    if focus in count_mode:
        lines += [f"**{focus} is in Count mode**, so the requests below matched it and were "
                  f"allowed through. That is the shadow-mode evidence for whether to switch it to "
                  f"Block.", ""]
    matched = json.dumps({"rule": focus})
    # Held in variables rather than read back out of `lines` by index. The first version did
    # `lines[lines.index("### Source IPs") + 1]`, which couples the data flow to the rendering: a
    # reordered section or a duplicated heading silently reads the wrong table.
    paths = _agg(group_by="uri", filter_by=matched)
    sources = _agg(group_by="clientIp", filter_by=matched)
    agents = _agg(group_by="ua", filter_by=matched)
    prints = _agg(group_by="ja4", filter_by=matched)
    lines += ["### Target paths", paths, "", "### Source IPs", sources, "",
              "### User agents", agents, "", "### TLS fingerprints", prints, ""]

    # Step 5. The step a prompt-driven sequence drops, and the reason this is a tool. `analyze_ip`
    # is called rather than reimplemented, so the NAT check, the labels and the JA4 lookup are the
    # same ones a direct call would give.
    ips = _extract_column(sources, "httpRequest.clientIp")
    ja4s = _extract_column(prints, "ja4Fingerprint")
    # A failed query and an empty one both extract to []. Only the empty one is evidence.
    unread_steps = {name: why for name, table in (("source IPs", sources), ("TLS fingerprints", prints))
                    for pairs, why in [_outcome(table)] if pairs is None}
    if ips:
        from tools.waf_logs import analyze_ip
        lines += [f"### Source profile: {ips[0]}",
                  "Run in code rather than suggested, so it cannot be skipped.", "",
                  analyze_ip._tool_func(ips[0], start_time, duration), ""]
    else:
        lines += ["### Source profile",
                  "Skipped: no source IP was found, so there is nothing to profile. That also "
                  "means the classification below has no IP evidence behind it.", ""]

    # Step 6. The matrix, in code.
    classification, recommendation = _classify(ips, ja4s)
    if unread_steps:
        classification = ("unknown, the " + " and ".join(unread_steps) + " query did not answer ("
                          + "; ".join(unread_steps.values()) + ")")
        recommendation = "Re-run once the query succeeds; nothing here says the pattern is absent."
    lines += ["### Assessment",
              f"Pattern: {classification}",
              f"Recommendation: {recommendation}", "",
              f"Distinct source IPs seen: {len(ips)}. Distinct fingerprints: "
              f"{len({j for j in ja4s if j})}.", "",
              CONFIDENCE, "",
              f"Next: call record_finding(title='Injection activity on {focus}', "
              f"severity='medium', detail='...') to keep this in the report."]
    return "\n".join(lines)


def _extract_pairs(table: str, column: str) -> list:
    """`[(value, hits)]` from an `aggregate_logs` count table, so the caller can rank locally.

    A row whose count will not parse is kept with a count of 0 rather than dropped: losing a rule
    that genuinely blocked would put it out of the running silently, which is worse than ranking it
    last."""
    out = []
    for value, hits in zip(_extract_column(table, column), _extract_column(table, "hits")):
        try:
            out.append((value, int(hits)))
        except (TypeError, ValueError):
            out.append((value, 0))
    return out


def _extract_column(table: str, column: str) -> list:
    """Values of one column from an `aggregate_logs` markdown table, in row order.

    Reading the rendered table back is not the tidy way to pass data between steps, and it is the
    honest one here: the alternative is a second code path that queries without the primitive's
    redaction and window handling. Returns `[]` for a refusal or a zero-result message, both of
    which lack a header row, so a failed step degrades the classification rather than crashing it.
    """
    rows = [r for r in table.splitlines() if r.startswith("|")]
    if len(rows) < 3:
        return []
    header = [c.strip() for c in rows[0].strip("|").split("|")]
    if column not in header:
        return []
    idx = header.index(column)
    out = []
    for row in rows[2:]:
        cells = [c.strip() for c in row.strip("|").split("|")]
        if len(cells) > idx and cells[idx]:
            out.append(cells[idx])
    return out
