# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Whether a request was counted by some rule, in the two query dialects, from one place.

**A counted request never carries `action = 'COUNT'`.** The top-level `action` is the
terminating action, so it is ALLOW, BLOCK, CHALLENGE or CAPTCHA: measured 2026-10-15 on
`response-id-on-page`, a full day held ALLOW 45196 and BLOCK 132 and nothing else. The
Count lives in a rule entry, and for a managed rule group it is NESTED. The same day had
**0** requests with a COUNT in the top-level `nonterminatingmatchingrules` and **1792** in
`rulegrouplist[].nonterminatingmatchingrules`, which is where a `RuleActionOverrides` Count
lands. On CloudWatch, `shield-sample-webacl` over 24 hours: 2 records matched
`nonTerminatingMatchingRules.0.action = 'COUNT'` and 515 matched `"action":"COUNT"`
anywhere, 513 of them only nested.

So `top_counted_ips`, `top_counted_countries` and `aggregate_logs(filter_by={"action":
"COUNT"})` all answered from the top level and came back empty, or close to it, for the
most common Count there is: a managed sub-rule left in Count while it is evaluated.

**On CloudWatch the substring is safe for the same reason `waf_aggregate._RULE_CWL` is.** A
client cannot produce `"action":"COUNT"` with bare quotes, because a quote inside a JSON
string value is escaped; and the only keys spelled `action` sit in rule entries or at the
top level, where COUNT never appears.

`EXCLUDED_AS_COUNT` is the legacy `ExcludedRules` mechanism and also means "matched, and
counted instead of acting". On Athena `excludedrules` is a string column holding the raw
JSON text with lowercased keys, which is why the search spells `exclusiontype` (see
`waf_aggregate._RULE_ATHENA`). No record on this account has one, so that branch is
exercised by construction only.

**Not covered, and the old predicates did not cover it either:** a whole rule group set to
`OverrideAction: Count`. Neither test WebACL has one, so where its sub-rule is recorded was
not measured, and guessing a shape would write an unmeasured claim into a query.
"""

EXCLUDED_ATHENA = ("any_match(rulegrouplist, rg -> strpos(rg.excludedrules,"
                   " '\"exclusiontype\":\"EXCLUDED_AS_COUNT\"') > 0)")
EXCLUDED_CWL = "@message like '\"exclusionType\":\"EXCLUDED_AS_COUNT\"'"

COUNTED_ATHENA = (
    "(any_match(nonterminatingmatchingrules, r -> r.action = 'COUNT')"
    " OR any_match(rulegrouplist, rg -> any_match(rg.nonterminatingmatchingrules,"
    " r -> r.action = 'COUNT'))"
    f" OR {EXCLUDED_ATHENA})"
)
COUNTED_CWL = f"(@message like '\"action\":\"COUNT\"' or {EXCLUDED_CWL})"
