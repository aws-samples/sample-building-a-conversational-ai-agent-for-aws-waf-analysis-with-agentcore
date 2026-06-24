# Continuously monitoring a WAF rule's hit rate (block rate / false-positive rate)

This explains how to set up **ongoing** monitoring of how often a WAF rule fires, as a share of
total traffic — useful after you move a rule from Count to Block/Challenge/CAPTCHA and want to
catch a spike in false positives. These are steps **you** apply in your own account; the agent
shows you how, it does not create alarms for you.

## What "hit rate" means and why it's a ratio

A raw match count ("rule X fired 5,000 times") has no context — 5,000 out of 10,000 requests is
very different from 5,000 out of 50 million. The useful signal is the **ratio**:

```
rule hit rate = (requests this rule matched) / (total requests) over a window
```

AWS WAF has **no built-in "hit rate" metric** — you build it from the per-rule and per-WebACL
CloudWatch metrics with **metric math**. There is also no `TotalRequests` metric, so you build
the denominator yourself from the WebACL's **mutually-exclusive terminal outcomes** — each
evaluated request lands in exactly one of these (query with `WebACL=<name>` + `Rule=ALL`):

```
total = AllowedRequests + BlockedRequests + ChallengeRequests + CaptchaRequests
```

Two metrics that look like they belong but **must NOT be added** (they double-count):
- **`PassedRequests` is a per-rule-group metric, not a WebACL terminal outcome.** It counts
  requests that passed *through one rule group* without matching, and is only emitted on the
  `RuleGroup` dimension (and only to the rule-group owner). That same request is then allowed by
  the WebACL and already counted in `AllowedRequests`. At the WebACL `Rule=ALL` level
  `PassedRequests` reads 0 — adding it would double-count allowed traffic. (This is the WAF
  capability boundary to be clear about: WAF does not expose a WebACL-level "passed/bypassed"
  count — requests that no rule acted on simply show up as `AllowedRequests`.)
- **`CountedRequests`** is a non-terminal action: a counted request continues evaluation and
  ends up in `AllowedRequests`/`BlockedRequests` too. Including it double-counts. (It's still
  useful as a *numerator* for a Count rule — see the shadow-rule section — just not in the
  denominator.)

Include `ChallengeRequests` / `CaptchaRequests` only if the WebACL actually uses those actions.

## Rule-level hit rate — a CloudWatch metric-math alarm

CloudWatch **supports alarms on a metric-math expression** (a single derived time series), so
you can alarm directly on the ratio. AWS CLI:

The example below is for a **CloudFront-scope** WebACL. Its metric dimensions are
`WebACL` + `Rule` only — **no `Region` dimension** (and the metrics live in `us-east-1`). A
**REGIONAL** WebACL (ALB/API Gateway/AppSync) adds a `{"Name":"Region","Value":"<region>"}`
dimension to every metric below and the alarm is created in that region. Getting this wrong is
the most common mistake — a Region dimension on a CloudFront WebACL matches no datapoints and the
alarm sits in INSUFFICIENT_DATA forever.

```bash
aws cloudwatch put-metric-alarm \
  --region us-east-1 \
  --alarm-name "WAF-MyRule-HitRate" \
  --alarm-description "Fires when MyRule blocks more than 5% of total traffic" \
  --metrics '[
    {"Id":"blocked","MetricStat":{"Metric":{"Namespace":"AWS/WAFV2","MetricName":"BlockedRequests","Dimensions":[{"Name":"WebACL","Value":"MyWebACL"},{"Name":"Rule","Value":"MyRule"}]},"Period":300,"Stat":"Sum"},"ReturnData":false},
    {"Id":"allowed","MetricStat":{"Metric":{"Namespace":"AWS/WAFV2","MetricName":"AllowedRequests","Dimensions":[{"Name":"WebACL","Value":"MyWebACL"},{"Name":"Rule","Value":"ALL"}]},"Period":300,"Stat":"Sum"},"ReturnData":false},
    {"Id":"challenged","MetricStat":{"Metric":{"Namespace":"AWS/WAFV2","MetricName":"ChallengeRequests","Dimensions":[{"Name":"WebACL","Value":"MyWebACL"},{"Name":"Rule","Value":"ALL"}]},"Period":300,"Stat":"Sum"},"ReturnData":false},
    {"Id":"captcha","MetricStat":{"Metric":{"Namespace":"AWS/WAFV2","MetricName":"CaptchaRequests","Dimensions":[{"Name":"WebACL","Value":"MyWebACL"},{"Name":"Rule","Value":"ALL"}]},"Period":300,"Stat":"Sum"},"ReturnData":false},
    {"Id":"hit_rate","Expression":"blocked/(allowed+blocked+challenged+captcha)*100","Label":"Hit Rate %","ReturnData":true}
  ]' \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 3 \
  --datapoints-to-alarm 2 \
  --treat-missing-data notBreaching
```

Key points:
- The denominator metrics use `Rule=ALL` (WebACL totals); the numerator uses `Rule=MyRule`.
- Exactly one expression has `ReturnData: true` — that's the series the alarm evaluates.
- **M-of-N** (`evaluation-periods 3`, `datapoints-to-alarm 2`) avoids false alarms on a single
  spiky 5-minute period. Don't use 1-of-1 — WAF traffic is naturally bursty.
- **`treat-missing-data notBreaching`** — WAF only emits metrics for non-zero periods; a quiet
  window has no datapoint and would otherwise look like a breach.

## Per-endpoint (per-URI) hit rate — needs a metric filter first

AWS WAF CloudWatch metrics have **no URI dimension** (hard platform limit), so you cannot alarm
on a per-endpoint ratio directly from `AWS/WAFV2`. To monitor a specific endpoint, first emit a
custom metric from the WAF **log group** with a CloudWatch Logs **metric filter**, then alarm on
that.

```bash
# Custom metric: count requests to /api/login that MyRule BLOCKED.
# A blocking (terminating) rule writes its id to terminatingRuleId:
aws logs put-metric-filter \
  --log-group-name "aws-waf-logs-your-group" \
  --filter-name "login-blocked-by-myrule" \
  --filter-pattern '{ ($.httpRequest.uri = "/api/login") && ($.terminatingRuleId = "MyRule") }' \
  --metric-transformations \
      metricName=LoginBlockedByMyRule,metricNamespace=Custom/WAF,metricValue=1,defaultValue=0
```

**Important — Count rules use a different field.** A rule in **Count** mode does NOT set
`terminatingRuleId`; it appears in `nonTerminatingMatchingRules[].ruleId`. This matters because
the shadow-rule pattern below relies on a Count rule. For a Count rule, match on that field
instead:

```bash
# Count rule on /api/login (e.g. the shadow rule) — match nonTerminatingMatchingRules
aws logs put-metric-filter \
  --log-group-name "aws-waf-logs-your-group" \
  --filter-name "login-counted-by-myrule" \
  --filter-pattern '{ ($.httpRequest.uri = "/api/login") && ($.nonTerminatingMatchingRules[0].ruleId = "MyRule") }' \
  --metric-transformations \
      metricName=LoginCountedByMyRule,metricNamespace=Custom/WAF,metricValue=1,defaultValue=0
```

Add a companion filter for *total* `/api/login` requests (drop the rule clause entirely), then
build the same metric-math ratio alarm against the two `Custom/WAF` metrics. (S3/Athena users can
instead aggregate `httprequest.uri` historically — but for live alarms the CWL metric filter is
the path.)

## Watching a Count→Block transition for false positives

When you flip a rule to Block, a safe pattern is to **keep a shadow Count rule** with the same
conditions at a lower priority. Its `CountedRequests` is your "would-have-blocked" signal — a
live false-positive proxy you can alarm on the same way, without users actually being blocked
while you tune.

A dashboard widget with the same `blocked/(allowed+blocked+challenged+captcha)*100` expression
gives you the ratio over time at a glance, alongside `CountedRequests` from the shadow rule (the
shadow Count is the one place `CountedRequests` is the signal you want — as the numerator of a
"would-have-blocked" rate, not in the denominator).

## Notes

- Per-rule metrics require `VisibilityConfig.CloudWatchMetricsEnabled = true` on the rule —
  verify that's set, or per-rule dimensions won't exist.
- Count-action rules inside **third-party / AWS-managed** rule groups emit metrics with
  `Rule`/`RuleGroup`/`Region` dimensions but **not** the `WebACL` dimension — so they can't go
  into a WebACL-level denominator from metrics alone.
- All of the above is configuration **you** own and apply. The agent's role is to explain the
  pattern and hand you the commands; it does not create or modify alarms in your account.
