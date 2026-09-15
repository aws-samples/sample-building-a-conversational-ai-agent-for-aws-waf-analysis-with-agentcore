# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The weekly report's Anti-DDoS section vanished without saying why, in two of its four states.

The section is built from three CloudWatch Logs Insights queries gated on
`caps["anti_ddos_amr"] and log_group`. `report.py`'s `empty` list tests three other sections for
emptiness and not this one, so the only route into `missing` was an exception. That left two silences:
the rule group declared no event, and the WebACL logs somewhere these queries cannot read.

**Measured 2026-09-15 on the deployment account.** In the week containing a 566,070-request burst, all
three queries returned zero rows: the rule group applied `challengeable-request` to 919,476 requests and
never emitted `event-detected` or `ddos-request`. The section was absent from the report and nothing said
anything about it. Full measurements in `design/audit-patrol-report-queries.md`.

Pulled out of ROADMAP 7.12's optimisation pass on the reviewer's argument that it does not belong there:
the pass waits on traffic this account has never produced, and this fix gives the section the treatment
the other three already have.
"""

from tools.report import _antiddos_skip

GROUP = "aws-waf-logs-group"


def test_no_event_says_so_rather_than_disappearing():
    """The state measured on the account. Zero events is a statement about the traffic, and the section
    being absent looks identical to the section having failed."""
    why = _antiddos_skip(has_amr=True, log_group=GROUP, num_events=0)
    assert why and "did not declare an event" in why, why
    assert "nothing to report rather than something missing" in why, (
        "the reason has to separate the two readings a reader would otherwise pick between")


def test_a_backend_these_queries_cannot_read_gets_a_different_reason():
    """**A different sentence, not a shared one.** On S3 or Firehose the branch never runs, so "no event"
    would be a claim about traffic nobody looked at. The report's own `ACTION:` line forbids one shared
    explanation across sections, and it applies inside a section too."""
    why = _antiddos_skip(has_amr=True, log_group=None, num_events=0)
    assert why and ("S3 or Firehose" in why and "could not run" in why), why
    assert "did not declare an event" not in why, (
        "the backend case must not claim the rule group was quiet; nothing queried it")


def test_the_two_reasons_are_not_the_same_sentence():
    """Pinned directly, because the cheap way to satisfy both tests above is one sentence mentioning
    both causes, which is the shape `test_no_two_reasons_are_the_same_sentence` already forbids for
    patrol."""
    a = _antiddos_skip(has_amr=True, log_group=GROUP, num_events=0)
    b = _antiddos_skip(has_amr=True, log_group=None, num_events=0)
    assert a != b and a and b


def test_a_webacl_without_the_rule_group_stays_silent():
    """The one absence that is not a gap. The other three sections are always applicable; this one
    describes a rule group the WebACL may not have, and reporting it missing sends a user looking for
    something that was never going to be there."""
    assert _antiddos_skip(has_amr=False, log_group=GROUP, num_events=0) is None
    assert _antiddos_skip(has_amr=False, log_group=None, num_events=0) is None


def test_a_section_that_rendered_says_nothing():
    """The control. A reason emitted alongside a rendered section would put the section in
    `MISSING_SECTIONS` while its cards are on the page."""
    assert _antiddos_skip(has_amr=True, log_group=GROUP, num_events=2) is None


def _call_site() -> str:
    """The block in `generate_weekly_report` that turns a reason into a `section_skips` entry."""
    import pathlib

    from tools import report

    src = pathlib.Path(report.__file__).read_text()
    key = '    if "anti_ddos_events" not in section_skips:'
    assert key in src, (
        "generate_weekly_report no longer asks _antiddos_skip for a reason, so every test above proves "
        "a function nothing calls and the section is silent again")
    block = src[src.index(key):]
    return block[:block.index("\n    # Bot Control")]


def test_the_reason_is_written_into_the_channel_that_reaches_the_report():
    """**The tests above all call `_antiddos_skip` directly, so none of them can see the call site
    disappear.** Measured: deleting the whole block leaves them green, which the perturbation reported as
    HOLLOW. `section_skips` is the only channel into `missing`, so the wiring is the property and the
    return values are worth nothing without it.

    Structural because reaching it needs the whole report, which needs fifteen metric reads."""
    block = _call_site()
    assert "_antiddos_skip(" in block, block
    assert 'section_skips["anti_ddos_events"] = why' in block, (
        f"the reason is computed and dropped rather than written into the channel: {block!r}")


def test_a_failure_keeps_its_own_reason():
    """The two `except` handlers write `section_skips["anti_ddos_events"]` with the engine error, and the
    new call is guarded on that key being absent. Without the guard a failed query would be relabelled
    "did not declare an event", which is the substitution this whole channel exists to prevent."""
    assert '"anti_ddos_events" not in section_skips' in _call_site(), (
        "the fallback reason is not guarded on the failure reason being absent, so a query failure would "
        "be reported as an idle rule group")
