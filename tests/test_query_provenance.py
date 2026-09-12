# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A log query answers from the session's WebACL, never from the one the question named.

`run_logs_query` reads the logging destination out of session state, set by the last
`get_waf_config` call. Nothing connects it to the WebACL the user asked about. So a question about
WebACL A is answered from WebACL B's logs whenever the context holds B, with no error.

**Measured on a real investigation, 2026-09-12.** The maintainer asked about a WebACL logging to
CloudWatch Logs (`aws-waf-logs-group`) while the session context held one logging to Firehose. The
runtime log records `dest=arn:aws:firehose:...:deliverystream/aws-waf-logs-kinesis-s3`. The answer was
"Query returned 0 results" followed by three candidate causes: wrong action filter, wrong time window,
no matching traffic. None of them was it.

**Zero rows was luck, and that is why the provenance line goes on the success path too.** Had the
other WebACL held matching traffic in that window, rows would have come back, been read as the answer,
and the zero-result branch that carries these hints would never have executed. The dangerous outcome
is rows, so a check that only covers the empty answer covers the safe half.
"""

import pathlib
import re

from tools import session_state, waf_logs

SOURCE = pathlib.Path(waf_logs.__file__).read_text()

FIREHOSE = "arn:aws:firehose:us-east-1:111122223333:deliverystream/aws-waf-logs-kinesis-s3"
LOG_GROUP_DEST = "arn:aws:logs:us-east-1:111122223333:log-group:aws-waf-logs-group"


def _context(name, dest):
    session_state.set_webacl_context(name, f"arn:aws:wafv2:::webacl/{name}/x", "CLOUDFRONT",
                                     "us-east-1", log_destination=dest)


def test_the_provenance_names_the_webacl_and_the_engine():
    """Both halves of what went wrong: which WebACL, and which engine that implies. Asserted for both
    destination kinds, because the engine is derived from the destination and a question about a
    CloudWatch WebACL answered through Athena is exactly the observed failure."""
    _context("shield-sample-webacl", LOG_GROUP_DEST)
    cwl = waf_logs._provenance()
    assert "shield-sample-webacl" in cwl and "CloudWatch Logs" in cwl, cwl

    _context("some-other-webacl", FIREHOSE)
    athena = waf_logs._provenance()
    assert "some-other-webacl" in athena and "Athena" in athena, athena
    assert cwl != athena, "the line does not change with the context, so it carries no information"


def test_it_says_when_the_session_context_was_bypassed():
    """An explicit `log_group` forces the CloudWatch path and skips session state entirely, so
    claiming the session's WebACL there would be a lie in the other direction."""
    _context("some-other-webacl", FIREHOSE)
    explicit = waf_logs._provenance("aws-waf-logs-group")
    assert "aws-waf-logs-group" in explicit
    assert "some-other-webacl" not in explicit, "named a WebACL that had nothing to do with the query"


def test_an_unset_context_says_so_rather_than_looking_confident():
    """The empty case has to read as empty. `None` or a blank name would render as a sentence that
    looks like it names something."""
    session_state.set_webacl_context("", "", "CLOUDFRONT", "us-east-1", log_destination=None)
    text = waf_logs._provenance()
    assert "(none set)" in text and "no destination" in text, text


def test_both_result_paths_carry_it():
    """**The load-bearing assertion, and it is structural because the alternative covers half.** The
    zero-result path is easy to test behaviourally and is the safe half; the path that matters is the
    one that returns rows, and reaching that in a unit test would mean standing up a fake CloudWatch
    Insights or Athena. So this asserts the call sites instead.

    Anchored on the two lines that build each answer, so moving either one fails here rather than
    silently dropping the line from one path."""
    zero = SOURCE.index('msg = f"Query returned 0 results.')
    rows = SOURCE.index('f"Query \'{query_type}\' returned {len(results)} results')
    for label, start in (("zero-results", zero), ("results", rows)):
        window = SOURCE[start:start + 1800]
        assert "_provenance(" in window, (
            f"the {label} path no longer states which WebACL it answered from. A wrong-WebACL answer "
            f"is indistinguishable from a right one without it.")


def test_the_zero_result_hints_do_not_claim_to_be_exhaustive():
    """The three causes offered on an empty answer are guesses, and on 2026-09-12 the real cause was
    none of them. They are worth keeping, so this only pins that the provenance line is emitted
    alongside them rather than the hints being the whole story."""
    hints = re.search(r"Possible reasons:.*", SOURCE)
    assert hints, "the hint list moved; retarget this test"
    following = SOURCE[hints.end():hints.end() + 700]
    assert "_provenance(" in following, (
        "the hints are printed without saying what was queried, which is what sent a maintainer "
        "looking at action filters and time windows for a wrong-WebACL answer")


def test_the_prompt_tells_the_model_to_read_the_source_line():
    """**The two halves are bound here on purpose.** The tool discloses which WebACL it used; only the
    model can tell whether that is the one the user asked about, because the tool never receives the
    question. So the disclosure is worthless without an instruction that consumes it, and an
    instruction is worthless if the disclosure gets renamed. Asserted from both sides so neither can
    drift alone.

    The prompt bullet this replaces read "After WebACL is selected: ALWAYS call get_waf_config",
    which is satisfied once and stays satisfied. Nothing covered a user naming a different WebACL
    halfway through a conversation, which is exactly what happened."""
    prompt = pathlib.Path(waf_logs.__file__).parents[1].joinpath("agent.py").read_text()
    # Cut the prompt out of the file so a mention of SOURCE in unrelated Python cannot satisfy this.
    start = prompt.index("## Behavior")
    behaviour = prompt[start:prompt.index("\n## ", start + 10)]
    assert "SOURCE:" in behaviour, (
        "the prompt does not mention the SOURCE line, so nothing instructs the model to compare the "
        "WebACL a result came from against the one the user asked about")
    assert "not a one-time setup step" in behaviour, (
        "the instruction to re-call get_waf_config mid-conversation is gone; the original wording was "
        "satisfiable once and that is how a question about one WebACL got answered from another")
    assert "SOURCE:" in waf_logs._provenance(), "the emitter no longer produces the marker"
