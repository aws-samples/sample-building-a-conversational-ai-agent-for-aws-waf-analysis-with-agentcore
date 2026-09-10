# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Per-test isolation for the two module-level caches the tools share.

Both are process-global dicts, so without this a test inherits whatever its predecessor
left behind. That produced a real defect:
`test_the_timeout_message_carries_the_granularity_advice` passed alone and failed in the
suite, because `poll_timeout_message` only offers narrowing advice on the FIRST consecutive
timeout and an earlier test had already incremented the counter in `session_state`.

**The mirror is worse and the same run cannot see it.** A test that passes in the suite and
would fail alone is borrowing state from a predecessor, and a fixed collection order hides
that permanently. So this exists to close the class rather than that one instance, which is
why it is here even though only one test currently needs it.

**Setup only, and that is measured rather than assumed.** Clearing on teardown as well was
the first version; removing the teardown half left the suite green, so it was protecting
nothing. Clearing *before* each test is the half that does the work, and it is also the half
that covers state established at import or collection time, which a teardown hook cannot
reach. Removing both halves turns the suite red, which is what says this fixture is
load-bearing at all.
"""
import pytest


@pytest.fixture(autouse=True)
def _isolate_module_state():
    from tools import session_state
    from tools import waf_athena
    session_state._state.clear()
    waf_athena.reset_table_cache()
    yield
