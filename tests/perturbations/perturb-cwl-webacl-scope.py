#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Unscope a CloudWatch Logs query and require `test_cwl_webacl_scope.py` to notice.

The first three cases are the state this project shipped in until 2026-09-15, one per executor: no
CloudWatch Logs query anywhere carried a WebACL filter, and the demonstrated consequence was a table of
another WebACL's blocked IPs signed with the session's WebACL.

The rest are the ways a fix can look present and not hold: a filter that matches a name as a substring
rather than as a path segment, a refusal downgraded to a silent pass-through, and patrol or the report
reading session state instead of the WebACL they were asked about, which is the mistake the whole 7.11
finding was about.
"""

import sys

from _harness import sweep

T = "tests/test_cwl_webacl_scope.py"
Q = "tools/waf_query.py"
P = "tools/waf_patrol.py"
R = "tools/report.py"

CASES = [
    # The shipped state, one per executor.
    ("the log-tool path unscoped again, which is what returned another WebACL's IPs",
     [(Q, "    query = scope_cwl_query(query, get_webacl_name())\n    region = get_logs_region()",
       "    region = get_logs_region()")],
     [f"{T}::test_a_log_query_is_scoped_to_the_session_webacl",
      f"{T}::test_each_scoped_site_reaches_the_shared_builder"], True),

    ("patrol's detail queries unscoped",
     [(P, "    query = scope_cwl_query(query, webacl_name)\n    try:", "    try:")],
     [f"{T}::test_patrol_scopes_to_the_webacl_it_was_asked_about_not_the_session_one",
      f"{T}::test_each_scoped_site_reaches_the_shared_builder"], True),

    ("the report's Anti-DDoS queries unscoped",
     [(R, "    query = scope_cwl_query(query, webacl_name)\n"
          "    resp = logs_client.start_query(", "    resp = logs_client.start_query(")],
     [f"{T}::test_the_report_scopes_the_same_way",
      f"{T}::test_each_scoped_site_reaches_the_shared_builder"], True),

    # A filter that reads like a fix and matches the wrong records. `test2` is a substring of
    # `test2-staging`, and without the slashes the name matches anywhere in the ARN.
    ("the slashes dropped, so the name matches as a substring instead of a path segment",
     [(Q, """    return f"filter webaclId like '/{webacl_name}/' | {query.strip()}\"""",
       """    return f"filter webaclId like '{webacl_name}' | {query.strip()}\"""")],
     [f"{T}::test_the_filter_names_the_webacl_as_a_path_segment"], True),

    # The degraded mode that is the defect.
    ("the refusal downgraded to a pass-through, so a missing name queries the whole group",
     [(Q, "    if not webacl_name or not _WEBACL_NAME.fullmatch(webacl_name):\n        raise RuntimeError(",
       "    if False:\n        raise RuntimeError(")],
     [f"{T}::test_a_missing_or_malformed_name_refuses_instead_of_querying_unscoped"], True),

    ("the charset guard dropped, so a quoted name rewrites the query",
     [(Q, "    if not webacl_name or not _WEBACL_NAME.fullmatch(webacl_name):",
       "    if not webacl_name:")],
     [f"{T}::test_a_missing_or_malformed_name_refuses_instead_of_querying_unscoped"], True),

    # Reading session state where the tool has its own name. This is 7.11's defect, moved one layer in.
    ("patrol scoping to the session WebACL rather than the one it was asked about",
     [(P, "    query = scope_cwl_query(query, webacl_name)",
       "    from tools.session_state import get_webacl_name as _gwn\n"
       "    query = scope_cwl_query(query, _gwn())")],
     [f"{T}::test_patrol_scopes_to_the_webacl_it_was_asked_about_not_the_session_one"], True),

    ("the report scoping to the session WebACL rather than the one it reports on",
     [(R, "    query = scope_cwl_query(query, webacl_name)",
       "    from tools.session_state import get_webacl_name as _gwn\n"
       "    query = scope_cwl_query(query, _gwn())")],
     [f"{T}::test_the_report_scopes_the_same_way"], True),

    # The inventory, and the dead site. No probe: both targets read source.
    ("a fourth query site added without being declared",
     [(Q, "def _run_cwl(log_group: str, query: str",
       "def _run_extra_cwl(log_group, query, start_epoch, end_epoch, limit):\n"
       "    client = get_client('logs')\n"
       "    return client.start_query(logGroupName=log_group, queryString=query,\n"
       "                              startTime=start_epoch, endTime=end_epoch, limit=limit)\n\n\n"
       "def _run_cwl(log_group: str, query: str")],
     [f"{T}::test_every_cloudwatch_logs_query_site_is_accounted_for"], False),

    ("the dead executor given a caller, so an unscoped query becomes reachable",
     [("tools/waf_logs.py", "def _execute_query_internal(client, log_group: str",
       "def _unused_caller(client, lg, s, e, q):\n"
       "    return _execute_query_internal(client, lg, s, e, q)\n\n\n"
       "def _execute_query_internal(client, log_group: str")],
     [f"{T}::test_the_dead_query_site_still_has_no_callers"], False),
]

sys.exit(sweep(CASES))
