# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Shared AWS session and credential management."""

import boto3
from datetime import timezone
from functools import lru_cache


@lru_cache(maxsize=4)
def get_session(profile_name: str | None = None, region_name: str | None = None) -> boto3.Session:
    """Get or create a cached boto3 session."""
    return boto3.Session(profile_name=profile_name, region_name=region_name)


def _epoch(dt) -> int:
    """`dt` as a Unix timestamp, reading a naive one as UTC because that is what AWS will read.

    **`datetime.timestamp()` interprets a naive datetime in the machine's local zone, and botocore
    serialises the same value with no offset, which AWS reads as UTC.** So without this the record and
    the request describe windows that differ by the local offset: measured on a `TZ=Asia/Shanghai`
    machine, `StartTime=datetime(2026, 5, 8)` recorded 2026-05-07T16:00Z while AWS received
    2026-05-08T00:00Z, eight hours apart. The chip would then show a window no query used, which is the
    0.24.0 defect appearing inside the mechanism built to expose it.

    No call site passes a naive datetime today, all 30 traced. **This exists because the funnel's claim
    is that it covers the call site written next year**, and that claim makes the funnel responsible for
    what such a call site hands it rather than leaving each one to remember a timezone.
    """
    return int((dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt).timestamp())


class _RecordingCloudWatch:
    """A CloudWatch client that records the window of every metric read that goes through it.

    **The funnel is the client rather than a wrapper function, and that is the difference between
    covering the next call site and not.** `get_metric_data` is called at 30 sites across five files:
    3 in `waf_metrics`, 7 in `waf_overview`, 7 in `waf_patrol`, 12 in `report` and 1 in `waf_bypass`.
    The census that planned this change said 29 in four files and missed `waf_bypass.py:304`, which is
    exactly the failure a structural test over call sites would then have had to catch. Here a new call
    site is covered by construction, so there is nothing to remember and no inventory to keep.

    Everything except the metric read delegates untouched. botocore's generated methods accept keyword
    arguments only, so no caller can pass the window positionally and slip past the record.

    A call missing `StartTime` or `EndTime` records nothing and is then refused by botocore's own
    parameter validation, so nothing proceeds unrecorded. Raising a `KeyError` here instead would
    replace a clear API error with an obscure one from the wrong layer.
    """

    def __init__(self, client):
        self._client = client

    def __getattr__(self, name):
        return getattr(self._client, name)

    def get_metric_data(self, **kwargs):
        start, end = kwargs.get("StartTime"), kwargs.get("EndTime")
        if start is not None and end is not None:
            from tools.session_state import note_query_provenance
            note_query_provenance("CloudWatch metrics", _epoch(start), _epoch(end))
        return self._client.get_metric_data(**kwargs)


def get_client(service: str, profile_name: str | None = None, region_name: str | None = None):
    """Get a boto3 client for the given service.

    The single place a client is built in this repository, `session.client` appearing nowhere else, so
    wrapping CloudWatch here reaches every metric read including the ones nobody has written yet.
    """
    session = get_session(profile_name=profile_name, region_name=region_name)
    client = session.client(service, region_name=region_name)
    return _RecordingCloudWatch(client) if service == "cloudwatch" else client
