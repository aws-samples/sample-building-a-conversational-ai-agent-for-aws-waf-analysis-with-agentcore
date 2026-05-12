# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Shared AWS session and credential management."""

import boto3
from functools import lru_cache


@lru_cache(maxsize=4)
def get_session(profile_name: str | None = None, region_name: str | None = None) -> boto3.Session:
    """Get or create a cached boto3 session."""
    return boto3.Session(profile_name=profile_name, region_name=region_name)


def get_client(service: str, profile_name: str | None = None, region_name: str | None = None):
    """Get a boto3 client for the given service."""
    session = get_session(profile_name=profile_name, region_name=region_name)
    return session.client(service, region_name=region_name)
