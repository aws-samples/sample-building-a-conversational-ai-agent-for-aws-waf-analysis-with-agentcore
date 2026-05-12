# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Shared utilities for WAF review scripts."""
import sys


def fatal(msg: str):
    """Print FATAL result block and exit with code 2."""
    print(msg, file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: FATAL")
    print("ACTION: FIX")
    print(f"CONTEXT: {msg}")
    sys.exit(2)
