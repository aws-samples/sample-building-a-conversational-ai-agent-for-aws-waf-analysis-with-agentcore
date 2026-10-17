# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Escaping for the HTML reports, so that a string reaches a page as text and never as markup."""

import html
import json


def escaped(value):
    """`value` with every string in it, dict keys included, escaped for HTML text and attributes.

    A backslash too, since the patrol report puts some of these inside JavaScript string literals,
    where a trailing one would swallow the closing quote. Applied to a renderer's whole input at
    its entry, so a field added later is escaped without anyone remembering to."""
    if isinstance(value, str):
        return html.escape(value).replace("\\", "&#92;")
    if isinstance(value, dict):
        return {escaped(k): escaped(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(escaped(v) for v in value)
    return value


def script_json(value) -> str:
    """JSON to put inside a `<script>` element. `json.dumps` leaves `<` alone, so a string holding
    `</script>` would close the element; these three become JSON escapes, which read back the same."""
    return (json.dumps(value, default=str)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))
