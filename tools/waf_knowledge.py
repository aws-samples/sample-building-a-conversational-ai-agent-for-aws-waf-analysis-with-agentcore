# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AWS WAF knowledge base retrieval tool."""

import os
from strands import tool
from tools.aws_session import get_client

KNOWLEDGE_BASE_ID = os.environ.get("KNOWLEDGE_BASE_ID", "")


@tool
def search_waf_knowledge(query: str) -> str:
    """Search AWS WAF best practices knowledge base for guidance on configuration,
    optimization, and security patterns.

    Use this for general WAF questions during conversation (e.g., "What's the best
    practice for rate-based rules?", "How should I configure Bot Control for a
    native app?").

    Do NOT use during review_waf_rules_deep workflow — reference documents are
    already provided in that tool's output.

    Args:
        query: The question or topic to search for.
    """
    if not KNOWLEDGE_BASE_ID:
        return "Knowledge base not configured."

    bedrock_rt = get_client("bedrock-agent-runtime")
    resp = bedrock_rt.retrieve(
        knowledgeBaseId=KNOWLEDGE_BASE_ID,
        retrievalQuery={"text": query},
        retrievalConfiguration={
            "vectorSearchConfiguration": {"numberOfResults": 5}
        },
    )

    results = resp.get("retrievalResults", [])
    if not results:
        return "No relevant AWS WAF documentation found for this query."

    formatted = []
    for i, r in enumerate(results, 1):
        text = r["content"]["text"]
        score = r.get("score", 0)
        formatted.append(f"[{i}] (relevance: {score:.2f})\n{text}")

    return "\n\n---\n\n".join(formatted)
