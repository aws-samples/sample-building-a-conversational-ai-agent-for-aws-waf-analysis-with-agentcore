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
        return ("No relevant AWS WAF documentation found for this query.\n"
                "HINT: The knowledge base returned nothing for this query. Tell the user you "
                "could not find documentation on it — do not answer from assumption as if it "
                "were documented best practice.")

    formatted = []
    for i, r in enumerate(results, 1):
        text = r["content"]["text"]
        score = r.get("score", 0)
        formatted.append(f"[{i}] (relevance: {score:.2f})\n{text}")

    top_score = max((r.get("score", 0) for r in results), default=0)
    hint = (
        "\n\n---\n\n"
        "HINT: These are retrieved documentation excerpts, not a finished answer. "
        "Synthesize across the relevant ones, cite them inline as [N], and base your "
        "guidance only on what they actually say. If none of them address the user's "
        "question, say so explicitly instead of inventing an answer — never present "
        "unsupported guidance as documented best practice."
    )
    if top_score < 0.4:
        hint += (
            "\n⚠️ Top relevance is low — these excerpts may not directly answer the "
            "question. Treat them as weak signal and tell the user if they don't fit."
        )

    return "\n\n---\n\n".join(formatted) + hint
