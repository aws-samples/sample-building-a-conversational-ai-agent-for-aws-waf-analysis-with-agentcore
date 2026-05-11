"""Ask user tool — Strands interrupt-based HITL."""

import sys
from strands import tool
from strands.types.tools import ToolContext


@tool(context=True)
def ask_user(tool_context: ToolContext, question: str, context: str = "") -> str:
    """Ask the user a clarifying question and wait for their response.

    This is FAST — the user is actively watching the chat and will respond immediately.
    Prefer asking over guessing. Wrong assumptions waste more time than a quick question.

    Use this when you need specific information to proceed:
    - Time range for investigation
    - Which domain/host is affected
    - Whether to continue analyzing more IPs/time ranges
    - SDK integration status, SPA architecture decisions

    You can ask multiple questions at once — users prefer answering everything in one reply.

    Args:
        question: The question to ask the user. Be specific and provide options when possible.
        context: Brief context for why you're asking (helps user give better answers).

    Returns:
        The user's response.
    """
    if sys.stdin and sys.stdin.isatty():
        # CLI mode: interactive input
        if context:
            print(f"\n💬 ({context})")
        print(f"   {question}")
        return input("\n> ")
    # AG-UI mode: interrupt agent loop, wait for user response
    response = tool_context.interrupt("ask_user", reason={"question": question, "context": context})
    return response
