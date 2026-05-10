"""Ask user tool — structured question to gather information."""

import sys
from strands import tool


@tool
def ask_user(question: str, context: str = "") -> str:
    """Ask the user a clarifying question and wait for their response.

    Use this when you need specific information to proceed with the investigation:
    - Time range (when did the issue start/end?)
    - Affected service (which domain/endpoint?)
    - Symptom description (what behavior are they seeing?)

    Do NOT ask more than 2 questions at a time. Prefer to auto-discover via APIs first.

    Args:
        question: The question to ask the user. Be specific and provide options when possible.
        context: Brief context for why you're asking (helps user give better answers).

    Returns:
        The user's response.
    """
    if sys.stdin and sys.stdin.isatty():
        # CLI mode: interactive input
        if context:
            print(f"\n💬 Agent question ({context}):")
        else:
            print("\n💬 Agent question:")
        print(f"   {question}")
        return input("\n   Your answer: ")
    else:
        # AG-UI mode: return question as tool result.
        # The agent will present this to the user via TEXT_MESSAGE_CONTENT.
        # Frontend detects ask_user in TOOL_CALL events and prompts user.
        # User's reply comes as the next /invocations request (same session).
        return f"[WAITING_FOR_USER] {question}"
