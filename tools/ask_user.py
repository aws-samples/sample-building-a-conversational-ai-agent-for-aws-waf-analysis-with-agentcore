"""Ask user tool — structured question to gather information."""

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
    # In AgentCore AG-UI mode, this becomes a structured event that pauses the agent.
    # In local CLI mode, we use input() for testing.
    if context:
        print(f"\n💬 Agent question ({context}):")
    else:
        print("\n💬 Agent question:")
    print(f"   {question}")
    response = input("\n   Your answer: ")
    return response
