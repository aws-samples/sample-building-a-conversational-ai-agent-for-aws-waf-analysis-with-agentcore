# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Memory was dead from v0.13.0 to v0.22.0 and every signal said it was working.

`_get_user_id_from_jwt` returns an email. That value became `actor_id` and all three retrieval
namespaces, AgentCore rejected each call on the identifier charset, and `except Exception: pass`
swallowed it. Measured on the deployed memory resource on 2026-09-12: `list_memory_records`,
`retrieve_memory_records` and `list_actors` all empty after four months, against six sessions sitting
in DynamoDB. The deployed agent had `MEMORY_ID` set and reported nothing wrong.

**The patterns below were read off the live service, not out of a document.** No AWS page states them.
`aws bedrock-agentcore list-events --actor-id 'chencch@amazon.com'` returns a `ValidationException`
quoting the pattern, and the sanitised form is accepted. That is also why the positive control in the
first test matters: a sanitiser that did nothing would satisfy an assertion that only checks its
output against the pattern if the pattern check were wrong, so the raw email is asserted to FAIL the
same check first.
"""

import re

import pytest

import agent

# Verbatim from the service's own error message, with the character classes rewritten so Python reads
# them the same way: AWS writes `[a-zA-Z0-9-_/]`, where the `-` after a finished range is a literal.
ACTOR_ID = re.compile(r"^[a-zA-Z0-9][A-Za-z0-9_/-]*(?::[A-Za-z0-9_/-]+)*[A-Za-z0-9_/-]*$")
# The namespace class is the same plus `*`, and it may lead with `/`. Only the leading and body classes
# were captured from the error, so this checks what was actually observed rather than a fuller guess.
NAMESPACE = re.compile(r"^[a-zA-Z0-9/*][A-Za-z0-9_/*-]*$")
MAX_LENGTH = 255

# Everything `_get_user_id_from_jwt` can return: an email claim, a Cognito `sub` when email is absent,
# and the empty string when the header is missing or unparseable. The last two exist because without
# them `lstrip("_-/")` in the sanitiser was unguarded: none of the others produces a leading illegal
# character, so deleting that call left every assertion here green. A local-part may legally begin with
# a dot in a quoted form, and the degenerate `@a.b` covers an empty local-part.
REAL_IDS = [
    "chencch@amazon.com",
    "first.last+tag@example.co.uk",
    "8f4c1d2e-3b7a-4f91-9c2d-1e5a7b3c9d40",
    "UPPER.Case@Example.COM",
    ".foo@bar.com",
    "@a.b",
    "",
]


@pytest.mark.parametrize("raw", REAL_IDS)
def test_the_sanitised_id_is_accepted_where_the_raw_one_is_not(raw):
    """Both directions in one test, because either alone can pass for the wrong reason. If the raw
    value already matched, the sanitiser would be untested; if only the output were checked, a
    do-nothing sanitiser would pass on any input that happened to be legal already."""
    safe = agent._memory_safe_id(raw)
    assert ACTOR_ID.match(safe), f"{raw!r} sanitised to {safe!r}, which the service rejects"
    assert len(safe) <= MAX_LENGTH
    for kind in ("facts", "preferences", "summaries"):
        namespace = f"/{kind}/{safe}/"
        assert NAMESPACE.match(namespace), namespace
        assert len(namespace) <= MAX_LENGTH

    if raw and not ACTOR_ID.match(raw):
        assert safe != raw, "the sanitiser returned an id the service rejects"


def test_at_least_one_real_input_is_actually_rejected_raw():
    """The positive control for the table above, kept separate so it cannot be skipped by a
    parametrisation change. If every entry in `REAL_IDS` were already legal, the whole file would pass
    against a sanitiser that returns its argument."""
    rejected = [raw for raw in REAL_IDS if raw and not ACTOR_ID.match(raw)]
    assert rejected, "no input in REAL_IDS is rejected raw, so nothing here tests the sanitiser"
    assert "chencch@amazon.com" in rejected, "the id the deployed agent actually used is now legal?"


def test_ids_that_differ_only_in_a_substituted_character_do_not_collide():
    """Why the hash is there. This id keys the per-user memory namespace, so two users mapping to one
    id is a cross-user memory leak, which is the thing `get_agent` recreates the agent to avoid.

    **Only `.` and `@` collapse**, and getting that wrong is how the first version of this test failed:
    `-`, `_` and `/` are legal in an actorId, so they survive untouched and ids differing in one of
    those never needed the hash. The pair below is the real case, since both spellings substitute to
    `a_b_c_com`."""
    first, second = agent._memory_safe_id("a.b@c.com"), agent._memory_safe_id("a@b.c.com")
    assert first != second, f"collision: {first}"
    assert first.rsplit("-", 1)[0] == second.rsplit("-", 1)[0] == "a_b_c_com", (
        "the readable parts no longer collide, so this pair has stopped testing the hash")

    legal = ["a_b@c.com", "a-b@c.com", "a/b@c.com"]
    produced = [agent._memory_safe_id(raw) for raw in legal]
    assert len(set(produced)) == len(legal), f"collision: {produced}"


def test_long_addresses_sharing_a_prefix_do_not_collide():
    """The truncation case, which is why the hash goes last rather than first. Both of these agree for
    far more than the 48 characters kept."""
    stem = "a" * 60
    first, second = agent._memory_safe_id(f"{stem}1@x.com"), agent._memory_safe_id(f"{stem}2@x.com")
    assert first != second
    assert len(first) <= MAX_LENGTH


def test_the_call_site_derives_every_identifier_from_the_sanitised_value(monkeypatch):
    """**`get_agent` is where the decision happens, and everything above only tests the helper.** With
    the helper covered but the call site not, changing one namespace back to `f"/facts/{user_id}/"`
    left the whole suite green, and the namespaces were half of the original bug. So this asserts on
    what the call site actually hands the service, not on what a function returns.

    **The strong assertion is the full-equality one, not `raw not in ...`.** Corrected after a
    perturbation that derived the namespaces differently (`actor.upper()`) rather than reverting them:
    `raw not in namespace` still held, and what failed was
    `sorted(retrieval_config) == [the three expected keys]`. So the equality decides "every namespace is
    derived from the same sanitised value" and `raw not in` is a format-independent backstop for the one
    case equality could miss, a sanitiser that changes shape and takes the assertion's own expectation
    with it. Both do work; write the backstop, keep the equality."""
    captured = {}

    class _Config:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(
        "bedrock_agentcore.memory.integrations.strands.config.AgentCoreMemoryConfig", _Config)
    monkeypatch.setattr(
        "bedrock_agentcore.memory.integrations.strands.session_manager.AgentCoreMemorySessionManager",
        lambda config, region_name=None: "manager")
    monkeypatch.setattr(agent, "MEMORY_ID", "mem-abc123")
    monkeypatch.setattr(agent, "_agent", None)
    monkeypatch.setattr(agent, "_agent_user_id", "")
    monkeypatch.setattr(agent, "Agent", lambda **kwargs: kwargs)

    raw = "chencch@amazon.com"
    built = agent.get_agent(session_id="s-1", user_id=raw)
    assert built["session_manager"] == "manager", (
        "memory setup did not complete, so nothing below was reached")

    expected = agent._memory_safe_id(raw)
    assert captured["actor_id"] == expected
    assert ACTOR_ID.match(captured["actor_id"])
    assert raw not in captured["actor_id"]

    assert sorted(captured["retrieval_config"]) == [
        f"/facts/{expected}/", f"/preferences/{expected}/", f"/summaries/{expected}/"], (
        "a namespace is no longer derived from the sanitised id")
    for namespace in captured["retrieval_config"]:
        assert NAMESPACE.match(namespace), namespace
        assert raw not in namespace, f"{namespace} still carries the raw user id"

    # And the session id is passed through untouched, which is correct: AgentCore's sessionId pattern
    # is stricter than the actorId one, and the frontend already produces UUIDs. Asserted so that
    # "sanitise everything" does not get applied here by reflex, changing the memory session key.
    assert captured["session_id"] == "s-1"


def test_memory_setup_failure_is_reported_rather_than_swallowed(monkeypatch, capsys):
    """The reason the charset bug survived nine releases was not the charset. `session_manager = None`
    meant both "no memory configured" and "memory setup raised", so the deployed agent looked
    identical to one deliberately running without memory.

    Driven through `get_agent` with the sanitiser raising, which is the only way to reach that
    `except` without a live service."""
    monkeypatch.setattr(agent, "MEMORY_ID", "mem-abc123")
    monkeypatch.setattr(agent, "_agent", None)
    monkeypatch.setattr(agent, "_agent_user_id", "")
    monkeypatch.setattr(agent, "_memory_safe_id",
                        lambda user_id: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(agent, "Agent", lambda **kwargs: kwargs)

    built = agent.get_agent(session_id="s-1", user_id="someone@example.com")
    assert built["session_manager"] is None, "memory should be off after a setup failure"
    printed = capsys.readouterr().out
    assert "memory disabled" in printed and "boom" in printed, printed


def test_the_frontend_session_id_stays_uuid_shaped():
    """AgentCore's sessionId pattern is `[a-zA-Z0-9][a-zA-Z0-9-_]*`, stricter than the actorId one: no
    `/`, and no `.`. The frontend's generator concatenates `crypto.randomUUID()`, which is legal, so
    there is no bug here today. It is guarded because the failure mode would be identical to the one
    this file exists for: a generator that grew a dot or a colon would kill memory silently, and
    nothing in Python would notice."""
    import pathlib
    source = (pathlib.Path(__file__).parent.parent / "frontend/src/App.jsx").read_text()
    generator = re.search(r"generateSessionId[^{]*\{([^}]*)\}", source)
    assert generator, "generateSessionId moved; retarget this test rather than deleting it"
    assert "crypto.randomUUID()" in generator.group(1), (
        "the session id is no longer UUID-derived. AgentCore rejects `.` and `/` in a sessionId, and a "
        "rejected memory call is silent.")
