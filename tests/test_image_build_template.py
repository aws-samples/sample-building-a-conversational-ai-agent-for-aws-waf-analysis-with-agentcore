# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ROADMAP 5.5: the remote build's two invariants, both of which fail silently.

`deploy/image-build.yaml` was exercised end to end against a real account on 2026-09-12: create,
update to a new tag, update to a tag already present, and a build that fails. That was ad-hoc, so it
proves the template worked once and guards nothing afterwards. These are the two properties whose
breakage produces a *plausible* result rather than an error, which is why they are worth a test.

**The Lambda must answer CloudFormation on every path.** If it raises, or is killed at its own
timeout, no response is sent, and CloudFormation waits a full hour before failing with nothing to
read. That is the documented failure mode for this shape and it is indistinguishable from a slow
build while it is happening. The handler lives inline in the template, so these tests extract and run
it rather than assert about its source: a claim about what the code says is weaker than the code.

**The ARM pairing must hold.** The buildspec runs a plain `docker build` with no `--platform`, which
is only correct because the build host is itself arm64. `Environment.Type` and the build image are
therefore one fact in two places. Break either and the build still succeeds, pushes an amd64 image,
and AgentCore fails at startup instead: a green build and a dead runtime, which is exactly the
distance this repo keeps trying to close.
"""

import json
import pathlib
import re
import textwrap
import types

import pytest

TEMPLATE = pathlib.Path(__file__).parent.parent / "deploy" / "image-build.yaml"
TEXT = TEMPLATE.read_text()

PROJECT = "a-project"


def _block_scalar(key):
    """The body of a `<key>: |` block, dedented. Asserts the block exists, because a regex that
    silently matches nothing turns every assertion below into a tautology."""
    match = re.search(rf"^(\s*){key}: \|\n((?:\1  .*\n|\n)*)", TEXT, re.M)
    assert match, f"no `{key}: |` block in {TEMPLATE.name}, so this test proves nothing"
    return textwrap.dedent(match.group(2))


class _CodeBuild:
    """Returns each status in turn, so a test says how the build behaves over time."""

    def __init__(self, statuses, phases=()):
        self.statuses = list(statuses)
        self.phases = list(phases)
        self.started = []

    def start_build(self, projectName):                     # noqa: N803 - boto3's own spelling
        self.started.append(projectName)
        return {"build": {"id": f"{projectName}:abc123"}}

    def batch_get_builds(self, ids):
        status = self.statuses.pop(0) if self.statuses else "IN_PROGRESS"
        return {"builds": [{"buildStatus": status, "currentPhase": "COMPLETED",
                            "phases": self.phases}]}


def _run(request_type, statuses=("SUCCEEDED",), phases=(), remaining_ms=900_000,
         send_raises=False):
    """Execute the template's inline handler with CodeBuild, the clock and the network replaced.

    Returns (responses, codebuild). `responses` is every payload PUT to the CloudFormation
    response URL, so "did it answer at all" is observable rather than inferred."""
    namespace = {}
    exec(compile(_block_scalar("ZipFile"), "<image-build ZipFile>", "exec"), namespace)

    codebuild = _CodeBuild(statuses, phases)
    responses = []

    def urlopen(request):
        if send_raises:
            raise OSError("the response URL is unreachable")
        responses.append(json.loads(request.body))
        return None

    namespace["boto3"] = types.SimpleNamespace(client=lambda name: codebuild)
    namespace["time"] = types.SimpleNamespace(sleep=lambda seconds: None)
    namespace["urllib"] = types.SimpleNamespace(request=types.SimpleNamespace(
        Request=lambda url, data, method, headers: types.SimpleNamespace(body=data),
        urlopen=urlopen))

    event = {
        "RequestType": request_type,
        "ResourceProperties": {"ProjectName": PROJECT, "ReleaseTag": "v1.2.3"},
        "ResponseURL": "https://cloudformation.example/response",
        "StackId": "arn:aws:cloudformation:::stack/s/1",
        "RequestId": "req-1",
        "LogicalResourceId": "Image",
    }
    context = types.SimpleNamespace(get_remaining_time_in_millis=lambda: remaining_ms)
    namespace["handler"](event, context)
    return responses, codebuild


# --- the Lambda answers, always -------------------------------------------------

@pytest.mark.parametrize("request_type,statuses,expected", [
    ("Create", ("SUCCEEDED",), "SUCCESS"),
    ("Update", ("SUCCEEDED",), "SUCCESS"),
    ("Create", ("IN_PROGRESS", "SUCCEEDED"), "SUCCESS"),
    ("Create", ("FAILED",), "FAILED"),
    ("Create", ("STOPPED",), "FAILED"),
    ("Create", ("TIMED_OUT",), "FAILED"),
    ("Delete", (), "SUCCESS"),
])
def test_every_request_type_and_build_outcome_sends_exactly_one_response(
        request_type, statuses, expected):
    """The sweep the failure mode demands: every `RequestType` the resource can receive, crossed
    with every terminal build status CodeBuild can report. A path that answers zero times hangs the
    stack for an hour; a path that answers twice is a protocol violation."""
    responses, _ = _run(request_type, statuses)
    assert len(responses) == 1, f"{len(responses)} responses sent, expected exactly 1"
    assert responses[0]["Status"] == expected


def test_running_out_of_time_reports_failure_instead_of_being_killed():
    """The path that exists only to avoid the hang. With less time left than the margin, the handler
    must stop polling and answer while it still can.

    The precondition is the point: the build is still `IN_PROGRESS`, so a `FAILED` here can only
    come from the deadline. If the fixture let the build finish, this would pass for the wrong
    reason."""
    responses, codebuild = _run("Create", statuses=("IN_PROGRESS",) * 5, remaining_ms=10_000)
    assert codebuild.statuses, "the build reached a terminal status, so the deadline was not tested"
    assert len(responses) == 1
    assert responses[0]["Status"] == "FAILED"
    assert "still running" in responses[0]["Reason"], responses[0]["Reason"]


def test_an_unreachable_response_url_does_not_raise():
    """The inner guard. If sending the response fails, raising would abandon the invocation and hang
    the stack for the same reason the outer guard exists to prevent."""
    _run("Create", ("FAILED",), send_raises=True)     # must simply return


def test_the_failure_reason_names_the_phase_that_failed_not_the_current_one():
    """`currentPhase` at a terminal status is always `COMPLETED`, so reporting it reads like phase
    information and carries none. Measured on a real failing build before this was fixed."""
    responses, _ = _run("Create", ("FAILED",), phases=[
        {"phaseType": "DOWNLOAD_SOURCE", "phaseStatus": "SUCCEEDED"},
        {"phaseType": "BUILD", "phaseStatus": "FAILED"},
        {"phaseType": "COMPLETED"}])
    reason = responses[0]["Reason"]
    assert "BUILD" in reason and "COMPLETED" not in reason, reason
    assert PROJECT in reason, "the reason does not say where to read the log"


def test_the_physical_id_is_the_same_for_create_and_update():
    """A physical id that changes makes CloudFormation read an update as a replacement, which calls
    the handler again with `Delete` for the old id. Changing `ReleaseTag` must be an update."""
    created, _ = _run("Create")
    updated, _ = _run("Update")
    assert created[0]["PhysicalResourceId"] == updated[0]["PhysicalResourceId"] == PROJECT


def test_delete_starts_no_build():
    """Tearing the stack down must not spend ten minutes building an image that is about to be
    deleted with its repository."""
    _, codebuild = _run("Delete")
    assert codebuild.started == []


# --- the ARM pairing ------------------------------------------------------------

def test_the_environment_type_and_the_build_image_agree_on_the_architecture():
    """One fact in two places. `ARM_CONTAINER` alone gives an arm64 host; the image alone gives
    arm64 tooling; a plain `docker build` needs both, and neither half errors on its own."""
    environment = re.search(r"^      Environment:\n((?:        .*\n)+)", TEXT, re.M)
    assert environment, "the CodeBuild Environment block moved; this test proves nothing"
    block = environment.group(1)
    assert re.search(r"^        Type: ARM_CONTAINER$", block, re.M), block
    assert re.search(r"^        Image: aws/codebuild/amazonlinux-aarch64-standard:", block, re.M), (
        "the build image is not an aarch64 one, so ARM_CONTAINER is carrying the whole claim")
    assert "PrivilegedMode: true" in block, "docker build needs the daemon"


def test_the_buildspec_does_not_ask_for_a_platform():
    """`--platform linux/arm64` here would be a false reassurance: it would keep working if the
    environment type regressed to x86, by silently falling back to emulation. The absence is what
    makes the previous test load-bearing."""
    assert "--platform" not in _block_scalar("BuildSpec")


def test_the_image_is_tagged_with_the_release_and_never_latest():
    """AgentCore resolves the tag once, when the runtime is created. A tag whose contents can change
    leaves the runtime serving old code with every signal reporting success."""
    buildspec = _block_scalar("BuildSpec")
    assert "BUILD_COMMIT=$RELEASE_TAG" in buildspec, \
        "the image would report BUILD_COMMIT=unknown in version.json"
    assert ":latest" not in TEXT, "principle 3 in AGENTS.md"
    assert "ImageTagMutability: IMMUTABLE" in TEXT


def test_the_lifecycle_policy_uses_a_count_type_ecr_accepts():
    """`imageCountMoreThanN` is not a valid `countType` and ECR rejects the whole repository with
    "instance failed to match exactly one schema", which names neither the field nor the value.
    Cost an hour on 2026-09-12; a whitelist is cheaper than reading that error again."""
    policy = json.loads(_block_scalar("LifecyclePolicyText"))
    for rule in policy["rules"]:
        count_type = rule["selection"]["countType"]
        assert count_type in {"imageCountMoreThan", "sinceImagePushed"}, count_type
        if count_type == "sinceImagePushed":
            assert "countUnit" in rule["selection"], "sinceImagePushed needs countUnit"


def test_the_no_source_project_carries_its_buildspec_inline():
    """With `NO_SOURCE` there is no source directory, so a buildspec *path* resolves against
    nothing. AWS's own NO_SOURCE example also omits `Location`, which the generic property text
    asks for."""
    source = re.search(r"^      Source:\n((?:        .*\n|\n)+?)(?=^ {0,7}\S|\Z)", TEXT, re.M)
    assert source, "the Source block moved; this test proves nothing"
    block = source.group(1)
    assert "Type: NO_SOURCE" in block
    assert "BuildSpec: |" in block, "the buildspec is not inline"
    assert not re.search(r"^        Location:", block, re.M), \
        "Location is set on a NO_SOURCE project"
