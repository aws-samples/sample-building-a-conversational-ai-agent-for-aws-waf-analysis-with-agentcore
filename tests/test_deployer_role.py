# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""`deploy/deployer-role.yaml` was derived from the other templates, and nothing else keeps it so.

Its service role was built from the handler permissions of every resource type the other templates
create, then exercised end to end on 2026-10-15: every stack created, the backend updated, everything
deleted, all through that role, with a permissions boundary on, from a principal holding only the
deployer policy. None of the drifts below is visible until someone deploys. A template that gains a
resource type deploys fine for an administrator and fails with AccessDenied for exactly the enterprise
user this file exists for, which is why each is asserted here instead of discovered there.

What this cannot check: whether a new resource type needs actions the role lacks. That takes the
CloudFormation registry and a real deploy. The coverage list is what makes the question get asked.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
DEPLOYER = DEPLOY / "deployer-role.yaml"
BOUNDARY = "PermissionsBoundary: !If [HasPermissionsBoundary, !Ref PermissionsBoundary, !Ref AWS::NoValue]"


def _templates():
    found = {p.name: p.read_text() for p in sorted(DEPLOY.glob("*.yaml")) if p != DEPLOYER}
    assert {"backend.yaml", "kb.yaml", "image-build.yaml"} <= set(found), (
        f"the templates moved; this test proves nothing: {sorted(found)}")
    return found


def _resources(text):
    """(logical id, type, body) for each resource, the body ending at the next two-space key."""
    section = text[text.index("\nResources:\n") + len("\nResources:\n"):]
    end = re.search(r"^[A-Za-z]", section, re.M)
    section = section[:end.start()] if end else section
    return re.findall(r"^  ([A-Za-z0-9]+):\n    Type: (\S+)\n((?:(?!  [A-Za-z0-9]+:\n).*\n)*)",
                      section, re.M)


def _covered():
    text = DEPLOYER.read_text()
    block = re.search(r"^  CoveredResourceTypes:\n((?:    - .*\n)+)", text, re.M)
    assert block, "CoveredResourceTypes moved; this test proves nothing"
    return set(re.findall(r"- (\S+)", block.group(1)))


def test_the_role_was_derived_for_every_resource_type_the_templates_create():
    """Both directions, because they fail differently. A type in a template and not in the list is the
    deploy that breaks; a type in the list and in no template is a grant nobody needs any more."""
    used = {t for text in _templates().values() for _, t, _ in _resources(text)}
    assert "AWS::IAM::Role" in used and len(used) >= 20, f"the resource parse broke: {sorted(used)}"
    covered = _covered()
    assert used == covered, {
        "created by a template, never derived into the role": sorted(used - covered),
        "derived into the role, created by no template": sorted(covered - used),
    }


def test_every_role_any_template_creates_takes_the_boundary():
    """An organization that mandates a boundary gets every role refused by the service role's
    `iam:PermissionsBoundary` condition unless the role carries one, so a single role without it fails
    the whole stack for exactly those users. Measured: the pre-change kb.yaml was refused this way."""
    roles = [(name, rid, body) for name, text in _templates().items()
             for rid, t, body in _resources(text) if t == "AWS::IAM::Role"]
    assert len(roles) >= 5, f"only {len(roles)} roles parsed: {[(n, r) for n, r, _ in roles]}"
    missing = [f"{name}:{rid}" for name, rid, body in roles if BOUNDARY not in body]
    assert not missing, f"roles with no PermissionsBoundary: {missing}"
    for name, text in _templates().items():
        if any(t == "AWS::IAM::Role" for _, t, _ in _resources(text)):
            assert re.search(r"^  PermissionsBoundary:\n    Type: String\n    Default: \"\"", text, re.M), (
                f"{name} creates a role but declares no optional PermissionsBoundary parameter")


def test_every_role_name_falls_inside_the_scope_the_service_role_can_manage():
    """The service role's IAM actions are scoped to `role/<prefix>*`, and the deployment guide's stack
    names all start with the prefix. A role named after anything but its stack falls outside it."""
    explicit = [(name, rid, m.group(1)) for name, text in _templates().items()
                for rid, t, body in _resources(text) if t == "AWS::IAM::Role"
                for m in [re.search(r"^      RoleName: (.+)$", body, re.M)] if m]
    assert explicit, "no explicit RoleName found; the backend's execution role should have one"
    outside = [e for e in explicit if not e[2].startswith("!Sub ${AWS::StackName}")]
    assert not outside, f"role names not derived from the stack name: {outside}"


def test_the_only_managed_policies_attached_are_the_ones_the_role_may_attach():
    """`iam:AttachRolePolicy` is pinned to named policy ARNs, so attaching another one deploys for an
    administrator and is refused for everyone using the service role."""
    attached = set()
    for text in _templates().values():
        for block in re.findall(r"ManagedPolicyArns:\n((?:\s+- .*\n)+)", text):
            attached |= set(re.findall(r"arn:aws:iam::aws:policy/\S+", block))
    assert attached, "no ManagedPolicyArns parsed; the sessions Lambda role attaches one"
    allowed = set(re.findall(r"iam:PolicyARN: !Sub arn:\$\{AWS::Partition\}:iam::aws:policy/(\S+)",
                             DEPLOYER.read_text()))
    assert allowed, "the iam:PolicyARN condition moved; this test proves nothing"
    assert {a.split("policy/", 1)[1] for a in attached} <= allowed, (attached, allowed)


def test_the_service_role_cannot_rewrite_itself():
    """Its IAM grants cover `role/<prefix>*`. Named inside that scope, it could put any policy on
    itself."""
    name = re.search(r"^  CloudFormationRole:\n(?:.*\n)*?      RoleName: !Sub (\S+)", DEPLOYER.read_text(), re.M)
    assert name, "the service role's RoleName moved"
    assert not name.group(1).startswith("${StackNamePrefix}"), name.group(1)
