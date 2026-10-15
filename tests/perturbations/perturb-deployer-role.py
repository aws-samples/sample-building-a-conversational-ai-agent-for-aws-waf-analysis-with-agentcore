#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each property `test_deployer_role.py` claims and require it to notice.

Every one of these deploys cleanly for an administrator and fails with AccessDenied only for someone
using `deploy/deployer-role.yaml`, so a green suite is the only place the drift can show before an
enterprise user meets it. Every target reads templates as text, so the reachability probe does not
apply.

**The two coverage cases point opposite ways on purpose.** Dropping a type is the deploy that breaks;
adding one nothing creates is a grant nobody needs. The test reports them separately, and each case
here has to turn it red on its own.
"""

import sys

from _harness import sweep

T = "tests/test_deployer_role.py"
D = "deploy/deployer-role.yaml"
BOUNDARY = "      PermissionsBoundary: !If [HasPermissionsBoundary, !Ref PermissionsBoundary, !Ref AWS::NoValue]\n"

CASES = [
    ("a resource type the templates create dropped from the coverage list",
     [(D, "    - AWS::S3Vectors::Index\n", "")],
     [f"{T}::test_the_role_was_derived_for_every_resource_type_the_templates_create"]),

    ("a type in the coverage list that no template creates",
     [(D, "    - AWS::WAFv2::WebACL\n", "    - AWS::WAFv2::WebACL\n    - AWS::SQS::Queue\n")],
     [f"{T}::test_the_role_was_derived_for_every_resource_type_the_templates_create"]),

    ("the knowledge-base role without a boundary, the shape the pre-change kb.yaml was refused for",
     [("deploy/kb.yaml", "  KBServiceRole:\n    Type: AWS::IAM::Role\n    Properties:\n" + BOUNDARY,
       "  KBServiceRole:\n    Type: AWS::IAM::Role\n    Properties:\n")],
     [f"{T}::test_every_role_any_template_creates_takes_the_boundary"]),

    ("a template that creates roles with no boundary parameter to pass",
     [("deploy/sessions-api.yaml", '  PermissionsBoundary:\n    Type: String\n    Default: ""\n',
       '  PermissionsBoundaryArn:\n    Type: String\n    Default: ""\n')],
     [f"{T}::test_every_role_any_template_creates_takes_the_boundary"]),

    ("the execution role named after something other than its stack",
     [("deploy/backend.yaml", "      RoleName: !Sub ${AWS::StackName}-execution-role",
       "      RoleName: waf-analyst-execution-role")],
     [f"{T}::test_every_role_name_falls_inside_the_scope_the_service_role_can_manage"]),

    ("a second managed policy attached, which iam:PolicyARN refuses",
     [("deploy/sessions-api.yaml",
       "        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole\n",
       "        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole\n"
       "        - arn:aws:iam::aws:policy/AWSXrayWriteOnlyAccess\n")],
     [f"{T}::test_the_only_managed_policies_attached_are_the_ones_the_role_may_attach"]),

    ("the service role named inside its own grant scope",
     [(D, "      RoleName: !Sub cfn-${StackNamePrefix}", "      RoleName: !Sub ${StackNamePrefix}-cloudformation")],
     [f"{T}::test_the_service_role_cannot_rewrite_itself"]),
]

sys.exit(sweep(CASES))
