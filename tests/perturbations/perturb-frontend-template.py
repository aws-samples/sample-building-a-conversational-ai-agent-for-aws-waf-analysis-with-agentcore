#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each property `test_frontend_template.py` claims and require it to notice.

That file had no perturbation script while it guarded five positions in `deploy/frontend.yaml`, and none
of them errors when wrong: a distribution with the cache policy on the wrong path deploys perfectly and
serves the previous build.

Every target reads the template or the guides as text, so the reachability probe does not apply.

**The two cases aimed at one test are the ones worth reading.** `a second behaviour back on the
optimized policy` restores exactly the design that was just removed, which is the edit a reasonable
person makes next. `a path pattern under a parent the test does not name` adds a `PathPattern` key
without writing `CacheBehaviors`, so the first of that test's two assertions stays green and only the
second can catch it. One case per assertion, so deleting either check cannot hide behind the other.
"""

import sys

from _harness import sweep

T = "tests/test_frontend_template.py"
Y = "deploy/frontend.yaml"
G = "docs/deployment.md"

CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"

CASES = [
    ("the one behaviour back on the optimized policy, which caches index.html",
     [(Y, "CachePolicyId: 4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
       f"CachePolicyId: {CACHING_OPTIMIZED}")],
     [f"{T}::test_every_request_is_served_by_a_policy_that_cannot_cache"]),

    ("a second behaviour back on the optimized policy, i.e. the design just removed",
     [(Y, "          Compress: true\n",
       "          Compress: true\n"
       "        CacheBehaviors:\n"
       "          - PathPattern: /assets/*\n"
       "            TargetOriginId: S3Origin\n"
       "            ViewerProtocolPolicy: redirect-to-https\n"
       f"            CachePolicyId: {CACHING_OPTIMIZED}\n"
       "            Compress: true\n")],
     [f"{T}::test_there_is_only_one_cache_behaviour"]),

    # The second assertion in that test earns its place here: this adds a PathPattern key without
    # ever writing `CacheBehaviors`, so the first assertion stays green and only the second catches
    # it. A real key rather than a comment, since both checks match YAML keys now.
    ("a path pattern under a parent the test does not name",
     [(Y, "          Compress: true\n",
       "          Compress: true\n"
       "          PathPattern: /assets/*\n")],
     [f"{T}::test_there_is_only_one_cache_behaviour"]),

    ("error caching back to its 300-second default on the 403 entry",
     [(Y, "          - ErrorCode: 403\n            ResponseCode: 200\n"
          "            ResponsePagePath: /index.html\n            ErrorCachingMinTTL: 0\n",
       "          - ErrorCode: 403\n            ResponseCode: 200\n"
          "            ResponsePagePath: /index.html\n")],
     [f"{T}::test_both_error_responses_disable_error_caching"]),

    ("only 404 mapped, so a deep link fails on an unhandled 403 from S3",
     [(Y, "          - ErrorCode: 403\n            ResponseCode: 200\n"
          "            ResponsePagePath: /index.html\n            ErrorCachingMinTTL: 0\n", "")],
     [f"{T}::test_both_error_responses_disable_error_caching"]),

    ("one domain parameter alone made sufficient, so an alias can be set with no certificate",
     [(Y, '    - !Not [!Equals [!Ref AcmCertificateArn, ""]]\n', "")],
     [f"{T}::test_the_custom_domain_stays_optional"]),

    ("a domain shipped as the template default",
     [(Y, '  DomainName:\n    Type: String\n    Default: ""',
       '  DomainName:\n    Type: String\n    Default: "waf-agent.example.com"')],
     [f"{T}::test_the_custom_domain_stays_optional"]),

    # Not `AWS::NoValue` deleted, which would break the YAML: replaced with an empty string, which
    # deploys and quietly makes a no-domain deployment differ from a template with no parameters.
    ("an empty alias instead of no alias at all",
     [(Y, 'Aliases: !If [HasCustomDomain, [!Ref DomainName], !Ref "AWS::NoValue"]',
       'Aliases: !If [HasCustomDomain, [!Ref DomainName], [""]]')],
     [f"{T}::test_the_custom_domain_stays_optional"]),

    ("no-store instead of no-cache on index.html, so every load is a full transfer",
     [(G, "--exclude '*' --include index.html --cache-control 'no-cache'",
       "--exclude '*' --include index.html --cache-control 'no-store'")],
     [f"{T}::test_the_upload_sends_opposite_headers_for_the_two_kinds_of_file"]),

    ("immutable dropped from the assets pass, so the browser revalidates a hashed name",
     [(G, "--exclude index.html --cache-control 'public, max-age=31536000, immutable'",
       "--exclude index.html --cache-control 'public'")],
     [f"{T}::test_the_upload_sends_opposite_headers_for_the_two_kinds_of_file"]),

    ("--delete on the upload, which breaks the tab still holding the old index.html",
     [(G, "--exclude index.html --cache-control 'public, max-age=31536000, immutable'",
       "--delete --exclude index.html --cache-control 'public, max-age=31536000, immutable'")],
     [f"{T}::test_the_upload_sends_opposite_headers_for_the_two_kinds_of_file"]),

    ("the two passes collapsed into one, which is the state that shipped",
     [(G, "\naws s3 sync dist/ s3://<FrontendBucket from Step 4>/ --region us-east-1 \\\n"
          "  --exclude '*' --include index.html --cache-control 'no-cache'\n", "\n")],
     [f"{T}::test_the_upload_sends_opposite_headers_for_the_two_kinds_of_file"]),
]

sys.exit(sweep(CASES))
