#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_entry_files_match_reality.py` fail?

Every assertion there reads a document and looks for a string, which is the easiest kind of test to
write hollow: move the heading it anchors on and the regex quietly matches nothing. The cases below are
the states that were actually true on 2026-09-12, plus two anchor moves that would silently disarm the
checks.

**`bare-docker-bullet-alongside-the-optional-one` is why this script earns its keep.** The first version
of the container-tool test asked whether "optional" appeared anywhere in the prerequisite block. That
case adds the original bare Docker bullet back while LEAVING the optional one in place, so the list
contradicts itself, and the test reported green. The fix was to judge per list item. A perturbation that
restores a defect the test was written for is worth more than one that deletes the thing it looks at.

Run from the repo root. Restores every touched file on any exit path.
"""

import sys

from _harness import sweep

FILE = "tests/test_entry_files_match_reality.py"
CASES = [
    # The three real states, as they actually read before this pass.
    ("docker-required-again", "README.md",
     "- A container tool is **optional**.", "- [Docker](https://docs.docker.com/get-docker/) with buildx",
     "test_no_prerequisite_item_presents_a_container_tool_as_required"),
    ("docker-required-again-zh", "README_zh.md",
     "- 容器工具**可以没有**。", "- [Docker](https://docs.docker.com/get-docker/)（需要 buildx）",
     "test_no_prerequisite_item_presents_a_container_tool_as_required"),
    ("structure-list-short", "README.md",
     "│   ├── image-build.yaml  # CloudFormation: builds the ARM64 image on CodeBuild, no local Docker\n",
     "", "test_every_file_in_deploy_is_listed_in_the_project_structure"),
    ("structure-list-short-zh", "README_zh.md",
     "│   ├── sessions-api.yaml # CloudFormation: API Gateway + Lambda（会话历史）\n",
     "", "test_every_file_in_deploy_is_listed_in_the_project_structure"),
    # The failure that actually happened: English updated, Chinese left behind. Every marker here
    # occurs TWICE per file, so these must replace all occurrences. A first-only replacement reported
    # MISSED on the first run of this script and the tests were fine; the script was not.
    # Both mentions, declared. Replacing one leaves the guide still naming the path, so the test
    # stays green and the case reports HOLLOW for a perturbation that was simply incomplete.
    ("chinese-guide-left-behind", "docs/deployment_zh.md", "image-build.yaml", "other.yaml",
     "test_every_document_that_explains_deployment_names_the_codebuild_path", 2),
    ("agents-md-silent", "AGENTS.md", "image-build.yaml", "other.yaml",
     "test_every_document_that_explains_deployment_names_the_codebuild_path"),
    ("readiness-caveat-dropped-zh", "docs/deployment_zh.md",
     "CloudFormation 会等 runtime 报 `READY` 才收尾，而 `READY` 只说明 runtime 建好了、镜像引用能解析。"
     "2026-09-12 实测：把 runtime 指向一个启动就退出、不监听任何端口、也没有 `/ping` 的镜像，它照样报 `READY`，栈照样成功。",
     "栈成功就说明起来了。",
     "test_both_guides_say_stack_success_is_not_readiness"),
    ("readiness-caveat-dropped-en", "docs/deployment.md",
     "CloudFormation waits for the runtime to report `READY`, and `READY` only means the runtime was "
     "created and the image reference resolved. Measured on 2026-09-12: a runtime pointed at an image "
     "that exits immediately, listens on no port and has no `/ping` still reached `READY`, and the "
     "stack still succeeded.",
     "A successful stack means it is up and serving.",
     "test_both_guides_say_stack_success_is_not_readiness"),
    ("roadmap-date-drift", "docs/roadmap_zh.md",
     "而不是直接拒绝 | 2026-09-10 |", "而不是直接拒绝 | |",
     "test_the_two_roadmaps_agree_on_what_has_shipped"),
    ("roadmap-row-count-drift", "docs/roadmap_zh.md",
     "## 文档\n", "| 多出来的一行 | |\n\n## 文档\n",
     "test_the_two_roadmaps_agree_on_what_has_shipped"),
    # The reviewer's exact repro of the hollow version: add the original bare bullet back and LEAVE
    # the optional one in place. The whole-block check stayed green here; the per-item check must not.
    ("bare-docker-bullet-alongside-the-optional-one", "README.md",
     "- AWS CLI v2 configured with appropriate permissions",
     "- [Docker](https://docs.docker.com/get-docker/) with buildx (for ARM64 images)\n- AWS CLI v2 configured with appropriate permissions",
     "test_no_prerequisite_item_presents_a_container_tool_as_required"),
    ("guide-docker-required-again", "docs/deployment.md",
     "2. **A container tool, optional.**",
     "2. **Docker Desktop** (includes buildx for cross-platform builds).",
     "test_no_prerequisite_item_presents_a_container_tool_as_required"),
    ("guide-docker-required-again-zh", "docs/deployment_zh.md",
     "2. **容器工具，可选。**", "2. **Docker Desktop**（含 buildx，用于构建容器镜像）。",
     "test_no_prerequisite_item_presents_a_container_tool_as_required"),
    # Anchor moves. These must be CAUGHT by the precondition assertions, not shrugged off.
    ("structure-anchor-moved", "README.md", "├── deploy/\n", "├── deployment/\n",
     "test_every_file_in_deploy_is_listed_in_the_project_structure"),
    ("prereq-anchor-moved", "README.md", "### Prerequisites", "### Before you start",
     "test_no_prerequisite_item_presents_a_container_tool_as_required"),
]

def _edit(case):
    """This script's one edit per case, carrying the declared anchor count when there is one.

    **Named rather than inlined, because `len(case) == 5` means something else three files over.**
    Seven scripts here pass exactly that expression to `sweep` as the reachability-probe flag. Written
    inline this read like the same idiom and is not: here it asks whether the case declares a count.
    """
    _, rel, old, new = case[:4]
    return (rel, old, new, case[5]) if len(case) > 5 else (rel, old, new)


# No reachability probe on any case: every target reads a document as text, so nothing executes the
# perturbed line and the probe would call every good perturbation unreachable.
sys.exit(sweep([(c[0], [_edit(c)], [f"{FILE}::{c[4]}"]) for c in CASES]))
