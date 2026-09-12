# AGENTS.md — Deployment playbook for AI agents

**Audience: an AI coding/ops agent driving a WAF Analyst deployment for a user.**

This is a **map, not a script.** It gives you the plan, the decision points, and the landmines.
The exact commands and parameters live in [`docs/deployment.md`](docs/deployment.md) — read the
relevant step there right before you run it, so you're always using the canonical, up-to-date
commands. (Commands are intentionally NOT duplicated here — one source of truth avoids drift.)

## What you're deploying

WAF Analyst is a read-only conversational AWS WAF analysis agent. Deployment is a container image
plus **up to 4 CloudFormation stacks** and a static frontend upload.

| Stack | Region | Required? |
|-------|--------|-----------|
| **backend** (Cognito + AgentCore Runtime + Memory + DynamoDB + IAM) | user's choice | ✅ required |
| **sessions** (API Gateway + Lambda — chat history sidebar) | same as backend | optional |
| **kb** (S3 Vectors + Bedrock Knowledge Base + docs bucket) | same as backend | optional (recommended) |
| **frontend** (CloudFront + S3 + WAF WebACL) | **us-east-1 (hard requirement)** | ✅ required |

**Minimal working deploy = image + backend + frontend + one Cognito user.** `sessions` and `kb` are
additive and can be added later without touching the others. Offer the minimal path first unless the
user asks for everything.

## Before you start

You're operating on the user's real AWS account — deploys create billable resources. **Confirm the
region and AWS profile with the user before the first deploy, and don't run Cleanup unless they
explicitly ask to tear down.**

Collect from the user first:
- **Backend region** — must support AgentCore CloudFormation **and** Claude Sonnet 4.6. See the
  supported list in [`docs/deployment.md` → Region Selection](docs/deployment.md#region-selection).
  (Frontend is always us-east-1 regardless.)
- **AWS profile / credentials** — verify `aws sts get-caller-identity` points at the intended account.
- **Which optional stacks** they want (session history? knowledge base?).
- **Model** — default is region-appropriate Claude; only override if they insist (see principle #5).
- **Prerequisites present:** AWS CLI v2, Node.js 18+, and the target WebACL(s) already have **WAF
  logging enabled** — without logging the agent can only read metrics.
- **A container tool is optional, and test for it with `docker info` / `finch info`, not `which`.**
  `which docker` succeeds on any machine that ever installed Docker Desktop while the daemon is not
  running, so it answers the wrong question. Then pick by what you are deploying, and do not ask:
  - **Nothing works, or the working tree matches a published release** → Step 1's CodeBuild path.
    It builds a published release on native Graviton, tags the image with the release, and needs no
    local tooling.
  - **They have local changes they want deployed** → only a local build can do that, because CodeBuild
    downloads a release tarball and never sees their files. If they also have no working container
    tool, say that plainly: their changes cannot be deployed until they have one.

  The two paths produce different artefacts, so say which one you took and why. A local build ships the
  working tree tagged by commit; CodeBuild ships a release tagged by release.

## The procedure

Follow the numbered steps in [`docs/deployment.md`](docs/deployment.md) — they're already in
dependency order. Your job is to execute them **carefully and statefully**, not to invent commands.

Working method for every stack:
1. Read that step in `docs/deployment.md`, substitute the user's real values.
2. Run it. **Wait for `CREATE_COMPLETE`.**
3. **Capture the stack outputs** (the doc's `describe-stacks` command) — the next stack and the
   frontend `.env` consume them. Echo them back to the user as a record.

Dependency flow (why the order matters — this is the part to keep in your head):
- **Image → backend.** Backend needs the ECR image URI. → Steps 1–2. Which of the two build paths you
  take was decided above, under prerequisites.
- **backend → sessions.** Sessions API needs backend's DynamoDB table ARN/name + Cognito ids. → Step 3.
- **backend + kb → backend again.** The KB stack is independent, but wiring it in **requires a second
  backend deploy** with `KnowledgeBaseId` (that's what sets the env var + `bedrock:Retrieve` IAM).
  → Steps 4–5. *Efficiency:* if the user definitely wants the KB, deploy kb first and pass
  `KnowledgeBaseId` on the very first backend deploy to skip the redeploy.
- **all outputs → frontend build.** The SPA `.env` is filled from backend + sessions outputs, built,
  and synced to the frontend bucket. → Steps 4 (frontend stack) + 6 (build/upload).
- **Cognito user** last, so the user can log in. → Step 7.

Then verify (Step 8 + the doc's runtime status check): open the CloudFront URL, sign in, send
`List all WebACLs`, then `what version are you running?` — it reports the release tag on the
CodeBuild path and the commit hash on a local build. If you cannot open a browser, the doc's Step 8
has a headless invoke you can run instead; **`CREATE_COMPLETE` and a `READY` runtime are not
verification**, because both happen for an image that cannot serve a request.

## Critical principles (internalize these — they cause the most failures)

1. **Image must be ARM64.** AgentCore only runs ARM64. Always build `--platform linux/arm64`; an
   amd64 image → runtime `FAILED` at startup.
2. **Frontend stack must be us-east-1.** Its WAF WebACL is `Scope: CLOUDFRONT`, and CloudFront-scope
   WebACLs only exist in us-east-1. AWS constraint, not a preference.
3. **Never tag the image `:latest` — use the git commit hash.** AgentCore only pulls a new image when
   CloudFormation sees the `AgentContainerUri` value *change*. Reusing `:latest` → the runtime keeps
   running stale code after a "redeploy". A unique tag forces the pull. The `deploy/image-build.yaml`
   path tags with the release tag instead, which is unique per release and immutable, so it satisfies
   this for the same reason.
4. **Whether CloudFormation forgets a parameter depends on which command you use, so use
   `deploy`.** Corrected 2026-09-12 after measuring it: `aws cloudformation deploy` sends
   `UsePreviousValue` for every parameter you do not override, so omitting one keeps its current
   value, and the console's Update wizard pre-fills from the stack. Calling `update-stack` or
   `create-change-set` directly is the dangerous path: an omitted parameter falls back to the
   template default. An earlier version of this principle described that behaviour as universal,
   which sent people re-passing parameters unnecessarily and, worse, offered a wrong explanation for
   failures that had another cause. **One exception that still bites:** a parameter introduced in the
   same deploy that first adds it has no previous value, so it takes the default. That is why the
   guard on the frontend stack's custom domain is "only use `deploy`" rather than the parameters
   themselves, and losing it that way is a legitimate update rather than drift, so
   `detect-stack-drift` will not warn you.
5. **Use a Claude model, not GPT-family.** This is a defensive tool but every prompt is full of
   "SQLi / XSS / bypass / payload". GPT-family models on Bedrock can hit upstream cyber-safety filters
   and **fail silently** — the UI just looks idle. Default Claude Sonnet 4.6 / Opus avoid this. If the
   user overrides `ModelId` to a GPT model, warn them.
6. **`AgentRuntimeName` must match `[a-zA-Z][a-zA-Z0-9_]{0,47}`** — no hyphens or spaces (default
   `waf_agent`).

## When something breaks

First classify the failure — the fix lives in different places:

- **Deploy-time** (stack error, runtime `FAILED`/`CREATING`, `504`, naming/param errors, frontend
  built with wrong values) → [`docs/deployment.md` → Troubleshooting](docs/deployment.md#troubleshooting).
  Most of these trace back to principles 1–6 above.
- **Runtime / data** (Athena timeouts, "hourly partition" query blocks, "no logging", empty report
  sections) → **not a deployment problem.** These are expected agent behaviors covered in
  [`docs/user-guide.md`](docs/user-guide.md), [`docs/athena-table-detection.md`](docs/athena-table-detection.md),
  [`docs/firehose-minute-partitioning.md`](docs/firehose-minute-partitioning.md), and
  [`docs/hourly-vs-minute-partitioning.md`](docs/hourly-vs-minute-partitioning.md) (why hourly log
  queries are handled the way they are, and the cost/speed trade behind it).
- **"What can the agent touch in my account?"** → [`docs/iam-permissions.md`](docs/iam-permissions.md)
  (read-only on production; the only writes are its own Athena temp tables, logs, sessions, memory).

**Behavior vs. roadmap.** The docs above describe how the *deployed* build behaves. What is
*planned but not yet shipped* lives in [`docs/roadmap.md`](docs/roadmap.md). Check the version you
deployed (the `what version are you running?` step) against the CHANGELOG before assuming a
roadmap item is live. **What that step reports depends on which build path you took.** The CodeBuild
path reports the release tag, so the CHANGELOG section with the same number tells you exactly what is
in it. A local build reports a commit hash instead, which maps to no heading, so with that path you
have to check what the commit predates. Hourly log-detail queries are the worked example of why: they were declined
for most of this project's life and now run, so a build from before that change still declines them
and the CHANGELOG is how you tell. Don't tell a user a roadmap item is present when their build
predates it.

## Updating & cleanup

- **Update the agent:** rebuild with a new commit tag, redeploy backend re-passing all non-default
  params (principles 3 & 4). Exact commands: [`docs/deployment.md` → Updating the Agent](docs/deployment.md#updating-the-agent).
  Existing sessions finish on old code; new sessions pick up the new image.
- **Tear down (only when explicitly asked):** buckets must be emptied before their stack deletes, and
  order matters. Follow [`docs/deployment.md` → Cleanup](docs/deployment.md#cleanup). The agent also left external Athena tables in
  a `waf_analysis_tmp` Glue database (no data copied) — drop with `DROP DATABASE waf_analysis_tmp CASCADE`.
