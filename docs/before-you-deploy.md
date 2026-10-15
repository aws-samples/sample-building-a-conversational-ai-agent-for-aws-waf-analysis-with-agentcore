# Before You Deploy

English | [中文](before-you-deploy_zh.md)

A customer asked what had to be in place before deploying, because their CloudFront distributions and
WebACLs sit in one account, Bedrock in another, and the WAF log buckets in a third. That question has a
short answer and a set of checks, and both are here. The [Deployment Guide](deployment.md) assumes
you have done this page.

## Which account to deploy into

**The agent reads everything with its own execution role, in the account it runs in, and assumes no role
anywhere else.** So one account has to hold the WebACL, reach its log destination and be allowed to call
the model. That account is the WebACL's.

| Piece | Where it has to be | Why |
|---|---|---|
| The WebACL and its CloudWatch metrics | The deployment account | This is what decides the account |
| The WebACL's log destination | The deployment account | AWS requires a CloudWatch Logs group or Firehose stream to share the WebACL's account. An S3 bucket in another account is something WAF allows and this agent does not support |
| Claude on Amazon Bedrock | Enabled in the deployment account | The agent invokes the model with its own role, so a Bedrock account elsewhere is not used |
| backend, kb and sessions stacks | The deployment account, one region | The backend's grant names the knowledge base in its own account and region, and the sessions API reads the backend's table and trusts its user pool |
| frontend stack | Any account, `us-east-1` | It hosts static files. The browser calls Cognito, the runtime and the sessions API over HTTPS with a Cognito token, so no IAM permission connects it to the backend's account |

Several WAF accounts means one deployment per account.

**The case most likely to stop you is central logging.** The AWS Security Reference Architecture
recommends Firewall Manager writing WAF logs to a bucket in a Log Archive account, and that is exactly the
shape this agent cannot read today. [Known Limitations](limitations.md#not-supported-yet) records why.
Two commands tell you which case you are in:

```bash
# CloudFront WebACLs live in us-east-1 whatever region you deploy the backend to
aws wafv2 get-logging-configuration --resource-arn <webacl-arn> --region us-east-1 \
  --query 'LoggingConfiguration.[LogDestinationConfigs[0],ManagedByFirewallManager]'
```

A log group or Firehose ARN names its account, so compare it with yours. `ManagedByFirewallManager: true`
means the logs go to the Firewall Manager administrator's bucket or stream. For an S3 destination, or the
bucket behind a Firehose stream, ask S3 who owns it:

```bash
aws s3api get-bucket-location --bucket <bucket> --expected-bucket-owner <your-account-id>
```

Success means the bucket is yours. `AccessDenied` means another account owns it, or that you cannot read
it at all. Measured 2026-10-15 both ways, with the right owner and with a made-up one.

## Account checks

Run these in the account and region you will deploy the backend to, as the person who will deploy.

### Claude Sonnet 5 is usable

```bash
aws bedrock get-foundation-model-availability --model-id anthropic.claude-sonnet-5 --region <region>
```

All four fields should read `AVAILABLE` or `AUTHORIZED`. If `agreementAvailability` does not, Anthropic's
first-time-use form has not been submitted. It is filed once per account, or once in the Organization's
management account, which member accounts then inherit. Submit it from any Anthropic model in the Bedrock
console's model catalog.

### Make the first call yourself

```bash
aws bedrock-runtime converse --model-id global.anthropic.claude-sonnet-5 --region <region> \
  --messages '[{"role":"user","content":[{"text":"Reply with OK"}]}]'
```

This one call settles two things that would otherwise surface as an agent that never answers.

**The first invocation in an account subscribes it to the model through AWS Marketplace,** and AWS
documents that the principal making that call needs `aws-marketplace:Subscribe` and
`aws-marketplace:ViewSubscriptions`. The agent's execution role does not have them, by design. Once one
call has succeeded, every role in the account can invoke the model without them. This step was not
exercised here, because the test account was already subscribed.

**A region allowlist SCP can block the default model.** A `global.` profile is evaluated with
`aws:RequestedRegion` set to `unspecified`, so an SCP that lists allowed regions has to include that
value, or exempt Bedrock with a `bedrock:InferenceProfileArn` condition. The failure is an
`AccessDeniedException` naming an explicit deny in a service control policy. If your organization forbids
global routing on purpose, set `ModelId` to a geographic profile: `us.` in us-east-1, us-east-2 and
us-west-2, `eu.` in eu-west-1 and eu-central-1, `au.` in ap-southeast-2. ap-northeast-1, ap-southeast-1
and ap-south-1 have none, so there the only alternative is pointing `ModelRegion` at a region that does,
which sends the inference outside your geography anyway.

### AgentCore's service-linked role

```bash
aws iam get-role --role-name AWSServiceRoleForBedrockAgentCoreRuntimeIdentity
```

If it exists, there is nothing to do. If not, AgentCore creates it with the first runtime in the account,
and whoever creates the backend stack needs `iam:CreateServiceLinkedRole` for it that once. The deployer
role below grants exactly that.

## Who deploys, with what permissions

An administrator can run the whole guide. If your organization does not hand out administrator access,
[`deploy/deployer-role.yaml`](../deploy/deployer-role.yaml) is the narrower path. An administrator deploys
it once, and it creates two things:

- `cfn-<prefix>`, a CloudFormation service role holding the permissions to create, update and delete
  every resource in the other templates;
- `<prefix>-deployer`, a managed policy for whoever runs the guide. It can drive stacks only through that
  role, plus the steps the guide runs outside CloudFormation: the checks above, the image push, the
  knowledge-base sync, the frontend upload, the first user and cleanup.

```bash
aws cloudformation deploy \
  --template-file deploy/deployer-role.yaml \
  --stack-name deployer-waf-agent \
  --region <region> \
  --capabilities CAPABILITY_NAMED_IAM

aws cloudformation describe-stacks --stack-name deployer-waf-agent --region <region> \
  --query 'Stacks[0].Outputs' --output table
```

Attach `DeployerPolicyArn` to the deploying user or role, then add `--role-arn <CloudFormationRoleArn>` to
every `aws cloudformation deploy` in the guide. Measured 2026-10-15: all five stacks created, the backend
updated, and everything deleted through that role, from a principal holding nothing but the deployer
policy and with a permissions boundary on every role, and the agent it deployed answered. That run built
the image on CodeBuild, so the policy's local image push and the service-linked role grant, which the
account already had, are the two parts it did not exercise.

Three rules come with it:

- **Stack names must start with `StackNamePrefix`,** default `waf-agent`. The roles each stack creates are
  named after it, and that prefix is what the IAM permissions are scoped to. The guide's names already
  comply. The deployer stack's own name, `deployer-waf-agent`, deliberately does not.
- **Do not attach the deployer policy to a role whose name starts with the prefix.** The service role can
  rewrite those.
- **Without a permissions boundary this limits mistakes, not intent.** A template that creates roles needs
  `iam:PutRolePolicy`, and IAM cannot constrain what goes inside an inline policy, so whoever can deploy
  through the role can mint a role with any permissions. A boundary caps every role it creates. That is
  the reason to set one.

## Permissions boundaries

If your organization requires one, pass `PermissionsBoundary=<policy-arn>` to `deployer-role.yaml`,
`image-build.yaml`, `kb.yaml`, `backend.yaml` and `sessions-api.yaml`. The frontend stack creates no
role. With the parameter set, the service role refuses to create a role without that exact boundary.
That was measured too: a template version whose role could not take one was rejected at `iam:CreateRole`.

The boundary has to allow what each role does, or the stack deploys and the agent fails later. The
execution role's actions are in [IAM Permissions](iam-permissions.md). The other four roles are small and
their policies are inline in the templates: the CodeBuild role pushes to ECR, the build Lambda starts the
build, the knowledge-base role reads its bucket, writes vectors and calls the Titan embedding model, and
the sessions Lambda reads and deletes items in the sessions table.

Leave `PermissionsBoundary` empty everywhere if your organization does not require one. Nothing changes.
