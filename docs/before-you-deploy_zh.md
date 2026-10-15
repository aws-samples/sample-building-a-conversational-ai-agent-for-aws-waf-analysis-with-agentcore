# 部署前检查

[English](before-you-deploy.md) | 中文

有客户问过：部署之前要准备什么？他们的 CloudFront 和 WebACL 在一个账号，Bedrock 在另一个账号，WAF 日志桶又在第三个账号。答案本身不长，另外还有几项要查的，都写在这页。[部署指南](deployment_zh.md)默认你已经过完这一页。

## 部署到哪个账号

**agent 读任何东西都只用自己的执行角色，只在它运行的那个账号里读，不会 assume 别的账号的角色。** 所以必须有一个账号同时满足三件事：WebACL 在这里，读得到它的日志，能调用模型。这个账号就是 WebACL 所在的账号。

| 组件 | 要放在哪 | 原因 |
|---|---|---|
| WebACL 和它的 CloudWatch 指标 | 部署账号 | 账号就是按它定的 |
| WebACL 的日志目的地 | 部署账号 | CloudWatch Logs 日志组和 Firehose 投递流，AWS 本来就要求和 WebACL 同账号。S3 桶放在别的账号，WAF 允许，这个 agent 不支持 |
| Amazon Bedrock 上的 Claude | 在部署账号里开通 | agent 用自己的角色调模型，别的账号里的 Bedrock 用不上 |
| backend、kb、sessions 三个栈 | 部署账号，同一个区域 | backend 的授权写死了本账号本区域的知识库，sessions API 要读 backend 的表、信任它的用户池 |
| frontend 栈 | 任意账号，`us-east-1` | 只放静态文件。浏览器带着 Cognito token 通过 HTTPS 访问 Cognito、runtime 和 sessions API，和 backend 所在账号之间没有任何 IAM 权限关系 |

WAF 分布在几个账号，就每个账号各部署一套。

**最容易卡住的是集中日志。** AWS Security Reference Architecture 推荐用 Firewall Manager 把 WAF 日志写进 Log Archive 账号的桶，这正好是 agent 现在读不了的情况，原因见[已知局限](limitations_zh.md#还不支持)。用两条命令就能看出你属于哪种：

```bash
# CloudFront 的 WebACL 在 us-east-1，不管 backend 部署在哪个区域
aws wafv2 get-logging-configuration --resource-arn <webacl-arn> --region us-east-1 \
  --query 'LoggingConfiguration.[LogDestinationConfigs[0],ManagedByFirewallManager]'
```

日志组和 Firehose 的 ARN 里带着账号 ID，和你自己的对一下就行。`ManagedByFirewallManager` 是 `true`，说明日志写到了 Firewall Manager 管理员账号的桶或投递流里。目的地是 S3 桶，或者 Firehose 背后投递的那个桶，就问 S3 它归谁：

```bash
aws s3api get-bucket-location --bucket <bucket> --expected-bucket-owner <你的账号 ID>
```

成功就是你自己的桶。返回 `AccessDenied`，要么桶归别的账号，要么你根本读不了它。2026-10-15 两种情况都实测过，一次填对的账号，一次填编造的账号。

## 账号级检查

在准备部署 backend 的账号和区域里，用准备来部署的那个身份跑。

### Claude Sonnet 5 能不能用

```bash
aws bedrock get-foundation-model-availability --model-id anthropic.claude-sonnet-5 --region <region>
```

四个字段都应该是 `AVAILABLE` 或 `AUTHORIZED`。`agreementAvailability` 不是的话，说明还没交 Anthropic 的首次使用表单。这张表每个账号交一次，也可以在 Organization 的管理账号交一次，成员账号会继承。在 Bedrock 控制台的模型目录里随便点开一个 Anthropic 模型就能交。

### 第一次调用你自己来

```bash
aws bedrock-runtime converse --model-id global.anthropic.claude-sonnet-5 --region <region> \
  --messages '[{"role":"user","content":[{"text":"Reply with OK"}]}]'
```

这一条能一次查清两件事。不查的话，它们只会表现成 agent 一直不回话。

**账号第一次调用模型时，会通过 AWS Marketplace 自动订阅。** AWS 文档写明，发起这次调用的身份需要 `aws-marketplace:Subscribe` 和 `aws-marketplace:ViewSubscriptions`。agent 的执行角色故意没给这两个权限。只要有一次调用成功，账号里所有角色以后调模型都不再需要它们。这一步这里没有实测到，因为测试账号早就订阅过了。

**按区域放行的 SCP 可能拦住默认模型。** `global.` 开头的 profile 在鉴权时，`aws:RequestedRegion` 的值是 `unspecified`。SCP 如果列了允许的区域，就得把这个值也加进去，或者用 `bedrock:InferenceProfileArn` 条件给 Bedrock 开例外。被拦住时报的是 `AccessDeniedException`，里面会提到 service control policy 的显式拒绝。如果组织本来就不允许 global 路由，就把 `ModelId` 换成地理 profile：us-east-1、us-east-2、us-west-2 用 `us.`，eu-west-1、eu-central-1 用 `eu.`，ap-southeast-2 用 `au.`。ap-northeast-1、ap-southeast-1、ap-south-1 没有地理 profile，唯一的办法是把 `ModelRegion` 指到有地理 profile 的区域，可这样推理照样出了你所在的地域。

### AgentCore 的 service-linked role

```bash
aws iam get-role --role-name AWSServiceRoleForBedrockAgentCoreRuntimeIdentity
```

已经有了就不用管。没有的话，账号里建第一个 runtime 时 AgentCore 会自动创建它，所以建 backend 栈的那个身份，这一次需要 `iam:CreateServiceLinkedRole`。下面的部署角色给的就是这个权限，不多不少。

## 谁来部署，用什么权限

管理员可以把整份指南跑完。组织不发管理员权限的话，就用 [`deploy/deployer-role.yaml`](../deploy/deployer-role.yaml)，权限窄得多。由管理员部署一次，它会建出两样东西：

- `cfn-<prefix>`：一个 CloudFormation service role，其他几个模板里所有资源的创建、更新、删除权限都在它身上。
- `<prefix>-deployer`：给跑指南的人用的托管策略。它只能通过上面那个 role 操作栈，另外能做指南里 CloudFormation 以外的那些步骤：上面的检查、推镜像、同步知识库、上传前端、建第一个用户、清理。

```bash
aws cloudformation deploy \
  --template-file deploy/deployer-role.yaml \
  --stack-name deployer-waf-agent \
  --region <region> \
  --capabilities CAPABILITY_NAMED_IAM

aws cloudformation describe-stacks --stack-name deployer-waf-agent --region <region> \
  --query 'Stacks[0].Outputs' --output table
```

把 `DeployerPolicyArn` 挂到负责部署的用户或角色上，然后指南里每一条 `aws cloudformation deploy` 都加上 `--role-arn <CloudFormationRoleArn>`。2026-10-15 实测：部署身份只挂了这一份策略，每个角色都带着 permissions boundary，通过这个 role 把五个栈全部建好、更新了一次 backend、再全部删掉，部署出来的 agent 能正常回答。那次镜像是在 CodeBuild 上构建的，所以有两部分没跑到：策略里本机推镜像的权限，以及 service-linked role 的创建权限（测试账号里早就有了）。

用它有三条规矩：

- **栈名必须以 `StackNamePrefix` 开头**，默认是 `waf-agent`。每个栈建的角色都按栈名命名，IAM 权限的范围也就按这个前缀划。指南里的栈名本来就符合。部署角色自己这个栈叫 `deployer-waf-agent`，是故意不带前缀的。
- **不要把部署策略挂到名字以这个前缀开头的角色上。** service role 能改写这类角色。
- **不设 permissions boundary 的话，它只能防误操作，防不了有意为之。** 模板要建角色，就得有 `iam:PutRolePolicy`，而 IAM 没法限制 inline 策略里写什么。所以能通过这个 role 部署的人，就能造出一个权限任意的角色。设了 boundary，它建出的每个角色都有上限，设它的理由就在这里。

## Permissions boundary

组织要求必须带 boundary 的话，给 `deployer-role.yaml`、`image-build.yaml`、`kb.yaml`、`backend.yaml`、`sessions-api.yaml` 都传 `PermissionsBoundary=<policy-arn>`。frontend 栈不建角色，不用传。设了这个参数以后，service role 只肯建带着这个 boundary 的角色，别的一律拒绝。这一点也实测过：有一版模板的角色没法带 boundary，结果在 `iam:CreateRole` 就被拒了。

boundary 必须放行每个角色要做的事。否则栈能部署成功，agent 却会在之后出错。执行角色的权限见 [IAM 权限说明](iam-permissions_zh.md)。另外四个角色权限很少，策略直接写在模板里：CodeBuild 角色往 ECR 推镜像；构建用的 Lambda 负责启动构建；知识库角色读文档桶、写向量、调用 Titan 向量模型；sessions 的 Lambda 读取和删除会话表里的条目。

组织不要求 boundary，就哪里都别传 `PermissionsBoundary`，什么都不会变。
