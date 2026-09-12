#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Sync KB documents to S3 and trigger ingestion.
# Usage: ./deploy/sync-kb.sh [stack-name] [docs-dir] [region]

set -euo pipefail

STACK="${1:-waf-agent-kb}"
DOCS_DIR="${2:-./kb-docs}"
# Third argument first, because the deployment guide has you `export REGION`, not
# AWS_REGION. A shell with AWS_REGION pointing somewhere else would otherwise read the
# stack outputs from the wrong region and fail with a confusing "stack does not exist".
REGION="${3:-${AWS_REGION:-${REGION:-ap-northeast-1}}}"
PROFILE="${AWS_PROFILE:-}"

PROFILE_ARG=""
if [ -n "$PROFILE" ]; then
  PROFILE_ARG="--profile $PROFILE"
fi

echo "Reading outputs from stack: $STACK (region: $REGION)"

BUCKET=$(aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" $PROFILE_ARG \
  --query "Stacks[0].Outputs[?OutputKey=='DocumentsBucketName'].OutputValue" --output text)
KB_ID=$(aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" $PROFILE_ARG \
  --query "Stacks[0].Outputs[?OutputKey=='KnowledgeBaseId'].OutputValue" --output text)
DS_ID=$(aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" $PROFILE_ARG \
  --query "Stacks[0].Outputs[?OutputKey=='DataSourceId'].OutputValue" --output text)

echo "Bucket: $BUCKET"
echo "KB ID:  $KB_ID"
echo "DS ID:  $DS_ID"
echo ""

echo "Syncing $DOCS_DIR → s3://$BUCKET/"
aws s3 sync "$DOCS_DIR" "s3://$BUCKET/" --region "$REGION" $PROFILE_ARG

echo ""
echo "Starting ingestion job..."
aws bedrock-agent start-ingestion-job \
  --knowledge-base-id "$KB_ID" --data-source-id "$DS_ID" --region "$REGION" $PROFILE_ARG

echo ""
echo "Done. Ingestion is async. Check status:"
echo "  aws bedrock-agent list-ingestion-jobs --knowledge-base-id $KB_ID --data-source-id $DS_ID --region $REGION $PROFILE_ARG"
