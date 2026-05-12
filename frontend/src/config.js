// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
// Configuration — fill from CloudFormation stack outputs
export const config = {
  // Cognito
  userPoolId: import.meta.env.VITE_USER_POOL_ID || '',
  clientId: import.meta.env.VITE_CLIENT_ID || '',
  region: import.meta.env.VITE_REGION || 'us-east-1',

  // AgentCore
  agentEndpoint: import.meta.env.VITE_AGENT_ENDPOINT || '',
  agentRuntimeArn: import.meta.env.VITE_AGENT_RUNTIME_ARN || '',

  // Sessions API
  sessionsApiUrl: import.meta.env.VITE_SESSIONS_API_URL || '',
};
