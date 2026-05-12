// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { config } from './config';

/**
 * Invoke AgentCore with AG-UI protocol format.
 * Yields parsed SSE events.
 *
 * @param {string|null} prompt - User message (null for resume)
 * @param {string} token - Cognito JWT
 * @param {string} sessionId - Session ID (≥33 chars)
 * @param {Array|null} interruptResponses - Resume payload [{interruptId, response}]
 */
export async function* invokeAgent(prompt, token, sessionId, interruptResponses = null, userEmail = '') {
  const arn = encodeURIComponent(config.agentRuntimeArn);
  const url = `${config.agentEndpoint}/runtimes/${arn}/invocations`;

  let body;
  if (interruptResponses) {
    // Resume from interrupt
    body = { threadId: sessionId, interruptResponses };
  } else {
    // Normal AG-UI RunAgentInput
    body = {
      threadId: sessionId,
      runId: crypto.randomUUID(),
      state: {},
      messages: [
        {
          id: crypto.randomUUID(),
          role: 'user',
          content: prompt,
          createdAt: new Date().toISOString(),
        },
      ],
      tools: [],
      context: [],
      forwardedProps: {},
    };
  }

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'text/event-stream',
      'Authorization': `Bearer ${token}`,
      'X-Amzn-Bedrock-AgentCore-Runtime-Session-Id': sessionId,
      ...(userEmail && { 'X-Amzn-Bedrock-AgentCore-Runtime-Custom-User-Id': userEmail }),
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const err = new Error(`Agent error: ${response.status}`);
    err.status = response.status;
    throw err;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop();

    for (const line of lines) {
      if (line.startsWith('data: ')) {
        try {
          yield JSON.parse(line.slice(6));
        } catch { /* skip malformed */ }
      }
    }
  }
}


/**
 * List user's session history.
 */
export async function listSessions(token, userEmail) {
  const arn = encodeURIComponent(config.agentRuntimeArn);
  const res = await fetch(`${config.agentEndpoint}/runtimes/${arn}/sessions`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      ...(userEmail && { 'X-Amzn-Bedrock-AgentCore-Runtime-Custom-User-Id': userEmail }),
    },
  });
  if (!res.ok) return [];
  const data = await res.json();
  return data.sessions || [];
}

/**
 * Get messages for a specific session.
 */
export async function getSessionMessages(token, userEmail, sessionId) {
  const arn = encodeURIComponent(config.agentRuntimeArn);
  const res = await fetch(`${config.agentEndpoint}/runtimes/${arn}/sessions/${sessionId}`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      ...(userEmail && { 'X-Amzn-Bedrock-AgentCore-Runtime-Custom-User-Id': userEmail }),
    },
  });
  if (!res.ok) return [];
  const data = await res.json();
  return data.messages || [];
}

/**
 * Delete a session.
 */
export async function deleteSession(token, userEmail, sessionId) {
  const arn = encodeURIComponent(config.agentRuntimeArn);
  await fetch(`${config.agentEndpoint}/runtimes/${arn}/sessions/${sessionId}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${token}`,
      ...(userEmail && { 'X-Amzn-Bedrock-AgentCore-Runtime-Custom-User-Id': userEmail }),
    },
  });
}
