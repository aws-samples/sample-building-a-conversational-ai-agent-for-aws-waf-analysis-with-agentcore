import { config } from './config';

/**
 * Invoke AgentCore with AG-UI streaming.
 * Yields parsed SSE events: { type, messageId, delta, toolCallId, toolCallName, content, ... }
 */
export async function* invokeAgent(prompt, token, sessionId) {
  const arn = encodeURIComponent(config.agentRuntimeArn);
  const url = `${config.agentEndpoint}/runtimes/${arn}/invocations`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'text/event-stream',
      'Authorization': `Bearer ${token}`,
      'X-Amzn-Bedrock-AgentCore-Runtime-Session-Id': sessionId,
    },
    body: JSON.stringify({ prompt }),
  });

  if (!response.ok) {
    throw new Error(`Agent error: ${response.status} ${response.statusText}`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop(); // keep incomplete line

    for (const line of lines) {
      if (line.startsWith('data: ')) {
        try {
          yield JSON.parse(line.slice(6));
        } catch { /* skip malformed */ }
      }
    }
  }
}
