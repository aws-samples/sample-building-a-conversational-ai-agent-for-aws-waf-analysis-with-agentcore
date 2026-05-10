import React, { useState, useRef, useEffect } from 'react';
import { signIn, signOut, getToken, getCurrentUser } from './auth';
import { invokeAgent } from './agent';

function generateSessionId() {
  return crypto.randomUUID() + crypto.randomUUID().slice(0, 2); // 38 chars > 33
}

export default function App() {
  const [user, setUser] = useState(getCurrentUser());
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [loginForm, setLoginForm] = useState({ email: '', password: '' });
  const sessionId = useRef(generateSessionId());
  const messagesEnd = useRef(null);
  const pendingResolve = useRef(null);

  useEffect(() => { messagesEnd.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  async function handleLogin(e) {
    e.preventDefault();
    try {
      await signIn(loginForm.email, loginForm.password);
      setUser(getCurrentUser());
    } catch (err) {
      alert(err.message);
    }
  }

  async function handleSend(e) {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const prompt = input.trim();
    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: prompt }]);
    await runAgent(prompt);
  }

  async function runAgent(prompt) {
    setLoading(true);
    try {
      const token = await getToken();
      let assistantMsg = { role: 'assistant', content: '', tools: [] };
      setMessages(prev => [...prev, assistantMsg]);

      for await (const event of invokeAgent(prompt, token, sessionId.current)) {
        switch (event.type) {
          case 'TEXT_MESSAGE_CONTENT':
            assistantMsg = { ...assistantMsg, content: assistantMsg.content + event.delta };
            setMessages(prev => [...prev.slice(0, -1), assistantMsg]);
            break;
          case 'TOOL_CALL_START':
            assistantMsg = { ...assistantMsg, tools: [...assistantMsg.tools, { name: event.toolCallName, id: event.toolCallId, status: 'running' }] };
            setMessages(prev => [...prev.slice(0, -1), assistantMsg]);
            break;
          case 'TOOL_CALL_END':
            assistantMsg = { ...assistantMsg, tools: assistantMsg.tools.map((t, i) => i === assistantMsg.tools.length - 1 ? { ...t, status: 'done' } : t) };
            setMessages(prev => [...prev.slice(0, -1), assistantMsg]);
            break;
          case 'TOOL_CALL_ARGS':
            // Check if ask_user tool — prompt user for input
            if (event.toolCallName === 'ask_user' || assistantMsg.tools.at(-1)?.name === 'ask_user') {
              try {
                const args = JSON.parse(event.delta || event.args || '{}');
                if (args.question) {
                  setLoading(false);
                  const answer = await waitForUserInput(args.question);
                  setMessages(prev => [...prev, { role: 'user', content: answer }]);
                  // Continue agent with user's answer
                  await runAgent(answer);
                  return;
                }
              } catch { /* not parseable yet, continue */ }
            }
            break;
        }
      }
    } catch (err) {
      if (err.message?.includes('Not signed in') || err.message?.includes('401')) {
        signOut();
        setUser(null);
        return;
      }
      setMessages(prev => [...prev, { role: 'error', content: err.message }]);
    }
    setLoading(false);
  }

  function waitForUserInput(question) {
    return new Promise((resolve) => {
      setMessages(prev => [...prev, { role: 'assistant', content: question, isQuestion: true }]);
      setLoading(false);
      pendingResolve.current = resolve;
    });
  }

  function handleUserReply(e) {
    e.preventDefault();
    if (!input.trim() || !pendingResolve.current) return;
    const answer = input.trim();
    setInput('');
    pendingResolve.current(answer);
    pendingResolve.current = null;
  }

  if (!user) {
    return (
      <div className="login">
        <h1>WAF Agent</h1>
        <form onSubmit={handleLogin}>
          <input type="email" placeholder="Email" value={loginForm.email} onChange={e => setLoginForm({ ...loginForm, email: e.target.value })} required />
          <input type="password" placeholder="Password" value={loginForm.password} onChange={e => setLoginForm({ ...loginForm, password: e.target.value })} required />
          <button type="submit">Sign In</button>
        </form>
      </div>
    );
  }

  return (
    <div className="chat">
      <header>
        <h1>WAF Agent</h1>
        <button onClick={() => { signOut(); setUser(null); }}>Sign Out</button>
      </header>
      <div className="messages">
        {messages.map((msg, i) => (
          <div key={i} className={`msg ${msg.role}`}>
            {msg.tools?.length > 0 && (
              <div className="tools">
                {msg.tools.map((t, j) => (
                  <span key={j} className={`tool ${t.status}`}>{t.status === 'running' ? '⏳' : '✅'} {t.name}</span>
                ))}
              </div>
            )}
            {msg.content && <div className="content">{msg.content}</div>}
          </div>
        ))}
        <div ref={messagesEnd} />
      </div>
      <form className="input-bar" onSubmit={pendingResolve.current ? handleUserReply : handleSend}>
        <input value={input} onChange={e => setInput(e.target.value)} placeholder="Ask about your WAF..." disabled={loading} autoFocus />
        <button type="submit" disabled={loading}>{loading ? '...' : '→'}</button>
      </form>
    </div>
  );
}
