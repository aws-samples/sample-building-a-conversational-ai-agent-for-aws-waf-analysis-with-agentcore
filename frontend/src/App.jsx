import React, { useState, useRef, useEffect } from 'react';
import { signIn, signOut, getToken, isAuthenticated, completeNewPassword, confirmResetPassword } from './auth';
import { invokeAgent } from './agent';

function generateSessionId() {
  return crypto.randomUUID() + crypto.randomUUID().slice(0, 2); // 38 chars > 33
}

export default function App() {
  const [user, setUser] = useState(isAuthenticated());
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [loginForm, setLoginForm] = useState({ email: '', password: '' });
  const [newPassForm, setNewPassForm] = useState(null); // { cognitoUser, newPassword }
  const [resetForm, setResetForm] = useState(null); // { email, code, newPassword }
  const sessionId = useRef(generateSessionId());
  const messagesEnd = useRef(null);
  const pendingResolve = useRef(null);

  useEffect(() => { messagesEnd.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  async function handleLogin(e) {
    e.preventDefault();
    try {
      const result = await signIn(loginForm.email, loginForm.password);
      if (result.newPasswordRequired) {
        setNewPassForm({ cognitoUser: result.cognitoUser, newPassword: '' });
      } else if (result.passwordResetRequired) {
        setResetForm({ email: result.email, code: '', newPassword: '' });
      } else {
        setUser(true);
      }
    } catch (err) {
      alert(err.message);
    }
  }

  async function handleNewPassword(e) {
    e.preventDefault();
    try {
      await completeNewPassword(newPassForm.cognitoUser, newPassForm.newPassword);
      setNewPassForm(null);
      setUser(true);
    } catch (err) {
      alert(err.message);
    }
  }

  async function handleResetPassword(e) {
    e.preventDefault();
    try {
      await confirmResetPassword(resetForm.email, resetForm.code, resetForm.newPassword);
      setResetForm(null);
      alert('Password reset successful. Please sign in with your new password.');
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
            assistantMsg = { ...assistantMsg, _argsBuffer: '', tools: [...assistantMsg.tools, { name: event.toolCallName, id: event.toolCallId, status: 'running' }] };
            setMessages(prev => [...prev.slice(0, -1), assistantMsg]);
            break;
          case 'TOOL_CALL_ARGS':
            if (assistantMsg.tools.at(-1)?.name === 'ask_user') {
              assistantMsg = { ...assistantMsg, _argsBuffer: (assistantMsg._argsBuffer || '') + (event.delta || '') };
              setMessages(prev => [...prev.slice(0, -1), assistantMsg]);
            }
            break;
          case 'TOOL_CALL_END':
            assistantMsg = { ...assistantMsg, tools: assistantMsg.tools.map((t, i) => i === assistantMsg.tools.length - 1 ? { ...t, status: 'done' } : t) };
            setMessages(prev => [...prev.slice(0, -1), assistantMsg]);
            // Handle ask_user completion
            if (assistantMsg.tools.at(-1)?.name === 'ask_user' && assistantMsg._argsBuffer) {
              try {
                const args = JSON.parse(assistantMsg._argsBuffer);
                if (args.question) {
                  setLoading(false);
                  const answer = await waitForUserInput(args.question);
                  setMessages(prev => [...prev, { role: 'user', content: answer }]);
                  await runAgent(answer);
                  return;
                }
              } catch { /* malformed args */ }
            }
            break;
        }
      }
    } catch (err) {
      if (err.status === 401 || err.message === 'Session expired') {
        setUser(null);
      } else {
        setMessages(prev => [...prev, { role: 'error', content: err.message }]);
      }
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
    if (resetForm) {
      return (
        <div className="login">
          <h1>Reset Password</h1>
          <p style={{color:'#aaa',fontSize:'0.9rem',marginBottom:'0.5rem'}}>Enter the code sent to your email</p>
          <form onSubmit={handleResetPassword}>
            <input type="text" placeholder="Verification code" value={resetForm.code} onChange={e => setResetForm({ ...resetForm, code: e.target.value })} required />
            <input type="password" placeholder="New password" value={resetForm.newPassword} onChange={e => setResetForm({ ...resetForm, newPassword: e.target.value })} required minLength={8} />
            <button type="submit">Reset Password</button>
          </form>
        </div>
      );
    }
    if (newPassForm) {
      return (
        <div className="login">
          <h1>Set New Password</h1>
          <form onSubmit={handleNewPassword}>
            <input type="password" placeholder="New password" value={newPassForm.newPassword} onChange={e => setNewPassForm({ ...newPassForm, newPassword: e.target.value })} required minLength={8} />
            <button type="submit">Set Password</button>
          </form>
        </div>
      );
    }
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
