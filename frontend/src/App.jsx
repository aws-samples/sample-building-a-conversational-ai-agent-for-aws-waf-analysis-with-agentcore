import React, { useState, useRef, useEffect } from 'react';
import { marked } from 'marked';
import { signIn, signOut, getToken, isAuthenticated, completeNewPassword, confirmResetPassword } from './auth';
import { invokeAgent } from './agent';

function generateSessionId() {
  return crypto.randomUUID() + crypto.randomUUID().slice(0, 2);
}

function ReportDownload({ html }) {
  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const [showPreview, setShowPreview] = useState(false);
  return (
    <div className="report-card">
      <div className="report-header">📊 WAF Weekly Business Report</div>
      <div className="report-actions">
        <a href={url} download="waf-weekly-report.html" className="btn btn-primary">⬇ Download HTML</a>
        <button onClick={() => setShowPreview(!showPreview)} className="btn btn-secondary">{showPreview ? '✕ Close Preview' : '👁 Preview Report'}</button>
      </div>
      {showPreview && <iframe srcDoc={html} sandbox="allow-scripts" className="report-iframe" />}
    </div>
  );
}

function MessageContent({ content }) {
  // Check if content contains an HTML report (may be mixed with text)
  const htmlMatch = content.match(/(<!DOCTYPE html[\s\S]*<\/html>)/i) || content.match(/(<html[\s\S]*<\/html>)/i);
  if (htmlMatch) {
    const textBefore = content.slice(0, htmlMatch.index).trim();
    const html = htmlMatch[1];
    return (
      <>
        {textBefore && <div className="content markdown" dangerouslySetInnerHTML={{ __html: marked.parse(textBefore, { breaks: true }) }} />}
        <ReportDownload html={html} />
      </>
    );
  }
  const rendered = marked.parse(content, { breaks: true });
  return <div className="content markdown" dangerouslySetInnerHTML={{ __html: rendered }} />;
}

export default function App() {
  const [user, setUser] = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [loginForm, setLoginForm] = useState({ email: '', password: '' });
  const [newPassForm, setNewPassForm] = useState(null);
  const [resetForm, setResetForm] = useState(null);
  const [darkMode, setDarkMode] = useState(true);
  const sessionId = useRef(generateSessionId());
  const messagesEnd = useRef(null);
  const pendingResolve = useRef(null);

  useEffect(() => { messagesEnd.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);
  useEffect(() => { document.documentElement.setAttribute('data-theme', darkMode ? 'dark' : 'light'); }, [darkMode]);

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
            assistantMsg = { ...assistantMsg, content: assistantMsg.content + (event.delta || '') };
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
          case 'TOOL_CALL_RESULT':
            assistantMsg = { ...assistantMsg, tools: assistantMsg.tools.map((t, i) => i === assistantMsg.tools.length - 1 ? { ...t, status: 'done' } : t) };
            if (assistantMsg.tools.at(-1)?.name === 'set_report_summary' && event.content) {
              const html = typeof event.content === 'string' ? event.content : JSON.stringify(event.content);
              if (html.includes('<!DOCTYPE') || html.includes('<html')) {
                assistantMsg = { ...assistantMsg, reportHtml: html };
              }
            }
            setMessages(prev => [...prev.slice(0, -1), assistantMsg]);
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
    if (resetForm) {
      return (
        <div className="login">
          <h1>Reset Password</h1>
          <p className="login-hint">Enter the code sent to your email</p>
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
        <div className="header-actions">
          <button onClick={() => setDarkMode(!darkMode)} className="theme-toggle">{darkMode ? '☀️' : '🌙'}</button>
          <button onClick={() => { signOut(); setUser(null); }}>Sign Out</button>
        </div>
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
            {msg.reportHtml && <ReportDownload html={msg.reportHtml} />}
            {msg.content && <MessageContent content={msg.content} />}
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
