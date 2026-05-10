import React, { useState, useRef, useEffect } from 'react';
import { marked } from 'marked';
import { signIn, signOut, getToken, isAuthenticated, completeNewPassword, confirmResetPassword } from './auth';
import { invokeAgent } from './agent';
import { config } from './config';

function generateSessionId() {
  return crypto.randomUUID() + crypto.randomUUID().slice(0, 2);
}

function ReportDownload({ sessionId }) {
  const [html, setHtml] = useState(null);
  const [error, setError] = useState(null);
  const [showPreview, setShowPreview] = useState(false);
  const fetched = useRef(false);

  useEffect(() => {
    if (fetched.current) return;
    fetched.current = true;
    fetchReport();
  }, []);

  async function fetchReport() {
    setError(null);
    try {
      const token = await getToken();
      const arn = encodeURIComponent(config.agentRuntimeArn);
      const res = await fetch(`${config.agentEndpoint}/runtimes/${arn}/invocations`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'text/event-stream',
          'Authorization': `Bearer ${token}`,
          'X-Amzn-Bedrock-AgentCore-Runtime-Session-Id': sessionId,
        },
        body: JSON.stringify({ prompt: '__get_report__' }),
      });
      if (!res.ok) { setError(`HTTP ${res.status}`); return; }
      const text = await res.text();
      let content = '';
      for (const line of text.split('\n')) {
        if (line.startsWith('data: ')) {
          try {
            const evt = JSON.parse(line.slice(6));
            if (evt.type === 'TEXT_MESSAGE_CONTENT') content += evt.delta || '';
          } catch {}
        }
      }
      if (!content) { setError('Empty report'); return; }
      setHtml(content);
      const blob = new Blob([content], { type: 'text/html' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'waf-weekly-report.html'; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { setError(e.message); }
  }

  return (
    <div className="report-card">
      <div className="report-header">📊 WAF Weekly Business Report</div>
      {error && <div style={{color:'#f87171',fontSize:'0.85rem',marginBottom:'0.5rem'}}>⚠ {error}</div>}
      <div className="report-actions">
        <button onClick={fetchReport} className="btn btn-primary">⬇ {html ? 'Download Again' : 'Download HTML'}</button>
        {html && <button onClick={() => setShowPreview(!showPreview)} className="btn btn-secondary">{showPreview ? '✕ Close' : '👁 Preview'}</button>}
      </div>
      {showPreview && html && <iframe srcDoc={html} sandbox="allow-scripts" className="report-iframe" />}
    </div>
  );
}

function MessageContent({ content }) {
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

  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [sidebarLang, setSidebarLang] = useState('zh');

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
            if (assistantMsg.tools.at(-1)?.name === 'set_report_summary') {
              assistantMsg = { ...assistantMsg, hasReport: true };
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

  const guideContent = {
    zh: {
      title: '使用指南',
      quickStart: '⚡ 试试这样问',
      items: ['"生成周报"', '"分析这个IP: 1.2.3.4"', '"检测绕过攻击"', '"检测爬虫"', '"你能做什么？"'],
      notes: '⚠️ 注意事项',
      noteItems: ['会话空闲 15 分钟后超时，请及时下载报告', '首次查询可能需要 ~30 秒（冷启动）', '周报生成约需 1–2 分钟'],
    },
    en: {
      title: 'Guide',
      quickStart: '⚡ Try asking',
      items: ['"Generate weekly report"', '"Analyze IP: 1.2.3.4"', '"Detect bypass attacks"', '"Detect crawlers"', '"What can you do?"'],
      notes: '⚠️ Notes',
      noteItems: ['Session times out after 15 min idle — download reports promptly', 'First query may take ~30s (cold start)', 'Report generation takes 1–2 min'],
    },
  };
  const guide = guideContent[sidebarLang];

  return (
    <div className="app-layout">
      {sidebarOpen && (
        <aside className="sidebar">
          <div className="sidebar-top">
            <button className="sidebar-close" onClick={() => setSidebarOpen(false)}>✕</button>
            <button className="sidebar-lang" onClick={() => setSidebarLang(sidebarLang === 'zh' ? 'en' : 'zh')}>{sidebarLang === 'zh' ? 'Eng' : '中文'}</button>
          </div>
          <h2>{guide.title}</h2>
          <section>
            <h3>{guide.quickStart}</h3>
            <ul>{guide.items.map((t, i) => <li key={i}><em>{t}</em></li>)}</ul>
          </section>
          <section>
            <h3>{guide.notes}</h3>
            <ul>{guide.noteItems.map((t, i) => <li key={i}>{t}</li>)}</ul>
          </section>
        </aside>
      )}
      <div className="chat">
        <header>
          {!sidebarOpen && <button className="sidebar-open" onClick={() => setSidebarOpen(true)}>☰</button>}
        <h1>WAF Agent</h1>
        <div className="header-actions">
          <button onClick={() => setDarkMode(!darkMode)} className="theme-toggle">{darkMode ? '☀️ Light' : '🌙 Dark'}</button>
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
            {msg.content && <MessageContent content={msg.content} />}
            {msg.hasReport && <ReportDownload sessionId={sessionId.current} />}
          </div>
        ))}
        <div ref={messagesEnd} />
      </div>
      <form className="input-bar" onSubmit={pendingResolve.current ? handleUserReply : handleSend}>
        <textarea value={input} onChange={e => { setInput(e.target.value); e.target.style.height = 'auto'; e.target.style.height = Math.min(e.target.scrollHeight, 200) + 'px'; }} onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); e.target.form.requestSubmit(); } }} placeholder="Ask about your WAF... (Shift+Enter for new line)" disabled={loading} autoFocus rows={1} />
        <button type="submit" disabled={loading}>{loading ? '...' : '→'}</button>
      </form>
    </div>
    </div>
  );
}
