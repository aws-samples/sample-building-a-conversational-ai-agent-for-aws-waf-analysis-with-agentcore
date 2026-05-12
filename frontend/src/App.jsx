// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import React, { useState, useRef, useEffect } from 'react';
import { marked } from 'marked';
import { signIn, signOut, getToken, isAuthenticated, completeNewPassword, confirmResetPassword, getUserProfile, changePassword } from './auth';
import { invokeAgent, listSessions, getSessionMessages, deleteSession } from './agent';
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
      a.href = url; a.download = 'waf-roi-report.html'; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { setError(e.message); }
  }

  return (
    <div className="report-card">
      <div className="report-header">📊 WAF ROI Report</div>
      {error && <div style={{color:'#f87171',fontSize:'0.85rem',marginBottom:'0.5rem'}}>⚠ {error}</div>}
      <div className="report-actions">
        <button onClick={fetchReport} className="btn btn-primary">⬇ {html ? 'Download Again' : 'Download HTML'}</button>
        {html && <button onClick={() => setShowPreview(!showPreview)} className="btn btn-secondary">{showPreview ? '✕ Close' : '👁 Preview'}</button>}
      </div>
      {showPreview && html && <iframe srcDoc={html} sandbox="allow-scripts" className="report-iframe" />}
    </div>
  );
}

function MessageContent({ content, onShare, selectMode }) {
  const [copied, setCopied] = useState(false);
  const rendered = marked.parse(content, { breaks: true });

  function copyMarkdown() {
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  function exportMarkdown() {
    const blob = new Blob([content], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'waf-agent-response.md'; a.click();
    URL.revokeObjectURL(url);
  }

  function exportHTML() {
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><style>body{font-family:system-ui,sans-serif;max-width:800px;margin:2rem auto;padding:0 1rem;line-height:1.6}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left}th{background:#f5f5f5}code{background:#f0f0f0;padding:2px 6px;border-radius:3px}pre{background:#f5f5f5;padding:1rem;overflow-x:auto;border-radius:6px}</style></head><body>${rendered}</body></html>`;
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'waf-agent-response.html'; a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="content-wrapper">
      <div className="content markdown" dangerouslySetInnerHTML={{ __html: rendered }} />
      {!selectMode && (
        <div className="msg-actions">
          <button className="msg-action-btn" onClick={copyMarkdown} title="Copy as Markdown">
            {copied ? <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="20 6 9 17 4 12"/></svg>
            : <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>}
          </button>
          <button className="msg-action-btn" onClick={exportMarkdown} title="Export as Markdown">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          </button>
          <button className="msg-action-btn" onClick={exportHTML} title="Export as HTML">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
          </button>
          <button className="msg-action-btn" onClick={onShare} title="Select messages to export">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
          </button>
        </div>
      )}
    </div>
  );
}

function UserMenu({ onSignOut }) {
  const [open, setOpen] = useState(false);
  const [profile, setProfile] = useState(null);
  const [pwForm, setPwForm] = useState(null);
  const [pwMsg, setPwMsg] = useState('');

  useEffect(() => { getUserProfile().then(setProfile).catch(() => {}); }, []);

  async function handleChangePw(e) {
    e.preventDefault();
    setPwMsg('');
    if (pwForm.newPw !== pwForm.confirmPw) { setPwMsg('❌ Passwords do not match'); return; }
    try {
      await changePassword(pwForm.oldPw, pwForm.newPw);
      setPwMsg('✅ Password changed');
      setPwForm(null);
    } catch (err) { setPwMsg('❌ ' + (err.message || err)); }
  }

  return (
    <div className="user-menu">
      <button className="user-avatar" onClick={() => setOpen(!open)}>👤</button>
      {open && (
        <div className="user-dropdown">
          {profile && <div className="user-email-display">{profile.email}</div>}
          <hr />
          {!pwForm ? (
            <button className="dropdown-btn" onClick={() => setPwForm({ oldPw: '', newPw: '', confirmPw: '' })}>Change Password</button>
          ) : (
            <form onSubmit={handleChangePw} className="pw-form">
              <input type="password" placeholder="Current password" value={pwForm.oldPw} onChange={e => setPwForm({ ...pwForm, oldPw: e.target.value })} required />
              <input type="password" placeholder="New password" value={pwForm.newPw} onChange={e => setPwForm({ ...pwForm, newPw: e.target.value })} required minLength={8} />
              <input type="password" placeholder="Confirm new password" value={pwForm.confirmPw} onChange={e => setPwForm({ ...pwForm, confirmPw: e.target.value })} required minLength={8} />
              <div className="pw-hint">Min 8 chars, uppercase, lowercase, number, special char</div>
              <div className="pw-form-actions">
                <button type="submit">Confirm</button>
                <button type="button" onClick={() => { setPwForm(null); setPwMsg(''); }}>Cancel</button>
              </div>
            </form>
          )}
          {pwMsg && <div className="pw-msg">{pwMsg}</div>}
          <hr />
          <button className="dropdown-btn signout" onClick={onSignOut}>Sign Out</button>
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState(null); // null = checking, false = not logged in, true = logged in
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [loginForm, setLoginForm] = useState({ email: '', password: '' });
  const [selectMode, setSelectMode] = useState(false);
  const [selected, setSelected] = useState(new Set());
  const [newPassForm, setNewPassForm] = useState(null);
  const [resetForm, setResetForm] = useState(null);
  const [darkMode, setDarkMode] = useState(true);
  const sessionId = useRef(generateSessionId());
  const messagesEnd = useRef(null);
  const pendingResolve = useRef(null);

  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [sidebarLang, setSidebarLang] = useState('zh');
  const [sessions, setSessions] = useState([]);
  const [activeSessionId, setActiveSessionId] = useState(sessionId.current);

  useEffect(() => { getToken().then(() => setUser(true)).catch(() => setUser(false)); }, []);
  useEffect(() => { messagesEnd.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);
  useEffect(() => { document.documentElement.setAttribute('data-theme', darkMode ? 'dark' : 'light'); }, [darkMode]);
  useEffect(() => { if (user) loadSessions(); }, [user]);

  async function loadSessions() {
    try {
      const token = await getToken();
      const list = await listSessions(token);
      setSessions(list);
    } catch {}
  }

  async function handleSwitchSession(sid) {
    if (sid === activeSessionId) return;
    try {
      const token = await getToken();
      const msgs = await getSessionMessages(token, sid);
      setMessages(msgs.map(m => ({ role: m.role, content: m.content, tools: m.tools?.map(t => ({ ...t })) || [] })));
      sessionId.current = generateSessionId(); // new runtime session (old container dead)
      setActiveSessionId(sid);
    } catch {}
  }

  function handleNewSession() {
    sessionId.current = generateSessionId();
    setActiveSessionId(sessionId.current);
    setMessages([]);
  }

  async function handleDeleteSession(sid, e) {
    e.stopPropagation();
    try {
      const token = await getToken();
      await deleteSession(token, sid);
      setSessions(prev => prev.filter(s => s.sessionId !== sid));
      if (sid === activeSessionId) handleNewSession();
    } catch {}
  }

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

  async function runAgent(prompt, interruptResponses = null) {
    setLoading(true);
    try {
      const token = await getToken();
      let assistantMsg = { role: 'assistant', content: '', tools: [] };
      setMessages(prev => [...prev, assistantMsg]);

      for await (const event of invokeAgent(prompt, token, sessionId.current, interruptResponses)) {
        switch (event.type) {
          case 'TEXT_MESSAGE_CONTENT':
            assistantMsg = { ...assistantMsg, content: assistantMsg.content + (event.delta || '') };
            setMessages(prev => [...prev.slice(0, -1), assistantMsg]);
            break;
          case 'TOOL_CALL_START':
            assistantMsg = { ...assistantMsg, tools: [...assistantMsg.tools, { name: event.toolCallName, id: event.toolCallId, status: 'running' }] };
            setMessages(prev => [...prev.slice(0, -1), assistantMsg]);
            break;
          case 'TOOL_CALL_END':
          case 'TOOL_CALL_RESULT':
            assistantMsg = { ...assistantMsg, tools: assistantMsg.tools.map(t => t.id === event.toolCallId ? { ...t, status: 'done' } : t) };
            if (assistantMsg.tools.at(-1)?.name === 'set_report_summary') {
              assistantMsg = { ...assistantMsg, hasReport: true };
            }
            setMessages(prev => [...prev.slice(0, -1), assistantMsg]);
            break;
          case 'CUSTOM':
            if (event.name === 'interrupt' && event.value?.interrupts?.length) {
              const interrupt = event.value.interrupts[0];
              const question = interrupt.reason?.question || interrupt.reason || 'Agent needs your input';
              setLoading(false);
              const answer = await waitForUserInput(question);
              setMessages(prev => [...prev, { role: 'user', content: answer }]);
              await runAgent(null, [{ interruptId: interrupt.id, response: answer }]);
              return;
            }
            break;
        }
      }
    } catch (err) {
      setMessages(prev => [...prev, { role: 'error', content: err.message }]);
    }
    setLoading(false);
    loadSessions();
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

  function toggleSelect(idx) {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(idx) ? next.delete(idx) : next.add(idx);
      return next;
    });
  }

  function exportSelectedHTML() {
    const msgs = [...selected].sort((a, b) => a - b).map(i => messages[i]).filter(Boolean);
    const body = msgs.map(msg => {
      const role = msg.role === 'user' ? 'You' : 'WAF Agent';
      const roleClass = msg.role === 'user' ? 'user' : 'assistant';
      const content = msg.role === 'user' ? `<p>${msg.content.replace(/</g,'&lt;').replace(/\n/g,'<br>')}</p>` : marked.parse(msg.content || '', { breaks: true });
      return `<div class="msg ${roleClass}"><div class="role">${role}</div><div class="content">${content}</div></div>`;
    }).join('\n');
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>WAF Agent Conversation</title><style>
body{font-family:system-ui,sans-serif;max-width:800px;margin:2rem auto;padding:0 1rem;line-height:1.6;background:#fafafa}
.msg{margin:1rem 0;padding:1rem 1.2rem;border-radius:10px;border:1px solid #e5e5e5}
.msg.user{background:#e8f4fd;border-color:#b8daef}
.msg.assistant{background:#fff;border-color:#ddd}
.role{font-weight:600;font-size:0.8rem;color:#666;margin-bottom:0.4rem;text-transform:uppercase;letter-spacing:0.5px}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left}th{background:#f5f5f5}
code{background:#f0f0f0;padding:2px 6px;border-radius:3px}pre{background:#f5f5f5;padding:1rem;overflow-x:auto;border-radius:6px}
</style></head><body><h1>WAF Agent Conversation</h1>${body}</body></html>`;
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'waf-agent-conversation.html'; a.click();
    URL.revokeObjectURL(url);
    setSelectMode(false);
    setSelected(new Set());
  }

  if (user === null) return null; // checking session...
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

  const guideItems = sidebarLang === 'zh'
    ? ['"生成价值报告"', '"检测绕过攻击"', '"检测爬虫"', '"你能做什么？"']
    : ['"Generate ROI report"', '"Detect bypass attacks"', '"Detect crawlers"', '"What can you do?"'];

  return (
    <div className="app-layout">
      {sidebarOpen && (
        <aside className="sidebar">
          <div className="sidebar-top">
            <button className="sidebar-close" onClick={() => setSidebarOpen(false)}>✕</button>
            <button className="sidebar-lang-btn" onClick={() => setSidebarLang(sidebarLang === 'zh' ? 'en' : 'zh')}>{sidebarLang === 'zh' ? 'EN' : '中'}</button>
          </div>
          <button className="new-session-btn" onClick={handleNewSession}>+ {sidebarLang === 'zh' ? '新建会话' : 'New Chat'}</button>
          {sessions.length > 0 && (
            <div className="session-list">
              {sessions.map(s => (
                <div key={s.sessionId} className={`session-item${s.sessionId === activeSessionId ? ' active' : ''}`} onClick={() => handleSwitchSession(s.sessionId)}>
                  <span className="session-title">{s.title || '(untitled)'}</span>
                  <button className="session-delete" onClick={(e) => handleDeleteSession(s.sessionId, e)}>×</button>
                </div>
              ))}
            </div>
          )}
          <div className="sidebar-quickstart">
            <h3>⚡ {sidebarLang === 'zh' ? '试试这样问' : 'Try asking'}</h3>
            <ul>{guideItems.map((t, i) => <li key={i}><em>{t}</em></li>)}</ul>
          </div>
        </aside>
      )}
      <div className="chat">
        <header>
          {!sidebarOpen && <button className="sidebar-open" onClick={() => setSidebarOpen(true)}>☰</button>}
        <h1>WAF Agent</h1>
        <div className="header-actions">
          <button onClick={() => setDarkMode(!darkMode)} className="theme-toggle">{darkMode ? '☀️ Light' : '🌙 Dark'}</button>
          <UserMenu onSignOut={() => { signOut(); setUser(null); }} />
        </div>
      </header>
      <div className="messages">
        {messages.map((msg, i) => (
          <div key={i} className={`msg ${msg.role}${selectMode && selected.has(i) ? ' selected' : ''}`} onClick={selectMode ? () => toggleSelect(i) : undefined}>
            {selectMode && <input type="checkbox" className="msg-checkbox" checked={selected.has(i)} onChange={() => toggleSelect(i)} />}
            {msg.tools?.length > 0 && (
              <div className="tools">
                {msg.tools.map((t, j) => (
                  <span key={j} className={`tool ${t.status}`}>{t.status === 'running' ? '⏳' : '✅'} {t.name}</span>
                ))}
              </div>
            )}
            {msg.content && <MessageContent content={msg.content} onShare={() => { setSelectMode(true); setSelected(new Set([i])); }} selectMode={selectMode} />}
            {msg.hasReport && <ReportDownload sessionId={sessionId.current} />}
          </div>
        ))}
        <div ref={messagesEnd} />
      </div>
      {selectMode && (
        <div className="select-bar">
          <span>{selected.size} message{selected.size !== 1 ? 's' : ''} selected</span>
          <button className="btn btn-primary" onClick={exportSelectedHTML} disabled={selected.size === 0}>Export HTML</button>
          <button className="btn btn-secondary" onClick={() => { setSelectMode(false); setSelected(new Set()); }}>Cancel</button>
        </div>
      )}
      <form className="input-bar" onSubmit={pendingResolve.current ? handleUserReply : handleSend}>
        <textarea value={input} onChange={e => { setInput(e.target.value); e.target.style.height = 'auto'; e.target.style.height = Math.min(e.target.scrollHeight, 200) + 'px'; }} onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); e.target.form.requestSubmit(); } }} placeholder="Ask about your WAF... (Shift+Enter for new line)" disabled={loading} autoFocus rows={1} />
        <button type="submit" disabled={loading}>{loading ? '...' : '→'}</button>
      </form>
    </div>
    </div>
  );
}
