import { useAuth } from '../context/AuthContext';
import { HiOutlineBell, HiOutlineSearch, HiOutlineLogout } from 'react-icons/hi';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { alertsAPI, threatIntelAPI } from '../api/client';

export default function TopBar({ title }: { title: string }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [unread, setUnread] = useState(0);
  const [query, setQuery] = useState('');
  const [hint, setHint] = useState<{ verdict: string; matches: number } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    alertsAPI.unreadCount().then(r => setUnread(r.data.unread_count)).catch(() => {});
  }, []);

  const handleQuick = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;
    setBusy(true); setHint(null);
    try {
      const res = await threatIntelAPI.lookup(query.trim());
      setHint({ verdict: res.data.verdict, matches: res.data.match_count });
    } catch {
      setHint(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <header className="topbar">
      <div className="topbar-left">
        <h1 className="topbar-title">{title}</h1>
        <span className="topbar-status-pill">
          <span className="dot" />
          OWASP + DarkWeb online
        </span>
      </div>
      <div className="topbar-right">
        <form onSubmit={handleQuick} className="topbar-search" style={{ display: 'flex', alignItems: 'center', gap: 6, position: 'relative' }}>
          <HiOutlineSearch />
          <input
            className="input" value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="IOC quick check (IP/URL/CVE)…"
            onKeyDown={e => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) navigate('/threat-intel'); }}
          />
          {hint && (
            <span className={`badge badge-${hint.matches ? hint.verdict : 'low'}`} style={{ marginLeft: 4 }}>
              {hint.matches ? `${hint.verdict.toUpperCase()} • ${hint.matches}` : 'CLEAN'}
            </span>
          )}
          {busy && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>…</span>}
        </form>
        <button className="notif-btn" onClick={() => navigate('/feed')} title="Live feed">
          <HiOutlineBell />
          {unread > 0 && <span className="notif-badge" />}
        </button>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div className="avatar" title={user?.username || 'User'}>{user?.username?.[0]?.toUpperCase() || 'U'}</div>
          <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{user?.username || 'User'}</span>
          <button className="notif-btn" onClick={logout} title="Logout">
            <HiOutlineLogout />
          </button>
        </div>
      </div>
    </header>
  );
}
