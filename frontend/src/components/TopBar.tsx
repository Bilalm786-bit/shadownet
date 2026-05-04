import { useAuth } from '../context/AuthContext';
import { HiOutlineBell, HiOutlineSearch } from 'react-icons/hi';
import { useState, useEffect } from 'react';
import { alertsAPI } from '../api/client';

export default function TopBar({ title }: { title: string }) {
  const { user, logout } = useAuth();
  const [unread, setUnread] = useState(0);

  useEffect(() => {
    alertsAPI.unreadCount().then(r => setUnread(r.data.unread_count)).catch(() => {});
  }, []);

  return (
    <header className="topbar">
      <div className="topbar-left">
        <h1 className="topbar-title">{title}</h1>
      </div>
      <div className="topbar-right">
        <div className="topbar-search">
          <HiOutlineSearch />
          <input className="input" placeholder="Search intel..." />
        </div>
        <button className="notif-btn">
          <HiOutlineBell />
          {unread > 0 && <span className="notif-badge" />}
        </button>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }} onClick={logout}>
          <div className="avatar">{user?.username?.[0]?.toUpperCase() || 'U'}</div>
          <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{user?.username || 'User'}</span>
        </div>
      </div>
    </header>
  );
}
