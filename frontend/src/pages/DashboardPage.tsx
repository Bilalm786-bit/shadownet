import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { dashboardAPI } from '../api/client';
import { HiOutlineFolder, HiOutlineUser, HiOutlineChartBar, HiOutlineBell } from 'react-icons/hi';

interface Stats {
  cases: { total: number; active: number };
  targets: number;
  scans: { total: number; completed: number; running: number };
  alerts: { unread: number };
  recent_scans: any[];
  recent_alerts: any[];
}

const defaultStats: Stats = {
  cases: { total: 0, active: 0 }, targets: 0,
  scans: { total: 0, completed: 0, running: 0 },
  alerts: { unread: 0 }, recent_scans: [], recent_alerts: [],
};

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats>(defaultStats);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    dashboardAPI.stats().then(r => setStats(r.data)).catch(() => {}).finally(() => setLoading(false));
  }, []);

  const statCards = [
    { label: 'Active Cases', value: stats.cases.active, total: stats.cases.total, icon: <HiOutlineFolder />, color: 'var(--accent)' },
    { label: 'Targets', value: stats.targets, icon: <HiOutlineUser />, color: 'var(--cyan)' },
    { label: 'Scans Complete', value: stats.scans.completed, total: stats.scans.total, icon: <HiOutlineChartBar />, color: 'var(--green)' },
    { label: 'Unread Alerts', value: stats.alerts.unread, icon: <HiOutlineBell />, color: 'var(--orange)' },
  ];

  if (loading) return <div className="empty-state pulse">Loading dashboard...</div>;

  return (
    <div className="fade-in">
      {/* Investigation Hub */}
      <div className="section-header">
        <h2 className="section-title">⬡ Investigation Hub</h2>
      </div>

      <div className="grid-3 stagger" style={{ marginBottom: 28 }}>
        {/* Person Card */}
        <div className="invest-card person slide-up" onClick={() => navigate('/investigate/person')}>
          <div className="invest-card-icon" style={{ background: 'var(--accent-dim)', color: 'var(--accent)' }}>👤</div>
          <div className="invest-card-title" style={{ color: 'var(--accent-hover)' }}>Person Intelligence</div>
          <div className="invest-card-desc">
            Investigate any person by email, username, phone, or name. Uncover social profiles, breach history, dark web mentions, and compile AI-powered dossiers.
          </div>
          <div className="invest-card-features">
            <span className="invest-feature">Breach Check</span>
            <span className="invest-feature">Social Media</span>
            <span className="invest-feature">Dark Web</span>
            <span className="invest-feature">AI Dossier</span>
          </div>
        </div>

        {/* Network Card */}
        <div className="invest-card network slide-up" onClick={() => navigate('/investigate/network')}>
          <div className="invest-card-icon" style={{ background: 'var(--cyan-dim)', color: 'var(--cyan)' }}>🌐</div>
          <div className="invest-card-title" style={{ color: 'var(--cyan)' }}>Network Intelligence</div>
          <div className="invest-card-desc">
            Scan any IP or domain with VirusTotal, Censys, port scanning, DNS recon, SSL analysis, and geolocation. Full network threat assessment.
          </div>
          <div className="invest-card-features">
            <span className="invest-feature">VirusTotal</span>
            <span className="invest-feature">Censys</span>
            <span className="invest-feature">Port Scan</span>
            <span className="invest-feature">Shodan</span>
          </div>
        </div>

        {/* Website Card */}
        <div className="invest-card website slide-up" onClick={() => navigate('/investigate/website')}>
          <div className="invest-card-icon" style={{ background: 'var(--orange-dim)', color: 'var(--orange)' }}>🔗</div>
          <div className="invest-card-title" style={{ color: 'var(--orange)' }}>Website Intelligence</div>
          <div className="invest-card-desc">
            Deep-scan any website for technology stack, SSL certs, subdomains, crawl data, Wayback history, and security vulnerabilities.
          </div>
          <div className="invest-card-features">
            <span className="invest-feature">Tech Stack</span>
            <span className="invest-feature">SSL Scan</span>
            <span className="invest-feature">Crawler</span>
            <span className="invest-feature">Wayback</span>
          </div>
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid-4 stagger" style={{ marginBottom: 28 }}>
        {statCards.map((s, i) => (
          <div className="card stat-card slide-up" key={i}>
            <div className="stat-icon" style={{ background: `${s.color}18`, color: s.color }}>{s.icon}</div>
            <div>
              <div className="stat-value">{s.value}{s.total !== undefined && <span style={{ fontSize: 14, color: 'var(--text-muted)', fontWeight: 400 }}> / {s.total}</span>}</div>
              <div className="stat-label">{s.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Recent Activity */}
      <div className="grid-2">
        <div className="card">
          <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>Recent Scans</h3>
          {stats.recent_scans.length === 0 ? (
            <div className="empty-state" style={{ padding: 30 }}>No scans yet. Start an investigation above.</div>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Module</th><th>Status</th><th>Severity</th></tr></thead>
                <tbody>
                  {stats.recent_scans.map((s: any, i: number) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{s.module}</td>
                      <td><span className={`badge badge-${s.status === 'completed' ? 'low' : s.status === 'running' ? 'medium' : 'info'}`}>{s.status}</span></td>
                      <td><span className={`badge badge-${s.severity || 'info'}`}>{s.severity || 'info'}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="card">
          <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>Recent Alerts</h3>
          {stats.recent_alerts.length === 0 ? (
            <div className="empty-state" style={{ padding: 30 }}>No alerts yet.</div>
          ) : (
            stats.recent_alerts.map((a: any, i: number) => (
              <div className="feed-item" key={i}>
                <div className="feed-dot" style={{ background: a.severity === 'critical' ? 'var(--red)' : a.severity === 'high' ? 'var(--orange)' : 'var(--accent)' }} />
                <div className="feed-content">
                  <div className="feed-title">{a.title}</div>
                  <div className="feed-meta"><span className={`badge badge-${a.severity || 'info'}`}>{a.severity}</span></div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
