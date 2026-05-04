import { useEffect, useState } from 'react';
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

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge badge-${severity || 'info'}`}>{severity || 'info'}</span>;
}

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats>(defaultStats);
  const [loading, setLoading] = useState(true);

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
      <div className="grid-4" style={{ marginBottom: 28 }}>
        {statCards.map((s, i) => (
          <div className="card stat-card" key={i}>
            <div className="stat-icon" style={{ background: `${s.color}22`, color: s.color }}>{s.icon}</div>
            <div>
              <div className="stat-value">{s.value}{s.total !== undefined && <span style={{ fontSize: 14, color: 'var(--text-muted)', fontWeight: 400 }}> / {s.total}</span>}</div>
              <div className="stat-label">{s.label}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="section-header">
            <h3 style={{ fontSize: 16, fontWeight: 600 }}>Recent Scans</h3>
          </div>
          {stats.recent_scans.length === 0 ? (
            <div className="empty-state" style={{ padding: 30 }}>No scans yet. Create a case and launch a scan.</div>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Module</th><th>Status</th><th>Severity</th></tr></thead>
                <tbody>
                  {stats.recent_scans.map((s: any, i: number) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{s.module}</td>
                      <td><span className={`badge badge-${s.status === 'completed' ? 'low' : s.status === 'running' ? 'medium' : 'info'}`}>{s.status}</span></td>
                      <td><SeverityBadge severity={s.severity} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="card">
          <div className="section-header">
            <h3 style={{ fontSize: 16, fontWeight: 600 }}>Recent Alerts</h3>
          </div>
          {stats.recent_alerts.length === 0 ? (
            <div className="empty-state" style={{ padding: 30 }}>No alerts yet.</div>
          ) : (
            stats.recent_alerts.map((a: any, i: number) => (
              <div className="feed-item" key={i}>
                <div className="feed-dot" style={{ background: a.severity === 'critical' ? 'var(--red)' : a.severity === 'high' ? 'var(--orange)' : 'var(--accent)' }} />
                <div className="feed-content">
                  <div className="feed-title">{a.title}</div>
                  <div className="feed-meta"><SeverityBadge severity={a.severity} /></div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
