import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { dashboardAPI, threatIntelAPI } from '../api/client';
import { wsUrl } from '../api/ws';
import {
  HiOutlineFolder, HiOutlineUser, HiOutlineChartBar, HiOutlineBell,
  HiOutlineShieldExclamation, HiOutlineFire, HiOutlineLightningBolt,
  HiOutlineGlobe, HiOutlineSearch, HiOutlineDatabase,
} from 'react-icons/hi';

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

interface ThreatIndicator {
  ioc_type: string; value: string; source: string; severity: string;
  threat?: string; first_seen?: string; tags?: string[];
}

function timeAgo(iso?: string) {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '';
  const s = Math.floor((Date.now() - t) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats>(defaultStats);
  const [loading, setLoading] = useState(true);
  const [threatSummary, setThreatSummary] = useState<any>(null);
  const [liveIndicators, setLiveIndicators] = useState<ThreatIndicator[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [quickQuery, setQuickQuery] = useState('');
  const [quickResult, setQuickResult] = useState<any>(null);
  const [quickLoading, setQuickLoading] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    Promise.all([
      dashboardAPI.stats().then(r => setStats(r.data)).catch(() => {}),
      threatIntelAPI.summary().then(r => setThreatSummary(r.data)).catch(() => {}),
    ]).finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    const ws = new WebSocket(wsUrl('/ws/feed?user_id=dashboard'));
    wsRef.current = ws;
    ws.onopen = () => setWsConnected(true);
    ws.onclose = () => setWsConnected(false);
    ws.onmessage = (ev) => {
      try {
        const d = JSON.parse(ev.data);
        if (d.type === 'threat_indicator' && d.indicator) {
          setLiveIndicators(prev => [d.indicator, ...prev].slice(0, 12));
        } else if (d.type === 'threat_intel_refresh') {
          threatIntelAPI.summary().then(r => setThreatSummary(r.data)).catch(() => {});
        }
      } catch {}
    };
    return () => { ws.close(); };
  }, []);

  const handleQuickLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickQuery.trim()) return;
    setQuickLoading(true);
    try {
      const res = await threatIntelAPI.lookup(quickQuery.trim());
      setQuickResult(res.data);
    } catch (err: any) {
      setQuickResult({ error: err.response?.data?.detail || 'Lookup failed' });
    }
    setQuickLoading(false);
  };

  if (loading) return <div className="empty-state pulse">Loading dashboard…</div>;

  const tStats = threatSummary?.stats || {};
  const sevCounts = tStats.by_severity || {};

  return (
    <div className="fade-in">
      {/* Top Hero — Threat status banner */}
      <div className="card" style={{
        marginBottom: 24, padding: 20, display: 'flex', alignItems: 'center',
        gap: 20, flexWrap: 'wrap', borderLeft: '3px solid var(--red)',
        background: 'linear-gradient(135deg, rgba(239,68,68,0.05), rgba(245,158,11,0.03))',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, flex: 1, minWidth: 280 }}>
          <div style={{
            width: 56, height: 56, borderRadius: 12,
            background: 'rgba(239,68,68,0.15)', display: 'flex', alignItems: 'center',
            justifyContent: 'center', fontSize: 28, color: 'var(--red)',
          }}><HiOutlineShieldExclamation /></div>
          <div>
            <div style={{ fontSize: 18, fontWeight: 700 }}>Threat Intelligence Posture</div>
            <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
              {tStats.total_indicators || 0} live indicators tracked across {Object.keys(tStats.by_source || {}).length} feeds •{' '}
              <span style={{
                display: 'inline-flex', alignItems: 'center', gap: 4,
                color: wsConnected ? 'var(--green)' : 'var(--red)',
              }}>
                <span style={{
                  width: 6, height: 6, borderRadius: '50%',
                  background: wsConnected ? 'var(--green)' : 'var(--red)',
                }} className={wsConnected ? 'pulse' : ''} />
                {wsConnected ? 'live stream active' : 'live stream offline'}
              </span>
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 16 }}>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--red)' }}>{sevCounts.critical || 0}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1 }}>Critical</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--orange)' }}>{sevCounts.high || 0}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1 }}>High</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--cyan)' }}>{sevCounts.medium || 0}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1 }}>Medium</div>
          </div>
          <button className="btn btn-primary" onClick={() => navigate('/threat-intel')}>
            Open Threat Center
          </button>
        </div>
      </div>

      {/* Quick IOC lookup */}
      <div className="card" style={{ marginBottom: 24 }}>
        <form onSubmit={handleQuickLookup} style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <HiOutlineSearch style={{ color: 'var(--text-muted)', fontSize: 20 }} />
          <input
            className="input" style={{ flex: 1 }} value={quickQuery}
            onChange={e => setQuickQuery(e.target.value)}
            placeholder="Quick check — paste an IP, domain, URL, hash or CVE…"
          />
          <button className="btn btn-primary" type="submit" disabled={quickLoading || !quickQuery.trim()}>
            {quickLoading ? 'Checking…' : 'Check IOC'}
          </button>
        </form>
        {quickResult && (
          <div style={{ marginTop: 12, padding: 12, borderRadius: 8, background: 'var(--bg-secondary)' }}>
            {quickResult.error ? (
              <span style={{ color: 'var(--red)' }}>{quickResult.error}</span>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                <span style={{ fontFamily: 'var(--font-mono)' }}>{quickResult.value}</span>
                <span className={`badge badge-${quickResult.match_count ? quickResult.verdict : 'low'}`}>
                  {quickResult.match_count ? `${quickResult.verdict} • ${quickResult.match_count} matches` : 'CLEAN'}
                </span>
                {quickResult.sources?.length > 0 && (
                  <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                    {quickResult.sources.join(', ')}
                  </span>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Investigation Hub */}
      <div className="section-header">
        <h2 className="section-title">⬡ Investigation Hub</h2>
      </div>

      <div className="grid-3 stagger" style={{ marginBottom: 28 }}>
        <div className="invest-card person slide-up" onClick={() => navigate('/investigate/person')}>
          <div className="invest-card-icon" style={{ background: 'var(--accent-dim)', color: 'var(--accent)' }}>👤</div>
          <div className="invest-card-title" style={{ color: 'var(--accent-hover)' }}>Person Intelligence</div>
          <div className="invest-card-desc">
            Investigate any person by email, username, phone, or name. Uncover social profiles,
            breach history, dark-web mentions, and compile AI-powered dossiers.
          </div>
          <div className="invest-card-features">
            <span className="invest-feature">Breach Check</span>
            <span className="invest-feature">Social Media</span>
            <span className="invest-feature">Dark Web</span>
            <span className="invest-feature">AI Dossier</span>
          </div>
        </div>

        <div className="invest-card network slide-up" onClick={() => navigate('/investigate/network')}>
          <div className="invest-card-icon" style={{ background: 'var(--cyan-dim)', color: 'var(--cyan)' }}>🌐</div>
          <div className="invest-card-title" style={{ color: 'var(--cyan)' }}>Network Intelligence</div>
          <div className="invest-card-desc">
            Scan any IP or domain with VirusTotal, Censys, port scanning, DNS recon, SSL analysis,
            geolocation, and threat-intel cross-reference.
          </div>
          <div className="invest-card-features">
            <span className="invest-feature">Threat Intel</span>
            <span className="invest-feature">Port Scan</span>
            <span className="invest-feature">DNS</span>
            <span className="invest-feature">Shodan</span>
          </div>
        </div>

        <div className="invest-card website slide-up" onClick={() => navigate('/investigate/website')}>
          <div className="invest-card-icon" style={{ background: 'var(--orange-dim)', color: 'var(--orange)' }}>🔗</div>
          <div className="invest-card-title" style={{ color: 'var(--orange)' }}>Website Intelligence</div>
          <div className="invest-card-desc">
            Deep-scan any website for technology stack, SSL certs, subdomains, crawl data,
            Wayback history, phishing reputation, and security vulnerabilities.
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
        <div className="card stat-card slide-up">
          <div className="stat-icon" style={{ background: 'var(--accent-dim)', color: 'var(--accent)' }}><HiOutlineFolder /></div>
          <div>
            <div className="stat-value">{stats.cases.active}<span style={{ fontSize: 14, color: 'var(--text-muted)', fontWeight: 400 }}> / {stats.cases.total}</span></div>
            <div className="stat-label">Active Cases</div>
          </div>
        </div>
        <div className="card stat-card slide-up">
          <div className="stat-icon" style={{ background: 'var(--cyan-dim)', color: 'var(--cyan)' }}><HiOutlineUser /></div>
          <div>
            <div className="stat-value">{stats.targets}</div>
            <div className="stat-label">Targets</div>
          </div>
        </div>
        <div className="card stat-card slide-up">
          <div className="stat-icon" style={{ background: 'var(--green-dim)', color: 'var(--green)' }}><HiOutlineChartBar /></div>
          <div>
            <div className="stat-value">{stats.scans.completed}<span style={{ fontSize: 14, color: 'var(--text-muted)', fontWeight: 400 }}> / {stats.scans.total}</span></div>
            <div className="stat-label">Scans Complete</div>
          </div>
        </div>
        <div className="card stat-card slide-up">
          <div className="stat-icon" style={{ background: 'rgba(168,85,247,0.12)', color: 'var(--purple)' }}><HiOutlineDatabase /></div>
          <div>
            <div className="stat-value">{tStats.total_indicators || 0}</div>
            <div className="stat-label">Threat IOCs</div>
          </div>
        </div>
      </div>

      {/* 3-column grid: live indicators, recent scans, recent alerts */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 20 }}>
        {/* Live indicators */}
        <div className="card">
          <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <HiOutlineLightningBolt style={{ color: 'var(--orange)' }} /> Live Threat Stream
          </h3>
          {liveIndicators.length === 0 && (threatSummary?.latest_critical || []).length === 0 ? (
            <div className="empty-state" style={{ padding: 24 }}>
              Awaiting threat intel… auto-refresh every 10 minutes.
            </div>
          ) : (
            <div style={{ maxHeight: 280, overflowY: 'auto' }}>
              {(liveIndicators.length > 0 ? liveIndicators : (threatSummary?.latest_critical || []).slice(0, 8))
                .map((ind: ThreatIndicator, i: number) => (
                <div key={i} style={{
                  padding: '8px 12px', borderBottom: '1px solid var(--border-glass)',
                  display: 'flex', alignItems: 'center', gap: 8,
                }}>
                  <span style={{
                    width: 8, height: 8, borderRadius: '50%',
                    background: ind.severity === 'critical' ? 'var(--red)' :
                                ind.severity === 'high' ? 'var(--orange)' : 'var(--cyan)',
                  }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{
                      fontFamily: 'var(--font-mono)', fontSize: 12,
                      whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                    }} title={ind.value}>{ind.value}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      {ind.source} • {ind.threat || ind.ioc_type}
                    </div>
                  </div>
                  <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{timeAgo(ind.first_seen)}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Scans */}
        <div className="card">
          <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <HiOutlineChartBar /> Recent Scans
          </h3>
          {stats.recent_scans.length === 0 ? (
            <div className="empty-state" style={{ padding: 24 }}>No scans yet. Start an investigation above.</div>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Module</th><th>Status</th><th>Severity</th></tr></thead>
                <tbody>
                  {stats.recent_scans.map((s: any, i: number) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{s.module}</td>
                      <td><span className={`badge badge-${s.status === 'completed' ? 'low' : s.status === 'running' ? 'medium' : 'info'}`}>{s.status}</span></td>
                      <td><span className={`badge badge-${s.severity || 'info'}`}>{s.severity || 'info'}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Recent Alerts */}
        <div className="card">
          <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <HiOutlineBell /> Alerts ({stats.alerts.unread} unread)
          </h3>
          {stats.recent_alerts.length === 0 ? (
            <div className="empty-state" style={{ padding: 24 }}>No alerts yet.</div>
          ) : (
            stats.recent_alerts.map((a: any, i: number) => (
              <div className="feed-item" key={i}>
                <div className="feed-dot" style={{
                  background: a.severity === 'critical' ? 'var(--red)' :
                              a.severity === 'high' ? 'var(--orange)' : 'var(--accent)',
                }} />
                <div className="feed-content">
                  <div className="feed-title">{a.title}</div>
                  <div className="feed-meta">
                    <span className={`badge badge-${a.severity || 'info'}`}>{a.severity}</span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
