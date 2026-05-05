import { useEffect, useMemo, useRef, useState } from 'react';
import { threatIntelAPI } from '../api/client';
import { wsUrl } from '../api/ws';
import {
  HiOutlineShieldExclamation, HiOutlineRefresh, HiOutlineSearch,
  HiOutlineGlobe, HiOutlineLightningBolt, HiOutlineFire,
  HiOutlineExternalLink, HiOutlineDatabase, HiOutlineExclamation,
  HiOutlineCheck,
} from 'react-icons/hi';

interface Indicator {
  ioc_type: string;
  value: string;
  source: string;
  threat: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  first_seen?: string;
  tags?: string[];
  reference?: string;
  confidence?: number;
  extra?: Record<string, any>;
}

interface FeedInfo {
  id: string;
  vendor: string;
  description: string;
  ioc_type: string;
  ok: boolean | null;
  count: number;
  error?: string | null;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f59e0b',
  medium: '#06b6d4',
  low: '#10b981',
  info: '#818cf8',
  clean: '#10b981',
};

const TYPE_ICONS: Record<string, string> = {
  ip: '🌐',
  domain: '🌍',
  url: '🔗',
  cve: '🛡️',
  hash_md5: '#️⃣',
  hash_sha1: '#️⃣',
  hash_sha256: '#️⃣',
  pulse: '📡',
  cidr: '🧱',
};

function timeAgo(iso?: string): string {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const s = Math.floor((Date.now() - t) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function StatTile({ label, value, color, icon }: { label: string; value: number | string; color: string; icon: JSX.Element }) {
  return (
    <div className="card stat-card slide-up">
      <div className="stat-icon" style={{ background: `${color}18`, color }}>{icon}</div>
      <div>
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}

function IndicatorRow({ ind }: { ind: Indicator }) {
  const color = SEVERITY_COLORS[ind.severity] || SEVERITY_COLORS.info;
  return (
    <div style={{
      display: 'grid', gridTemplateColumns: '24px 1fr 130px 100px 80px',
      gap: 12, padding: '10px 14px', borderBottom: '1px solid var(--border-glass)',
      alignItems: 'center', fontSize: 13,
    }}>
      <span style={{ fontSize: 16 }}>{TYPE_ICONS[ind.ioc_type] || '⚠️'}</span>
      <div style={{ minWidth: 0 }}>
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-primary)',
          whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
        }} title={ind.value}>{ind.value}</div>
        <div style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 2 }}>
          {ind.threat || ind.ioc_type}
          {ind.tags && ind.tags.length > 0 && (
            <span style={{ marginLeft: 8 }}>
              {ind.tags.slice(0, 3).map(t => (
                <span key={t} style={{
                  background: 'rgba(255,255,255,0.05)', padding: '1px 6px',
                  borderRadius: 4, marginRight: 4, fontSize: 10,
                }}>{t}</span>
              ))}
            </span>
          )}
        </div>
      </div>
      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{ind.source}</span>
      <span className={`badge badge-${ind.severity || 'info'}`}>{ind.severity}</span>
      <span style={{ fontSize: 11, color: 'var(--text-muted)', textAlign: 'right' }}>{timeAgo(ind.first_seen)}</span>
    </div>
  );
}

export default function ThreatIntelPage() {
  const [summary, setSummary] = useState<any>(null);
  const [feeds, setFeeds] = useState<FeedInfo[]>([]);
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [filter, setFilter] = useState<{ type: string; severity: string }>({ type: 'all', severity: 'all' });

  // Lookup
  const [lookupValue, setLookupValue] = useState('');
  const [lookupResult, setLookupResult] = useState<any>(null);
  const [lookupLoading, setLookupLoading] = useState(false);

  // Live WS
  const wsRef = useRef<WebSocket | null>(null);
  const [wsConnected, setWsConnected] = useState(false);
  const [liveIndicators, setLiveIndicators] = useState<Indicator[]>([]);
  const [refreshTick, setRefreshTick] = useState<any>(null);

  const loadAll = async () => {
    setLoading(true);
    try {
      const [s, f, i] = await Promise.all([
        threatIntelAPI.summary().catch(() => ({ data: null })),
        threatIntelAPI.feeds().catch(() => ({ data: { feeds: [] } })),
        threatIntelAPI.indicators({ limit: 100 }).catch(() => ({ data: { indicators: [] } })),
      ]);
      setSummary(s.data);
      setFeeds(f.data?.feeds || []);
      setIndicators(i.data?.indicators || []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAll();
  }, []);

  useEffect(() => {
    const ws = new WebSocket(wsUrl('/ws/feed?user_id=threat-intel'));
    wsRef.current = ws;
    ws.onopen = () => setWsConnected(true);
    ws.onclose = () => setWsConnected(false);
    ws.onerror = () => setWsConnected(false);
    ws.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data.type === 'threat_indicator' && data.indicator) {
          setLiveIndicators(prev => [data.indicator, ...prev].slice(0, 50));
        } else if (data.type === 'threat_intel_refresh') {
          setRefreshTick(data);
          loadAll();
        }
      } catch {}
    };
    return () => { ws.close(); };
  }, []);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await threatIntelAPI.refresh();
      await loadAll();
    } finally {
      setRefreshing(false);
    }
  };

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!lookupValue.trim()) return;
    setLookupLoading(true);
    try {
      const res = await threatIntelAPI.lookup(lookupValue.trim());
      setLookupResult(res.data);
    } catch (err: any) {
      setLookupResult({ error: err.response?.data?.detail || 'Lookup failed' });
    } finally {
      setLookupLoading(false);
    }
  };

  const filteredIndicators = useMemo(() => {
    return indicators.filter(i => {
      if (filter.type !== 'all' && i.ioc_type !== filter.type) return false;
      if (filter.severity !== 'all' && i.severity !== filter.severity) return false;
      return true;
    });
  }, [indicators, filter]);

  const stats = summary?.stats || {};
  const sevCounts = stats.by_severity || {};
  const typeCounts = stats.by_type || {};

  return (
    <div className="fade-in">
      {/* Header */}
      <div className="section-header">
        <h2 className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <HiOutlineShieldExclamation style={{ color: 'var(--red)' }} /> Threat Intelligence
        </h2>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 12, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{
              width: 8, height: 8, borderRadius: '50%',
              background: wsConnected ? 'var(--green)' : 'var(--red)',
            }} className={wsConnected ? 'pulse' : ''} />
            {wsConnected ? 'Live feed connected' : 'Live feed offline'}
          </span>
          <button className="btn btn-ghost btn-sm" onClick={handleRefresh} disabled={refreshing}>
            <HiOutlineRefresh className={refreshing ? 'spin' : ''} /> {refreshing ? 'Refreshing…' : 'Refresh feeds'}
          </button>
        </div>
      </div>

      <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 20, maxWidth: 760 }}>
        Real-time aggregation of public threat-intel feeds: URLhaus, ThreatFox, Feodo Tracker, OpenPhish,
        PhishTank, CISA KEV, NVD, AlienVault OTX, Tor exits, and Spamhaus DROP. New IOCs stream in via the live feed.
      </p>

      {/* Stats */}
      <div className="grid-4 stagger" style={{ marginBottom: 24 }}>
        <StatTile label="Total Indicators" value={stats.total_indicators || 0} color="var(--accent)" icon={<HiOutlineDatabase />} />
        <StatTile label="Critical" value={sevCounts.critical || 0} color="#ef4444" icon={<HiOutlineFire />} />
        <StatTile label="High" value={sevCounts.high || 0} color="#f59e0b" icon={<HiOutlineLightningBolt />} />
        <StatTile label="Live Events" value={liveIndicators.length} color="#10b981" icon={<HiOutlineGlobe />} />
      </div>

      {/* IOC Lookup */}
      <div className="card" style={{ marginBottom: 24 }}>
        <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
          <HiOutlineSearch /> IOC Lookup
        </h3>
        <form onSubmit={handleLookup} style={{ display: 'flex', gap: 12 }}>
          <input
            className="input" style={{ flex: 1 }} value={lookupValue}
            onChange={e => setLookupValue(e.target.value)}
            placeholder="Check IP, domain, URL, hash, or CVE against all feeds…"
          />
          <button className="btn btn-primary" type="submit" disabled={lookupLoading || !lookupValue.trim()}>
            {lookupLoading ? 'Checking…' : 'Lookup'}
          </button>
        </form>
        {lookupResult && (
          <div style={{ marginTop: 16, padding: 16, borderRadius: 8, background: 'var(--bg-secondary)' }}>
            {lookupResult.error ? (
              <div style={{ color: 'var(--red)' }}>
                <HiOutlineExclamation /> {lookupResult.error}
              </div>
            ) : (
              <>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginBottom: 10 }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-primary)' }}>
                    {lookupResult.value}
                  </span>
                  {lookupResult.match_count > 0 ? (
                    <span className={`badge badge-${lookupResult.verdict}`}>
                      {lookupResult.verdict} • {lookupResult.match_count} matches
                    </span>
                  ) : (
                    <span className="badge badge-low" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                      <HiOutlineCheck /> CLEAN
                    </span>
                  )}
                  {lookupResult.sources?.length > 0 && (
                    <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                      Flagged by: {lookupResult.sources.join(', ')}
                    </span>
                  )}
                </div>
                {lookupResult.matches?.length > 0 && (
                  <div style={{ maxHeight: 240, overflowY: 'auto' }}>
                    {lookupResult.matches.slice(0, 20).map((m: Indicator, i: number) => (
                      <IndicatorRow key={i} ind={m} />
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>

      <div className="grid-2" style={{ marginBottom: 24, gridTemplateColumns: '1fr 1fr' }}>
        {/* Feeds Panel */}
        <div className="card">
          <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 12 }}>Connected Feeds</h3>
          {feeds.length === 0 ? (
            <div className="empty-state" style={{ padding: 30 }}>
              No feeds reported yet. Click <strong>Refresh feeds</strong> to start.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {feeds.map(f => (
                <div key={f.id} style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '10px 12px', background: 'var(--bg-secondary)',
                  borderRadius: 8, border: '1px solid var(--border-glass)',
                  borderLeft: `3px solid ${f.ok ? 'var(--green)' : f.ok === false ? 'var(--red)' : 'var(--text-muted)'}`,
                }}>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 600 }}>{f.vendor}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{f.description}</div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: 14, fontWeight: 700 }}>{f.count}</div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{f.ioc_type}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Live indicators */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <HiOutlineLightningBolt style={{ color: 'var(--orange)' }} /> Live Stream
          </h3>
          <div style={{ flex: 1, maxHeight: 360, overflowY: 'auto' }}>
            {liveIndicators.length === 0 ? (
              <div className="empty-state" style={{ padding: 30 }}>
                Awaiting new IOCs from feeds…
                <div style={{ fontSize: 11, marginTop: 8 }}>
                  Auto-refresh runs every 10 minutes.
                </div>
              </div>
            ) : (
              liveIndicators.map((ind, i) => <IndicatorRow key={i} ind={ind} />)
            )}
          </div>
        </div>
      </div>

      {/* Filterable indicator table */}
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12, flexWrap: 'wrap', gap: 8 }}>
          <h3 style={{ fontSize: 16, fontWeight: 600 }}>Latest Indicators ({filteredIndicators.length})</h3>
          <div style={{ display: 'flex', gap: 8 }}>
            <select className="input" style={{ width: 'auto' }} value={filter.type}
              onChange={e => setFilter(f => ({ ...f, type: e.target.value }))}>
              <option value="all">All types</option>
              {Object.keys(typeCounts).map(t => (
                <option key={t} value={t}>{t} ({typeCounts[t]})</option>
              ))}
            </select>
            <select className="input" style={{ width: 'auto' }} value={filter.severity}
              onChange={e => setFilter(f => ({ ...f, severity: e.target.value }))}>
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>
        </div>
        {loading ? (
          <div className="empty-state pulse">Loading indicators…</div>
        ) : filteredIndicators.length === 0 ? (
          <div className="empty-state">
            No indicators match the current filter. Click <strong>Refresh feeds</strong> to populate.
          </div>
        ) : (
          <div>
            <div style={{
              display: 'grid', gridTemplateColumns: '24px 1fr 130px 100px 80px',
              gap: 12, padding: '8px 14px', borderBottom: '1px solid var(--border-glass)',
              fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600,
            }}>
              <span></span><span>Indicator / Threat</span><span>Source</span><span>Severity</span><span style={{ textAlign: 'right' }}>Seen</span>
            </div>
            {filteredIndicators.map((ind, i) => <IndicatorRow key={i} ind={ind} />)}
          </div>
        )}
      </div>
    </div>
  );
}
