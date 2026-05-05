import { useEffect, useRef, useState } from 'react';
import { HiOutlineBell, HiOutlineFilter, HiOutlineLightningBolt, HiOutlineRefresh } from 'react-icons/hi';

type EventKind = 'all' | 'scan' | 'threat' | 'alert' | 'ai';

interface FeedEvent {
  id?: string;
  type: string;
  scan_id?: string;
  module?: string;
  status?: string;
  target?: string;
  summary?: string;
  severity?: string;
  entity_count?: number;
  error?: string;
  timestamp?: string;
  // threat-intel
  indicator?: any;
  // alert
  title?: string;
  message?: string;
  alert_id?: string;
  // refresh
  total?: number;
  fresh?: number;
  feed_status?: Record<string, any>;
  kind?: EventKind;
}

const KIND_FILTERS: { key: EventKind; label: string; icon: JSX.Element }[] = [
  { key: 'all', label: 'All', icon: <HiOutlineBell /> },
  { key: 'threat', label: 'Threat IOCs', icon: <HiOutlineLightningBolt /> },
  { key: 'scan', label: 'Scans', icon: <HiOutlineRefresh /> },
  { key: 'alert', label: 'Alerts', icon: <HiOutlineBell /> },
  { key: 'ai', label: 'AI', icon: <HiOutlineFilter /> },
];

function eventKind(evt: FeedEvent): EventKind {
  if (evt.type === 'threat_indicator' || evt.type === 'threat_intel_refresh') return 'threat';
  if (evt.type === 'scan_update') return 'scan';
  if (evt.type === 'alert') return 'alert';
  if (evt.type === 'ai_analysis') return 'ai';
  return 'all';
}

function eventColor(evt: FeedEvent): string {
  const sev = evt.severity || evt.indicator?.severity;
  if (sev === 'critical' || evt.status === 'failed') return 'var(--red)';
  if (sev === 'high') return 'var(--orange)';
  if (sev === 'medium' || evt.status === 'running') return 'var(--cyan)';
  if (sev === 'low' || evt.status === 'completed') return 'var(--green)';
  return 'var(--accent)';
}

function eventTitle(evt: FeedEvent): string {
  if (evt.type === 'threat_indicator' && evt.indicator) {
    return `New IOC: ${evt.indicator.ioc_type} — ${evt.indicator.value}`;
  }
  if (evt.type === 'threat_intel_refresh') {
    return `Threat-intel refresh — ${evt.fresh || 0} new of ${evt.total || 0} total`;
  }
  if (evt.type === 'scan_update') return `${evt.module || 'scan'} — ${evt.status || ''}`;
  if (evt.type === 'alert') return evt.title || 'Alert';
  if (evt.type === 'ai_analysis') return 'AI Analysis Complete';
  return evt.type || 'Event';
}

function eventDescription(evt: FeedEvent): string {
  const parts: string[] = [];
  if (evt.indicator) {
    if (evt.indicator.threat) parts.push(evt.indicator.threat);
    if (evt.indicator.source) parts.push(`source: ${evt.indicator.source}`);
    if (evt.indicator.tags?.length) parts.push(`tags: ${evt.indicator.tags.slice(0, 3).join(', ')}`);
  }
  if (evt.target) parts.push(`Target: ${evt.target}`);
  if (evt.summary) parts.push(evt.summary);
  if (evt.message) parts.push(evt.message);
  if (evt.error) parts.push(`Error: ${evt.error}`);
  return parts.join(' • ');
}

export default function FeedPage() {
  const [events, setEvents] = useState<FeedEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [filter, setFilter] = useState<EventKind>('all');
  const [paused, setPaused] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  const connect = () => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/feed?user_id=feed`);
    wsRef.current = ws;
    ws.onopen = () => {
      setConnected(true);
      ws.send(JSON.stringify({ type: 'ping' }));
    };
    ws.onmessage = (event) => {
      if (paused) return;
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'pong') return;
        const evt: FeedEvent = { ...data, timestamp: data.timestamp || new Date().toISOString(), kind: eventKind(data) };
        setEvents(prev => [evt, ...prev].slice(0, 200));
      } catch {}
    };
    ws.onclose = () => { setConnected(false); setTimeout(connect, 3000); };
    ws.onerror = () => { ws.close(); };
  };

  useEffect(() => {
    connect();
    return () => { wsRef.current?.close(); };
  }, [paused]);

  const filtered = filter === 'all' ? events : events.filter(e => eventKind(e) === filter);

  const counts: Record<EventKind, number> = {
    all: events.length,
    scan: events.filter(e => eventKind(e) === 'scan').length,
    threat: events.filter(e => eventKind(e) === 'threat').length,
    alert: events.filter(e => eventKind(e) === 'alert').length,
    ai: events.filter(e => eventKind(e) === 'ai').length,
  };

  return (
    <div className="fade-in">
      <div className="section-header">
        <h2 className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <HiOutlineBell /> Live Intel Feed
        </h2>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{
              width: 8, height: 8, borderRadius: '50%',
              background: connected ? 'var(--green)' : 'var(--red)',
            }} className={connected ? 'pulse' : ''} />
            {connected ? 'Connected' : 'Reconnecting…'}
          </span>
          <button className="btn btn-ghost btn-sm" onClick={() => setPaused(p => !p)}>
            {paused ? '▶ Resume' : '⏸ Pause'}
          </button>
          <button className="btn btn-ghost btn-sm" onClick={() => setEvents([])}>Clear</button>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 6, marginBottom: 16, flexWrap: 'wrap' }}>
        {KIND_FILTERS.map(f => (
          <button key={f.key} onClick={() => setFilter(f.key)} style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '8px 14px', borderRadius: 'var(--radius-sm)',
            border: filter === f.key ? '1px solid var(--accent)' : '1px solid var(--border-glass)',
            background: filter === f.key ? 'rgba(99,102,241,0.15)' : 'transparent',
            color: filter === f.key ? 'var(--accent)' : 'var(--text-secondary)',
            cursor: 'pointer', fontSize: 13, fontWeight: 600, fontFamily: 'var(--font-sans)',
          }}>
            {f.icon} {f.label}
            <span style={{ fontSize: 11, opacity: 0.7 }}>({counts[f.key]})</span>
          </button>
        ))}
      </div>

      <div className="card" style={{ maxHeight: 'calc(100vh - 240px)', overflowY: 'auto', padding: 0 }}>
        {filtered.length === 0 ? (
          <div className="empty-state" style={{ padding: 60 }}>
            <HiOutlineBell style={{ fontSize: 48, opacity: 0.3 }} />
            <p style={{ marginTop: 12 }}>No events yet. Threat-intel feed refreshes every 10 minutes.</p>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 8 }}>
              WebSocket {connected ? 'connected' : 'disconnected'} — waiting for intel…
            </p>
          </div>
        ) : (
          filtered.map((evt, i) => (
            <div className="feed-item" key={i}>
              <div className="feed-dot" style={{ background: eventColor(evt) }} />
              <div className="feed-content">
                <div className="feed-title">{eventTitle(evt)}</div>
                <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 4 }}>
                  {eventDescription(evt)}
                </div>
                <div className="feed-meta">
                  {(evt.severity || evt.indicator?.severity) && (
                    <span className={`badge badge-${evt.severity || evt.indicator?.severity}`} style={{ marginRight: 6 }}>
                      {evt.severity || evt.indicator?.severity}
                    </span>
                  )}
                  {evt.indicator?.source && (
                    <span style={{ fontSize: 11, color: 'var(--text-muted)', marginRight: 8 }}>
                      {evt.indicator.source}
                    </span>
                  )}
                  {evt.entity_count !== undefined && <span>{evt.entity_count} entities</span>}
                  {evt.timestamp && (
                    <span style={{ marginLeft: 8 }}>{new Date(evt.timestamp).toLocaleTimeString()}</span>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
