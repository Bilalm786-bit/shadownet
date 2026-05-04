import { useEffect, useState, useRef } from 'react';
import { HiOutlineBell, HiOutlineRefresh } from 'react-icons/hi';

interface FeedEvent {
  type: string; scan_id?: string; module?: string; status?: string;
  target?: string; summary?: string; severity?: string; entity_count?: number;
  error?: string; timestamp?: string;
}

export default function FeedPage() {
  const [events, setEvents] = useState<FeedEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const feedRef = useRef<HTMLDivElement>(null);

  const connect = () => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/feed?user_id=dashboard`);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      ws.send(JSON.stringify({ type: 'ping' }));
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'pong') return;
        setEvents(prev => [{ ...data, timestamp: new Date().toISOString() }, ...prev].slice(0, 100));
      } catch {}
    };

    ws.onclose = () => { setConnected(false); setTimeout(connect, 3000); };
    ws.onerror = () => { ws.close(); };
  };

  useEffect(() => { connect(); return () => { wsRef.current?.close(); }; }, []);

  const getEventColor = (evt: FeedEvent) => {
    if (evt.status === 'failed' || evt.severity === 'critical') return 'var(--red)';
    if (evt.severity === 'high') return 'var(--orange)';
    if (evt.status === 'completed') return 'var(--green)';
    if (evt.status === 'running') return 'var(--cyan)';
    return 'var(--accent)';
  };

  return (
    <div className="fade-in">
      <div className="section-header">
        <h2 className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <HiOutlineBell /> Live Intel Feed
        </h2>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: connected ? 'var(--green)' : 'var(--red)' }} />
            {connected ? 'Connected' : 'Reconnecting...'}
          </span>
        </div>
      </div>

      <div className="card" ref={feedRef} style={{ maxHeight: 'calc(100vh - 200px)', overflowY: 'auto' }}>
        {events.length === 0 ? (
          <div className="empty-state" style={{ padding: 60 }}>
            <HiOutlineBell style={{ fontSize: 48, opacity: 0.3 }} />
            <p style={{ marginTop: 12 }}>No events yet. Launch a scan to see real-time updates.</p>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 8 }}>
              WebSocket {connected ? 'connected' : 'disconnected'} — waiting for intel...
            </p>
          </div>
        ) : (
          events.map((evt, i) => (
            <div className="feed-item" key={i}>
              <div className="feed-dot" style={{ background: getEventColor(evt) }} />
              <div className="feed-content">
                <div className="feed-title">
                  {evt.type === 'scan_update' && `${evt.module} — ${evt.status}`}
                  {evt.type === 'ai_analysis' && 'AI Analysis Complete'}
                  {!['scan_update', 'ai_analysis'].includes(evt.type) && evt.type}
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 4 }}>
                  {evt.target && <span>Target: <strong>{evt.target}</strong></span>}
                  {evt.summary && <span> — {evt.summary}</span>}
                  {evt.error && <span style={{ color: 'var(--red)' }}> Error: {evt.error}</span>}
                </div>
                <div className="feed-meta">
                  {evt.severity && <span className={`badge badge-${evt.severity}`} style={{ marginRight: 6 }}>{evt.severity}</span>}
                  {evt.entity_count !== undefined && <span>{evt.entity_count} entities found</span>}
                  {evt.timestamp && <span style={{ marginLeft: 8 }}>{new Date(evt.timestamp).toLocaleTimeString()}</span>}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
