interface TimelineEntry {
  module: string;
  status: string;
  ms?: number;
  severity?: string;
  entities?: number;
  error?: string;
}

interface Props {
  timeline: TimelineEntry[];
}

const STATUS_COLOR: Record<string, string> = {
  completed: 'var(--green)',
  failed: 'var(--red)',
  timeout: 'var(--orange)',
};

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)',
  high: 'var(--orange)',
  medium: 'var(--cyan)',
  low: 'var(--green)',
  info: 'var(--text-muted)',
};

export default function ScanTimeline({ timeline }: Props) {
  if (!timeline || !timeline.length) {
    return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 24 }}>No timeline data.</div>;
  }
  const sorted = [...timeline].sort((a, b) => (b.ms || 0) - (a.ms || 0));
  const max = Math.max(...sorted.map(t => t.ms || 0), 1);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {sorted.map((t, i) => {
        const pct = ((t.ms || 0) / max) * 100;
        return (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 12 }}>
            <div style={{ flex: '0 0 240px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {t.module}
            </div>
            <div style={{ flex: 1, height: 8, background: 'var(--bg-secondary)', borderRadius: 4, position: 'relative', overflow: 'hidden' }}>
              <div style={{
                width: `${pct}%`, height: '100%',
                background: STATUS_COLOR[t.status] || 'var(--accent)',
                opacity: 0.6,
                transition: 'width .6s ease',
              }} />
            </div>
            <div style={{ flex: '0 0 80px', textAlign: 'right', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              {t.ms ? `${t.ms}ms` : '—'}
            </div>
            <div style={{ flex: '0 0 60px', textAlign: 'right', fontSize: 11, color: SEV_COLOR[t.severity || 'info'] }}>
              {t.entities ?? '—'}
            </div>
          </div>
        );
      })}
    </div>
  );
}
