interface Props {
  data: Record<string, number>;
}

const ORDER: Array<{ key: string; label: string; color: string }> = [
  { key: 'critical', label: 'Critical', color: '#ef4444' },
  { key: 'high', label: 'High', color: '#f59e0b' },
  { key: 'medium', label: 'Medium', color: '#06b6d4' },
  { key: 'low', label: 'Low', color: '#10b981' },
  { key: 'info', label: 'Info', color: '#6366f1' },
];

export default function SeverityLegend({ data }: Props) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {ORDER.map(({ key, label, color }) => (
        <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ width: 10, height: 10, borderRadius: 2, background: color, flexShrink: 0 }} />
          <span style={{ flex: 1, fontSize: 13, color: 'var(--text-secondary)' }}>{label}</span>
          <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', minWidth: 30, textAlign: 'right' }}>
            {data[key] || 0}
          </span>
        </div>
      ))}
    </div>
  );
}
