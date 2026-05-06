import { HiOutlineExternalLink } from 'react-icons/hi';

interface OwaspCategory {
  code: string;
  id: string;
  title: string;
  description?: string;
  reference?: string;
  count: number;
  severity_max: string;
  by_severity: Record<string, number>;
}

interface Props {
  categories: OwaspCategory[];
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#ff5165',
  high: '#ffa747',
  medium: '#22d3ee',
  low: '#22d3a8',
  info: '#7c8aff',
};

export default function OwaspCoverage({ categories }: Props) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 12 }}>
      {categories.map(cat => {
        const covered = cat.count > 0;
        const color = covered ? SEVERITY_COLOR[cat.severity_max] || 'var(--accent)' : 'var(--text-faint)';
        return (
          <div
            key={cat.code}
            className="owasp-card"
            style={{
              ['--severity-color' as any]: color,
              opacity: covered ? 1 : 0.55,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
              <div className="owasp-card-id">{cat.id}</div>
              {covered ? (
                <span className={`badge badge-${cat.severity_max}`} style={{ flexShrink: 0 }}>
                  {cat.severity_max}
                </span>
              ) : (
                <span style={{ fontSize: 10.5, color: 'var(--text-faint)', textTransform: 'uppercase', letterSpacing: 0.6 }}>clear</span>
              )}
            </div>
            <div className="owasp-card-title" style={{ color: covered ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
              {cat.title}
            </div>
            {cat.description && (
              <div style={{ fontSize: 11.5, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                {cat.description}
              </div>
            )}
            <div className="owasp-card-count">
              <div style={{ display: 'flex', gap: 6 }}>
                {(['critical', 'high', 'medium', 'low'] as const).map(s => (
                  cat.by_severity[s] > 0 ? (
                    <span key={s} style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: SEVERITY_COLOR[s] }}>
                      {cat.by_severity[s]} {s[0].toUpperCase()}
                    </span>
                  ) : null
                ))}
              </div>
              <span style={{ fontWeight: 700, color }}>{cat.count}</span>
            </div>
            {cat.reference && (
              <a
                href={cat.reference}
                target="_blank"
                rel="noreferrer"
                style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 10.5, color: 'var(--text-muted)', marginTop: 4 }}
              >
                <HiOutlineExternalLink /> owasp.org
              </a>
            )}
          </div>
        );
      })}
    </div>
  );
}
