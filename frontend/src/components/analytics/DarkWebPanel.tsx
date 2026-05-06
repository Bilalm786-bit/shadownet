import { useMemo, useState } from 'react';
import { HiOutlineExternalLink, HiOutlineGlobe, HiOutlineDocument, HiOutlineExclamationCircle, HiOutlineFire, HiOutlineSearch } from 'react-icons/hi';

interface Indicator {
  category: string;
  source: string;
  module?: string;
  value: string;
  type?: string;
  severity?: string;
  description?: string;
  url?: string | null;
  first_seen?: string | null;
  tags?: string[];
  query?: string;
  confidence?: number;
}

interface DarkWebReport {
  queries_run?: number;
  queries?: string[];
  sources_consulted?: string[];
  indicator_count?: number;
  by_category?: Record<string, number>;
  by_severity?: Record<string, number>;
  risk_uplift?: number;
  indicators?: Indicator[];
  summary?: string;
}

interface Props {
  report?: DarkWebReport;
}

const CATEGORY_META: Record<string, { label: string; icon: any; color: string; desc: string }> = {
  breach: { label: 'Breach DB', icon: HiOutlineExclamationCircle, color: 'var(--red)', desc: 'Credentials / records found in known data breaches.' },
  paste: { label: 'Paste Sites', icon: HiOutlineDocument, color: 'var(--orange)', desc: 'Pastebin / Ghostbin / GitHub Gist hits.' },
  onion: { label: '.onion Sites', icon: HiOutlineGlobe, color: 'var(--purple)', desc: 'Dark-web search-engine results referencing the target.' },
  threat_intel: { label: 'Threat Intel Feeds', icon: HiOutlineFire, color: 'var(--red)', desc: 'IOC feeds (URLhaus, ThreatFox, OpenPhish, OTX, KEV...).' },
  google_dork: { label: 'Google Dorks', icon: HiOutlineSearch, color: 'var(--cyan)', desc: 'Targeted Google dork results.' },
  ai_search: { label: 'AI / Tavily', icon: HiOutlineSearch, color: 'var(--accent)', desc: 'AI-assisted dark-web aware search.' },
  other: { label: 'Other', icon: HiOutlineExternalLink, color: 'var(--text-muted)', desc: '' },
};

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#ff5165',
  high: '#ffa747',
  medium: '#22d3ee',
  low: '#22d3a8',
  info: '#7c8aff',
};

export default function DarkWebPanel({ report }: Props) {
  const [filter, setFilter] = useState<string>('all');
  const indicators = report?.indicators || [];
  const categories = report?.by_category || {};

  const filtered = useMemo(() => {
    if (filter === 'all') return indicators;
    return indicators.filter(i => i.category === filter);
  }, [indicators, filter]);

  if (!report || !report.queries_run) {
    return (
      <div className="empty-state">
        <HiOutlineGlobe style={{ fontSize: 40, opacity: 0.4 }} />
        <div style={{ marginTop: 8, fontSize: 13 }}>Dark-web correlator not configured for this scan.</div>
      </div>
    );
  }

  const total = report.indicator_count || 0;

  return (
    <div>
      <div style={{
        background: 'linear-gradient(135deg, rgba(192,132,252,0.08), rgba(124,138,255,0.04))',
        border: '1px solid var(--border-glass-strong)',
        borderRadius: 'var(--radius)', padding: 16, marginBottom: 16,
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--purple)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 6 }}>
              Dark Web Correlation
            </div>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 22, fontWeight: 700 }}>
              {total} indicators across {report.sources_consulted?.length || 0} sources
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
              {report.queries_run} queries · risk uplift +{report.risk_uplift || 0}
            </div>
          </div>
          {report.by_severity && (
            <div style={{ display: 'flex', gap: 14 }}>
              {(['critical', 'high', 'medium', 'low'] as const).map(s => (
                <div key={s} style={{ textAlign: 'center' }}>
                  <div style={{ fontFamily: 'var(--font-display)', fontSize: 22, fontWeight: 700, color: SEVERITY_COLOR[s] }}>
                    {report.by_severity?.[s] || 0}
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1 }}>
                    {s}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
        {report.summary && (
          <p
            style={{ fontSize: 13.5, color: 'var(--text-secondary)', lineHeight: 1.6, marginTop: 14 }}
            dangerouslySetInnerHTML={{ __html: report.summary.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>') }}
          />
        )}
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
        <button
          className={`tab-button ${filter === 'all' ? 'active' : ''}`}
          onClick={() => setFilter('all')}
        >
          All ({total})
        </button>
        {Object.entries(categories).map(([cat, count]) => {
          const meta = CATEGORY_META[cat] || CATEGORY_META.other;
          const Icon = meta.icon;
          return (
            <button
              key={cat}
              className={`tab-button ${filter === cat ? 'active' : ''}`}
              onClick={() => setFilter(cat)}
            >
              <Icon /> {meta.label} ({count})
            </button>
          );
        })}
      </div>

      {filtered.length === 0 ? (
        <div className="empty-state">
          <HiOutlineGlobe />
          <div style={{ marginTop: 8 }}>No indicators in this category.</div>
        </div>
      ) : (
        <div>
          {filtered.slice(0, 80).map((ind, i) => {
            const meta = CATEGORY_META[ind.category] || CATEGORY_META.other;
            const sevColor = SEVERITY_COLOR[ind.severity || 'info'] || 'var(--text-muted)';
            const Icon = meta.icon;
            return (
              <div
                key={i}
                className="darkweb-row"
                style={{ ['--severity-color' as any]: sevColor }}
              >
                <div style={{
                  flex: '0 0 32px', height: 32, borderRadius: 8,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: 'var(--bg-tertiary)', color: meta.color,
                  fontSize: 16,
                }}>
                  <Icon />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4, flexWrap: 'wrap' }}>
                    <span className={`badge badge-${ind.severity || 'info'}`}>{ind.severity || 'info'}</span>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.7 }}>{meta.label}</span>
                    {ind.source && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>· {ind.source}</span>}
                  </div>
                  <div style={{
                    fontFamily: 'var(--font-mono)', fontSize: 12.5,
                    color: 'var(--text-primary)', fontWeight: 500,
                    wordBreak: 'break-all',
                  }}>
                    {ind.value}
                  </div>
                  {ind.description && (
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4, lineHeight: 1.5 }}>
                      {ind.description}
                    </div>
                  )}
                  {ind.query && (
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                      Query: <code style={{ color: 'var(--accent)' }}>{ind.query}</code>
                    </div>
                  )}
                </div>
                {ind.url && (
                  <a
                    href={ind.url}
                    target="_blank"
                    rel="noreferrer"
                    className="btn btn-ghost btn-sm"
                    style={{ flexShrink: 0 }}
                  >
                    <HiOutlineExternalLink /> Open
                  </a>
                )}
              </div>
            );
          })}
          {filtered.length > 80 && (
            <div style={{ textAlign: 'center', fontSize: 12, color: 'var(--text-muted)', padding: 12 }}>
              Showing 80 of {filtered.length}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
