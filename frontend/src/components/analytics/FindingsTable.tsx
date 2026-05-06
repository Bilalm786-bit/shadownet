import { useMemo, useState } from 'react';
import { HiOutlineSearch, HiOutlineX, HiOutlineExternalLink } from 'react-icons/hi';

export interface Finding {
  id: string;
  plugin: string;
  family: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | string;
  cvss?: number;
  cwe?: string | null;
  affected?: string;
  evidence?: string;
  solution?: string;
  references?: string[];
}

interface Props {
  findings: Finding[];
}

const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

export default function FindingsTable({ findings }: Props) {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [familyFilter, setFamilyFilter] = useState<string>('all');
  const [selected, setSelected] = useState<Finding | null>(null);

  const families = useMemo(() => {
    const s = new Set<string>();
    findings.forEach(f => f.family && s.add(f.family));
    return Array.from(s).sort();
  }, [findings]);

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    return findings.filter(f => {
      if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
      if (familyFilter !== 'all' && f.family !== familyFilter) return false;
      if (!q) return true;
      return (
        f.title.toLowerCase().includes(q) ||
        (f.affected || '').toLowerCase().includes(q) ||
        (f.plugin || '').toLowerCase().includes(q) ||
        (f.cwe || '').toLowerCase().includes(q)
      );
    }).sort((a, b) => {
      const sa = SEV_RANK[a.severity] || 0;
      const sb = SEV_RANK[b.severity] || 0;
      if (sa !== sb) return sb - sa;
      return (b.cvss || 0) - (a.cvss || 0);
    });
  }, [findings, search, severityFilter, familyFilter]);

  return (
    <div>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 16 }}>
        <div style={{ position: 'relative', flex: '1 1 260px' }}>
          <HiOutlineSearch style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            className="input"
            style={{ paddingLeft: 36 }}
            placeholder="Search title / affected / CWE / plugin..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <select className="input" style={{ flex: '0 0 160px' }} value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select className="input" style={{ flex: '0 0 220px' }} value={familyFilter} onChange={e => setFamilyFilter(e.target.value)}>
          <option value="all">All families</option>
          {families.map(f => <option key={f} value={f}>{f}</option>)}
        </select>
      </div>

      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>
        Showing {filtered.length} of {findings.length} findings
      </div>

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th style={{ width: 90 }}>Severity</th>
              <th style={{ width: 60 }}>CVSS</th>
              <th>Title</th>
              <th style={{ width: 200 }}>Family</th>
              <th style={{ width: 80 }}>CWE</th>
              <th style={{ width: 240 }}>Affected</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((f) => (
              <tr key={`${f.plugin}-${f.id}`} onClick={() => setSelected(f)} style={{ cursor: 'pointer' }}>
                <td>
                  <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600 }}>
                  {(f.cvss ?? 0).toFixed(1)}
                </td>
                <td style={{ fontSize: 13, color: 'var(--text-primary)' }}>{f.title}</td>
                <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{f.family}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>{f.cwe || '—'}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {f.affected || '—'}
                </td>
              </tr>
            ))}
            {!filtered.length && (
              <tr><td colSpan={6} style={{ textAlign: 'center', padding: 28, color: 'var(--text-muted)' }}>No findings match the filters.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {selected && <FindingDrawer finding={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function FindingDrawer({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(6,8,15,0.7)', backdropFilter: 'blur(8px)',
        zIndex: 1000, display: 'flex', justifyContent: 'flex-end',
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%', maxWidth: 640, height: '100%', overflowY: 'auto',
          background: 'var(--bg-secondary)', borderLeft: '1px solid var(--border-active)',
          padding: 24, animation: 'slideRight .3s ease',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, marginBottom: 20 }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 12 }}>
              <span className={`badge badge-${finding.severity}`}>{finding.severity}</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)' }}>
                CVSS {(finding.cvss ?? 0).toFixed(1)}
              </span>
              {finding.cwe && (
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)' }}>{finding.cwe}</span>
              )}
            </div>
            <h2 style={{ fontSize: 18, fontWeight: 700, lineHeight: 1.4, marginBottom: 6 }}>{finding.title}</h2>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              {finding.family} · plugin <code style={{ color: 'var(--accent)' }}>{finding.plugin}</code>
            </div>
          </div>
          <button onClick={onClose} className="btn btn-ghost btn-sm" style={{ flexShrink: 0 }}>
            <HiOutlineX />
          </button>
        </div>

        <DrawerSection title="Affected">
          <code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
            {finding.affected || 'n/a'}
          </code>
        </DrawerSection>

        {finding.evidence && (
          <DrawerSection title="Evidence">
            <pre style={{
              background: 'var(--bg-card)', padding: 14, borderRadius: 8, fontSize: 12,
              fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)',
              whiteSpace: 'pre-wrap', wordBreak: 'break-word', lineHeight: 1.6,
              border: '1px solid var(--border-glass)', maxHeight: 240, overflow: 'auto',
            }}>{finding.evidence}</pre>
          </DrawerSection>
        )}

        {finding.solution && (
          <DrawerSection title="Recommended Solution">
            <p style={{ fontSize: 14, lineHeight: 1.7, color: 'var(--text-secondary)' }}>{finding.solution}</p>
          </DrawerSection>
        )}

        {finding.references && finding.references.length > 0 && (
          <DrawerSection title="References">
            {finding.references.map((r, i) => (
              <a
                key={i}
                href={r}
                target="_blank"
                rel="noreferrer"
                style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 0', fontSize: 13, wordBreak: 'break-all' }}
              >
                <HiOutlineExternalLink style={{ flexShrink: 0 }} /> {r}
              </a>
            ))}
          </DrawerSection>
        )}
      </div>
    </div>
  );
}

function DrawerSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 22 }}>
      <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 10 }}>
        {title}
      </div>
      {children}
    </div>
  );
}
