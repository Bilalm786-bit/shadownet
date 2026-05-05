import { useState } from 'react';
import { osintAPI } from '../api/client';
import { HiOutlineSearch, HiOutlineShieldCheck, HiOutlineExclamation, HiOutlineChevronDown, HiOutlineChevronUp } from 'react-icons/hi';

interface InvestigationResult {
  target: string;
  target_type: string;
  started_at: string;
  completed_at: string;
  modules_run: string[];
  results: Record<string, any>;
  entities_found: any[];
  ai_analysis: any;
  risk_score: number;
  summary: string;
  errors: string[];
}

const TYPE_ICONS: Record<string, string> = {
  email: '📧', domain: '🌐', ip: '🔢', username: '👤', phone: '📱', url: '🔗', person: '🧑',
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)',
  low: 'var(--green)', info: 'var(--text-muted)',
};

function RiskGauge({ score }: { score: number }) {
  const color = score >= 75 ? 'var(--red)' : score >= 50 ? 'var(--orange)' : score >= 25 ? 'var(--yellow)' : 'var(--green)';
  return (
    <div style={{ textAlign: 'center', padding: 16 }}>
      <div style={{ position: 'relative', width: 120, height: 120, margin: '0 auto' }}>
        <svg viewBox="0 0 120 120" width="120" height="120">
          <circle cx="60" cy="60" r="52" fill="none" stroke="var(--border-glass)" strokeWidth="8" />
          <circle cx="60" cy="60" r="52" fill="none" stroke={color} strokeWidth="8"
            strokeDasharray={`${(score / 100) * 327} 327`}
            strokeLinecap="round" transform="rotate(-90 60 60)"
            style={{ transition: 'stroke-dasharray 1s ease' }} />
        </svg>
        <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', fontSize: 28, fontWeight: 700, color }}>
          {score}
        </div>
      </div>
      <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 8 }}>Risk Score</div>
    </div>
  );
}

function ModuleResult({ name, data }: { name: string; data: any }) {
  const [expanded, setExpanded] = useState(false);
  const severity = data.severity || 'info';

  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden', marginBottom: 8 }}>
      <div
        onClick={() => setExpanded(!expanded)}
        style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px', cursor: 'pointer',
          borderLeft: `3px solid ${SEVERITY_COLORS[severity] || 'var(--border-glass)'}`,
          background: expanded ? 'rgba(255,255,255,0.02)' : 'transparent' }}
      >
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, flex: 1 }}>{name}</span>
        <span className={`badge badge-${severity}`}>{severity}</span>
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{data.entity_count || 0} entities</span>
        {expanded ? <HiOutlineChevronUp /> : <HiOutlineChevronDown />}
      </div>
      {expanded && (
        <div style={{ padding: '0 16px 12px', fontSize: 13, lineHeight: 1.6, borderTop: '1px solid var(--border-glass)' }}>
          <p style={{ color: 'var(--text-secondary)', margin: '8px 0' }}>{data.summary}</p>
          {data.data && (
            <pre style={{ background: 'var(--bg-tertiary)', padding: 12, borderRadius: 6, fontSize: 11,
              maxHeight: 300, overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
              {JSON.stringify(data.data, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

export default function InvestigatePage() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [detectedType, setDetectedType] = useState('');
  const [error, setError] = useState('');
  const [depth, setDepth] = useState(1);

  const handleDetect = async (value: string) => {
    setTarget(value);
    if (value.trim().length > 2) {
      try {
        const res = await osintAPI.detectType(value.trim());
        setDetectedType(res.data.detected_type);
      } catch { setDetectedType(''); }
    } else {
      setDetectedType('');
    }
  };

  const handleInvestigate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;
    setLoading(true); setError(''); setResult(null);
    try {
      const res = await osintAPI.autoInvestigate({ target: target.trim(), depth });
      setResult(res.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Investigation failed');
    }
    setLoading(false);
  };

  return (
    <div className="fade-in">
      <div className="section-header">
        <h2 className="section-title">🔍 Auto-Investigate</h2>
        <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>
          Paste any target — email, domain, IP, username, phone — and let ShadowNet do the rest.
        </p>
      </div>

      <div className="card" style={{ marginBottom: 24, padding: 24 }}>
        <form onSubmit={handleInvestigate}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end' }}>
            <div style={{ flex: 1 }}>
              <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
                Target {detectedType && <span style={{ color: 'var(--accent)' }}>— detected as: {TYPE_ICONS[detectedType] || '❓'} {detectedType}</span>}
              </label>
              <div style={{ position: 'relative' }}>
                <HiOutlineSearch style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', fontSize: 18 }} />
                <input
                  className="input" style={{ paddingLeft: 42, fontSize: 15, height: 48 }}
                  value={target} onChange={e => handleDetect(e.target.value)}
                  placeholder="Enter email, domain, IP, username, or phone number..."
                />
              </div>
            </div>
            <div>
              <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>Depth</label>
              <select className="input" value={depth} onChange={e => setDepth(Number(e.target.value))} style={{ width: 80, height: 48 }}>
                <option value={1}>1</option>
                <option value={2}>2</option>
              </select>
            </div>
            <button className="btn btn-primary" type="submit" disabled={loading || !target.trim()}
              style={{ height: 48, minWidth: 160, fontSize: 15 }}>
              {loading ? '⏳ Investigating...' : '🚀 Investigate'}
            </button>
          </div>
        </form>
      </div>

      {error && <div className="card" style={{ borderLeft: '3px solid var(--red)', padding: 16, marginBottom: 16 }}>
        <HiOutlineExclamation style={{ color: 'var(--red)', marginRight: 8 }} />
        <span style={{ color: 'var(--red)' }}>{error}</span>
      </div>}

      {loading && (
        <div className="card" style={{ textAlign: 'center', padding: 60 }}>
          <div className="pulse" style={{ fontSize: 48, marginBottom: 16 }}>🔎</div>
          <div style={{ fontSize: 16, color: 'var(--accent)', marginBottom: 8 }}>Investigation in progress...</div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>Running all OSINT modules against {target}. This may take 30-60 seconds.</div>
        </div>
      )}

      {result && !loading && (
        <div className="fade-in">
          {/* Overview Strip */}
          <div className="grid-4" style={{ marginBottom: 20 }}>
            <div className="card stat-card">
              <div className="stat-value">{TYPE_ICONS[result.target_type] || '❓'} {result.target_type}</div>
              <div className="stat-label">Target Type</div>
            </div>
            <div className="card stat-card">
              <div className="stat-value">{result.modules_run.length}</div>
              <div className="stat-label">Modules Run</div>
            </div>
            <div className="card stat-card">
              <div className="stat-value">{result.entities_found.length}</div>
              <div className="stat-label">Entities Found</div>
            </div>
            <div className="card stat-card">
              <RiskGauge score={result.risk_score} />
            </div>
          </div>

          {/* Summary */}
          <div className="card" style={{ marginBottom: 20, padding: 20, borderLeft: '3px solid var(--accent)' }}>
            <HiOutlineShieldCheck style={{ color: 'var(--accent)', fontSize: 20, marginRight: 8, verticalAlign: 'middle' }} />
            <span style={{ fontWeight: 600 }}>Summary:</span>
            <p style={{ margin: '8px 0 0', fontSize: 14, lineHeight: 1.6, color: 'var(--text-secondary)' }}>{result.summary}</p>
          </div>

          {/* AI Analysis */}
          {result.ai_analysis && (
            <div className="card" style={{ marginBottom: 20, padding: 20 }}>
              <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 12 }}>🤖 AI Threat Analysis</h3>
              {result.ai_analysis.executive_summary && (
                <p style={{ fontSize: 14, lineHeight: 1.7, color: 'var(--text-secondary)', marginBottom: 12 }}>
                  {result.ai_analysis.executive_summary}
                </p>
              )}
              {result.ai_analysis.key_findings && (
                <div>
                  <h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Key Findings</h4>
                  <ul style={{ paddingLeft: 20 }}>
                    {result.ai_analysis.key_findings.map((f: any, i: number) => (
                      <li key={i} style={{ fontSize: 13, marginBottom: 4, color: 'var(--text-secondary)' }}>
                        {typeof f === 'string' ? f : f.finding || JSON.stringify(f)}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {result.ai_analysis.recommendations && (
                <div style={{ marginTop: 12 }}>
                  <h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Recommendations</h4>
                  <ul style={{ paddingLeft: 20 }}>
                    {result.ai_analysis.recommendations.map((r: any, i: number) => (
                      <li key={i} style={{ fontSize: 13, marginBottom: 4, color: 'var(--text-secondary)' }}>
                        {typeof r === 'string' ? r : r.recommendation || JSON.stringify(r)}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Module Results */}
          <div className="card" style={{ padding: 20, marginBottom: 20 }}>
            <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>📊 Module Results</h3>
            {Object.entries(result.results).map(([name, data]) => (
              <ModuleResult key={name} name={name} data={data} />
            ))}
          </div>

          {/* Entities */}
          {result.entities_found.length > 0 && (
            <div className="card" style={{ padding: 20 }}>
              <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>
                🎯 Discovered Entities ({result.entities_found.length})
              </h3>
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>Type</th><th>Value</th><th>Source</th><th>Confidence</th></tr></thead>
                  <tbody>
                    {result.entities_found.slice(0, 100).map((e: any, i: number) => (
                      <tr key={i}>
                        <td><span className="badge badge-info">{e.type}</span></td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.value}</td>
                        <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{e.source}</td>
                        <td>{Math.round(e.confidence * 100)}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {result.entities_found.length > 100 && (
                <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 8 }}>Showing 100 of {result.entities_found.length} entities</p>
              )}
            </div>
          )}

          {/* Errors */}
          {result.errors.length > 0 && (
            <div className="card" style={{ marginTop: 20, padding: 16, borderLeft: '3px solid var(--orange)' }}>
              <h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8, color: 'var(--orange)' }}>⚠️ Errors ({result.errors.length})</h4>
              {result.errors.map((err, i) => (
                <div key={i} style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: 4 }}>{err}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
