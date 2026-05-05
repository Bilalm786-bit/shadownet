import { useState } from 'react';
import { investigateAPI } from '../api/client';
import { HiOutlineSearch, HiOutlineShieldCheck, HiOutlineExclamation, HiOutlineChevronDown, HiOutlineChevronUp, HiOutlineCode } from 'react-icons/hi';

function RiskGauge({ score }: { score: number }) {
  const color = score >= 75 ? 'var(--red)' : score >= 50 ? 'var(--orange)' : score >= 25 ? 'var(--yellow)' : 'var(--green)';
  return (
    <div className="risk-gauge">
      <div style={{ position: 'relative', width: 110, height: 110 }}>
        <svg viewBox="0 0 120 120" width="110" height="110">
          <circle cx="60" cy="60" r="52" fill="none" stroke="var(--border-glass)" strokeWidth="7" />
          <circle cx="60" cy="60" r="52" fill="none" stroke={color} strokeWidth="7"
            strokeDasharray={`${(score / 100) * 327} 327`} strokeLinecap="round" transform="rotate(-90 60 60)"
            style={{ transition: 'stroke-dasharray 1.2s ease', filter: `drop-shadow(0 0 6px ${color})` }} />
        </svg>
        <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', fontSize: 26, fontWeight: 700, color }}>{score}</div>
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>Security Score</div>
    </div>
  );
}

function ModuleResult({ name, data }: { name: string; data: any }) {
  const [open, setOpen] = useState(false);
  const sev = data.severity || 'info';
  const colors: Record<string, string> = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--cyan)', low: 'var(--green)', info: 'var(--text-muted)' };
  return (
    <div className="module-result">
      <div className="module-result-header" onClick={() => setOpen(!open)} style={{ borderLeft: `3px solid ${colors[sev] || 'var(--border-glass)'}` }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, flex: 1, color: 'var(--text-secondary)' }}>{name}</span>
        <span className={`badge badge-${sev}`}>{sev}</span>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{data.entity_count || 0} entities</span>
        {open ? <HiOutlineChevronUp /> : <HiOutlineChevronDown />}
      </div>
      {open && (
        <div className="module-result-body">
          <p style={{ color: 'var(--text-secondary)', margin: '10px 0', fontSize: 13, lineHeight: 1.6 }}>{data.summary}</p>
          {data.data && <pre style={{ background: 'var(--bg-secondary)', padding: 12, borderRadius: 6, fontSize: 11, maxHeight: 250, overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-word', color: 'var(--text-muted)' }}>{JSON.stringify(data.data, null, 2)}</pre>}
        </div>
      )}
    </div>
  );
}

export default function WebsiteInvestigation() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;
    setLoading(true); setError(''); setResult(null);
    try {
      const res = await investigateAPI.website(target.trim());
      setResult(res.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Investigation failed');
    }
    setLoading(false);
  };

  // Extract tech stack from results
  const techData = result?.results?.['network.tech_detector']?.data || {};
  const techs = [
    techData.server && `Server: ${techData.server}`,
    techData.cms && `CMS: ${techData.cms}`,
    ...(techData.waf || []).map((w: string) => `WAF: ${w}`),
    ...(techData.js_libraries || []).map((l: string) => l),
  ].filter(Boolean);

  return (
    <div className="fade-in">
      <div className="section-header">
        <h2 className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 28 }}>🔗</span> Website Investigation
        </h2>
      </div>
      <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 20, maxWidth: 600 }}>
        Investigate any website or URL. ShadowNet scans technology stack, SSL certificates, DNS records,
        subdomains, Wayback Machine history, VirusTotal reputation, and performs deep crawling with AI analysis.
      </p>

      <div className="card" style={{ marginBottom: 24, padding: 24 }}>
        <form onSubmit={handleSubmit}>
          <div className="invest-search-bar">
            <div style={{ flex: 1, position: 'relative' }}>
              <HiOutlineSearch className="invest-search-icon" />
              <input className="input" style={{ paddingLeft: 48, fontSize: 15, height: 52 }} value={target}
                onChange={e => setTarget(e.target.value)} placeholder="Enter URL or domain (e.g. example.com, https://target.com)..." />
            </div>
            <button className="btn btn-primary btn-lg" type="submit" disabled={loading || !target.trim()}>
              {loading ? '⏳ Scanning...' : '🔗 Investigate Website'}
            </button>
          </div>
        </form>
      </div>

      {error && <div className="card" style={{ borderLeft: '3px solid var(--red)', padding: 16, marginBottom: 16 }}>
        <HiOutlineExclamation style={{ color: 'var(--red)', marginRight: 8 }} /><span style={{ color: 'var(--red)' }}>{error}</span>
      </div>}

      {loading && (
        <div className="card" style={{ textAlign: 'center', padding: 60 }}>
          <div className="pulse" style={{ fontSize: 52, marginBottom: 16 }}>🕸️</div>
          <div style={{ fontSize: 16, color: 'var(--orange)', marginBottom: 8, fontWeight: 600 }}>Analyzing website...</div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>Running tech detection, SSL analysis, crawler, DNS, WHOIS, subdomains, Wayback, and VirusTotal.</div>
          <div className="progress-bar" style={{ marginTop: 20, maxWidth: 400, margin: '20px auto 0' }}>
            <div className="progress-fill" style={{ width: '50%', animation: 'shimmer 2s infinite' }} />
          </div>
        </div>
      )}

      {result && !loading && (
        <div className="slide-up">
          <div className="grid-4 stagger" style={{ marginBottom: 20 }}>
            <div className="card stat-card slide-up"><div className="stat-icon" style={{ background: 'var(--orange-dim)', color: 'var(--orange)' }}><HiOutlineCode /></div><div><div className="stat-value">{result.category || 'website'}</div><div className="stat-label">Category</div></div></div>
            <div className="card stat-card slide-up"><div className="stat-icon" style={{ background: 'var(--accent-dim)', color: 'var(--accent)' }}>📊</div><div><div className="stat-value">{result.modules_run?.length || 0}</div><div className="stat-label">Modules Run</div></div></div>
            <div className="card stat-card slide-up"><div className="stat-icon" style={{ background: 'var(--green-dim)', color: 'var(--green)' }}>🎯</div><div><div className="stat-value">{result.entities_found?.length || 0}</div><div className="stat-label">Entities Found</div></div></div>
            <div className="card stat-card slide-up"><RiskGauge score={result.risk_score || 0} /></div>
          </div>

          {techs.length > 0 && (
            <div className="card" style={{ marginBottom: 20, padding: 20 }}>
              <h3 className="result-section-title">⚙️ Technology Stack</h3>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {techs.map((t, i) => <span key={i} className="entity-tag" style={{ fontSize: 12, padding: '6px 14px' }}>{t}</span>)}
              </div>
            </div>
          )}

          <div className="card" style={{ marginBottom: 20, padding: 20, borderLeft: '3px solid var(--orange)' }}>
            <HiOutlineShieldCheck style={{ color: 'var(--orange)', fontSize: 20, marginRight: 8, verticalAlign: 'middle' }} />
            <span style={{ fontWeight: 600 }}>Summary</span>
            <p style={{ margin: '8px 0 0', fontSize: 14, lineHeight: 1.7, color: 'var(--text-secondary)' }}>{result.summary}</p>
          </div>

          {result.ai_analysis && (
            <div className="card result-section" style={{ padding: 20 }}>
              <h3 className="result-section-title">🤖 AI Security Analysis</h3>
              {result.ai_analysis.executive_summary && <p style={{ fontSize: 14, lineHeight: 1.7, color: 'var(--text-secondary)', marginBottom: 16 }}>{result.ai_analysis.executive_summary}</p>}
              {result.ai_analysis.attack_surface && (<><h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Attack Surface</h4>
                <ul style={{ paddingLeft: 20, marginBottom: 16 }}>{result.ai_analysis.attack_surface.map((a: any, i: number) => <li key={i} style={{ fontSize: 13, marginBottom: 4, color: 'var(--text-secondary)' }}>{typeof a === 'string' ? a : JSON.stringify(a)}</li>)}</ul></>)}
              {result.ai_analysis.recommendations && (<><h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Security Recommendations</h4>
                <ul style={{ paddingLeft: 20 }}>{result.ai_analysis.recommendations.map((r: any, i: number) => <li key={i} style={{ fontSize: 13, marginBottom: 4, color: 'var(--text-secondary)' }}>{typeof r === 'string' ? r : JSON.stringify(r)}</li>)}</ul></>)}
            </div>
          )}

          <div className="card result-section" style={{ padding: 20 }}>
            <h3 className="result-section-title">📊 Module Results ({Object.keys(result.results || {}).length})</h3>
            {Object.entries(result.results || {}).map(([name, data]: [string, any]) => <ModuleResult key={name} name={name} data={data} />)}
          </div>

          {result.entities_found?.length > 0 && (
            <div className="card result-section" style={{ padding: 20 }}>
              <h3 className="result-section-title">🎯 Discovered Entities ({result.entities_found.length})</h3>
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>Type</th><th>Value</th><th>Source</th><th>Confidence</th></tr></thead>
                  <tbody>{result.entities_found.slice(0, 100).map((e: any, i: number) => (
                    <tr key={i}><td><span className="badge badge-info">{e.type}</span></td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.value}</td>
                      <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{e.source}</td>
                      <td>{Math.round((e.confidence || 0) * 100)}%</td></tr>))}</tbody>
                </table>
              </div>
            </div>
          )}

          {result.errors?.length > 0 && (
            <div className="card" style={{ padding: 16, borderLeft: '3px solid var(--orange)' }}>
              <h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8, color: 'var(--orange)' }}>⚠️ Errors ({result.errors.length})</h4>
              {result.errors.map((err: string, i: number) => <div key={i} style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: 4 }}>{err}</div>)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
