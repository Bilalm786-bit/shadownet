import { useState, useEffect } from 'react';
import { darkwebAPI } from '../api/client';
import { HiOutlineGlobe, HiOutlineSearch, HiOutlineShieldCheck, HiOutlineExclamation,
  HiOutlineDownload, HiOutlineRefresh, HiOutlineEye, HiOutlineLink,
  HiOutlineDatabase, HiOutlineCode, HiOutlineKey } from 'react-icons/hi';

type TabKey = 'all' | 'onion' | 'breaches' | 'leaks' | 'dorks';

const TABS: { key: TabKey; label: string; icon: JSX.Element }[] = [
  { key: 'all', label: 'All Results', icon: <HiOutlineGlobe /> },
  { key: 'onion', label: 'Onion Sites', icon: <HiOutlineLink /> },
  { key: 'breaches', label: 'Breaches', icon: <HiOutlineDatabase /> },
  { key: 'leaks', label: 'Code Leaks', icon: <HiOutlineCode /> },
  { key: 'dorks', label: 'Intel Dorks', icon: <HiOutlineKey /> },
];

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444', high: '#f59e0b', medium: '#06b6d4', low: '#10b981', info: '#818cf8',
};

const TYPE_FILTERS: Record<TabKey, string[]> = {
  all: [],
  onion: ['onion_result'],
  breaches: ['breach', 'breach_reference', 'reputation'],
  leaks: ['code_leak'],
  dorks: ['dork_query'],
};

function RiskRing({ score, level }: { score: number; level: string }) {
  const pct = Math.min(score / 10, 1);
  const r = 54, circ = 2 * Math.PI * r;
  const offset = circ * (1 - pct);
  const color = SEVERITY_COLORS[level] || '#818cf8';
  return (
    <div style={{ position: 'relative', width: 130, height: 130 }}>
      <svg width="130" height="130" viewBox="0 0 130 130">
        <circle cx="65" cy="65" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" />
        <circle cx="65" cy="65" r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 1s ease', transform: 'rotate(-90deg)', transformOrigin: 'center' }} />
      </svg>
      <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
        <span style={{ fontSize: 28, fontWeight: 800, color }}>{score.toFixed(1)}</span>
        <span style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, color: 'var(--text-muted)', fontWeight: 600 }}>{level}</span>
      </div>
    </div>
  );
}

function StatBox({ icon, value, label, color }: { icon: JSX.Element; value: number | string; label: string; color: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '16px 20px', background: 'var(--bg-glass)',
      border: '1px solid var(--border-glass)', borderRadius: 'var(--radius-sm)' }}>
      <div style={{ width: 42, height: 42, borderRadius: 'var(--radius-sm)', background: `${color}18`,
        display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 20, color, flexShrink: 0 }}>{icon}</div>
      <div>
        <div style={{ fontSize: 22, fontWeight: 700, lineHeight: 1 }}>{value}</div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 3 }}>{label}</div>
      </div>
    </div>
  );
}

export default function DarkWebPage() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState<TabKey>('all');
  const [riskAssessment, setRiskAssessment] = useState<any>(null);
  const [summary, setSummary] = useState<any>(null);
  const [sourcesChecked, setSourcesChecked] = useState<string[]>([]);
  const [engineStatus, setEngineStatus] = useState<any>(null);
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  useEffect(() => {
    darkwebAPI.status().then(r => setEngineStatus(r.data)).catch(() => {});
  }, []);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;
    setLoading(true); setSearched(true); setError(''); setActiveTab('all'); setSeverityFilter('all'); setExpandedIdx(null);
    try {
      const res = await darkwebAPI.search(query, 50);
      setResults(res.data.results || []);
      setRiskAssessment(res.data.risk_assessment || null);
      setSummary(res.data.summary || null);
      setSourcesChecked(res.data.sources_checked || []);
      if (res.data.errors?.length) setError(res.data.errors.join('; '));
    } catch (err: any) {
      setResults([]); setRiskAssessment(null); setSummary(null);
      setError(err.response?.data?.detail || 'Dark web search failed');
    }
    setLoading(false);
  };

  const handleExport = async () => {
    if (!query) return;
    try {
      const res = await darkwebAPI.exportResults(query, 'json');
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url;
      a.download = `darkweb_${query}_${new Date().toISOString().slice(0, 10)}.json`;
      a.click(); URL.revokeObjectURL(url);
    } catch { /* ignore */ }
  };

  // Filter results by tab and severity
  const filteredResults = results.filter(r => {
    const typeMatch = TYPE_FILTERS[activeTab].length === 0 || TYPE_FILTERS[activeTab].includes(r.type);
    const sevMatch = severityFilter === 'all' || r.severity === severityFilter;
    return typeMatch && sevMatch;
  });

  const tabCounts: Record<TabKey, number> = {
    all: results.length,
    onion: results.filter(r => TYPE_FILTERS.onion.includes(r.type)).length,
    breaches: results.filter(r => TYPE_FILTERS.breaches.includes(r.type)).length,
    leaks: results.filter(r => TYPE_FILTERS.leaks.includes(r.type)).length,
    dorks: results.filter(r => TYPE_FILTERS.dorks.includes(r.type)).length,
  };

  return (
    <div className="fade-in">
      {/* Header */}
      <div className="section-header">
        <h2 className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <HiOutlineGlobe style={{ color: 'var(--orange)' }} /> Dark Web Intelligence
        </h2>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {engineStatus && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-muted)',
              padding: '6px 12px', background: 'var(--bg-glass)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-glass)' }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%',
                background: engineStatus.tor?.connected ? 'var(--green)' : 'var(--red)' }} />
              Tor: {engineStatus.tor?.connected ? 'Connected' : 'Offline'}
              <span style={{ margin: '0 6px', color: 'var(--border-glass)' }}>|</span>
              {engineStatus.sources?.length || 0} Sources
            </div>
          )}
          {searched && results.length > 0 && (
            <button className="btn btn-ghost btn-sm" onClick={handleExport} title="Export results">
              <HiOutlineDownload /> Export
            </button>
          )}
        </div>
      </div>

      {/* Search Bar */}
      <div className="card" style={{ marginBottom: 24 }}>
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: 12 }}>
          <div style={{ flex: 1, position: 'relative' }}>
            <HiOutlineSearch style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', fontSize: 18 }} />
            <input className="input" style={{ paddingLeft: 42 }} value={query} onChange={e => setQuery(e.target.value)}
              placeholder="Search emails, domains, keywords on the dark web..." />
          </div>
          <button className="btn btn-primary" type="submit" disabled={loading}>
            {loading ? <><HiOutlineRefresh className="pulse" /> Scanning...</> : <><HiOutlineShieldCheck /> Investigate</>}
          </button>
        </form>
        <div style={{ display: 'flex', gap: 16, marginTop: 10, fontSize: 11, color: 'var(--text-muted)' }}>
          <span>🔍 Ahmia.fi</span><span>🛡️ HIBP Breaches</span><span>🐙 GitHub Leaks</span>
          <span>📋 Paste Sites</span><span>🧅 Onion Dorks</span><span>🔓 No API keys required</span>
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="card" style={{ textAlign: 'center', padding: 48 }}>
          <div className="pulse" style={{ fontSize: 48, marginBottom: 16, opacity: 0.4 }}>🌐</div>
          <p style={{ color: 'var(--text-secondary)', fontSize: 15 }}>Querying dark web intelligence sources...</p>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 6 }}>Scanning Ahmia, breach databases, GitHub, paste sites...</p>
        </div>
      )}

      {/* Error */}
      {error && !loading && (
        <div className="card" style={{ padding: 16, marginBottom: 16, display: 'flex', alignItems: 'center', gap: 10, borderColor: 'rgba(245,158,11,0.3)' }}>
          <HiOutlineExclamation style={{ color: 'var(--orange)', fontSize: 20, flexShrink: 0 }} />
          <span style={{ color: 'var(--orange)', fontSize: 13 }}>{error}</span>
        </div>
      )}

      {/* Results Dashboard */}
      {!loading && searched && results.length > 0 && (
        <>
          {/* Risk & Stats Row */}
          <div style={{ display: 'grid', gridTemplateColumns: '150px 1fr', gap: 20, marginBottom: 24 }}>
            {/* Risk Ring */}
            <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
              <RiskRing score={riskAssessment?.risk_score || 0} level={riskAssessment?.risk_level || 'info'} />
              <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8, textAlign: 'center' }}>Threat Score</p>
            </div>
            {/* Stats Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 12 }}>
              <StatBox icon={<HiOutlineGlobe />} value={summary?.onion_results || 0} label="Onion Results" color="#f59e0b" />
              <StatBox icon={<HiOutlineDatabase />} value={summary?.breach_mentions || 0} label="Breach Mentions" color="#ef4444" />
              <StatBox icon={<HiOutlineCode />} value={summary?.code_leaks || 0} label="Code Leaks" color="#a855f7" />
              <StatBox icon={<HiOutlineKey />} value={summary?.dork_queries || 0} label="Intel Dorks" color="#06b6d4" />
              <StatBox icon={<HiOutlineShieldCheck />} value={sourcesChecked.length} label="Sources Checked" color="#10b981" />
              <StatBox icon={<HiOutlineEye />} value={riskAssessment?.total_iocs || 0} label="IOCs Found" color="#f59e0b" />
            </div>
          </div>

          {/* Tabs & Severity Filter */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16, flexWrap: 'wrap', gap: 10 }}>
            <div style={{ display: 'flex', gap: 4 }}>
              {TABS.map(tab => (
                <button key={tab.key} onClick={() => setActiveTab(tab.key)}
                  style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 16px', borderRadius: 'var(--radius-sm)',
                    border: activeTab === tab.key ? '1px solid var(--accent)' : '1px solid var(--border-glass)',
                    background: activeTab === tab.key ? 'rgba(99,102,241,0.15)' : 'transparent',
                    color: activeTab === tab.key ? 'var(--accent)' : 'var(--text-secondary)',
                    cursor: 'pointer', fontSize: 13, fontWeight: 600, fontFamily: 'var(--font-sans)', transition: 'all .2s' }}>
                  {tab.icon} {tab.label}
                  <span style={{ fontSize: 11, opacity: 0.7 }}>({tabCounts[tab.key]})</span>
                </button>
              ))}
            </div>
            <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-primary)', border: '1px solid var(--border-glass)',
                borderRadius: 'var(--radius-sm)', padding: '6px 12px', fontSize: 12, fontFamily: 'var(--font-sans)', cursor: 'pointer' }}>
              <option value="all">All Severities</option>
              <option value="critical">🔴 Critical</option>
              <option value="high">🟠 High</option>
              <option value="medium">🔵 Medium</option>
              <option value="low">🟢 Low</option>
              <option value="info">⚪ Info</option>
            </select>
          </div>

          {/* Results List */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              Showing {filteredResults.length} of {results.length} results
            </p>
            {filteredResults.map((r: any, i: number) => {
              const sevColor = SEVERITY_COLORS[r.severity] || '#818cf8';
              const isExpanded = expandedIdx === i;
              return (
                <div className="card" key={i} style={{ padding: 0, cursor: 'pointer', borderLeft: `3px solid ${sevColor}` }}
                  onClick={() => setExpandedIdx(isExpanded ? null : i)}>
                  <div style={{ padding: '16px 20px' }}>
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                      <div style={{ width: 10, height: 10, borderRadius: '50%', background: sevColor, marginTop: 5, flexShrink: 0 }} />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
                          <h4 style={{ fontSize: 14, fontWeight: 600, margin: 0 }}>{r.title || 'Untitled'}</h4>
                          <span className={`badge badge-${r.severity || 'info'}`}>{r.severity || 'info'}</span>
                          {r.threat_score > 0 && (
                            <span style={{ fontSize: 11, color: sevColor, fontWeight: 600 }}>
                              Score: {r.threat_score}
                            </span>
                          )}
                        </div>
                        {r.url && (
                          <a href={r.url} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()}
                            style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--orange)',
                              display: 'block', marginBottom: 6, wordBreak: 'break-all', textDecoration: 'none' }}>
                            {r.url.length > 100 ? r.url.slice(0, 100) + '...' : r.url}
                          </a>
                        )}
                        <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                          {r.description || 'No description available'}
                        </p>
                        <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                          <span className="badge badge-info">{r.source || 'unknown'}</span>
                          <span style={{ fontSize: 11, color: 'var(--text-muted)', padding: '2px 8px',
                            background: 'rgba(255,255,255,0.04)', borderRadius: 4 }}>{r.type}</span>
                          {r.threat_categories?.map((c: string) => (
                            <span key={c} style={{ fontSize: 10, color: sevColor, padding: '2px 8px',
                              background: `${sevColor}15`, borderRadius: 4, fontWeight: 600 }}>{c.replace(/_/g, ' ')}</span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                  {/* Expanded Details */}
                  {isExpanded && (
                    <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border-glass)', background: 'rgba(0,0,0,0.15)' }}>
                      {r.matched_keywords?.length > 0 && (
                        <div style={{ marginBottom: 10 }}>
                          <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Matched Keywords: </span>
                          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{r.matched_keywords.join(', ')}</span>
                        </div>
                      )}
                      {r.iocs && Object.keys(r.iocs).length > 0 && (
                        <div style={{ marginBottom: 10 }}>
                          <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>IOCs Extracted:</span>
                          {Object.entries(r.iocs).map(([type, values]: [string, any]) => (
                            <div key={type} style={{ marginTop: 4 }}>
                              <span style={{ fontSize: 11, color: 'var(--orange)', fontWeight: 600 }}>{type}: </span>
                              <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                                {values.slice(0, 5).join(', ')}{values.length > 5 ? ` (+${values.length - 5} more)` : ''}
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                      {r.threat_description && (
                        <div>
                          <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Threat Analysis: </span>
                          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{r.threat_description}</span>
                        </div>
                      )}
                      {r.metadata && (
                        <div style={{ marginTop: 8 }}>
                          <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Metadata: </span>
                          <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                            {JSON.stringify(r.metadata).slice(0, 200)}
                          </span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
            {filteredResults.length === 0 && (
              <div className="card empty-state">
                <p>No results match the current filter.</p>
              </div>
            )}
          </div>
        </>
      )}

      {/* Empty state */}
      {!loading && searched && results.length === 0 && !error && (
        <div className="card empty-state">
          <HiOutlineGlobe style={{ fontSize: 48, opacity: 0.3 }} />
          <p style={{ marginTop: 12 }}>No dark web results found for "{query}"</p>
          <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>Try broader terms or different keywords</p>
        </div>
      )}

      {/* Initial state */}
      {!searched && !loading && (
        <div className="card" style={{ padding: 48, textAlign: 'center' }}>
          <HiOutlineShieldCheck style={{ fontSize: 56, color: 'var(--accent)', opacity: 0.3 }} />
          <h3 style={{ marginTop: 16, fontSize: 18, fontWeight: 700, color: 'var(--text-secondary)' }}>
            Dark Web Intelligence Engine
          </h3>
          <p style={{ color: 'var(--text-muted)', fontSize: 13, marginTop: 8, maxWidth: 500, margin: '8px auto 0' }}>
            Search across Ahmia.fi, breach databases, GitHub leaks, paste sites, and more.
            All sources are free and require no API keys. Results include threat classification and IOC extraction.
          </p>
          <div style={{ display: 'flex', justifyContent: 'center', gap: 12, marginTop: 20, flexWrap: 'wrap' }}>
            {['bitcoin', 'test@example.com', 'facebook.com', 'leaked database'].map(ex => (
              <button key={ex} className="btn btn-ghost btn-sm" onClick={() => { setQuery(ex); }}>
                {ex}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
