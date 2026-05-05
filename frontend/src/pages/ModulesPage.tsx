import { useEffect, useMemo, useState } from 'react';
import { osintAPI } from '../api/client';
import { HiOutlineChartBar, HiOutlineSearch, HiOutlinePlay, HiOutlineX } from 'react-icons/hi';

interface ModuleInfo {
  name: string;
  description: string;
  supported_target_types: string[];
  requires_api_key: boolean;
}

const CATEGORY_PALETTE: Record<string, string> = {
  identity: '#6366f1',
  network: '#06b6d4',
  breach: '#ef4444',
  socmint: '#a855f7',
  document: '#10b981',
  threat: '#f59e0b',
  darkweb: '#0f172a',
};

function categoryOf(name: string): string {
  return name.split('.')[0] || 'other';
}

export default function ModulesPage() {
  const [modules, setModules] = useState<ModuleInfo[]>([]);
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState<string>('all');
  const [testMod, setTestMod] = useState<ModuleInfo | null>(null);
  const [testTarget, setTestTarget] = useState('');
  const [testResult, setTestResult] = useState<any>(null);
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    osintAPI.modules().then(r => setModules(r.data)).catch(() => {});
  }, []);

  const categories = useMemo(() => {
    const set = new Set<string>();
    modules.forEach(m => set.add(categoryOf(m.name)));
    return Array.from(set).sort();
  }, [modules]);

  const filtered = useMemo(() => {
    return modules.filter(m => {
      if (category !== 'all' && categoryOf(m.name) !== category) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        return m.name.toLowerCase().includes(q) || m.description.toLowerCase().includes(q);
      }
      return true;
    });
  }, [modules, search, category]);

  const runTest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!testMod || !testTarget.trim()) return;
    setTesting(true); setTestResult(null);
    try {
      const res = await osintAPI.quickScan({ target: testTarget.trim(), module: testMod.name });
      setTestResult(res.data);
    } catch (err: any) {
      setTestResult({ error: err.response?.data?.detail || 'Quick scan failed' });
    }
    setTesting(false);
  };

  return (
    <div className="fade-in">
      <div className="section-header">
        <h2 className="section-title">OSINT Module Catalog</h2>
        <span className="badge badge-info">{modules.length} modules loaded</span>
      </div>

      <div className="card" style={{ marginBottom: 20, padding: 16 }}>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: 1, minWidth: 240 }}>
            <HiOutlineSearch style={{
              position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)',
              color: 'var(--text-muted)',
            }} />
            <input className="input" style={{ paddingLeft: 36 }} value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search modules by name or description…" />
          </div>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            <button onClick={() => setCategory('all')} className="btn btn-ghost btn-sm"
              style={{ borderColor: category === 'all' ? 'var(--accent)' : '', color: category === 'all' ? 'var(--accent)' : '' }}>
              All ({modules.length})
            </button>
            {categories.map(c => {
              const count = modules.filter(m => categoryOf(m.name) === c).length;
              const active = category === c;
              const color = CATEGORY_PALETTE[c] || 'var(--accent)';
              return (
                <button key={c} onClick={() => setCategory(c)} className="btn btn-ghost btn-sm"
                  style={{
                    borderColor: active ? color : '', color: active ? color : '',
                    textTransform: 'capitalize',
                  }}>
                  {c} ({count})
                </button>
              );
            })}
          </div>
        </div>
      </div>

      <div className="grid-3 stagger">
        {filtered.map((m, i) => {
          const color = CATEGORY_PALETTE[categoryOf(m.name)] || 'var(--accent)';
          return (
            <div className="card slide-up" key={i} style={{ borderLeft: `3px solid ${color}` }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <HiOutlineChartBar style={{ color, fontSize: 20 }} />
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 600 }}>{m.name}</span>
                </div>
                <button className="btn btn-ghost btn-sm" onClick={() => { setTestMod(m); setTestTarget(''); setTestResult(null); }} title="Quick test">
                  <HiOutlinePlay />
                </button>
              </div>
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 12, lineHeight: 1.5 }}>{m.description}</p>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 8 }}>
                {(m.supported_target_types || []).map(t => (
                  <span key={t} className="badge badge-info">{t}</span>
                ))}
              </div>
              <span className={`badge ${m.requires_api_key ? 'badge-high' : 'badge-low'}`}>
                {m.requires_api_key ? 'API Key Required' : 'Free — No API Key'}
              </span>
            </div>
          );
        })}
      </div>

      {filtered.length === 0 && (
        <div className="card empty-state">
          <p>No modules match your search.</p>
        </div>
      )}

      {testMod && (
        <div className="modal-overlay" onClick={() => setTestMod(null)}>
          <div className="card modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Quick Test — {testMod.name}</h2>
              <button className="modal-close" onClick={() => setTestMod(null)}><HiOutlineX /></button>
            </div>
            <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 12 }}>{testMod.description}</p>
            <form onSubmit={runTest} style={{ display: 'flex', gap: 8 }}>
              <input className="input" value={testTarget}
                onChange={e => setTestTarget(e.target.value)}
                placeholder={`Enter ${testMod.supported_target_types.join(' / ') || 'target'}…`} />
              <button className="btn btn-primary" type="submit" disabled={testing || !testTarget.trim()}>
                {testing ? 'Running…' : 'Run'}
              </button>
            </form>
            {testResult && (
              <div style={{ marginTop: 16 }}>
                {testResult.error ? (
                  <div style={{ color: 'var(--red)' }}>{testResult.error}</div>
                ) : (
                  <>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                      <span className={`badge badge-${testResult.severity || 'info'}`}>{testResult.severity || 'info'}</span>
                      <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        {testResult.entity_count || 0} entities • success={String(testResult.success)}
                      </span>
                    </div>
                    <div style={{ fontSize: 13, marginBottom: 8 }}>{testResult.summary}</div>
                    <pre style={{
                      background: 'var(--bg-secondary)', padding: 12, borderRadius: 6,
                      fontSize: 11, maxHeight: 300, overflow: 'auto', color: 'var(--text-muted)',
                    }}>{JSON.stringify(testResult.raw_data, null, 2)}</pre>
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
