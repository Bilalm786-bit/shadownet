import { useState } from 'react';
import { osintAPI } from '../api/client';
import { HiOutlineSearch, HiOutlineExclamation } from 'react-icons/hi';
import InvestigationReport from '../components/analytics/InvestigationReport';

const TYPE_ICONS: Record<string, string> = {
  email: '📧', domain: '🌐', ip: '🔢', username: '👤', phone: '📱', url: '🔗', person: '🧑',
};

export default function InvestigatePage() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<any>(null);
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
    setLoading(true); setError(''); setReport(null);
    try {
      const res = await osintAPI.autoInvestigate({ target: target.trim(), depth });
      const r = res.data;
      r.category = r.category || r.target_type || 'auto';
      setReport(r);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Investigation failed');
    }
    setLoading(false);
  };

  return (
    <div className="fade-in">
      <div className="section-header">
        <div>
          <h2 className="section-title">🔍 Auto-Investigate</h2>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 6 }}>
            Paste any target — email, domain, IP, username, phone — and ShadowNet will pick the right modules.
          </p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 20, padding: 20 }}>
        <form onSubmit={handleInvestigate}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end' }}>
            <div style={{ flex: 1 }}>
              <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
                Target
                {detectedType && (
                  <span style={{ color: 'var(--accent)', marginLeft: 8 }}>
                    — detected as: {TYPE_ICONS[detectedType] || '❓'} {detectedType}
                  </span>
                )}
              </label>
              <div style={{ position: 'relative' }}>
                <HiOutlineSearch style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', fontSize: 18 }} />
                <input
                  className="input" style={{ paddingLeft: 42, fontSize: 15, height: 48 }}
                  value={target} onChange={e => handleDetect(e.target.value)}
                  placeholder="Email, domain, IP, username, or phone number..."
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
              {loading ? '⏳ Investigating…' : '🚀 Investigate'}
            </button>
          </div>
        </form>
      </div>

      {error && (
        <div className="card" style={{ borderLeft: '3px solid var(--red)', padding: 16, marginBottom: 16 }}>
          <HiOutlineExclamation style={{ color: 'var(--red)', marginRight: 8 }} />
          <span style={{ color: 'var(--red)' }}>{error}</span>
        </div>
      )}

      {loading && (
        <div className="card" style={{ textAlign: 'center', padding: 60 }}>
          <div className="pulse" style={{ fontSize: 60, marginBottom: 16 }}>🔎</div>
          <div style={{ fontSize: 16, color: 'var(--accent)', fontWeight: 600 }}>Investigation in progress…</div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 8 }}>
            Running OSINT modules against {target}.
          </div>
          <div className="progress-bar" style={{ marginTop: 24, maxWidth: 480, margin: '24px auto 0' }}>
            <div className="progress-fill" style={{ width: '60%', animation: 'shimmer 2s infinite' }} />
          </div>
        </div>
      )}

      {report && !loading && <InvestigationReport report={report} emoji="🔎" />}
    </div>
  );
}
