import { useState } from 'react';
import { HiOutlineSearch, HiOutlineExclamation } from 'react-icons/hi';
import { investigateAPI } from '../api/client';
import InvestigationReport from '../components/analytics/InvestigationReport';

export default function NetworkInvestigation() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<any>(null);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;
    setLoading(true); setError(''); setReport(null);
    try {
      const res = await investigateAPI.network(target.trim());
      setReport(res.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Investigation failed');
    }
    setLoading(false);
  };

  return (
    <div className="fade-in">
      <div className="section-header">
        <div>
          <h2 className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 28 }}>🌐</span> Network Intelligence
          </h2>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 6, maxWidth: 720 }}>
            Deep network reconnaissance: ASN / BGP, DNS (zone transfer, DMARC/SPF/DKIM, DNSSEC), TLS audit,
            port scan, subdomain enum, CDN / WAF detection, threat-intel cross-reference.
          </p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 20, padding: 20 }}>
        <form onSubmit={handleSubmit}>
          <div className="invest-search-bar">
            <div style={{ flex: 1, position: 'relative' }}>
              <HiOutlineSearch className="invest-search-icon" />
              <input className="input" style={{ paddingLeft: 48, fontSize: 15, height: 52 }}
                value={target} onChange={e => setTarget(e.target.value)}
                placeholder="Enter IP, domain, or CIDR (e.g. 8.8.8.8, example.com)..." />
            </div>
            <button className="btn btn-primary btn-lg" type="submit" disabled={loading || !target.trim()}>
              {loading ? '⏳ Scanning…' : '🌐 Run Network Recon'}
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
          <div className="pulse" style={{ fontSize: 60, marginBottom: 16 }}>🌐</div>
          <div style={{ fontSize: 16, color: 'var(--cyan)', fontWeight: 600 }}>Mapping network surface...</div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 8 }}>
            DNS, TLS, ASN, ports, subdomains, CDN/WAF, threat-intel — running in parallel.
          </div>
          <div className="progress-bar" style={{ marginTop: 24, maxWidth: 480, margin: '24px auto 0' }}>
            <div className="progress-fill" style={{ width: '60%', animation: 'shimmer 2s infinite' }} />
          </div>
        </div>
      )}

      {report && !loading && <InvestigationReport report={report} emoji="🌐" />}
    </div>
  );
}
