import { useState } from 'react';
import {
  HiOutlineSearch, HiOutlineExclamation, HiOutlineShieldExclamation,
  HiOutlineDocumentReport, HiOutlineLightningBolt, HiOutlineFire,
  HiOutlineDownload, HiOutlineClock, HiOutlineCog,
} from 'react-icons/hi';
import { investigateAPI } from '../api/client';
import SeverityDonut from '../components/analytics/SeverityDonut';
import SeverityLegend from '../components/analytics/SeverityLegend';
import FamilyChart from '../components/analytics/FamilyChart';
import RiskScoreCard from '../components/analytics/RiskScoreCard';
import AssetInventoryView from '../components/analytics/AssetInventory';
import FindingsTable, { Finding } from '../components/analytics/FindingsTable';
import ScanTimeline from '../components/analytics/ScanTimeline';

type Tab = 'overview' | 'findings' | 'inventory' | 'timeline';

export default function VulnScanPage() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [report, setReport] = useState<any>(null);
  const [tab, setTab] = useState<Tab>('overview');

  const runScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;
    setLoading(true);
    setError('');
    setReport(null);
    try {
      const res = await investigateAPI.vulnScan(target.trim());
      setReport(res.data);
      setTab('overview');
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Scan failed');
    }
    setLoading(false);
  };

  const exportJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `shadownet-vulnscan-${report.target.replace(/[^a-z0-9]+/gi, '_')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportCsv = () => {
    if (!report) return;
    const headers = ['severity', 'cvss', 'cwe', 'family', 'plugin', 'title', 'affected', 'solution'];
    const rows = (report.findings as Finding[]).map(f => [
      f.severity, f.cvss ?? '', f.cwe ?? '', f.family,
      f.plugin, f.title.replace(/"/g, "'"), f.affected ?? '', (f.solution || '').replace(/"/g, "'"),
    ]);
    const csv = [headers, ...rows].map(r => r.map(c => `"${String(c).replace(/\n/g, ' ')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `shadownet-vulnscan-${report.target.replace(/[^a-z0-9]+/gi, '_')}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fade-in">
      <div className="section-header">
        <div>
          <h2 className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 28 }}>🛡️</span> Vulnerability Scanner
          </h2>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 6, maxWidth: 720 }}>
            Nessus-style unified scanner. Runs 35+ recon, enumeration, and read-only vulnerability
            modules and produces a normalized report with executive summary, asset inventory,
            severity analytics, and per-finding evidence + remediation.
          </p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 20, padding: 20 }}>
        <form onSubmit={runScan}>
          <div className="invest-search-bar">
            <div style={{ flex: 1, position: 'relative' }}>
              <HiOutlineSearch className="invest-search-icon" />
              <input
                className="input"
                style={{ paddingLeft: 48, fontSize: 15, height: 52 }}
                value={target}
                onChange={e => setTarget(e.target.value)}
                placeholder="Target you are authorized to assess (e.g. example.com)"
              />
            </div>
            <button className="btn btn-primary btn-lg" type="submit" disabled={loading || !target.trim()}>
              {loading ? '⏳ Scanning…' : '⚡ Run Vulnerability Scan'}
            </button>
          </div>
          <p style={{ fontSize: 11, color: 'var(--orange)', marginTop: 10, fontStyle: 'italic' }}>
            ⚠️ Only scan assets you own or have explicit written permission to test.
          </p>
        </form>
      </div>

      {error && (
        <div className="card" style={{ borderLeft: '3px solid var(--red)', padding: 16, marginBottom: 16 }}>
          <HiOutlineExclamation style={{ color: 'var(--red)', marginRight: 8 }} />
          <span style={{ color: 'var(--red)' }}>{error}</span>
        </div>
      )}

      {loading && <ScanProgressView />}

      {report && !loading && (
        <div className="slide-up">
          <Toolbar report={report} onExportJson={exportJson} onExportCsv={exportCsv} />

          <div style={{ display: 'flex', gap: 8, marginBottom: 18, borderBottom: '1px solid var(--border-glass)', overflowX: 'auto' }}>
            {[
              { id: 'overview', label: 'Overview', icon: <HiOutlineDocumentReport /> },
              { id: 'findings', label: `Findings (${report.findings?.length || 0})`, icon: <HiOutlineFire /> },
              { id: 'inventory', label: 'Asset Inventory', icon: <HiOutlineCog /> },
              { id: 'timeline', label: `Modules (${report.modules_run?.length || 0})`, icon: <HiOutlineClock /> },
            ].map(t => (
              <button
                key={t.id}
                onClick={() => setTab(t.id as Tab)}
                className="btn btn-ghost btn-sm"
                style={{
                  border: 'none', borderRadius: 0, padding: '12px 16px',
                  borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
                  color: tab === t.id ? 'var(--accent)' : 'var(--text-secondary)',
                  fontWeight: tab === t.id ? 600 : 500,
                }}
              >
                {t.icon} {t.label}
              </button>
            ))}
          </div>

          {tab === 'overview' && <OverviewTab report={report} onJump={(t: Tab) => setTab(t)} />}
          {tab === 'findings' && <FindingsTable findings={report.findings || []} />}
          {tab === 'inventory' && <AssetInventoryView asset={report.asset_inventory} />}
          {tab === 'timeline' && (
            <div className="card" style={{ padding: 20 }}>
              <ScanTimeline timeline={report.timeline} />
              {report.errors?.length > 0 && (
                <div style={{ marginTop: 24, paddingTop: 16, borderTop: '1px solid var(--border-glass)' }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--orange)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: 1 }}>
                    Module Errors ({report.errors.length})
                  </div>
                  {report.errors.map((e: string, i: number) => (
                    <div key={i} style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', padding: '4px 0' }}>{e}</div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Toolbar({ report, onExportJson, onExportCsv }: { report: any; onExportJson: () => void; onExportCsv: () => void }) {
  return (
    <div style={{
      display: 'flex', gap: 16, alignItems: 'center', padding: 14, marginBottom: 16,
      background: 'var(--bg-card)', borderRadius: 12, border: '1px solid var(--border-glass)',
    }}>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>Target</div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 16, fontWeight: 600 }}>{report.target}</div>
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>Modules</div>
        <div style={{ fontSize: 14 }}>
          <strong style={{ color: 'var(--green)' }}>{report.modules_run?.length || 0}</strong> /
          <span style={{ color: 'var(--text-muted)' }}> {report.modules_total || 0}</span> succeeded
        </div>
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>Duration</div>
        <div style={{ fontSize: 14, fontFamily: 'var(--font-mono)' }}>
          {((report.duration_ms || 0) / 1000).toFixed(1)}s
        </div>
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        <button className="btn btn-ghost btn-sm" onClick={onExportCsv}><HiOutlineDownload /> CSV</button>
        <button className="btn btn-ghost btn-sm" onClick={onExportJson}><HiOutlineDownload /> JSON</button>
      </div>
    </div>
  );
}

function OverviewTab({ report, onJump }: { report: any; onJump: (t: Tab) => void }) {
  const dist = report.severity_distribution || {};

  return (
    <div className="slide-up">
      <div className="card" style={{ marginBottom: 18, padding: 22, borderLeft: '3px solid var(--accent)' }}>
        <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 8 }}>
          Executive Summary
        </div>
        <p style={{ fontSize: 14, lineHeight: 1.75, color: 'var(--text-primary)' }}
           dangerouslySetInnerHTML={{ __html: (report.executive_summary || '').replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>') }} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16, marginBottom: 18 }}>
        <div className="card" style={{ padding: 18, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 8 }}>
            Severity Distribution
          </div>
          <SeverityDonut data={dist} />
          <div style={{ width: '100%', marginTop: 14 }}>
            <SeverityLegend data={dist} />
          </div>
        </div>

        <div className="card" style={{ padding: 18 }}>
          <RiskScoreCard score={report.risk_score || 0} />
        </div>

        <div className="card" style={{ padding: 18 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 12 }}>
            Top Affected Families
          </div>
          <FamilyChart data={report.family_distribution || []} />
        </div>
      </div>

      <div className="card" style={{ padding: 22, marginBottom: 18 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ fontSize: 16, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 10 }}>
            <HiOutlineFire style={{ color: 'var(--red)' }} /> Top Risks
          </h3>
          <button className="btn btn-ghost btn-sm" onClick={() => onJump('findings')}>View all findings →</button>
        </div>
        {report.top_risks?.length ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {report.top_risks.map((f: Finding, i: number) => (
              <div key={i} style={{
                display: 'flex', alignItems: 'flex-start', gap: 14, padding: 14,
                background: 'var(--bg-card)', borderRadius: 10, border: '1px solid var(--border-glass)',
                borderLeft: `3px solid ${f.severity === 'critical' ? 'var(--red)' : 'var(--orange)'}`,
              }}>
                <div style={{ flex: '0 0 56px', textAlign: 'center' }}>
                  <span className={`badge badge-${f.severity}`} style={{ marginBottom: 6 }}>{f.severity}</span>
                  <div style={{ fontSize: 16, fontWeight: 700, fontFamily: 'var(--font-mono)', color: f.severity === 'critical' ? 'var(--red)' : 'var(--orange)' }}>
                    {(f.cvss ?? 0).toFixed(1)}
                  </div>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>{f.title}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>
                    <span style={{ color: 'var(--accent)' }}>{f.family}</span>
                    {f.cwe && <span style={{ color: 'var(--text-muted)', marginLeft: 8 }}>· {f.cwe}</span>}
                  </div>
                  {f.affected && (
                    <code style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                      {f.affected.length > 90 ? f.affected.slice(0, 90) + '…' : f.affected}
                    </code>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state" style={{ padding: 30 }}>
            <HiOutlineShieldExclamation />
            <div style={{ marginTop: 8 }}>No critical or high-severity findings.</div>
          </div>
        )}
      </div>

      <div className="card" style={{ padding: 22 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <h3 style={{ fontSize: 16, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 10 }}>
            <HiOutlineLightningBolt style={{ color: 'var(--accent)' }} /> Asset Snapshot
          </h3>
          <button className="btn btn-ghost btn-sm" onClick={() => onJump('inventory')}>Full inventory →</button>
        </div>
        <AssetInventoryView asset={report.asset_inventory || {}} />
      </div>
    </div>
  );
}

function ScanProgressView() {
  return (
    <div className="card" style={{ textAlign: 'center', padding: 60 }}>
      <div className="pulse" style={{ fontSize: 64, marginBottom: 18 }}>🛡️</div>
      <div style={{ fontSize: 17, color: 'var(--accent)', fontWeight: 600, marginBottom: 8 }}>
        Running 35+ scanner modules in parallel...
      </div>
      <div style={{ fontSize: 13, color: 'var(--text-muted)', maxWidth: 540, margin: '0 auto' }}>
        Recon (DNS, TLS, ASN, CDN, WAF) → Enumeration (subdomains, dirs, JS, params, S3, vhosts) →
        Vulnerability checks (headers, takeover, CORS, SQLi, XSS, host-header, JWT, CVE, secrets, defaults).
        Typical run: 30–120 seconds depending on target responsiveness.
      </div>
      <div className="progress-bar" style={{ marginTop: 24, maxWidth: 480, margin: '24px auto 0' }}>
        <div className="progress-fill" style={{ width: '60%', animation: 'shimmer 2s infinite' }} />
      </div>
    </div>
  );
}
