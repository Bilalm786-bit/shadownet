import { useState } from 'react';
import {
  HiOutlineSearch, HiOutlineExclamation, HiOutlineShieldExclamation,
  HiOutlineDocumentReport, HiOutlineLightningBolt, HiOutlineFire,
  HiOutlineDownload, HiOutlineClock, HiOutlineCog, HiOutlineGlobe,
  HiOutlineBookmark,
} from 'react-icons/hi';
import { investigateAPI } from '../api/client';
import SeverityDonut from '../components/analytics/SeverityDonut';
import SeverityLegend from '../components/analytics/SeverityLegend';
import FamilyChart from '../components/analytics/FamilyChart';
import RiskScoreCard from '../components/analytics/RiskScoreCard';
import AssetInventoryView from '../components/analytics/AssetInventory';
import FindingsTable, { Finding } from '../components/analytics/FindingsTable';
import ScanTimeline from '../components/analytics/ScanTimeline';
import KpiBar from '../components/analytics/KpiBar';
import OwaspRadar from '../components/analytics/OwaspRadar';
import OwaspCoverage from '../components/analytics/OwaspCoverage';
import DarkWebPanel from '../components/analytics/DarkWebPanel';

type Tab = 'overview' | 'findings' | 'owasp' | 'darkweb' | 'inventory' | 'timeline';

export default function VulnScanPage() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [report, setReport] = useState<any>(null);
  const [tab, setTab] = useState<Tab>('overview');

  const runScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;
    setLoading(true); setError(''); setReport(null);
    try {
      const res = await investigateAPI.vulnScan(target.trim());
      setReport(res.data); setTab('overview');
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
    const headers = ['severity', 'cvss', 'owasp', 'cwe', 'family', 'plugin', 'title', 'affected', 'solution'];
    const rows = (report.findings as Finding[]).map(f => [
      f.severity, f.cvss ?? '', (f as any).owasp?.id || '', f.cwe ?? '', f.family,
      f.plugin, f.title.replace(/"/g, "'"), f.affected ?? '',
      (f.solution || '').replace(/"/g, "'"),
    ]);
    const csv = [headers, ...rows].map(r => r.map(c => `"${String(c).replace(/\n/g, ' ')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `shadownet-vulnscan-${report.target.replace(/[^a-z0-9]+/gi, '_')}.csv`;
    a.click(); URL.revokeObjectURL(url);
  };

  return (
    <div className="fade-in">
      <div className="hero-header">
        <div style={{ position: 'relative', zIndex: 1 }}>
          <h2 className="hero-title">⚡ Industry-Grade Vulnerability Scanner</h2>
          <p className="hero-subtitle">
            Nessus-style unified scanner with <strong>OWASP Top 10 (2021)</strong> mapping and
            full <strong>dark-web correlation</strong>. Runs 40+ recon, enumeration & defensive
            vulnerability modules — every finding annotated with CVSS, CWE and OWASP category;
            asset inventory cross-referenced against breach DBs, paste sites, .onion search, and 10+ threat-intel feeds.
          </p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 22, padding: 20 }}>
        <form onSubmit={runScan}>
          <div className="invest-search-bar">
            <div style={{ flex: 1, position: 'relative' }}>
              <HiOutlineSearch className="invest-search-icon" />
              <input className="input" style={{ paddingLeft: 48, fontSize: 15, height: 54 }} value={target}
                onChange={e => setTarget(e.target.value)}
                placeholder="Target you are authorized to assess (e.g. example.com)" />
            </div>
            <button className="btn btn-primary btn-lg" type="submit" disabled={loading || !target.trim()}>
              {loading ? '⏳ Scanning…' : '⚡ Run Vulnerability Scan'}
            </button>
          </div>
          <p style={{ fontSize: 11, color: 'var(--orange)', marginTop: 10, fontStyle: 'italic' }}>
            ⚠ Only scan assets you own or have explicit written permission to test.
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

          <div className="tab-strip">
            {[
              { id: 'overview', label: 'Overview', icon: <HiOutlineDocumentReport /> },
              { id: 'findings', label: `Findings (${report.findings?.length || 0})`, icon: <HiOutlineFire /> },
              { id: 'owasp', label: `OWASP Top 10 (${report.owasp_coverage?.categories_covered || 0}/10)`, icon: <HiOutlineBookmark /> },
              { id: 'darkweb', label: `Dark Web (${report.dark_web?.indicator_count || 0})`, icon: <HiOutlineGlobe /> },
              { id: 'inventory', label: 'Asset Inventory', icon: <HiOutlineCog /> },
              { id: 'timeline', label: `Modules (${report.modules_run?.length || 0})`, icon: <HiOutlineClock /> },
            ].map(t => (
              <button
                key={t.id}
                onClick={() => setTab(t.id as Tab)}
                className={`tab-button ${tab === t.id ? 'active' : ''}`}
              >
                {t.icon} {t.label}
              </button>
            ))}
          </div>

          {tab === 'overview' && <OverviewTab report={report} onJump={(t: Tab) => setTab(t)} />}
          {tab === 'findings' && <FindingsTable findings={report.findings || []} />}
          {tab === 'owasp' && <OwaspTab report={report} />}
          {tab === 'darkweb' && <div className="card" style={{ padding: 22 }}><DarkWebPanel report={report.dark_web} /></div>}
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
  const dist = report.severity_distribution || {};
  return (
    <KpiBar kpis={[
      { label: 'Target', value: <span style={{ fontFamily: 'var(--font-mono)', fontSize: 16 }}>{report.target}</span> },
      { label: 'Modules', value: report.modules_run?.length || 0, meta: `of ${report.modules_total || 0}`, color: 'var(--green)' },
      { label: 'Findings', value: (report.findings?.length || 0), color: dist.critical ? 'var(--red)' : dist.high ? 'var(--orange)' : 'var(--green)' },
      { label: 'Critical / High', value: `${dist.critical || 0} / ${dist.high || 0}`, color: dist.critical ? 'var(--red)' : 'var(--orange)' },
      { label: 'Risk Score', value: report.risk_score || 0, meta: '/ 100', color: report.risk_score >= 75 ? 'var(--red)' : report.risk_score >= 50 ? 'var(--orange)' : 'var(--green)' },
      { label: 'OWASP', value: `${report.owasp_coverage?.categories_covered || 0} / 10`, color: 'var(--accent)' },
      { label: 'Dark Web', value: report.dark_web?.indicator_count || 0, meta: `+${report.dark_web?.risk_uplift || 0} risk`, color: 'var(--purple)' },
      { label: 'Duration', value: `${((report.duration_ms || 0) / 1000).toFixed(1)}s`, color: 'var(--text-secondary)' },
    ]} />
  );
}

function OverviewTab({ report, onJump }: { report: any; onJump: (t: Tab) => void }) {
  const dist = report.severity_distribution || {};
  return (
    <div className="slide-up">
      <div className="card" style={{ marginBottom: 18, padding: 22, borderLeft: '3px solid var(--accent)' }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: 1.4, marginBottom: 8 }}>
          Executive Summary
        </div>
        <p style={{ fontSize: 14, lineHeight: 1.75, color: 'var(--text-primary)' }}
           dangerouslySetInnerHTML={{ __html: (report.executive_summary || '').replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>') }} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, marginBottom: 18 }}>
        <div className="card" style={{ padding: 18, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <div className="result-section-title" style={{ fontSize: 13, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, fontWeight: 700 }}>
            Severity
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
          <div className="result-section-title" style={{ fontSize: 13, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, fontWeight: 700 }}>
            Top Families
          </div>
          <FamilyChart data={report.family_distribution || []} />
        </div>
        {report.owasp_coverage?.categories?.length > 0 && (
          <div className="card" style={{ padding: 18 }}>
            <div className="result-section-title" style={{ fontSize: 13, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, fontWeight: 700 }}>
              OWASP Top 10 Map
            </div>
            <OwaspRadar categories={report.owasp_coverage.categories} />
          </div>
        )}
      </div>

      <div className="card" style={{ padding: 22, marginBottom: 18 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 8 }}>
          <h3 className="result-section-title" style={{ marginBottom: 0 }}>
            <HiOutlineFire style={{ color: 'var(--red)' }} /> Top Risks
          </h3>
          <button className="btn btn-ghost btn-sm" onClick={() => onJump('findings')}>View all findings →</button>
        </div>
        {report.top_risks?.length ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {report.top_risks.map((f: Finding, i: number) => (
              <TopRiskRow key={i} finding={f} />
            ))}
          </div>
        ) : (
          <div className="empty-state" style={{ padding: 30 }}>
            <HiOutlineShieldExclamation />
            <div style={{ marginTop: 8 }}>No critical or high-severity findings.</div>
          </div>
        )}
      </div>

      {report.dark_web?.indicator_count > 0 && (
        <div className="card" style={{ padding: 22, marginBottom: 18 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <h3 className="result-section-title" style={{ marginBottom: 0 }}>
              <HiOutlineGlobe style={{ color: 'var(--purple)' }} /> Dark Web Snapshot
            </h3>
            <button className="btn btn-ghost btn-sm" onClick={() => onJump('darkweb')}>Full panel →</button>
          </div>
          <DarkWebPanel report={report.dark_web} />
        </div>
      )}

      <div className="card" style={{ padding: 22 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <h3 className="result-section-title" style={{ marginBottom: 0 }}>
            <HiOutlineLightningBolt style={{ color: 'var(--accent)' }} /> Asset Snapshot
          </h3>
          <button className="btn btn-ghost btn-sm" onClick={() => onJump('inventory')}>Full inventory →</button>
        </div>
        <AssetInventoryView asset={report.asset_inventory || {}} />
      </div>
    </div>
  );
}

function OwaspTab({ report }: { report: any }) {
  const cov = report.owasp_coverage;
  if (!cov || !cov.categories) {
    return <div className="empty-state">No OWASP coverage data.</div>;
  }
  return (
    <div className="slide-up">
      <div className="card" style={{ padding: 22, marginBottom: 18 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14, flexWrap: 'wrap', gap: 8 }}>
          <h3 className="result-section-title" style={{ marginBottom: 0 }}>
            <HiOutlineBookmark /> OWASP Top 10 (2021) Coverage Map
          </h3>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {cov.categories_covered} / 10 categories flagged
          </span>
        </div>
        <OwaspRadar categories={cov.categories} />
      </div>
      <div className="card" style={{ padding: 22 }}>
        <h3 className="result-section-title">Categories</h3>
        <OwaspCoverage categories={cov.categories} />
      </div>
    </div>
  );
}

function TopRiskRow({ finding: f }: { finding: Finding & { owasp?: { id?: string; title?: string } } }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'flex-start', gap: 14, padding: 14,
      background: 'var(--bg-card)', borderRadius: 10, border: '1px solid var(--border-glass)',
      borderLeft: `3px solid ${f.severity === 'critical' ? 'var(--red)' : 'var(--orange)'}`,
    }}>
      <div style={{ flex: '0 0 64px', textAlign: 'center' }}>
        <span className={`badge badge-${f.severity}`} style={{ marginBottom: 6 }}>{f.severity}</span>
        <div style={{
          fontFamily: 'var(--font-display)', fontSize: 18, fontWeight: 700,
          color: f.severity === 'critical' ? 'var(--red)' : 'var(--orange)',
          marginTop: 4,
        }}>
          {(f.cvss ?? 0).toFixed(1)}
        </div>
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>{f.title}</div>
        <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>
          <span style={{ color: 'var(--accent)' }}>{f.family}</span>
          {f.cwe && <span style={{ color: 'var(--text-muted)', marginLeft: 8 }}>· {f.cwe}</span>}
          {f.owasp?.id && <span style={{ color: 'var(--purple)', marginLeft: 8 }}>· {f.owasp.id}</span>}
        </div>
        {f.affected && (
          <code style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
            {f.affected.length > 90 ? f.affected.slice(0, 90) + '…' : f.affected}
          </code>
        )}
      </div>
    </div>
  );
}

function ScanProgressView() {
  return (
    <div className="card" style={{ textAlign: 'center', padding: 60 }}>
      <div className="pulse" style={{ fontSize: 64, marginBottom: 18 }}>⚡</div>
      <div style={{ fontFamily: 'var(--font-display)', fontSize: 18, color: 'var(--accent)', fontWeight: 600, marginBottom: 8 }}>
        Running 40+ scanner modules in parallel...
      </div>
      <div style={{ fontSize: 13, color: 'var(--text-muted)', maxWidth: 600, margin: '0 auto', lineHeight: 1.6 }}>
        Recon (DNS, TLS, ASN, CDN, WAF) → Enumeration (subdomains, dirs, JS, params, S3, vhosts) →
        Vulnerability checks (headers, takeover, CORS, SQLi, XSS, SSRF, SSTI, XXE, JWT, GraphQL,
        cookies, auth bypass, cache poisoning) → OWASP mapping → Dark-web correlation.
        Typical run: 60-180 seconds.
      </div>
      <div className="progress-bar" style={{ marginTop: 24, maxWidth: 480, margin: '24px auto 0' }}>
        <div className="progress-fill" style={{ width: '60%', animation: 'shimmer 2s infinite' }} />
      </div>
    </div>
  );
}
