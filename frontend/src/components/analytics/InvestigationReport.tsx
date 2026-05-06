import { useMemo, useState } from 'react';
import {
  HiOutlineDocumentReport, HiOutlineFire, HiOutlineCog, HiOutlineClock,
  HiOutlineDownload, HiOutlineLightningBolt, HiOutlineGlobe, HiOutlineBookmark,
} from 'react-icons/hi';
import SeverityDonut from './SeverityDonut';
import SeverityLegend from './SeverityLegend';
import FamilyChart from './FamilyChart';
import RiskScoreCard from './RiskScoreCard';
import AssetInventoryView from './AssetInventory';
import FindingsTable, { Finding } from './FindingsTable';
import ScanTimeline from './ScanTimeline';
import KpiBar from './KpiBar';
import OwaspRadar from './OwaspRadar';
import OwaspCoverage from './OwaspCoverage';
import DarkWebPanel from './DarkWebPanel';

type Tab = 'overview' | 'findings' | 'owasp' | 'darkweb' | 'inventory' | 'timeline';

interface OrchestratorReport {
  category: string;
  target: string;
  modules_run?: string[];
  results?: Record<string, any>;
  entities_found?: any[];
  ai_analysis?: any;
  risk_score?: number;
  summary?: string;
  errors?: string[];
  timeline?: any[];
  owasp_coverage?: { categories?: any[]; categories_covered?: number };
  dark_web?: any;
}

const SEV_TO_CVSS: Record<string, number> = { critical: 9.5, high: 7.5, medium: 5.0, low: 3.5, info: 0.0 };

const FAMILY_BY_PLUGIN: Record<string, string> = {
  'recon.dns_advanced': 'DNS / Email Authentication',
  'recon.tls_audit': 'TLS / SSL',
  'recon.cdn_detector': 'Edge / CDN',
  'recon.waf_detector': 'WAF Detection',
  'recon.http_methods': 'HTTP Methods',
  'recon.http_fingerprint': 'HTTP Fingerprint',
  'recon.asn_lookup': 'Network',
  'recon.reverse_ip': 'Network',
  'recon.robots_sitemap': 'Information Disclosure',
  'network.ssl_analyzer': 'TLS / SSL',
  'network.port_scanner': 'Network Services',
  'network.dns_recon': 'DNS',
  'network.subdomain_enum': 'Subdomain Enumeration',
  'network.tech_detector': 'Technology Stack',
  'network.web_crawler': 'Web Crawler',
  'enumeration.directory_buster': 'Information Disclosure',
  'enumeration.parameter_finder': 'Application Surface',
  'enumeration.js_endpoints': 'Application Surface',
  'enumeration.cms_enum': 'CMS Enumeration',
  'enumeration.s3_buckets': 'Cloud Storage',
  'enumeration.vhost_enum': 'Virtual Hosts',
  'exploit.security_headers': 'HTTP Security Headers',
  'exploit.subdomain_takeover': 'Subdomain Takeover',
  'exploit.cors_misconfig': 'CORS Misconfiguration',
  'exploit.open_redirect': 'Open Redirect',
  'exploit.reflection_probe': 'Reflected XSS Pre-condition',
  'exploit.sqli_fingerprint': 'SQL Injection',
  'exploit.secrets_scanner': 'Secret Disclosure',
  'exploit.sensitive_files': 'Sensitive File Disclosure',
  'exploit.default_creds': 'Authentication / Default Credentials',
  'exploit.host_header_injection': 'Host Header Injection',
  'exploit.jwt_analyzer': 'JWT / Authentication',
};

function deriveFindings(report: OrchestratorReport): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const e of report.entities_found || []) {
    if (e.type !== 'vulnerability' && e.type !== 'leaked_secret' && e.type !== 'leaked_path' &&
        e.type !== 'sensitive_endpoint' && e.type !== 'missing_header' && e.type !== 'info_disclosure' &&
        e.type !== 'cloud_bucket' && e.type !== 'dns_misconfig' && e.type !== 'email_misconfig') {
      continue;
    }
    const sev = (e.metadata?.severity as string) || 'info';
    const cvss = e.metadata?.cvss ?? SEV_TO_CVSS[sev];
    const family = FAMILY_BY_PLUGIN[e.source] || 'Other';
    const id = `${e.source}:${e.value}`;
    if (seen.has(id)) continue;
    seen.add(id);
    findings.push({
      id,
      plugin: e.source,
      family,
      title: e.metadata?.title || e.metadata?.detail || e.value,
      severity: sev as any,
      cvss,
      cwe: e.metadata?.cwe,
      affected: e.metadata?.url || e.metadata?.domain || report.target,
      evidence: e.metadata?.evidence || e.metadata?.banner || '',
      solution: e.metadata?.advice || e.metadata?.solution || '',
      references: e.metadata?.references || [],
    });
  }
  for (const [name, data] of Object.entries(report.results || {})) {
    if (!data || (data as any).severity === 'info') continue;
    const dsev = (data as any).severity as string;
    if (dsev === 'low' || dsev === 'medium' || dsev === 'high' || dsev === 'critical') {
      const id = `module:${name}`;
      if (seen.has(id)) continue;
      seen.add(id);
      findings.push({
        id,
        plugin: name,
        family: FAMILY_BY_PLUGIN[name] || 'Other',
        title: (data as any).summary || `Module ${name} flagged ${dsev}`,
        severity: dsev as any,
        cvss: SEV_TO_CVSS[dsev],
        cwe: null,
        affected: report.target,
        evidence: (data as any).summary,
        solution: '',
        references: [],
      });
    }
  }
  return findings;
}

function deriveAsset(report: OrchestratorReport) {
  const a: any = {};
  const r = report.results || {};
  const src = (k: string) => r[k]?.data || {};

  const fp = src('recon.http_fingerprint');
  const primary = fp.https || fp.http || {};
  a.http = primary.status ? { status: primary.status, final_url: primary.final_url, ms: primary.ms } : {};
  a.favicon_md5 = fp.favicon_md5;
  a.redirects = fp.redirects;

  const asn = src('recon.asn_lookup');
  a.ip = asn.ip; a.asn = asn.asn; a.asn_name = asn.asn_name; a.country = asn.country;

  const cdn = src('recon.cdn_detector');
  a.cdn = (cdn.detections || []).map((d: any) => d.vendor);
  if (!a.ip && (cdn.ips || []).length) a.ip = cdn.ips[0];
  a.cnames = cdn.cnames || [];

  const waf = src('recon.waf_detector');
  a.waf = (waf.detections || []).map((d: any) => d.vendor);

  const tls = src('recon.tls_audit');
  if (tls && tls.host) {
    a.tls = {
      protocols: (tls.protocols_supported || []).map((p: any) => p.protocol),
      cipher: tls.negotiated_cipher,
      key_bits: tls.key_info?.bits,
      cert: tls.cert,
      hsts: tls.hsts,
    };
  } else {
    const ssl = src('network.ssl_analyzer');
    if (ssl.subject) {
      a.tls = {
        protocols: ssl.protocol ? [ssl.protocol] : [],
        cipher: ssl.cipher, key_bits: ssl.cipher_bits,
        cert: { issuer: ssl.issuer, not_after: ssl.not_after, days_until_expiry: ssl.days_until_expiry },
      };
    }
  }

  const dnsAdv = src('recon.dns_advanced');
  a.nameservers = dnsAdv.ns || [];
  a.mailservers = dnsAdv.mx || [];

  const tech = src('network.tech_detector');
  a.tech = [
    tech.server && `server:${tech.server}`,
    tech.cms && `cms:${tech.cms}`,
    ...(tech.waf || []).map((w: string) => `waf:${w}`),
    ...(tech.js_libraries || []).map((l: string) => `js:${l}`),
  ].filter(Boolean);

  const ports = src('network.port_scanner');
  a.open_ports = ports.open_ports || [];

  const subs = new Set<string>();
  (src('network.subdomain_enum').subdomains || []).forEach((s: string) => subs.add(s));
  (src('network.dns_recon').subdomains || []).forEach((s: string) => subs.add(s));
  a.subdomains = Array.from(subs);

  const crawler = src('network.web_crawler');
  a.emails = crawler.emails || [];
  a.social_profiles = Object.values(crawler.social_profiles || {}).flat() as string[];

  const params = src('enumeration.parameter_finder');
  a.parameters = params.params || [];

  const js = src('enumeration.js_endpoints');
  a.endpoints = js.endpoints || [];

  const ri = src('recon.reverse_ip');
  a.co_hosted_domains = ri.domains || [];

  const robots = src('recon.robots_sitemap');
  a.disallowed_paths = robots.disallowed || [];
  a.sitemaps = robots.sitemaps || [];

  return a;
}

function executiveSummary(report: OrchestratorReport, findings: Finding[], asset: any): string {
  const total = findings.length;
  const c = findings.filter(f => f.severity === 'critical').length;
  const h = findings.filter(f => f.severity === 'high').length;
  const m = findings.filter(f => f.severity === 'medium').length;
  const parts: string[] = [];
  parts.push(
    `${report.category?.toUpperCase() || 'Investigation'} of <strong>${report.target}</strong> ` +
    `identified <strong>${total} findings</strong> ` +
    `(${c} critical, ${h} high, ${m} medium) ` +
    `across <strong>${report.modules_run?.length || 0} modules</strong>.`
  );
  if (asset.ip) {
    parts.push(`Resolves to <strong>${asset.ip}</strong>${asset.asn_name ? ` on ${asset.asn_name}` : ''}${asset.country ? ` (${asset.country})` : ''}.`);
  }
  if (asset.cdn?.length || asset.waf?.length) {
    parts.push(`Edge stack: <strong>${[...asset.cdn, ...asset.waf].join(', ')}</strong>.`);
  }
  if (asset.subdomains?.length) {
    parts.push(`<strong>${asset.subdomains.length}</strong> subdomains enumerated.`);
  }
  if (c) {
    parts.push(`⚠️ <strong>${c} critical issue${c > 1 ? 's' : ''}</strong> require immediate attention.`);
  } else if (h) {
    parts.push(`<strong>${h} high-severity issue${h > 1 ? 's' : ''}</strong> should be addressed in the next sprint.`);
  } else {
    parts.push(`No critical or high-severity issues identified.`);
  }
  return parts.join(' ');
}

interface Props {
  report: OrchestratorReport;
  emoji?: string;
}

export default function InvestigationReport({ report, emoji = '🔎' }: Props) {
  const [tab, setTab] = useState<Tab>('overview');
  const findings = useMemo(() => deriveFindings(report), [report]);
  const asset = useMemo(() => deriveAsset(report), [report]);
  const dist = useMemo(() => {
    const d: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => { d[f.severity] = (d[f.severity] || 0) + 1; });
    return d;
  }, [findings]);
  const familyDist = useMemo(() => {
    const c: Record<string, number> = {};
    findings.forEach(f => { c[f.family] = (c[f.family] || 0) + 1; });
    return Object.entries(c).map(([family, count]) => ({ family, count })).sort((a, b) => b.count - a.count);
  }, [findings]);
  const timeline = useMemo(() => {
    return (report.timeline || []).map((t: any) => ({
      module: t.module, status: t.status,
      ms: t.ms, severity: t.severity, entities: t.entities, error: t.error,
    }));
  }, [report.timeline]);
  const topRisks = useMemo(() =>
    findings.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 8),
    [findings]
  );
  const execSummary = useMemo(() => executiveSummary(report, findings, asset), [report, findings, asset]);

  const exportCsv = () => {
    const headers = ['severity', 'cvss', 'family', 'plugin', 'title', 'affected'];
    const rows = findings.map(f => [
      f.severity, f.cvss ?? '', f.family, f.plugin,
      f.title.replace(/"/g, "'"), f.affected ?? '',
    ]);
    const csv = [headers, ...rows].map(r => r.map(c => `"${String(c).replace(/\n/g, ' ')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `shadownet-${report.category}-${report.target.replace(/[^a-z0-9]+/gi, '_')}.csv`;
    a.click(); URL.revokeObjectURL(url);
  };

  const owasp = report.owasp_coverage;
  const darkWeb = report.dark_web;

  return (
    <div className="slide-up">
      <KpiBar kpis={[
        { label: 'Target', value: <span style={{ fontFamily: 'var(--font-mono)', fontSize: 15 }}>{report.target}</span> },
        { label: 'Modules', value: report.modules_run?.length || 0, color: 'var(--green)' },
        { label: 'Findings', value: findings.length, color: dist.critical ? 'var(--red)' : dist.high ? 'var(--orange)' : 'var(--green)' },
        { label: 'Critical / High', value: `${dist.critical || 0} / ${dist.high || 0}`, color: dist.critical ? 'var(--red)' : 'var(--orange)' },
        { label: 'Risk', value: `${report.risk_score || 0}/100`, color: (report.risk_score || 0) >= 50 ? 'var(--red)' : 'var(--accent)' },
        ...(owasp ? [{ label: 'OWASP', value: `${owasp.categories_covered || 0}/10`, color: 'var(--accent)' }] : []),
        ...(darkWeb ? [{ label: 'Dark Web', value: darkWeb.indicator_count || 0, color: 'var(--purple)' }] : []),
      ]} />

      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 14 }}>
        <button className="btn btn-ghost btn-sm" onClick={exportCsv}><HiOutlineDownload /> Export CSV</button>
      </div>

      <div className="tab-strip">
        {[
          { id: 'overview', label: 'Overview', icon: <HiOutlineDocumentReport /> },
          { id: 'findings', label: `Findings (${findings.length})`, icon: <HiOutlineFire /> },
          ...(owasp ? [{ id: 'owasp', label: `OWASP (${owasp.categories_covered || 0}/10)`, icon: <HiOutlineBookmark /> }] : []),
          ...(darkWeb ? [{ id: 'darkweb', label: `Dark Web (${darkWeb.indicator_count || 0})`, icon: <HiOutlineGlobe /> }] : []),
          { id: 'inventory', label: 'Inventory', icon: <HiOutlineCog /> },
          { id: 'timeline', label: `Modules (${timeline.length})`, icon: <HiOutlineClock /> },
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

      {tab === 'overview' && (
        <div className="slide-up">
          <div className="card" style={{ marginBottom: 18, padding: 22, borderLeft: '3px solid var(--accent)' }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 8 }}>
              Executive Summary
            </div>
            <p style={{ fontSize: 14, lineHeight: 1.75, color: 'var(--text-primary)' }} dangerouslySetInnerHTML={{ __html: execSummary }} />
            {report.summary && (
              <p style={{ fontSize: 12, lineHeight: 1.6, color: 'var(--text-muted)', marginTop: 12, fontStyle: 'italic' }}>
                {report.summary}
              </p>
            )}
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
              <FamilyChart data={familyDist} />
            </div>
          </div>

          <div className="card" style={{ padding: 22, marginBottom: 18 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h3 style={{ fontSize: 16, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 10 }}>
                <HiOutlineFire style={{ color: 'var(--red)' }} /> Top Risks
              </h3>
              <button className="btn btn-ghost btn-sm" onClick={() => setTab('findings')}>View all findings →</button>
            </div>
            {topRisks.length ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {topRisks.map((f, i) => (
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
                      <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                        <span style={{ color: 'var(--accent)' }}>{f.family}</span>
                        {f.cwe && <span style={{ color: 'var(--text-muted)', marginLeft: 8 }}>· {f.cwe}</span>}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state" style={{ padding: 30 }}>
                <span style={{ fontSize: 32 }}>{emoji}</span>
                <div style={{ marginTop: 8 }}>No critical or high-severity findings.</div>
              </div>
            )}
          </div>

          <div className="card" style={{ padding: 22 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <h3 style={{ fontSize: 16, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 10 }}>
                <HiOutlineLightningBolt style={{ color: 'var(--accent)' }} /> Asset Snapshot
              </h3>
              <button className="btn btn-ghost btn-sm" onClick={() => setTab('inventory')}>Full inventory →</button>
            </div>
            <AssetInventoryView asset={asset} />
          </div>
        </div>
      )}

      {tab === 'findings' && <FindingsTable findings={findings} />}
      {tab === 'owasp' && owasp && (
        <div className="slide-up">
          <div className="card" style={{ padding: 22, marginBottom: 18 }}>
            <h3 className="result-section-title">
              <HiOutlineBookmark /> OWASP Top 10 (2021) Coverage Map
            </h3>
            <OwaspRadar categories={owasp.categories || []} />
          </div>
          <div className="card" style={{ padding: 22 }}>
            <h3 className="result-section-title">Categories</h3>
            <OwaspCoverage categories={owasp.categories || []} />
          </div>
        </div>
      )}
      {tab === 'darkweb' && darkWeb && (
        <div className="card" style={{ padding: 22 }}>
          <DarkWebPanel report={darkWeb} />
        </div>
      )}
      {tab === 'inventory' && <AssetInventoryView asset={asset} />}
      {tab === 'timeline' && (
        <div className="card" style={{ padding: 20 }}>
          <ScanTimeline timeline={timeline} />
          {report.errors && report.errors.length > 0 && (
            <div style={{ marginTop: 24, paddingTop: 16, borderTop: '1px solid var(--border-glass)' }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--orange)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: 1 }}>
                Module Errors ({report.errors.length})
              </div>
              {report.errors.map((e, i) => (
                <div key={i} style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', padding: '4px 0' }}>{e}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
