import { useState } from 'react';
import { investigateAPI } from '../api/client';
import { HiOutlineSearch, HiOutlineShieldCheck, HiOutlineExclamation, HiOutlineChevronDown, HiOutlineChevronUp, HiOutlineUser, HiOutlineMail, HiOutlinePhone, HiOutlineIdentification, HiOutlineGlobe, HiOutlinePhotograph } from 'react-icons/hi';

/* ── Seed Data Form ──────────────────────────────────── */
interface SeedData {
  target: string; username: string; email: string; phone: string;
  cnic: string; name: string; photo_url: string; aliases: string;
}
const emptySeed: SeedData = { target: '', username: '', email: '', phone: '', cnic: '', name: '', photo_url: '', aliases: '' };

/* ── Tiny Components ─────────────────────────────────── */
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
      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>Risk Score</div>
    </div>
  );
}

const PHASE_META: Record<string, { icon: string; label: string }> = {
  seed_data: { icon: '🌱', label: 'Seed Data' },
  search_recon: { icon: '🔍', label: 'Search Engine Recon' },
  social_media: { icon: '📱', label: 'Social Media Profiling' },
  username_enum: { icon: '👤', label: 'Username Enumeration' },
  breach_data: { icon: '🔓', label: 'Email & Breach Data' },
  public_records: { icon: '📋', label: 'Public Records & WHOIS' },
  image_geo: { icon: '📍', label: 'Image & Geolocation' },
  correlation: { icon: '🧠', label: 'AI Correlation' },
};

function PhaseTracker({ phases }: { phases: Record<string, any> }) {
  return (
    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 20 }}>
      {Object.entries(PHASE_META).map(([key, meta]) => {
        const phase = phases?.[key];
        const status = phase?.status || 'pending';
        const bg = status === 'completed' ? 'rgba(16,185,129,0.15)' : status === 'running' ? 'rgba(59,130,246,0.15)' : 'rgba(255,255,255,0.04)';
        const border = status === 'completed' ? 'var(--green)' : status === 'running' ? 'var(--cyan)' : 'var(--border-glass)';
        const statusIcon = status === 'completed' ? '✅' : status === 'running' ? '🔄' : '⏳';
        return (
          <div key={key} style={{ background: bg, border: `1px solid ${border}`, borderRadius: 8, padding: '8px 14px', fontSize: 12, display: 'flex', alignItems: 'center', gap: 6, minWidth: 160 }}>
            <span>{meta.icon}</span>
            <span style={{ flex: 1, color: 'var(--text-secondary)' }}>{meta.label}</span>
            <span style={{ fontSize: 11 }}>{statusIcon}</span>
          </div>
        );
      })}
    </div>
  );
}

const PLATFORM_COLORS: Record<string, string> = {
  GitHub: '#333', 'Twitter/X': '#1DA1F2', LinkedIn: '#0077B5', Instagram: '#E4405F',
  Facebook: '#1877F2', Reddit: '#FF4500', TikTok: '#010101', Pinterest: '#E60023',
  YouTube: '#FF0000', Twitch: '#9146FF', Steam: '#171a21', Mastodon: '#6364FF',
};

function SocialProfileCard({ profile }: { profile: any }) {
  const color = PLATFORM_COLORS[profile.platform] || 'var(--accent)';
  return (
    <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-glass)', borderRadius: 12, padding: 16, borderTop: `3px solid ${color}`, transition: 'transform 0.2s, box-shadow 0.2s' }}
      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.transform = 'translateY(-2px)'; (e.currentTarget as HTMLElement).style.boxShadow = `0 4px 20px ${color}33`; }}
      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.transform = ''; (e.currentTarget as HTMLElement).style.boxShadow = ''; }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
        {profile.avatar_url ? (
          <img src={profile.avatar_url} alt="" style={{ width: 40, height: 40, borderRadius: '50%', objectFit: 'cover', border: `2px solid ${color}` }}
            onError={e => { (e.target as HTMLImageElement).style.display = 'none'; }} />
        ) : (
          <div style={{ width: 40, height: 40, borderRadius: '50%', background: `${color}22`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18, border: `2px solid ${color}` }}>👤</div>
        )}
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>{profile.display_name || profile.username}</div>
          <div style={{ fontSize: 11, color }}>{profile.platform} {profile.verified && '✓'}</div>
        </div>
        <a href={profile.url} target="_blank" rel="noopener noreferrer" style={{ fontSize: 11, color: 'var(--accent)', textDecoration: 'none' }}>↗</a>
      </div>
      {profile.bio && <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8, lineHeight: 1.5, maxHeight: 48, overflow: 'hidden' }}>{profile.bio}</div>}
      <div style={{ display: 'flex', gap: 12, fontSize: 11, color: 'var(--text-muted)' }}>
        {profile.followers && <span>👥 {profile.followers}</span>}
        {profile.following && <span>➡️ {profile.following}</span>}
        {profile.posts_count && <span>📝 {profile.posts_count}</span>}
      </div>
      <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 6, opacity: 0.6 }}>{profile.method}</div>
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

/* ── Input Field Component ───────────────────────────── */
function SeedField({ icon, label, placeholder, value, onChange, type = 'text' }: {
  icon: React.ReactNode; label: string; placeholder: string; value: string;
  onChange: (v: string) => void; type?: string;
}) {
  return (
    <div style={{ position: 'relative' }}>
      <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4, marginBottom: 4 }}>
        {icon} {label}
      </label>
      <input className="input" type={type} value={value} onChange={e => onChange(e.target.value)}
        placeholder={placeholder} style={{ fontSize: 13, height: 42, background: 'var(--bg-secondary)' }} />
    </div>
  );
}

/* ── Main Page ───────────────────────────────────────── */
export default function PersonInvestigation() {
  const [seed, setSeed] = useState<SeedData>(emptySeed);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');

  const update = (field: keyof SeedData) => (v: string) => setSeed(prev => ({ ...prev, [field]: v }));
  const hasAnyInput = seed.target.trim() || seed.username.trim() || seed.email.trim() || seed.phone.trim();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!hasAnyInput) return;
    setLoading(true); setError(''); setResult(null);
    try {
      const payload: any = { target: seed.target.trim() || seed.username.trim() || seed.email.trim() || seed.phone.trim() };
      if (seed.username.trim()) payload.username = seed.username.trim();
      if (seed.email.trim()) payload.email = seed.email.trim();
      if (seed.phone.trim()) payload.phone = seed.phone.trim();
      if (seed.cnic.trim()) payload.cnic = seed.cnic.trim();
      if (seed.name.trim()) payload.name = seed.name.trim();
      if (seed.photo_url.trim()) payload.photo_url = seed.photo_url.trim();
      if (seed.aliases.trim()) payload.aliases = seed.aliases.split(',').map((a: string) => a.trim()).filter(Boolean);
      const res = await investigateAPI.person(payload);
      setResult(res.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Investigation failed');
    }
    setLoading(false);
  };

  return (
    <div className="fade-in">
      <div className="section-header">
        <h2 className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 28 }}>👤</span> Person Investigation
        </h2>
      </div>
      <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 20, maxWidth: 700 }}>
        Enter any combination of seed data — username, email, phone, CNIC, name, or photo URL.
        ShadowNet runs <strong>16 OSINT modules</strong> across 8 phases: social media scraping, breach databases,
        Google dorking, dark web monitoring, reverse image search, WHOIS, and AI-powered correlation.
      </p>

      {/* ── Seed Data Form ──────────────────────── */}
      <div className="card" style={{ marginBottom: 24, padding: 24 }}>
        <form onSubmit={handleSubmit}>
          {/* Primary target row */}
          <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
            <div style={{ flex: 1, position: 'relative' }}>
              <HiOutlineSearch style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', fontSize: 18, zIndex: 1 }} />
              <input className="input" style={{ paddingLeft: 48, fontSize: 15, height: 52 }} value={seed.target}
                onChange={e => update('target')(e.target.value)} placeholder="Primary target — email, username, phone, or name..." />
            </div>
            <button className="btn btn-primary btn-lg" type="submit" disabled={loading || !hasAnyInput} style={{ minWidth: 180 }}>
              {loading ? '⏳ Investigating...' : '🔍 Investigate'}
            </button>
          </div>

          {/* Toggle advanced fields */}
          <button type="button" onClick={() => setShowAdvanced(!showAdvanced)}
            style={{ background: 'none', border: 'none', color: 'var(--accent)', cursor: 'pointer', fontSize: 13, display: 'flex', alignItems: 'center', gap: 6, padding: 0, marginBottom: showAdvanced ? 16 : 0 }}>
            {showAdvanced ? <HiOutlineChevronUp /> : <HiOutlineChevronDown />}
            {showAdvanced ? 'Hide' : 'Show'} Advanced Seed Data ({Object.values(seed).filter((v, i) => i > 0 && v).length} fields set)
          </button>

          {/* Advanced seed fields */}
          {showAdvanced && (
            <div className="slide-up" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))', gap: 14 }}>
              <SeedField icon={<HiOutlineUser style={{ fontSize: 14 }} />} label="Username / Handle" placeholder="e.g. johndoe" value={seed.username} onChange={update('username')} />
              <SeedField icon={<HiOutlineMail style={{ fontSize: 14 }} />} label="Email Address" placeholder="e.g. john@example.com" value={seed.email} onChange={update('email')} type="email" />
              <SeedField icon={<HiOutlinePhone style={{ fontSize: 14 }} />} label="Phone Number" placeholder="e.g. +923001234567" value={seed.phone} onChange={update('phone')} type="tel" />
              <SeedField icon={<HiOutlineIdentification style={{ fontSize: 14 }} />} label="CNIC / National ID" placeholder="e.g. 35202-1234567-1" value={seed.cnic} onChange={update('cnic')} />
              <SeedField icon={<HiOutlineGlobe style={{ fontSize: 14 }} />} label="Full Name" placeholder="e.g. John Doe" value={seed.name} onChange={update('name')} />
              <SeedField icon={<HiOutlinePhotograph style={{ fontSize: 14 }} />} label="Photo URL" placeholder="https://..." value={seed.photo_url} onChange={update('photo_url')} type="url" />
              <div style={{ gridColumn: 'span 2' }}>
                <SeedField icon={<span style={{ fontSize: 14 }}>🏷️</span>} label="Known Aliases (comma-separated)" placeholder="e.g. j_doe, john.d, johnd123" value={seed.aliases} onChange={update('aliases')} />
              </div>
            </div>
          )}
        </form>
      </div>

      {/* ── Error ──────────────────────────────── */}
      {error && <div className="card" style={{ borderLeft: '3px solid var(--red)', padding: 16, marginBottom: 16 }}>
        <HiOutlineExclamation style={{ color: 'var(--red)', marginRight: 8 }} /><span style={{ color: 'var(--red)' }}>{error}</span>
      </div>}

      {/* ── Loading ────────────────────────────── */}
      {loading && (
        <div className="card" style={{ textAlign: 'center', padding: 60 }}>
          <div className="pulse" style={{ fontSize: 52, marginBottom: 16 }}>🔎</div>
          <div style={{ fontSize: 16, color: 'var(--accent)', marginBottom: 8, fontWeight: 600 }}>Investigating person...</div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', maxWidth: 500, margin: '0 auto' }}>
            Running 16 modules: social media scraping, breach databases, username enumeration,
            Google dorking, CNIC analysis, reverse WHOIS, stealth browser, and AI correlation.
            This may take 30-120 seconds.
          </div>
          <div className="progress-bar" style={{ marginTop: 20, maxWidth: 400, margin: '20px auto 0' }}>
            <div className="progress-fill" style={{ width: '60%', animation: 'shimmer 2s infinite' }} />
          </div>
        </div>
      )}

      {/* ── Results ────────────────────────────── */}
      {result && !loading && (
        <div className="slide-up">
          {/* Phase Tracker */}
          {result.phases && <PhaseTracker phases={result.phases} />}

          {/* Stats Strip */}
          <div className="grid-4 stagger" style={{ marginBottom: 20 }}>
            <div className="card stat-card slide-up"><div className="stat-icon" style={{ background: 'var(--accent-dim)', color: 'var(--accent)' }}><HiOutlineUser /></div><div><div className="stat-value">{result.target_type || 'person'}</div><div className="stat-label">Target Type</div></div></div>
            <div className="card stat-card slide-up"><div className="stat-icon" style={{ background: 'var(--cyan-dim)', color: 'var(--cyan)' }}>📊</div><div><div className="stat-value">{result.modules_run?.length || 0}</div><div className="stat-label">Modules Run</div></div></div>
            <div className="card stat-card slide-up"><div className="stat-icon" style={{ background: 'var(--green-dim)', color: 'var(--green)' }}>🎯</div><div><div className="stat-value">{result.entities_found?.length || 0}</div><div className="stat-label">Entities Found</div></div></div>
            <div className="card stat-card slide-up"><RiskGauge score={result.risk_score || 0} /></div>
          </div>

          {/* Summary */}
          <div className="card" style={{ marginBottom: 20, padding: 20, borderLeft: '3px solid var(--accent)' }}>
            <HiOutlineShieldCheck style={{ color: 'var(--accent)', fontSize: 20, marginRight: 8, verticalAlign: 'middle' }} />
            <span style={{ fontWeight: 600 }}>Summary</span>
            <p style={{ margin: '8px 0 0', fontSize: 14, lineHeight: 1.7, color: 'var(--text-secondary)' }}>{result.summary}</p>
          </div>

          {/* Social Media Profiles Grid */}
          {result.social_profiles?.length > 0 && (
            <div className="card result-section" style={{ padding: 20, marginBottom: 20 }}>
              <h3 className="result-section-title" style={{ marginBottom: 16 }}>📱 Social Media Profiles ({result.social_profiles.length})</h3>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 14 }}>
                {result.social_profiles.map((p: any, i: number) => <SocialProfileCard key={i} profile={p} />)}
              </div>
            </div>
          )}

          {/* AI Analysis */}
          {result.ai_analysis && (
            <div className="card result-section" style={{ padding: 20, marginBottom: 20 }}>
              <h3 className="result-section-title">🤖 AI Threat Analysis</h3>
              {result.ai_analysis.executive_summary && <p style={{ fontSize: 14, lineHeight: 1.7, color: 'var(--text-secondary)', marginBottom: 16 }}>{result.ai_analysis.executive_summary}</p>}
              {result.ai_analysis.key_findings && (<><h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Key Findings</h4>
                <ul style={{ paddingLeft: 20, marginBottom: 16 }}>{result.ai_analysis.key_findings.map((f: any, i: number) => <li key={i} style={{ fontSize: 13, marginBottom: 4, color: 'var(--text-secondary)' }}>{typeof f === 'string' ? f : f.finding || JSON.stringify(f)}</li>)}</ul></>)}
              {result.ai_analysis.recommendations && (<><h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Recommendations</h4>
                <ul style={{ paddingLeft: 20 }}>{result.ai_analysis.recommendations.map((r: any, i: number) => <li key={i} style={{ fontSize: 13, marginBottom: 4, color: 'var(--text-secondary)' }}>{typeof r === 'string' ? r : JSON.stringify(r)}</li>)}</ul></>)}
            </div>
          )}

          {/* Breach Analysis */}
          {result.breach_explanations?.length > 0 && (
            <div className="card result-section" style={{ padding: 20, marginBottom: 20 }}>
              <h3 className="result-section-title">🔓 Breach Analysis — How It Happened</h3>
              {result.breach_explanations.map((b: any, i: number) => (
                <div className="breach-card" key={i}>
                  <div className="breach-card-title">{b.breach_name || `Breach #${i + 1}`}</div>
                  <div className="breach-card-meta">
                    {b.what_happened && <><strong>What:</strong> {b.what_happened}<br /></>}
                    {b.attack_vector && <><strong>How:</strong> {b.attack_vector}<br /></>}
                    {b.data_exposed && <><strong>Data Exposed:</strong> {(Array.isArray(b.data_exposed) ? b.data_exposed : [b.data_exposed]).join(', ')}<br /></>}
                    {b.impact_assessment && <><strong>Impact:</strong> {b.impact_assessment}<br /></>}
                    {b.timeline && <><strong>Timeline:</strong> {b.timeline}<br /></>}
                    {b.dark_web_status && <><strong>Dark Web:</strong> {b.dark_web_status}</>}
                  </div>
                  {b.severity && <span className={`badge badge-${b.severity}`} style={{ marginTop: 8, display: 'inline-flex' }}>{b.severity}</span>}
                </div>
              ))}
            </div>
          )}

          {/* Module Results */}
          <div className="card result-section" style={{ padding: 20, marginBottom: 20 }}>
            <h3 className="result-section-title">📊 Module Results ({Object.keys(result.results || {}).length})</h3>
            {Object.entries(result.results || {}).map(([name, data]: [string, any]) => <ModuleResult key={name} name={name} data={data} />)}
          </div>

          {/* Entities Table */}
          {result.entities_found?.length > 0 && (
            <div className="card result-section" style={{ padding: 20, marginBottom: 20 }}>
              <h3 className="result-section-title">🎯 Discovered Entities ({result.entities_found.length})</h3>
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>Type</th><th>Value</th><th>Source</th><th>Confidence</th></tr></thead>
                  <tbody>
                    {result.entities_found.slice(0, 100).map((e: any, i: number) => (
                      <tr key={i}>
                        <td><span className="badge badge-info">{e.type}</span></td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.value}</td>
                        <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{e.source}</td>
                        <td>{Math.round((e.confidence || 0) * 100)}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Errors */}
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
