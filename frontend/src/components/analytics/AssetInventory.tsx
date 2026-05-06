import {
  HiOutlineGlobeAlt, HiOutlineShieldCheck, HiOutlineLockClosed,
  HiOutlineLightningBolt, HiOutlineDatabase, HiOutlineMail,
  HiOutlineCloud, HiOutlineCode,
} from 'react-icons/hi';
import { ReactNode } from 'react';

interface AssetInventory {
  ip?: string | null;
  asn?: number | null;
  asn_name?: string | null;
  country?: string | null;
  cdn?: string[];
  waf?: string[];
  tls?: {
    protocols?: string[];
    cipher?: string;
    key_bits?: number;
    cert?: { issuer?: string; not_after?: string; days_until_expiry?: number };
    hsts?: string | null;
  };
  tech?: string[];
  subdomains?: string[];
  open_ports?: Array<{ port: number; service: string; banner?: string; risk?: string }>;
  nameservers?: string[];
  mailservers?: string[];
  emails?: string[];
  social_profiles?: string[];
  endpoints?: string[];
  parameters?: string[];
  favicon_md5?: string | null;
  http?: { status?: number; final_url?: string; ms?: number };
  co_hosted_domains?: string[];
}

interface Props {
  asset: AssetInventory;
}

function Section({ icon, title, children }: { icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <div className="card-flat" style={{ padding: 18, borderRadius: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12, fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: 0.6 }}>
        <span style={{ color: 'var(--accent)', fontSize: 18, display: 'inline-flex' }}>{icon}</span>
        {title}
      </div>
      {children}
    </div>
  );
}

function Pill({ children, color = 'var(--accent)' }: { children: ReactNode; color?: string }) {
  return (
    <span style={{
      display: 'inline-block', padding: '4px 10px', borderRadius: 99,
      background: 'var(--bg-tertiary)', border: '1px solid var(--border-glass)',
      color, fontSize: 11.5, fontWeight: 500, fontFamily: 'var(--font-mono)',
      margin: '2px 4px 2px 0',
    }}>{children}</span>
  );
}

function KV({ k, v }: { k: string; v: ReactNode }) {
  if (v === null || v === undefined || v === '' || (Array.isArray(v) && v.length === 0)) return null;
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '6px 0', borderBottom: '1px solid rgba(99,102,241,0.05)', fontSize: 12.5 }}>
      <span style={{ color: 'var(--text-muted)', flexShrink: 0 }}>{k}</span>
      <span style={{ color: 'var(--text-primary)', textAlign: 'right', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{v}</span>
    </div>
  );
}

export default function AssetInventoryView({ asset }: Props) {
  if (!asset) return null;

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 16 }}>
      <Section icon={<HiOutlineGlobeAlt />} title="Identity">
        <KV k="IP" v={asset.ip} />
        <KV k="ASN" v={asset.asn ? `AS${asset.asn}` : null} />
        <KV k="Operator" v={asset.asn_name} />
        <KV k="Country" v={asset.country} />
        <KV k="HTTP" v={asset.http?.status ? `${asset.http.status} • ${asset.http.ms || '?'}ms` : null} />
        <KV k="Final URL" v={asset.http?.final_url} />
        <KV k="Favicon (md5)" v={asset.favicon_md5} />
      </Section>

      {(asset.cdn?.length || asset.waf?.length) ? (
        <Section icon={<HiOutlineShieldCheck />} title="Edge / WAF">
          {(asset.cdn || []).map(c => <Pill key={c} color="var(--cyan)">{c}</Pill>)}
          {(asset.waf || []).map(w => <Pill key={w} color="var(--green)">WAF: {w}</Pill>)}
        </Section>
      ) : null}

      {asset.tls?.cipher || asset.tls?.protocols?.length ? (
        <Section icon={<HiOutlineLockClosed />} title="TLS / SSL">
          <KV k="Protocols" v={(asset.tls.protocols || []).join(', ')} />
          <KV k="Cipher" v={asset.tls.cipher} />
          <KV k="Key bits" v={asset.tls.key_bits} />
          <KV k="Issuer" v={asset.tls.cert?.issuer} />
          <KV k="Expires" v={asset.tls.cert?.not_after ? `${asset.tls.cert.not_after} (${asset.tls.cert.days_until_expiry}d)` : null} />
          <KV k="HSTS" v={asset.tls.hsts || (asset.tls.hsts === null ? 'none' : null)} />
        </Section>
      ) : null}

      {asset.tech?.length ? (
        <Section icon={<HiOutlineCode />} title={`Technology (${asset.tech.length})`}>
          <div>{asset.tech.slice(0, 30).map(t => <Pill key={t}>{t}</Pill>)}</div>
        </Section>
      ) : null}

      {asset.open_ports?.length ? (
        <Section icon={<HiOutlineLightningBolt />} title={`Open Ports (${asset.open_ports.length})`}>
          {asset.open_ports.slice(0, 30).map(p => (
            <Pill key={p.port} color={p.risk === 'high' ? 'var(--red)' : 'var(--accent)'}>
              {p.port}/{p.service}
            </Pill>
          ))}
        </Section>
      ) : null}

      {asset.subdomains?.length ? (
        <Section icon={<HiOutlineGlobeAlt />} title={`Subdomains (${asset.subdomains.length})`}>
          <div style={{ maxHeight: 180, overflowY: 'auto' }}>
            {asset.subdomains.slice(0, 60).map(s => <Pill key={s}>{s}</Pill>)}
          </div>
        </Section>
      ) : null}

      {asset.nameservers?.length || asset.mailservers?.length ? (
        <Section icon={<HiOutlineDatabase />} title="DNS Records">
          {asset.nameservers?.map(n => <Pill key={n} color="var(--purple)">NS: {n}</Pill>)}
          {asset.mailservers?.map(m => <Pill key={m} color="var(--orange)">MX: {m}</Pill>)}
        </Section>
      ) : null}

      {asset.emails?.length ? (
        <Section icon={<HiOutlineMail />} title={`Emails (${asset.emails.length})`}>
          <div style={{ maxHeight: 180, overflowY: 'auto' }}>
            {asset.emails.slice(0, 30).map(e => <Pill key={e}>{e}</Pill>)}
          </div>
        </Section>
      ) : null}

      {asset.endpoints?.length ? (
        <Section icon={<HiOutlineCode />} title={`API Endpoints (${asset.endpoints.length})`}>
          <div style={{ maxHeight: 180, overflowY: 'auto' }}>
            {asset.endpoints.slice(0, 40).map(e => <Pill key={e}>{e}</Pill>)}
          </div>
        </Section>
      ) : null}

      {asset.parameters?.length ? (
        <Section icon={<HiOutlineCode />} title={`Parameters (${asset.parameters.length})`}>
          <div style={{ maxHeight: 180, overflowY: 'auto' }}>
            {asset.parameters.slice(0, 60).map(p => <Pill key={p}>{p}</Pill>)}
          </div>
        </Section>
      ) : null}

      {asset.co_hosted_domains?.length ? (
        <Section icon={<HiOutlineCloud />} title={`Co-hosted Domains (${asset.co_hosted_domains.length})`}>
          <div style={{ maxHeight: 180, overflowY: 'auto' }}>
            {asset.co_hosted_domains.slice(0, 40).map(d => <Pill key={d}>{d}</Pill>)}
          </div>
        </Section>
      ) : null}

      {asset.social_profiles?.length ? (
        <Section icon={<HiOutlineGlobeAlt />} title={`Social Profiles (${asset.social_profiles.length})`}>
          {asset.social_profiles.slice(0, 16).map(s => (
            <a key={s} href={s} target="_blank" rel="noreferrer" style={{ display: 'block', fontSize: 12, padding: '4px 0' }}>{s}</a>
          ))}
        </Section>
      ) : null}
    </div>
  );
}
