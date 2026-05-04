import { useEffect, useState } from 'react';
import { osintAPI } from '../api/client';
import { HiOutlineChartBar } from 'react-icons/hi';

export default function ModulesPage() {
  const [modules, setModules] = useState<any[]>([]);

  useEffect(() => {
    osintAPI.modules().then(r => setModules(r.data)).catch(() => {});
  }, []);

  return (
    <div className="fade-in">
      <div className="section-header">
        <h2 className="section-title">OSINT Modules</h2>
        <span className="badge badge-info">{modules.length} modules loaded</span>
      </div>
      <div className="grid-3">
        {modules.map((m: any, i: number) => (
          <div className="card" key={i}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
              <HiOutlineChartBar style={{ color: 'var(--accent)', fontSize: 20 }} />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 14, fontWeight: 600 }}>{m.name}</span>
            </div>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 12, lineHeight: 1.4 }}>{m.description}</p>
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
              {(m.supported_target_types || []).map((t: string) => (
                <span key={t} className="badge badge-info">{t}</span>
              ))}
            </div>
            <div style={{ marginTop: 8 }}>
              <span className={`badge ${m.requires_api_key ? 'badge-high' : 'badge-low'}`}>
                {m.requires_api_key ? 'API Key Required' : 'Free — No API Key'}
              </span>
            </div>
          </div>
        ))}
      </div>
      {modules.length === 0 && (
        <div className="card empty-state"><p>No modules loaded. Start the backend to see available modules.</p></div>
      )}
    </div>
  );
}
