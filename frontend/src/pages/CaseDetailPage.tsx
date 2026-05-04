import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { casesAPI, targetsAPI, osintAPI } from '../api/client';
import { HiOutlinePlus, HiOutlinePlay, HiOutlineGlobe, HiOutlineArrowLeft } from 'react-icons/hi';

const TARGET_TYPES = ['email', 'username', 'domain', 'ip', 'phone', 'person', 'organization', 'url'];

export default function CaseDetailPage() {
  const { caseId } = useParams<{ caseId: string }>();
  const navigate = useNavigate();
  const [caseData, setCaseData] = useState<any>(null);
  const [targets, setTargets] = useState<any[]>([]);
  const [results, setResults] = useState<Record<string, any[]>>({});
  const [showAddTarget, setShowAddTarget] = useState(false);
  const [targetForm, setTargetForm] = useState({ target_type: 'email', value: '', label: '' });
  const [scanning, setScanning] = useState<string | null>(null);

  const load = () => {
    if (!caseId) return;
    casesAPI.get(caseId).then(r => setCaseData(r.data)).catch(() => navigate('/cases'));
    targetsAPI.list(caseId).then(r => setTargets(r.data)).catch(() => {});
  };
  useEffect(load, [caseId]);

  const loadResults = (targetId: string) => {
    osintAPI.results(targetId).then(r => setResults(prev => ({ ...prev, [targetId]: r.data }))).catch(() => {});
  };

  const addTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!caseId) return;
    await targetsAPI.create(caseId, targetForm);
    setShowAddTarget(false);
    setTargetForm({ target_type: 'email', value: '', label: '' });
    load();
  };

  const launchScan = async (targetId: string) => {
    setScanning(targetId);
    try {
      await osintAPI.scan({ target_id: targetId, modules: ['all'] });
      setTimeout(() => { loadResults(targetId); setScanning(null); }, 3000);
    } catch { setScanning(null); }
  };

  if (!caseData) return <div className="empty-state pulse">Loading case...</div>;

  return (
    <div className="fade-in">
      <div style={{ marginBottom: 20 }}>
        <button className="btn btn-ghost btn-sm" onClick={() => navigate('/cases')}>
          <HiOutlineArrowLeft /> Back to Cases
        </button>
      </div>
      <div className="section-header">
        <div>
          <h2 className="section-title">{caseData.name}</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: 14, marginTop: 4 }}>{caseData.description || 'No description'}</p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-ghost btn-sm" onClick={() => navigate(`/graph/${caseId}`)}>
            <HiOutlineGlobe /> View Graph
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => setShowAddTarget(true)}>
            <HiOutlinePlus /> Add Target
          </button>
        </div>
      </div>

      {targets.length === 0 ? (
        <div className="card empty-state"><p>No targets yet. Add a target to start scanning.</p></div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {targets.map((t: any) => (
            <div className="card" key={t.id}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span className="badge badge-info">{t.target_type}</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 15, fontWeight: 600 }}>{t.value}</span>
                  {t.label && t.label !== t.value && <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>({t.label})</span>}
                </div>
                <button className="btn btn-primary btn-sm" onClick={() => launchScan(t.id)} disabled={scanning === t.id}>
                  <HiOutlinePlay /> {scanning === t.id ? 'Scanning...' : 'Scan'}
                </button>
              </div>
              {results[t.id] && results[t.id].length > 0 && (
                <div className="table-wrap">
                  <table className="table">
                    <thead><tr><th>Module</th><th>Status</th><th>Severity</th><th>Summary</th></tr></thead>
                    <tbody>
                      {results[t.id].map((r: any) => (
                        <tr key={r.id}>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{r.module}</td>
                          <td><span className={`badge badge-${r.status === 'completed' ? 'low' : 'medium'}`}>{r.status}</span></td>
                          <td><span className={`badge badge-${r.severity}`}>{r.severity}</span></td>
                          <td style={{ fontSize: 13, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.summary || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {!results[t.id] && (
                <button className="btn btn-ghost btn-sm" onClick={() => loadResults(t.id)}>Load Results</button>
              )}
            </div>
          ))}
        </div>
      )}

      {showAddTarget && (
        <div className="modal-overlay" onClick={() => setShowAddTarget(false)}>
          <div className="card modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Add Target</h2>
              <button className="modal-close" onClick={() => setShowAddTarget(false)}>✕</button>
            </div>
            <form onSubmit={addTarget} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div className="input-group">
                <label>Target Type</label>
                <select className="input" value={targetForm.target_type} onChange={e => setTargetForm({...targetForm, target_type: e.target.value})}>
                  {TARGET_TYPES.map(t => <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>)}
                </select>
              </div>
              <div className="input-group">
                <label>Value *</label>
                <input className="input" value={targetForm.value} onChange={e => setTargetForm({...targetForm, value: e.target.value})} required placeholder="target@example.com" />
              </div>
              <div className="input-group">
                <label>Label</label>
                <input className="input" value={targetForm.label} onChange={e => setTargetForm({...targetForm, label: e.target.value})} placeholder="Suspect Alpha" />
              </div>
              <button className="btn btn-primary" type="submit">Add Target</button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
