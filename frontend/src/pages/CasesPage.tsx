import { useEffect, useState } from 'react';
import { casesAPI } from '../api/client';
import { useNavigate } from 'react-router-dom';
import { HiOutlinePlus, HiOutlineFolder, HiOutlineTrash } from 'react-icons/hi';

export default function CasesPage() {
  const [cases, setCases] = useState<any[]>([]);
  const [showModal, setShowModal] = useState(false);
  const [form, setForm] = useState({ name: '', description: '', priority: 0, tags: '' });
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  const loadCases = () => {
    casesAPI.list().then(r => setCases(r.data)).catch(() => {}).finally(() => setLoading(false));
  };
  useEffect(loadCases, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    await casesAPI.create({
      name: form.name, description: form.description, priority: form.priority,
      tags: form.tags ? form.tags.split(',').map(t => t.trim()) : [],
    });
    setShowModal(false); setForm({ name: '', description: '', priority: 0, tags: '' });
    loadCases();
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (confirm('Delete this case and all its data?')) {
      await casesAPI.delete(id); loadCases();
    }
  };

  const priorityLabel = (p: number) => p === 2 ? 'Critical' : p === 1 ? 'High' : 'Normal';
  const priorityClass = (p: number) => p === 2 ? 'critical' : p === 1 ? 'high' : 'info';
  const statusClass = (s: string) => s === 'active' ? 'low' : s === 'closed' ? 'critical' : 'info';

  if (loading) return <div className="empty-state pulse">Loading cases...</div>;

  return (
    <div className="fade-in">
      <div className="section-header">
        <h2 className="section-title">Investigation Cases</h2>
        <button className="btn btn-primary" onClick={() => setShowModal(true)}>
          <HiOutlinePlus /> New Case
        </button>
      </div>

      {cases.length === 0 ? (
        <div className="card empty-state">
          <HiOutlineFolder style={{ fontSize: 48, marginBottom: 16, opacity: 0.4 }} />
          <p>No cases yet. Create your first investigation.</p>
        </div>
      ) : (
        <div className="table-wrap card" style={{ padding: 0 }}>
          <table className="table">
            <thead>
              <tr><th>Case Name</th><th>Status</th><th>Priority</th><th>Targets</th><th>Tags</th><th></th></tr>
            </thead>
            <tbody>
              {cases.map((c: any) => (
                <tr key={c.id} onClick={() => navigate(`/cases/${c.id}`)} style={{ cursor: 'pointer' }}>
                  <td style={{ fontWeight: 600 }}>{c.name}</td>
                  <td><span className={`badge badge-${statusClass(c.status)}`}>{c.status}</span></td>
                  <td><span className={`badge badge-${priorityClass(c.priority)}`}>{priorityLabel(c.priority)}</span></td>
                  <td>{c.target_count}</td>
                  <td>{(c.tags || []).map((t: string, i: number) => <span key={i} className="badge badge-info" style={{ marginRight: 4 }}>{t}</span>)}</td>
                  <td><button className="btn btn-ghost btn-sm" onClick={(e) => handleDelete(c.id, e)}><HiOutlineTrash /></button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showModal && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="card modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2>New Investigation Case</h2>
              <button className="modal-close" onClick={() => setShowModal(false)}>✕</button>
            </div>
            <form onSubmit={handleCreate} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div className="input-group">
                <label>Case Name *</label>
                <input className="input" value={form.name} onChange={e => setForm({...form, name: e.target.value})} required placeholder="Operation Phantom" />
              </div>
              <div className="input-group">
                <label>Description</label>
                <textarea className="input" value={form.description} onChange={e => setForm({...form, description: e.target.value})} rows={3} placeholder="Investigation details..." />
              </div>
              <div className="input-group">
                <label>Priority</label>
                <select className="input" value={form.priority} onChange={e => setForm({...form, priority: Number(e.target.value)})}>
                  <option value={0}>Normal</option><option value={1}>High</option><option value={2}>Critical</option>
                </select>
              </div>
              <div className="input-group">
                <label>Tags (comma separated)</label>
                <input className="input" value={form.tags} onChange={e => setForm({...form, tags: e.target.value})} placeholder="apt, ransomware, phishing" />
              </div>
              <button className="btn btn-primary" type="submit">Create Case</button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
