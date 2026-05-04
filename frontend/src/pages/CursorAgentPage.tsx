import { useState, useEffect, useRef, useCallback } from 'react';
import { cursorAgentAPI } from '../api/client';

interface Agent {
  id: string;
  name?: string;
  status: string;
  url?: string;
  branchName?: string;
  createdAt: string;
  updatedAt?: string;
  latestRunId?: string;
  repos?: { url: string; startingRef: string }[];
}

interface StreamEvent {
  event: string;
  text?: string;
  status?: string;
  raw?: string;
}

export default function CursorAgentPage() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(false);
  const [creating, setCreating] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
  const [streamEvents, setStreamEvents] = useState<StreamEvent[]>([]);
  const [streaming, setStreaming] = useState(false);
  const [models, setModels] = useState<any[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [apiInfo, setApiInfo] = useState<any>(null);
  const streamRef = useRef<EventSource | null>(null);
  const outputRef = useRef<HTMLDivElement>(null);

  // Form state
  const [formPrompt, setFormPrompt] = useState('');
  const [formRepo, setFormRepo] = useState('');
  const [formBranch, setFormBranch] = useState('main');
  const [formModel, setFormModel] = useState('');
  const [formAutoPR, setFormAutoPR] = useState(true);

  // Follow-up
  const [followUpPrompt, setFollowUpPrompt] = useState('');

  const fetchAgents = useCallback(async () => {
    setLoading(true);
    try {
      const res = await cursorAgentAPI.agents(50);
      setAgents(res.data?.items || res.data || []);
    } catch (e: any) {
      console.error('Failed to fetch agents:', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAgents();
    cursorAgentAPI.models().then(r => {
      setModels(r.data?.items || r.data?.models || []);
    }).catch(() => {});
    cursorAgentAPI.me().then(r => setApiInfo(r.data)).catch(() => {});
  }, [fetchAgents]);

  const handleCreate = async () => {
    if (!formPrompt.trim() || !formRepo.trim()) return;
    setCreating(true);
    try {
      const res = await cursorAgentAPI.create({
        prompt: formPrompt,
        repo_url: formRepo,
        starting_ref: formBranch || 'main',
        model_id: formModel || undefined,
        auto_create_pr: formAutoPR,
      });
      setShowCreate(false);
      setFormPrompt('');
      setFormRepo('');
      await fetchAgents();
      const agent = res.data?.agent;
      if (agent) setSelectedAgent(agent);
    } catch (e: any) {
      alert('Failed to create agent: ' + (e.response?.data?.detail || e.message));
    } finally {
      setCreating(false);
    }
  };

  const handleStream = (agent: Agent) => {
    if (!agent.latestRunId) return;
    setStreamEvents([]);
    setStreaming(true);
    const url = `/api/v1/cursor-agent/agents/${agent.id}/stream/${agent.latestRunId}`;
    const es = new EventSource(url);
    streamRef.current = es;

    const addEvent = (event: string, data: any) => {
      setStreamEvents(prev => [...prev, { event, ...data }]);
      setTimeout(() => outputRef.current?.scrollTo(0, outputRef.current.scrollHeight), 50);
    };

    es.addEventListener('status', (e) => addEvent('status', JSON.parse(e.data)));
    es.addEventListener('assistant', (e) => addEvent('assistant', JSON.parse(e.data)));
    es.addEventListener('thinking', (e) => addEvent('thinking', JSON.parse(e.data)));
    es.addEventListener('tool_call', (e) => addEvent('tool_call', JSON.parse(e.data)));
    es.addEventListener('result', (e) => { addEvent('result', JSON.parse(e.data)); es.close(); setStreaming(false); });
    es.addEventListener('done', () => { addEvent('done', {}); es.close(); setStreaming(false); });
    es.addEventListener('error', (e) => { addEvent('error', { raw: 'Stream error' }); es.close(); setStreaming(false); });
    es.onerror = () => { es.close(); setStreaming(false); };
  };

  const handleCancelRun = async (agent: Agent) => {
    if (!agent.latestRunId) return;
    try {
      await cursorAgentAPI.cancelRun(agent.id, agent.latestRunId);
      streamRef.current?.close();
      setStreaming(false);
      fetchAgents();
    } catch (e: any) {
      alert('Cancel failed: ' + (e.response?.data?.detail || e.message));
    }
  };

  const handleFollowUp = async () => {
    if (!selectedAgent || !followUpPrompt.trim()) return;
    try {
      const res = await cursorAgentAPI.createRun(selectedAgent.id, followUpPrompt);
      setFollowUpPrompt('');
      const run = res.data;
      if (run?.id) {
        setSelectedAgent({ ...selectedAgent, latestRunId: run.id });
      }
      fetchAgents();
    } catch (e: any) {
      alert('Follow-up failed: ' + (e.response?.data?.detail || e.message));
    }
  };

  const handleDelete = async (agent: Agent) => {
    if (!confirm('Permanently delete this agent?')) return;
    try {
      await cursorAgentAPI.deleteAgent(agent.id);
      if (selectedAgent?.id === agent.id) setSelectedAgent(null);
      fetchAgents();
    } catch (e: any) {
      alert('Delete failed: ' + (e.response?.data?.detail || e.message));
    }
  };

  const statusColor = (s: string) => {
    switch (s?.toUpperCase()) {
      case 'ACTIVE': case 'RUNNING': return '#00ff88';
      case 'FINISHED': case 'COMPLETED': return '#8b5cf6';
      case 'CREATING': return '#fbbf24';
      case 'CANCELLED': case 'FAILED': case 'ERROR': return '#ef4444';
      case 'ARCHIVED': return '#6b7280';
      default: return '#94a3b8';
    }
  };

  return (
    <div style={{ display: 'flex', gap: 24, height: '100%', minHeight: 'calc(100vh - 80px)' }}>
      {/* Left Panel — Agent List */}
      <div style={{ width: 380, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 style={{ margin: 0, fontSize: 20, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 24 }}>⚡</span> Cloud Agents
          </h2>
          <button className="btn-accent" onClick={() => setShowCreate(!showCreate)}
            style={{ padding: '6px 16px', borderRadius: 8, background: 'var(--accent)', color: '#000', fontWeight: 600, border: 'none', cursor: 'pointer', fontSize: 13 }}>
            + New Agent
          </button>
        </div>

        {/* API Info Badge */}
        {apiInfo && (
          <div style={{ padding: '8px 12px', borderRadius: 8, background: 'rgba(139,92,246,0.1)', border: '1px solid rgba(139,92,246,0.3)', fontSize: 11, color: '#a78bfa' }}>
            🔑 {apiInfo.apiKeyName || 'API Key'} • {apiInfo.userEmail || 'Connected'}
          </div>
        )}

        {/* Create Form */}
        {showCreate && (
          <div style={{ padding: 16, borderRadius: 12, background: 'var(--glass)', border: '1px solid var(--border-glass)', display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--accent)' }}>🚀 Launch New Agent</div>
            <input placeholder="GitHub repo URL (e.g. https://github.com/user/repo)" value={formRepo} onChange={e => setFormRepo(e.target.value)}
              style={{ padding: '8px 12px', borderRadius: 8, background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-glass)', color: 'var(--text)', fontSize: 13, outline: 'none' }} />
            <input placeholder="Branch (default: main)" value={formBranch} onChange={e => setFormBranch(e.target.value)}
              style={{ padding: '8px 12px', borderRadius: 8, background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-glass)', color: 'var(--text)', fontSize: 13, outline: 'none' }} />
            <textarea placeholder="Task prompt for the agent..." value={formPrompt} onChange={e => setFormPrompt(e.target.value)} rows={4}
              style={{ padding: '8px 12px', borderRadius: 8, background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-glass)', color: 'var(--text)', fontSize: 13, outline: 'none', resize: 'vertical', fontFamily: 'inherit' }} />
            {models.length > 0 && (
              <select value={formModel} onChange={e => setFormModel(e.target.value)}
                style={{ padding: '8px 12px', borderRadius: 8, background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-glass)', color: 'var(--text)', fontSize: 13 }}>
                <option value="">Default Model</option>
                {models.map((m: any) => <option key={m.id || m} value={m.id || m}>{m.name || m.id || m}</option>)}
              </select>
            )}
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-muted)' }}>
              <input type="checkbox" checked={formAutoPR} onChange={e => setFormAutoPR(e.target.checked)} />
              Auto-create Pull Request
            </label>
            <button onClick={handleCreate} disabled={creating || !formPrompt.trim() || !formRepo.trim()}
              style={{ padding: '10px 16px', borderRadius: 8, background: creating ? '#4b5563' : 'linear-gradient(135deg, #8b5cf6, #06b6d4)', color: '#fff', fontWeight: 700, border: 'none', cursor: creating ? 'wait' : 'pointer', fontSize: 14 }}>
              {creating ? '⏳ Launching...' : '🚀 Launch Agent'}
            </button>
          </div>
        )}

        {/* Agent List */}
        <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
          {loading ? (
            <div style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>Loading agents...</div>
          ) : agents.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)', fontSize: 13 }}>
              No agents yet. Launch one to get started!
            </div>
          ) : agents.map(agent => (
            <div key={agent.id} onClick={() => setSelectedAgent(agent)}
              style={{
                padding: '12px 14px', borderRadius: 10,
                background: selectedAgent?.id === agent.id ? 'rgba(139,92,246,0.15)' : 'var(--glass)',
                border: selectedAgent?.id === agent.id ? '1px solid rgba(139,92,246,0.5)' : '1px solid var(--border-glass)',
                cursor: 'pointer', transition: 'all 0.2s',
              }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text)' }}>
                  {agent.name || agent.id.slice(0, 20) + '...'}
                </span>
                <span style={{ fontSize: 10, fontWeight: 700, color: statusColor(agent.status), textTransform: 'uppercase', padding: '2px 8px', borderRadius: 4, background: `${statusColor(agent.status)}18` }}>
                  {agent.status}
                </span>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                {agent.repos?.[0]?.url?.replace('https://github.com/', '') || 'No repo'}
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
                {new Date(agent.createdAt).toLocaleString()}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Right Panel — Agent Detail / Stream */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 16 }}>
        {!selectedAgent ? (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 16 }}>
            <div style={{ fontSize: 64, opacity: 0.3 }}>⚡</div>
            <div style={{ fontSize: 16, color: 'var(--text-muted)' }}>Select an agent or create a new one</div>
          </div>
        ) : (
          <>
            {/* Agent Header */}
            <div style={{ padding: 20, borderRadius: 12, background: 'var(--glass)', border: '1px solid var(--border-glass)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: 18, fontWeight: 700 }}>
                    {selectedAgent.name || 'Cloud Agent'}
                  </h3>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace', marginTop: 4 }}>
                    {selectedAgent.id}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  {selectedAgent.latestRunId && (
                    <button onClick={() => handleStream(selectedAgent)}
                      disabled={streaming}
                      style={{ padding: '6px 12px', borderRadius: 6, background: streaming ? '#374151' : '#059669', color: '#fff', border: 'none', cursor: 'pointer', fontSize: 12, fontWeight: 600 }}>
                      {streaming ? '📡 Streaming...' : '▶ Stream'}
                    </button>
                  )}
                  {streaming && (
                    <button onClick={() => handleCancelRun(selectedAgent)}
                      style={{ padding: '6px 12px', borderRadius: 6, background: '#dc2626', color: '#fff', border: 'none', cursor: 'pointer', fontSize: 12, fontWeight: 600 }}>
                      ⏹ Cancel
                    </button>
                  )}
                  <button onClick={() => handleDelete(selectedAgent)}
                    style={{ padding: '6px 12px', borderRadius: 6, background: 'rgba(239,68,68,0.15)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.3)', cursor: 'pointer', fontSize: 12, fontWeight: 600 }}>
                    🗑️
                  </button>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12 }}>
                <InfoCard label="Status" value={selectedAgent.status} color={statusColor(selectedAgent.status)} />
                <InfoCard label="Branch" value={selectedAgent.branchName || '-'} />
                <InfoCard label="Repo" value={selectedAgent.repos?.[0]?.url?.replace('https://github.com/', '') || '-'} />
                <InfoCard label="Latest Run" value={selectedAgent.latestRunId?.slice(0, 16) || 'None'} />
              </div>

              {selectedAgent.url && (
                <a href={selectedAgent.url} target="_blank" rel="noopener noreferrer"
                  style={{ display: 'inline-block', marginTop: 12, fontSize: 12, color: '#8b5cf6', textDecoration: 'underline' }}>
                  View on Cursor →
                </a>
              )}
            </div>

            {/* Follow-up Prompt */}
            <div style={{ display: 'flex', gap: 8 }}>
              <input placeholder="Send follow-up prompt..." value={followUpPrompt}
                onChange={e => setFollowUpPrompt(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleFollowUp()}
                style={{ flex: 1, padding: '10px 14px', borderRadius: 8, background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-glass)', color: 'var(--text)', fontSize: 13, outline: 'none' }} />
              <button onClick={handleFollowUp} disabled={!followUpPrompt.trim()}
                style={{ padding: '10px 20px', borderRadius: 8, background: 'var(--accent)', color: '#000', fontWeight: 700, border: 'none', cursor: 'pointer', fontSize: 13, whiteSpace: 'nowrap' }}>
                Send ↗
              </button>
            </div>

            {/* Stream Output */}
            <div ref={outputRef}
              style={{ flex: 1, minHeight: 300, maxHeight: 'calc(100vh - 420px)', overflowY: 'auto', padding: 16, borderRadius: 12, background: '#0a0a0f', border: '1px solid var(--border-glass)', fontFamily: '"Berkeley Mono", "JetBrains Mono", "Fira Code", monospace', fontSize: 12, lineHeight: 1.6 }}>
              {streamEvents.length === 0 ? (
                <div style={{ color: '#4b5563', textAlign: 'center', paddingTop: 40 }}>
                  {streaming ? '📡 Waiting for events...' : 'Stream output will appear here. Click ▶ Stream to watch a run.'}
                </div>
              ) : streamEvents.map((ev, i) => (
                <div key={i} style={{ marginBottom: 4, display: 'flex', gap: 8 }}>
                  <span style={{ color: eventColor(ev.event), fontWeight: 600, minWidth: 80 }}>[{ev.event}]</span>
                  <span style={{ color: ev.event === 'assistant' ? '#e2e8f0' : ev.event === 'thinking' ? '#94a3b8' : '#6b7280' }}>
                    {ev.text || ev.status || ev.raw || JSON.stringify(ev)}
                  </span>
                </div>
              ))}
              {streaming && <span className="pulse" style={{ color: '#8b5cf6' }}>█</span>}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function InfoCard({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div style={{ padding: '8px 12px', borderRadius: 8, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
      <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 2 }}>{label}</div>
      <div style={{ fontSize: 13, fontWeight: 600, color: color || 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{value}</div>
    </div>
  );
}

function eventColor(e: string) {
  switch (e) {
    case 'status': return '#fbbf24';
    case 'assistant': return '#00ff88';
    case 'thinking': return '#8b5cf6';
    case 'tool_call': return '#06b6d4';
    case 'result': return '#22c55e';
    case 'done': return '#22c55e';
    case 'error': return '#ef4444';
    case 'heartbeat': return '#374151';
    default: return '#6b7280';
  }
}
