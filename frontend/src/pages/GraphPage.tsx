import { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { graphAPI } from '../api/client';
import { HiOutlineArrowLeft } from 'react-icons/hi';

interface GNode { id: string; label: string; entity_type: string; }
interface GEdge { id: string; source: string; target: string; relationship: string; }

const TYPE_COLORS: Record<string, string> = {
  Email: '#6366f1', Username: '#06b6d4', Domain: '#10b981', IP: '#f59e0b',
  Phone: '#a855f7', Person: '#ef4444', Organization: '#ec4899', URL: '#14b8a6',
  Case: '#3b82f6', Entity: '#64748b',
};

export default function GraphPage() {
  const { caseId } = useParams<{ caseId: string }>();
  const navigate = useNavigate();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [nodes, setNodes] = useState<GNode[]>([]);
  const [edges, setEdges] = useState<GEdge[]>([]);
  const [positions, setPositions] = useState<Record<string, { x: number; y: number }>>({});
  const [error, setError] = useState('');

  useEffect(() => {
    if (!caseId) return;
    graphAPI.caseGraph(caseId).then(r => {
      const n = r.data.nodes || [];
      const e = r.data.edges || [];
      setNodes(n); setEdges(e);
      if (r.data.error) setError(r.data.error);
      // Simple force layout
      const pos: Record<string, { x: number; y: number }> = {};
      n.forEach((node: GNode, i: number) => {
        const angle = (2 * Math.PI * i) / n.length;
        const radius = Math.min(300, 80 + n.length * 20);
        pos[node.id] = { x: 400 + radius * Math.cos(angle), y: 300 + radius * Math.sin(angle) };
      });
      setPositions(pos);
    }).catch(() => setError('Failed to load graph data'));
  }, [caseId]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || nodes.length === 0) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    canvas.width = canvas.offsetWidth; canvas.height = canvas.offsetHeight;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw edges
    edges.forEach(edge => {
      const from = positions[edge.source]; const to = positions[edge.target];
      if (!from || !to) return;
      ctx.beginPath(); ctx.moveTo(from.x, from.y); ctx.lineTo(to.x, to.y);
      ctx.strokeStyle = 'rgba(99,102,241,0.3)'; ctx.lineWidth = 1.5; ctx.stroke();
      // Label
      ctx.fillStyle = '#64748b'; ctx.font = '10px Inter';
      ctx.fillText(edge.relationship, (from.x + to.x) / 2, (from.y + to.y) / 2 - 5);
    });

    // Draw nodes
    nodes.forEach(node => {
      const pos = positions[node.id];
      if (!pos) return;
      const color = TYPE_COLORS[node.entity_type] || '#64748b';
      // Glow
      ctx.beginPath(); ctx.arc(pos.x, pos.y, 24, 0, Math.PI * 2);
      ctx.fillStyle = color + '33'; ctx.fill();
      // Circle
      ctx.beginPath(); ctx.arc(pos.x, pos.y, 16, 0, Math.PI * 2);
      ctx.fillStyle = color; ctx.fill();
      ctx.strokeStyle = color + '88'; ctx.lineWidth = 2; ctx.stroke();
      // Label
      ctx.fillStyle = '#e2e8f0'; ctx.font = '12px Inter'; ctx.textAlign = 'center';
      ctx.fillText(node.label.slice(0, 20), pos.x, pos.y + 30);
      ctx.fillStyle = '#64748b'; ctx.font = '10px Inter';
      ctx.fillText(node.entity_type, pos.x, pos.y + 44);
    });
  }, [nodes, edges, positions]);

  return (
    <div className="fade-in" style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
        <button className="btn btn-ghost btn-sm" onClick={() => navigate(-1)}><HiOutlineArrowLeft /> Back</button>
        <h2 className="section-title">Entity Relationship Graph</h2>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {Object.entries(TYPE_COLORS).slice(0, 6).map(([type, color]) => (
            <span key={type} style={{ fontSize: 11, color, display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, display: 'inline-block' }} />{type}
            </span>
          ))}
        </div>
      </div>
      {error && <div className="card" style={{ padding: 16, marginBottom: 16, color: 'var(--orange)', fontSize: 13 }}>⚠ {error}</div>}
      <div className="card" style={{ flex: 1, padding: 0, overflow: 'hidden', minHeight: 400 }}>
        {nodes.length === 0 ? (
          <div className="empty-state" style={{ padding: 60 }}>
            <p>No graph data yet. Add targets and run scans to build the entity graph.</p>
          </div>
        ) : (
          <canvas ref={canvasRef} style={{ width: '100%', height: '100%', display: 'block' }} />
        )}
      </div>
    </div>
  );
}
