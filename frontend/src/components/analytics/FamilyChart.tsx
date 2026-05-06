import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Cell } from 'recharts';

interface Props {
  data: Array<{ family: string; count: number }>;
}

const PALETTE = ['#6366f1', '#06b6d4', '#10b981', '#f59e0b', '#ef4444', '#a855f7', '#eab308'];

export default function FamilyChart({ data }: Props) {
  if (!data || data.length === 0) {
    return <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 24 }}>No families to plot.</div>;
  }
  const top = data.slice(0, 8);
  return (
    <ResponsiveContainer width="100%" height={Math.max(220, top.length * 40)}>
      <BarChart data={top} layout="vertical" margin={{ left: 4, right: 24, top: 8, bottom: 8 }}>
        <XAxis type="number" hide />
        <YAxis
          type="category"
          dataKey="family"
          width={170}
          tick={{ fontSize: 12, fill: '#8b95a8' }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip
          cursor={{ fill: 'rgba(99,102,241,0.06)' }}
          contentStyle={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-active)',
            borderRadius: 8,
            fontSize: 12,
          }}
        />
        <Bar dataKey="count" radius={[0, 6, 6, 0]} barSize={18}>
          {top.map((_, i) => (
            <Cell key={i} fill={PALETTE[i % PALETTE.length]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
