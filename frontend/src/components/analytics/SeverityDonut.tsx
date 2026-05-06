import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

const COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f59e0b',
  medium: '#06b6d4',
  low: '#10b981',
  info: '#6366f1',
};

interface Props {
  data: Record<string, number>;
  size?: number;
}

export default function SeverityDonut({ data, size = 220 }: Props) {
  const total = Object.values(data).reduce((a, b) => a + b, 0);
  const chartData = Object.entries(data)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({ name: k, value: v }));

  if (total === 0) {
    return (
      <div style={{ height: size, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', flexDirection: 'column' }}>
        <div style={{ fontSize: 32, marginBottom: 8 }}>✓</div>
        <div style={{ fontSize: 13 }}>No findings</div>
      </div>
    );
  }

  return (
    <div style={{ position: 'relative', width: '100%', height: size }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            innerRadius={size * 0.28}
            outerRadius={size * 0.42}
            paddingAngle={2}
            dataKey="value"
            stroke="none"
          >
            {chartData.map((entry) => (
              <Cell key={entry.name} fill={COLORS[entry.name] || '#6366f1'} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-active)',
              borderRadius: 8,
              fontSize: 12,
              textTransform: 'capitalize',
            }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div
        style={{
          position: 'absolute',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          textAlign: 'center',
          pointerEvents: 'none',
        }}
      >
        <div style={{ fontSize: 32, fontWeight: 800, lineHeight: 1 }}>{total}</div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, letterSpacing: 0.5 }}>
          FINDINGS
        </div>
      </div>
    </div>
  );
}
