import { Radar, RadarChart, PolarGrid, PolarAngleAxis, ResponsiveContainer, Tooltip, PolarRadiusAxis } from 'recharts';

interface OwaspCategory {
  code: string;
  id: string;
  title: string;
  count: number;
  severity_max: string;
}

interface Props {
  categories: OwaspCategory[];
}

export default function OwaspRadar({ categories }: Props) {
  if (!categories || categories.length === 0) return null;
  const data = categories.map(c => ({
    code: c.code,
    fullName: `${c.id} ${c.title}`,
    findings: c.count,
  }));
  return (
    <ResponsiveContainer width="100%" height={300}>
      <RadarChart data={data} margin={{ top: 10, right: 24, bottom: 10, left: 24 }}>
        <PolarGrid stroke="rgba(124,138,255,0.18)" />
        <PolarAngleAxis dataKey="code" tick={{ fill: '#98a3c4', fontSize: 11, fontWeight: 600 }} />
        <PolarRadiusAxis angle={90} domain={[0, 'auto']} tick={{ fill: '#5c6584', fontSize: 10 }} stroke="rgba(124,138,255,0.15)" />
        <Tooltip
          contentStyle={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-active)',
            borderRadius: 10, fontSize: 12,
          }}
          labelFormatter={(label) => {
            const cat = data.find(d => d.code === label);
            return cat ? cat.fullName : label;
          }}
        />
        <Radar
          name="Findings"
          dataKey="findings"
          stroke="#7c8aff"
          strokeWidth={2}
          fill="url(#radarGradient)"
          fillOpacity={0.55}
        />
        <defs>
          <radialGradient id="radarGradient">
            <stop offset="0%" stopColor="#7c8aff" stopOpacity={0.7} />
            <stop offset="100%" stopColor="#c084fc" stopOpacity={0.2} />
          </radialGradient>
        </defs>
      </RadarChart>
    </ResponsiveContainer>
  );
}
