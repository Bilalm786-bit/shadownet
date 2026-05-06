interface Props {
  score: number;
  label?: string;
}

export default function RiskScoreCard({ score, label = 'Risk Score' }: Props) {
  const clamp = Math.max(0, Math.min(100, score || 0));
  const color =
    clamp >= 75 ? 'var(--red)' :
    clamp >= 50 ? 'var(--orange)' :
    clamp >= 25 ? 'var(--yellow)' : 'var(--green)';
  const grade =
    clamp >= 80 ? 'F' :
    clamp >= 65 ? 'D' :
    clamp >= 50 ? 'C' :
    clamp >= 30 ? 'B' :
    clamp >= 15 ? 'A' : 'A+';

  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (clamp / 100) * circumference;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: 12 }}>
      <div style={{ position: 'relative', width: 130, height: 130 }}>
        <svg viewBox="0 0 120 120" width="130" height="130">
          <defs>
            <linearGradient id="risk-grad" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0" stopColor={color} stopOpacity={0.4} />
              <stop offset="1" stopColor={color} stopOpacity={1} />
            </linearGradient>
          </defs>
          <circle cx="60" cy="60" r={radius} fill="none" stroke="rgba(99,102,241,0.08)" strokeWidth="8" />
          <circle
            cx="60" cy="60" r={radius}
            fill="none"
            stroke="url(#risk-grad)"
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            transform="rotate(-90 60 60)"
            style={{ transition: 'stroke-dashoffset 1.2s ease', filter: `drop-shadow(0 0 8px ${color})` }}
          />
        </svg>
        <div
          style={{
            position: 'absolute',
            top: '50%', left: '50%',
            transform: 'translate(-50%, -50%)',
            textAlign: 'center',
          }}
        >
          <div style={{ fontSize: 30, fontWeight: 800, color, lineHeight: 1 }}>{clamp}</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: 1 }}>/ 100</div>
        </div>
      </div>
      <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 8, textTransform: 'uppercase', letterSpacing: 1 }}>
        {label}
      </div>
      <div style={{ fontSize: 12, marginTop: 4, color }}>{grade} grade</div>
    </div>
  );
}
