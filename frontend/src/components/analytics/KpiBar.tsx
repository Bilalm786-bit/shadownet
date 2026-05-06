import { ReactNode } from 'react';

interface Kpi {
  label: string;
  value: ReactNode;
  meta?: ReactNode;
  color?: string;
}

interface Props {
  kpis: Kpi[];
}

export default function KpiBar({ kpis }: Props) {
  return (
    <div className="kpi-bar">
      {kpis.map((k, i) => (
        <div key={i} className="kpi-cell">
          <div className="kpi-cell-label">{k.label}</div>
          <div className="kpi-cell-value" style={{ color: k.color }}>{k.value}</div>
          {k.meta && <div className="kpi-cell-meta">{k.meta}</div>}
        </div>
      ))}
    </div>
  );
}
