import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
  ReferenceLine,
} from 'recharts';

interface ShapBarChartProps {
  features: Array<{ feature: string; impact: number }>;
  height?: number;
}

export const ShapBarChart: React.FC<ShapBarChartProps> = ({
  features,
  height = 240,
}) => {
  // Sort descending by magnitude of impact
  const sorted = [...features].sort((a, b) => Math.abs(b.impact) - Math.abs(a.impact));

  return (
    <div style={{ width: '100%', height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          layout="vertical"
          data={sorted}
          margin={{ top: 10, right: 20, left: 40, bottom: 5 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" horizontal={false} />
          <XAxis
            type="number"
            stroke="#94A3B8"
            tick={{ fill: '#94A3B8', fontSize: 11, fontFamily: 'monospace' }}
            tickLine={false}
          />
          <YAxis
            type="category"
            dataKey="feature"
            stroke="#94A3B8"
            tick={{ fill: '#F8FAFC', fontSize: 11, fontFamily: 'monospace' }}
            tickLine={false}
            width={140}
          />
          <ReferenceLine x={0} stroke="#475569" strokeWidth={1.5} />
          <Tooltip
            content={({ active, payload }) => {
              if (active && payload && payload.length) {
                const item = payload[0].payload as { feature: string; impact: number };
                const isMaliciousPush = item.impact > 0;
                return (
                  <div className="bg-[#121216] border border-[#1E293B] p-2.5 rounded-lg shadow-xl text-xs font-mono">
                    <p className="font-semibold text-white">{item.feature}</p>
                    <p className="mt-1">
                      SHAP Contribution:{' '}
                      <strong className={isMaliciousPush ? 'text-[#FF2D95]' : 'text-[#007BA7]'}>
                        {item.impact > 0 ? `+${item.impact.toFixed(3)}` : item.impact.toFixed(3)}
                      </strong>
                    </p>
                    <p className="text-[#94A3B8] text-[10px] mt-0.5">
                      {isMaliciousPush
                        ? 'Pushes prediction toward MALICIOUS attack'
                        : 'Pushes prediction toward BENIGN traffic'}
                    </p>
                  </div>
                );
              }
              return null;
            }}
          />
          <Bar dataKey="impact" radius={[0, 4, 4, 0]}>
            {sorted.map((entry, index) => (
              <Cell
                key={`shap-bar-${index}`}
                // Strict theme: Neon Rose #FF2D95 for malicious push, Cerulean Blue #007BA7 for benign
                fill={entry.impact > 0 ? '#FF2D95' : '#007BA7'}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};
