import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { AttackDistributionItem } from '../../types';

interface AttackDistributionChartProps {
  data: AttackDistributionItem[];
  height?: number;
}

const COLORS = [
  '#FF2D95', // Neon Rose for top critical attacks
  '#007BA7', // Cerulean Blue
  '#F59E0B', // Amber
  '#8B5CF6', // Purple
  '#3B82F6', // Blue
  '#10B981', // Emerald
];

export const AttackDistributionChart: React.FC<AttackDistributionChartProps> = ({
  data,
  height = 240,
}) => {
  const total = data.reduce((sum, item) => sum + item.count, 0);

  return (
    <div style={{ width: '100%', height }} className="relative flex items-center justify-center">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={85}
            paddingAngle={4}
            dataKey="count"
            stroke="#121216"
            strokeWidth={2}
          >
            {data.map((entry, index) => (
              <Cell
                key={`cell-${entry.attack_type}-${index}`}
                fill={COLORS[index % COLORS.length]}
              />
            ))}
          </Pie>
          <Tooltip
            content={({ active, payload }) => {
              if (active && payload && payload.length) {
                const item = payload[0].payload as AttackDistributionItem;
                return (
                  <div className="bg-[#121216] border border-[#1E293B] p-2.5 rounded-lg shadow-xl text-xs font-mono">
                    <p className="font-semibold text-white">{item.attack_type}</p>
                    <p className="text-[#94A3B8] mt-1">
                      Count: <strong className="text-white">{item.count}</strong> ({item.percentage}%)
                    </p>
                  </div>
                );
              }
              return null;
            }}
          />
        </PieChart>
      </ResponsiveContainer>

      {/* Center Donut summary */}
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span className="text-xl font-bold font-mono text-[#F8FAFC]">{total}</span>
        <span className="text-[10px] text-[#94A3B8] uppercase tracking-wider">Threats</span>
      </div>
    </div>
  );
};
