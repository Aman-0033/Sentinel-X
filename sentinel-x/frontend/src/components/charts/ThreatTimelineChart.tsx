import React from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { TrendPoint } from '../../types';

interface ThreatTimelineChartProps {
  data: TrendPoint[];
  height?: number;
}

export const ThreatTimelineChart: React.FC<ThreatTimelineChartProps> = ({
  data,
  height = 260,
}) => {
  // Format data for chart display
  const chartData = data.map((d) => ({
    time: d.timestamp,
    threats: d.count,
    isCritical: d.severity === 'CRITICAL' || d.severity === 'HIGH',
    attackType: d.attack_type,
  }));

  return (
    <div style={{ width: '100%', height }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>
            {/* Cerulean Blue gradient for baseline normal traffic */}
            <linearGradient id="ceruleanGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#007BA7" stopOpacity={0.5} />
              <stop offset="95%" stopColor="#007BA7" stopOpacity={0.0} />
            </linearGradient>
            {/* Neon Rose gradient for threat spike highlights */}
            <linearGradient id="roseGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#FF2D95" stopOpacity={0.6} />
              <stop offset="95%" stopColor="#FF2D95" stopOpacity={0.0} />
            </linearGradient>
          </defs>

          <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />

          <XAxis
            dataKey="time"
            stroke="#94A3B8"
            tick={{ fill: '#94A3B8', fontSize: 11, fontFamily: 'monospace' }}
            tickLine={false}
          />
          <YAxis
            stroke="#94A3B8"
            tick={{ fill: '#94A3B8', fontSize: 11, fontFamily: 'monospace' }}
            tickLine={false}
          />

          <Tooltip
            content={({ active, payload }) => {
              if (active && payload && payload.length) {
                const item = payload[0].payload;
                return (
                  <div className="bg-[#121216] border border-[#1E293B] p-3 rounded-lg shadow-xl text-xs font-mono">
                    <p className="text-[#94A3B8]">{item.time}</p>
                    <p className="font-semibold text-white mt-1">
                      Event Count:{' '}
                      <span className={item.isCritical ? 'text-[#FF2D95]' : 'text-[#007BA7]'}>
                        {item.threats}
                      </span>
                    </p>
                    <p className="text-gray-400 mt-0.5">
                      Classifier: <strong className="text-gray-200">{item.attackType}</strong>
                    </p>
                  </div>
                );
              }
              return null;
            }}
          />

          <Area
            type="monotone"
            dataKey="threats"
            stroke="#007BA7"
            strokeWidth={2}
            fillOpacity={1}
            fill="url(#ceruleanGradient)"
            dot={(props: any) => {
              const { cx, cy, payload } = props;
              if (payload.isCritical && payload.threats > 40) {
                return (
                  <circle
                    key={`dot-${cx}-${cy}`}
                    cx={cx}
                    cy={cy}
                    r={5}
                    fill="#FF2D95"
                    stroke="#121216"
                    strokeWidth={2}
                    className="animate-pulse"
                  />
                );
              }
              return (
                <circle
                  key={`dot-${cx}-${cy}`}
                  cx={cx}
                  cy={cy}
                  r={3}
                  fill="#007BA7"
                  stroke="#121216"
                  strokeWidth={1}
                />
              );
            }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};
