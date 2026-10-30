import React from 'react';
import { cn } from '../../utils/cn';

interface RiskGaugeProps {
  score: number; // 0 to 100
  title?: string;
  size?: number;
  label?: string;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score,
  title = 'Security Posture',
  size = 180,
  label,
}) => {
  const normalized = Math.min(100, Math.max(0, score));
  const strokeWidth = 14;
  const radius = (size - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  // Semi-circle or 260 degree arc
  const arcLength = circumference * 0.75;
  const strokeDashoffset = arcLength - (arcLength * normalized) / 100;

  let color = '#007BA7'; // Cerulean Blue
  let statusText = 'HEALTHY';

  if (normalized < 60) {
    color = '#FF2D95'; // Neon Rose
    statusText = 'ELEVATED RISK';
  } else if (normalized < 80) {
    color = '#F59E0B'; // Amber
    statusText = 'MODERATE';
  }

  return (
    <div className="flex flex-col items-center justify-center relative">
      <svg width={size} height={size * 0.85} viewBox={`0 0 ${size} ${size}`}>
        {/* Background Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#1E293B"
          strokeWidth={strokeWidth}
          strokeDasharray={`${arcLength} ${circumference}`}
          strokeLinecap="round"
          transform={`rotate(135 ${size / 2} ${size / 2})`}
        />

        {/* Dynamic Score Value Arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={`${arcLength} ${circumference}`}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          transform={`rotate(135 ${size / 2} ${size / 2})`}
          className="transition-all duration-1000 ease-out"
        />
      </svg>

      {/* Center Value */}
      <div className="absolute top-[32%] flex flex-col items-center justify-center">
        <span className="text-3xl font-extrabold font-mono tracking-tight" style={{ color }}>
          {normalized}
        </span>
        <span className="text-[10px] uppercase font-mono tracking-wider text-[#94A3B8]">
          {label || '/ 100'}
        </span>
      </div>

      <div className="text-center mt-[-10px]">
        <p className="text-xs font-semibold text-[#F8FAFC]">{title}</p>
        <p
          className={cn(
            'text-[10px] font-mono font-bold tracking-widest uppercase mt-0.5',
            normalized < 60 ? 'text-[#FF2D95]' : normalized < 80 ? 'text-amber-400' : 'text-[#007BA7]'
          )}
        >
          {statusText}
        </p>
      </div>
    </div>
  );
};
