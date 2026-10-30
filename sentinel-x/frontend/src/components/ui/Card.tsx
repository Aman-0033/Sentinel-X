import React from 'react';
import { cn } from '../../utils/cn';

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  glow?: 'cerulean' | 'rose' | 'none';
  interactive?: boolean;
}

export const Card: React.FC<CardProps> = ({
  children,
  className,
  glow = 'none',
  interactive = false,
  ...props
}) => {
  return (
    <div
      className={cn(
        'bg-[#121216] border border-[#1E293B] rounded-xl p-5 transition-all duration-200 shadow-soc-card',
        glow === 'cerulean' && 'border-[#007BA7]/50 shadow-glow-cerulean',
        glow === 'rose' && 'border-[#FF2D95]/50 shadow-glow-rose',
        interactive && 'hover:border-[#007BA7]/60 hover:bg-[#181822] cursor-pointer',
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
};

export const CardHeader: React.FC<{
  title: string | React.ReactNode;
  subtitle?: string | React.ReactNode;
  action?: React.ReactNode;
  icon?: React.ReactNode;
  className?: string;
}> = ({ title, subtitle, action, icon, className }) => {
  return (
    <div className={cn('flex items-start justify-between pb-4 border-b border-[#1E293B]/60 mb-4', className)}>
      <div className="flex items-center gap-2.5">
        {icon && <div className="text-[#007BA7]">{icon}</div>}
        <div>
          <h3 className="text-base font-semibold text-[#F8FAFC] tracking-tight">{title}</h3>
          {subtitle && <p className="text-xs text-[#94A3B8] mt-0.5">{subtitle}</p>}
        </div>
      </div>
      {action && <div>{action}</div>}
    </div>
  );
};
