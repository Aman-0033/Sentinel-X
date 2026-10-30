import React from 'react';
import { SeverityLevel } from '../../types';
import { getSeverityColor } from '../../utils/formatters';
import { cn } from '../../utils/cn';

interface BadgeProps {
  severity?: SeverityLevel | string;
  variant?: 'solid' | 'subtle' | 'outline';
  children: React.ReactNode;
  className?: string;
  showDot?: boolean;
}

export const Badge: React.FC<BadgeProps> = ({
  severity = 'BENIGN',
  variant = 'subtle',
  children,
  className,
  showDot = false,
}) => {
  const colors = getSeverityColor(severity);

  let variantStyles = `${colors.badgeBg} ${colors.badgeText} border ${colors.badgeBorder}`;
  if (variant === 'solid') {
    if (severity === 'CRITICAL') {
      variantStyles = 'bg-[#FF2D95] text-white shadow-glow-rose font-semibold';
    } else if (severity === 'HIGH') {
      variantStyles = 'bg-rose-600 text-white font-semibold';
    } else {
      variantStyles = 'bg-[#007BA7] text-white font-semibold';
    }
  }

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono tracking-wide uppercase',
        variantStyles,
        className
      )}
    >
      {showDot && (
        <span
          className={cn(
            'w-1.5 h-1.5 rounded-full',
            colors.dotColor,
            severity === 'CRITICAL' && 'animate-ping'
          )}
        />
      )}
      {children}
    </span>
  );
};
