import React from 'react';
import { cn } from '../../utils/cn';

export const Spinner: React.FC<{ size?: 'sm' | 'md' | 'lg'; className?: string }> = ({
  size = 'md',
  className,
}) => {
  const sizeMap = {
    sm: 'w-4 h-4 border-2',
    md: 'w-8 h-8 border-3',
    lg: 'w-12 h-12 border-4',
  };

  return (
    <div
      className={cn(
        'rounded-full border-[#007BA7]/20 border-t-[#007BA7] animate-spin',
        sizeMap[size],
        className
      )}
    />
  );
};
