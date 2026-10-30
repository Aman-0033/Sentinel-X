import React from 'react';
import { cn } from '../../utils/cn';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'danger' | 'secondary' | 'outline' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  isLoading?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({
  children,
  variant = 'primary',
  size = 'md',
  isLoading = false,
  leftIcon,
  rightIcon,
  className,
  disabled,
  ...props
}) => {
  const baseStyles =
    'inline-flex items-center justify-center font-medium transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-[#0A0A0A] disabled:opacity-50 disabled:cursor-not-allowed select-none rounded-lg';

  const sizeStyles = {
    sm: 'text-xs px-2.5 py-1.5 gap-1.5',
    md: 'text-sm px-4 py-2 gap-2',
    lg: 'text-base px-6 py-2.5 gap-2.5',
  };

  const variantStyles = {
    primary:
      'bg-[#007BA7] text-white hover:bg-[#006990] active:scale-[0.98] shadow-glow-cerulean focus:ring-[#007BA7]/50',
    danger:
      'bg-[#FF2D95] text-white hover:bg-[#e02682] active:scale-[0.98] shadow-glow-rose focus:ring-[#FF2D95]/50',
    secondary:
      'bg-[#121216] text-[#F8FAFC] border border-[#1E293B] hover:bg-[#181822] hover:border-[#007BA7]/40 active:scale-[0.98] focus:ring-[#1E293B]',
    outline:
      'bg-transparent text-[#007BA7] border border-[#007BA7] hover:bg-[#007BA7]/10 active:scale-[0.98] focus:ring-[#007BA7]/40',
    ghost:
      'bg-transparent text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#121216] active:scale-[0.98] focus:ring-[#1E293B]',
  };

  return (
    <button
      className={cn(baseStyles, sizeStyles[size], variantStyles[variant], className)}
      disabled={disabled || isLoading}
      {...props}
    >
      {isLoading ? (
        <span className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
      ) : (
        leftIcon
      )}
      {children}
      {!isLoading && rightIcon}
    </button>
  );
};
