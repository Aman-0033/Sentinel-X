import React from 'react';
import { cn } from '../../utils/cn';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, leftIcon, rightIcon, className, ...props }, ref) => {
    return (
      <div className="w-full">
        {label && (
          <label className="block text-xs font-medium text-[#94A3B8] mb-1.5 uppercase tracking-wider">
            {label}
          </label>
        )}
        <div className="relative flex items-center">
          {leftIcon && (
            <div className="absolute left-3 text-[#94A3B8] pointer-events-none flex items-center">
              {leftIcon}
            </div>
          )}
          <input
            ref={ref}
            className={cn(
              'w-full bg-[#0A0A0A] border border-[#1E293B] rounded-lg px-3.5 py-2 text-sm text-[#F8FAFC] placeholder-[#94A3B8]/50 focus:outline-none focus:border-[#007BA7] focus:ring-1 focus:ring-[#007BA7] transition-colors font-mono',
              leftIcon && 'pl-10',
              rightIcon && 'pr-10',
              error && 'border-[#FF2D95] focus:border-[#FF2D95] focus:ring-[#FF2D95]',
              className
            )}
            {...props}
          />
          {rightIcon && (
            <div className="absolute right-3 text-[#94A3B8] flex items-center">
              {rightIcon}
            </div>
          )}
        </div>
        {error && <p className="text-xs text-[#FF2D95] mt-1 font-mono">{error}</p>}
      </div>
    );
  }
);

Input.displayName = 'Input';

export interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  error?: string;
  options: Array<{ label: string; value: string }>;
}

export const Select = React.forwardRef<HTMLSelectElement, SelectProps>(
  ({ label, error, options, className, ...props }, ref) => {
    return (
      <div className="w-full">
        {label && (
          <label className="block text-xs font-medium text-[#94A3B8] mb-1.5 uppercase tracking-wider">
            {label}
          </label>
        )}
        <select
          ref={ref}
          className={cn(
            'w-full bg-[#0A0A0A] border border-[#1E293B] rounded-lg px-3.5 py-2 text-sm text-[#F8FAFC] focus:outline-none focus:border-[#007BA7] focus:ring-1 focus:ring-[#007BA7] transition-colors font-mono',
            error && 'border-[#FF2D95]',
            className
          )}
          {...props}
        >
          {options.map((opt) => (
            <option key={opt.value} value={opt.value} className="bg-[#121216] text-[#F8FAFC]">
              {opt.label}
            </option>
          ))}
        </select>
        {error && <p className="text-xs text-[#FF2D95] mt-1 font-mono">{error}</p>}
      </div>
    );
  }
);

Select.displayName = 'Select';
