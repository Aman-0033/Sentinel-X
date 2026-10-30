import { SeverityLevel } from '../types';

export function formatDate(isoString?: string | null): string {
  if (!isoString) return '—';
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    return d.toLocaleString('en-US', {
      month: 'short',
      day: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch {
    return isoString;
  }
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export function formatNumber(val: number): string {
  return new Intl.NumberFormat('en-US').format(val);
}

export function getSeverityColor(severity: SeverityLevel | string): {
  badgeBg: string;
  badgeText: string;
  badgeBorder: string;
  dotColor: string;
} {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL':
      return {
        badgeBg: 'bg-[#FF2D95]/15',
        badgeText: 'text-[#FF2D95]',
        badgeBorder: 'border-[#FF2D95]/40',
        dotColor: 'bg-[#FF2D95]',
      };
    case 'HIGH':
      return {
        badgeBg: 'bg-rose-500/15',
        badgeText: 'text-rose-400',
        badgeBorder: 'border-rose-500/40',
        dotColor: 'bg-rose-400',
      };
    case 'MEDIUM':
      return {
        badgeBg: 'bg-amber-500/15',
        badgeText: 'text-amber-400',
        badgeBorder: 'border-amber-500/40',
        dotColor: 'bg-amber-400',
      };
    case 'LOW':
      return {
        badgeBg: 'bg-blue-500/15',
        badgeText: 'text-blue-400',
        badgeBorder: 'border-blue-500/40',
        dotColor: 'bg-blue-400',
      };
    case 'BENIGN':
    default:
      return {
        badgeBg: 'bg-emerald-500/15',
        badgeText: 'text-emerald-400',
        badgeBorder: 'border-emerald-500/40',
        dotColor: 'bg-emerald-400',
      };
  }
}

export function getRiskScoreColor(score: number): string {
  if (score >= 90) return 'text-[#FF2D95]';
  if (score >= 70) return 'text-rose-400';
  if (score >= 40) return 'text-amber-400';
  if (score >= 20) return 'text-blue-400';
  return 'text-emerald-400';
}
