import React from 'react';
import { AlertTriangle, X, ShieldAlert, ArrowRight } from 'lucide-react';
import { DetectionItem } from '../../types';
import { Link } from 'react-router-dom';

interface AlertBannerProps {
  alert: DetectionItem | null;
  onDismiss: () => void;
}

export const AlertBanner: React.FC<AlertBannerProps> = ({ alert, onDismiss }) => {
  if (!alert) return null;

  return (
    <div className="relative bg-[#FF2D95]/15 border-b border-[#FF2D95]/40 text-[#F8FAFC] px-4 py-2.5 flex items-center justify-between shadow-glow-rose z-50">
      <div className="flex items-center gap-3 overflow-hidden">
        <span className="flex h-3 w-3 relative">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#FF2D95] opacity-75"></span>
          <span className="relative inline-flex rounded-full h-3 w-3 bg-[#FF2D95]"></span>
        </span>
        <div className="flex items-center gap-2 text-xs font-mono">
          <ShieldAlert className="w-4 h-4 text-[#FF2D95] shrink-0" />
          <span className="font-bold text-[#FF2D95] uppercase">
            LIVE CRITICAL INTRUSION DETECTED:
          </span>
          <span className="font-semibold text-white truncate">
            {alert.attack_type} attack from {alert.flow?.source_ip || 'Unknown IP'} targeting {alert.flow?.destination_ip || 'Internal'}
          </span>
          <span className="text-[#94A3B8] hidden md:inline">
            (Risk Score: <strong className="text-[#FF2D95]">{alert.risk_score}</strong> | Confidence: {(alert.confidence * 100).toFixed(1)}%)
          </span>
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0 ml-4">
        <Link
          to={`/threats/${alert.id}`}
          className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium bg-[#FF2D95] text-white rounded hover:bg-[#e02682] transition-colors"
        >
          <span>Triage</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </Link>
        <button
          onClick={onDismiss}
          className="text-[#94A3B8] hover:text-white p-1 rounded transition-colors"
          title="Dismiss Alert"
        >
          <X className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};
