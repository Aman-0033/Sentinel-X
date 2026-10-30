import React from 'react';
import { useAuth } from '../../app/context/AuthContext';
import { useTelemetry } from '../../app/context/TelemetryContext';
import { LogOut, User, Radio, Gauge } from 'lucide-react';
import { Badge } from '../ui/Badge';

export const TopNav: React.FC = () => {
  const { user, logout } = useAuth();
  const { wsStatus, packetRate, securityScore } = useTelemetry();

  return (
    <header className="h-16 bg-[#121216] border-b border-[#1E293B] px-6 flex items-center justify-between z-30 shrink-0">
      {/* Left: Telemetry Tickers */}
      <div className="flex items-center gap-6">
        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="flex h-2.5 w-2.5 relative">
            {wsStatus === 'CONNECTED' ? (
              <>
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#007BA7] opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-[#007BA7]"></span>
              </>
            ) : (
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-amber-500"></span>
            )}
          </span>
          <span className="text-[#94A3B8]">FEED:</span>
          <span
            className={
              wsStatus === 'CONNECTED'
                ? 'text-[#007BA7] font-bold uppercase'
                : 'text-amber-400 font-bold uppercase'
            }
          >
            {wsStatus}
          </span>
        </div>

        <div className="hidden md:flex items-center gap-2 font-mono text-xs border-l border-[#1E293B] pl-4">
          <Radio className="w-3.5 h-3.5 text-[#007BA7]" />
          <span className="text-[#94A3B8]">INGRESS:</span>
          <span className="text-[#F8FAFC] font-semibold">{packetRate.toLocaleString()} pkts/s</span>
        </div>

        <div className="hidden lg:flex items-center gap-2 font-mono text-xs border-l border-[#1E293B] pl-4">
          <Gauge className="w-3.5 h-3.5 text-[#007BA7]" />
          <span className="text-[#94A3B8]">DEFENSE SCORE:</span>
          <span
            className={
              securityScore >= 80
                ? 'text-[#007BA7] font-bold'
                : securityScore >= 60
                ? 'text-amber-400 font-bold'
                : 'text-[#FF2D95] font-bold'
            }
          >
            {securityScore}/100
          </span>
        </div>
      </div>

      {/* Right: User identity & Logout */}
      <div className="flex items-center gap-4">
        {user && (
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-full bg-[#007BA7]/20 border border-[#007BA7]/40 flex items-center justify-center text-[#007BA7]">
                <User className="w-4 h-4" />
              </div>
              <div className="hidden sm:block text-left">
                <div className="text-xs font-semibold text-[#F8FAFC]">{user.name}</div>
                <div className="text-[10px] text-[#94A3B8] font-mono">{user.email}</div>
              </div>
            </div>

            <Badge
              severity={
                user.role === 'ADMIN'
                  ? 'CRITICAL'
                  : user.role === 'ANALYST'
                  ? 'HIGH'
                  : 'LOW'
              }
              variant="subtle"
            >
              {user.role}
            </Badge>

            <button
              onClick={() => logout()}
              className="p-1.5 text-[#94A3B8] hover:text-[#FF2D95] hover:bg-[#1E293B] rounded-lg transition-colors ml-2"
              title="Terminate SOC Session"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
};
