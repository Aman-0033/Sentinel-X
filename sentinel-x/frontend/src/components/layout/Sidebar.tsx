import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Activity,
  AlertOctagon,
  FolderLock,
  Network,
  Cpu,
  Search,
  Layers,
  FileText,
  ClipboardList,
  Settings,
  Shield,
} from 'lucide-react';
import { cn } from '../../utils/cn';
import { useTelemetry } from '../../app/context/TelemetryContext';

interface NavItem {
  label: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: number;
  hasPulse?: boolean;
}

export const Sidebar: React.FC<{ isOpen?: boolean }> = () => {
  const { activeThreatsCount, wsStatus } = useTelemetry();

  const navItems: NavItem[] = [
    { label: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
    {
      label: 'Live Monitoring',
      path: '/live-monitoring',
      icon: Activity,
      hasPulse: wsStatus === 'CONNECTED',
    },
    {
      label: 'Threat Detections',
      path: '/threats',
      icon: AlertOctagon,
      badge: activeThreatsCount > 0 ? activeThreatsCount : undefined,
    },
    { label: 'Incidents', path: '/incidents', icon: FolderLock },
    { label: 'Network Attack Map', path: '/network', icon: Network },
    { label: 'AI Explainability (XAI)', path: '/ai-analysis', icon: Cpu },
    { label: 'Threat Intelligence', path: '/threat-intelligence', icon: Search },
    { label: 'ML Model Registry', path: '/models', icon: Layers },
    { label: 'Security Reports', path: '/reports', icon: FileText },
    { label: 'Audit Trail', path: '/audit-logs', icon: ClipboardList },
    { label: 'System & RBAC Settings', path: '/settings', icon: Settings },
  ];

  return (
    <aside className="w-64 bg-[#121216] border-r border-[#1E293B] flex flex-col shrink-0 min-h-[calc(100vh-4rem)]">
      {/* Brand Header */}
      <div className="p-4 border-b border-[#1E293B] flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-[#007BA7]/20 border border-[#007BA7] flex items-center justify-center text-[#007BA7] shadow-glow-cerulean">
          <Shield className="w-5 h-5 text-[#007BA7]" />
        </div>
        <div>
          <h1 className="text-sm font-bold tracking-wider text-[#F8FAFC] flex items-center gap-1.5 font-mono">
            <span>SENTINEL-X</span>
            <span className="text-[10px] px-1 py-0.2 bg-[#FF2D95]/20 text-[#FF2D95] rounded border border-[#FF2D95]/30">
              v1.0
            </span>
          </h1>
          <p className="text-[10px] text-[#94A3B8] font-mono">AI INTRUSION DEFENSE</p>
        </div>
      </div>

      {/* Navigation Items */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <div className="text-[10px] font-mono uppercase text-[#94A3B8]/60 px-3 py-1 font-semibold tracking-wider">
          Operations Center
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                cn(
                  'flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all group select-none',
                  isActive
                    ? 'bg-[#007BA7] text-white shadow-glow-cerulean font-semibold'
                    : 'text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#181822]'
                )
              }
            >
              {({ isActive }) => (
                <>
                  <div className="flex items-center gap-3">
                    <Icon
                      className={cn(
                        'w-4 h-4 transition-colors',
                        isActive ? 'text-white' : 'text-[#94A3B8] group-hover:text-[#007BA7]'
                      )}
                    />
                    <span>{item.label}</span>
                  </div>

                  <div className="flex items-center gap-1.5">
                    {item.hasPulse && (
                      <span className="flex h-2 w-2 relative">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#007BA7] opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-2 w-2 bg-[#007BA7]"></span>
                      </span>
                    )}
                    {item.badge !== undefined && (
                      <span
                        className={cn(
                          'px-1.5 py-0.5 rounded text-[10px] font-mono font-bold',
                          isActive
                            ? 'bg-black/30 text-white'
                            : 'bg-[#FF2D95]/20 text-[#FF2D95] border border-[#FF2D95]/30'
                        )}
                      >
                        {item.badge}
                      </span>
                    )}
                  </div>
                </>
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* Bottom Status Box */}
      <div className="p-3 m-3 bg-[#0A0A0A] border border-[#1E293B] rounded-lg">
        <div className="flex items-center justify-between text-[11px] font-mono text-[#94A3B8]">
          <span>SOC ENGINE:</span>
          <span className="text-[#007BA7] font-semibold">ACTIVE</span>
        </div>
        <div className="flex items-center justify-between text-[11px] font-mono text-[#94A3B8] mt-1">
          <span>MODEL:</span>
          <span className="text-white truncate max-w-[100px]">XGBoost v1.2</span>
        </div>
      </div>
    </aside>
  );
};
