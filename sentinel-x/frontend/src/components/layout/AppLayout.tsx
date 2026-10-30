import React from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { TopNav } from './TopNav';
import { AlertBanner } from '../ui/AlertBanner';
import { useTelemetry } from '../../app/context/TelemetryContext';

export const AppLayout: React.FC = () => {
  const { activeCriticalAlert, dismissCriticalAlert } = useTelemetry();

  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#F8FAFC] flex flex-col font-sans">
      {/* Top Banner Alert on Critical Live Threat */}
      <AlertBanner alert={activeCriticalAlert} onDismiss={dismissCriticalAlert} />

      {/* Main App Top Telemetry Header */}
      <TopNav />

      {/* App Body (Sidebar + Content Workspace) */}
      <div className="flex-1 flex overflow-hidden">
        <Sidebar />

        <main className="flex-1 overflow-y-auto p-6 bg-[#0A0A0A] cyber-grid">
          <div className="max-w-7xl mx-auto space-y-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
};
