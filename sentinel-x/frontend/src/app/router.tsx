import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './context/AuthContext';
import { AppLayout } from '../components/layout/AppLayout';
import { Spinner } from '../components/ui/Spinner';

// 14 Core Pages
import { Login } from '../pages/Login';
import { Dashboard } from '../pages/Dashboard';
import { LiveMonitoring } from '../pages/LiveMonitoring';
import { Threats } from '../pages/Threats';
import { ThreatDetail } from '../pages/ThreatDetail';
import { Incidents } from '../pages/Incidents';
import { IncidentDetail } from '../pages/IncidentDetail';
import { NetworkTopology } from '../pages/Network';
import { AIAnalysis } from '../pages/AIAnalysis';
import { ThreatIntelligence } from '../pages/ThreatIntelligence';
import { Models } from '../pages/Models';
import { Reports } from '../pages/Reports';
import { AuditLogs } from '../pages/AuditLogs';
import { Settings } from '../pages/Settings';

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#0A0A0A] flex flex-col items-center justify-center font-mono text-xs text-[#94A3B8]">
        <Spinner size="lg" className="mb-4" />
        <span>Authenticating Sentinel-X SOC Session...</span>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};

export const AppRouter: React.FC = () => {
  return (
    <Routes>
      {/* Public Login Route */}
      <Route path="/login" element={<Login />} />

      {/* Authenticated SOC Workspace Routes wrapped by AppLayout */}
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <AppLayout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="live-monitoring" element={<LiveMonitoring />} />
        <Route path="threats" element={<Threats />} />
        <Route path="threats/:id" element={<ThreatDetail />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="incidents/:id" element={<IncidentDetail />} />
        <Route path="network" element={<NetworkTopology />} />
        <Route path="ai-analysis" element={<AIAnalysis />} />
        <Route path="threat-intelligence" element={<ThreatIntelligence />} />
        <Route path="models" element={<Models />} />
        <Route path="reports" element={<Reports />} />
        <Route path="audit-logs" element={<AuditLogs />} />
        <Route path="settings" element={<Settings />} />
      </Route>

      {/* Catch-all route */}
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
};
