import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { TelemetryProvider } from './context/TelemetryContext';
import { ErrorBoundary } from '../components/ui/ErrorBoundary';

export const AppProviders: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <AuthProvider>
          <TelemetryProvider>
            {children}
          </TelemetryProvider>
        </AuthProvider>
      </BrowserRouter>
    </ErrorBoundary>
  );
};

