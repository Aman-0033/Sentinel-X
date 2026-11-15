import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw, LogIn, Bug } from 'lucide-react';

interface ErrorBoundaryProps {
  children: ReactNode;
  fallback?: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[Sentinel-X ErrorBoundary] Uncaught runtime exception caught:', error, errorInfo);
    this.setState({ error, errorInfo });
  }

  handleReload = () => {
    window.location.reload();
  };

  handleResetToLogin = () => {
    try {
      localStorage.clear();
      sessionStorage.clear();
    } catch {
      // Ignore storage clear errors
    }
    window.location.href = '/login';
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      const errorMessage = this.state.error?.message || 'An unexpected application runtime error occurred.';
      const componentStack = this.state.errorInfo?.componentStack || '';

      return (
        <div className="min-h-screen w-full bg-[#0A0A0A] text-[#F8FAFC] flex flex-col items-center justify-center p-6 cyber-grid selection:bg-[#007BA7] selection:text-white">
          {/* Ambient glow effects */}
          <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-96 h-96 bg-[#FF2D95]/10 rounded-full blur-3xl pointer-events-none" />
          <div className="absolute bottom-1/4 right-1/3 w-64 h-64 bg-[#007BA7]/10 rounded-full blur-3xl pointer-events-none" />

          <div className="w-full max-w-2xl bg-[#121216] border border-[#1E293B] rounded-2xl shadow-2xl p-8 relative z-10">
            {/* Header */}
            <div className="flex items-center gap-4 mb-6">
              <div className="w-12 h-12 rounded-xl bg-[#FF2D95]/15 border border-[#FF2D95]/40 text-[#FF2D95] flex items-center justify-center shadow-glow-rose shrink-0">
                <AlertTriangle className="w-6 h-6 text-[#FF2D95]" />
              </div>
              <div>
                <h1 className="text-xl font-bold font-mono tracking-tight text-[#F8FAFC]">
                  SENTINEL-X SOC RUNTIME ERROR
                </h1>
                <p className="text-xs text-[#94A3B8] font-mono mt-0.5">
                  The client-side application encountered an uncaught runtime exception.
                </p>
              </div>
            </div>

            {/* Error Message Box */}
            <div className="mb-6 p-4 bg-[#0A0A0A] border border-[#1E293B] rounded-lg">
              <div className="flex items-center gap-2 text-xs font-mono text-[#FF2D95] mb-2 font-semibold">
                <Bug className="w-4 h-4" />
                <span>Error Details</span>
              </div>
              <pre className="text-xs font-mono text-[#F8FAFC] whitespace-pre-wrap break-all bg-black/40 p-3 rounded border border-rose-950/40">
                {errorMessage}
              </pre>

              {componentStack && (
                <details className="mt-3">
                  <summary className="text-[11px] font-mono text-[#94A3B8] cursor-pointer hover:text-white transition-colors">
                    View Component Stack Trace
                  </summary>
                  <pre className="mt-2 text-[10px] font-mono text-[#94A3B8] max-h-48 overflow-y-auto bg-black/60 p-2.5 rounded border border-[#1E293B] whitespace-pre-wrap">
                    {componentStack}
                  </pre>
                </details>
              )}
            </div>

            {/* Recovery Action Buttons */}
            <div className="flex flex-wrap items-center gap-3 pt-4 border-t border-[#1E293B]">
              <button
                type="button"
                onClick={this.handleReload}
                className="flex items-center gap-2 px-4 py-2 bg-[#007BA7] hover:bg-[#007BA7]/80 text-white font-mono text-xs font-medium rounded-lg transition-colors shadow-glow-cerulean cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Reload Platform</span>
              </button>

              <button
                type="button"
                onClick={this.handleResetToLogin}
                className="flex items-center gap-2 px-4 py-2 bg-[#1E293B] hover:bg-[#2A3B52] text-[#F8FAFC] font-mono text-xs font-medium rounded-lg transition-colors cursor-pointer border border-[#334155]"
              >
                <LogIn className="w-3.5 h-3.5" />
                <span>Reset Session & Return to Login</span>
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
