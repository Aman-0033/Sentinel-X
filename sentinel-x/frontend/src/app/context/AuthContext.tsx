import React, { createContext, useContext, useEffect, useState } from 'react';
import { UserSummary, UserRole } from '../../types';
import { authService, authStorage } from '../../services/auth';
import { wsService } from '../../services/websocket';

interface AuthContextType {
  user: UserSummary | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  hasRole: (roles: UserRole[]) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserSummary | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Attempt silent refresh upon page load using HttpOnly refresh cookie
    const initAuth = async () => {
      try {
        const token = await authService.refresh();
        if (token) {
          const profile = await authService.getMe();
          if (profile) {
            setUser({
              id: profile.id,
              email: profile.email,
              name: profile.full_name,
              role: profile.role,
            });
            wsService.connect();
          }
        }
      } catch (err) {
        console.warn('Initial session restore skipped:', err);
      } finally {
        setIsLoading(false);
      }
    };

    initAuth();
  }, []);

  const login = async (email: string, password: string) => {
    setIsLoading(true);
    try {
      const resp = await authService.login(email, password);
      setUser(resp.user);
      wsService.connect();
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    setIsLoading(true);
    try {
      await authService.logout();
      setUser(null);
      wsService.disconnect();
    } finally {
      setIsLoading(false);
    }
  };

  const hasRole = (roles: UserRole[]): boolean => {
    if (!user) return false;
    return roles.includes(user.role);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user && authStorage.hasValidToken(),
        isLoading,
        login,
        logout,
        hasRole,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
