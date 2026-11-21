import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { api, getStoredToken, setStoredToken, setUnauthorizedHandler } from '../lib/api';
import { hasAnyPerm, hasPerm } from '../lib/permissions';
import type { DemoAccount, HealthResponse, User } from '../types/api';

interface AuthContextValue {
  user: User | null;
  token: string | null;
  loading: boolean;
  health: HealthResponse | null;
  demoAccounts: DemoAccount[];
  login: (username: string, password: string) => Promise<User>;
  logout: () => void;
  refreshMe: () => Promise<void>;
  can: (perm: string) => boolean;
  canAny: (perms: string[]) => boolean;
}

const AuthContext = createContext<AuthContextValue>({
  user: null,
  token: null,
  loading: true,
  health: null,
  demoAccounts: [],
  login: async () => {
    throw new Error('AuthProvider not mounted');
  },
  logout: () => {},
  refreshMe: async () => {},
  can: () => false,
  canAny: () => false,
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(() => getStoredToken());
  const [loading, setLoading] = useState<boolean>(true);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [demoAccounts, setDemoAccounts] = useState<DemoAccount[]>([]);

  const logout = useCallback(() => {
    setStoredToken(null);
    setToken(null);
    setUser(null);
  }, []);

  const refreshMe = useCallback(async () => {
    const current = getStoredToken();
    if (!current) {
      setUser(null);
      return;
    }
    const me = await api.me();
    setUser(me);
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(logout);
    return () => setUnauthorizedHandler(null);
  }, [logout]);

  useEffect(() => {
    let active = true;
    async function init() {
      try {
        const [h, demos] = await Promise.allSettled([api.health(), api.demoAccounts()]);
        if (!active) return;
        if (h.status === 'fulfilled') setHealth(h.value);
        if (demos.status === 'fulfilled') setDemoAccounts(demos.value);

        const existing = getStoredToken();
        if (existing) {
          try {
            const me = await api.me();
            if (active) {
              setToken(existing);
              setUser(me);
            }
          } catch {
            if (active) {
              setStoredToken(null);
              setToken(null);
              setUser(null);
            }
          }
        }
      } finally {
        if (active) setLoading(false);
      }
    }
    init();
    return () => {
      active = false;
    };
  }, []);

  const login = useCallback(async (username: string, password: string): Promise<User> => {
    const res = await api.login(username, password);
    setStoredToken(res.token);
    setToken(res.token);
    try {
      const me = await api.me();
      setUser(me);
      return me;
    } catch {
      setUser(res.user);
      return res.user;
    }
  }, []);

  const can = useCallback((perm: string) => hasPerm(user, perm), [user]);
  const canAny = useCallback((perms: string[]) => hasAnyPerm(user, perms), [user]);

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        loading,
        health,
        demoAccounts,
        login,
        logout,
        refreshMe,
        can,
        canAny,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
