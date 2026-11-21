import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowRight, KeyRound, Lock, Shield, UserCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import { getRoleBadgeClasses } from '../lib/permissions';

import type { DemoAccount } from '../types/api';

const FALLBACK_DEMOS: DemoAccount[] = [
  {
    username: 'admin',
    password: 'Admin123!',
    role_slug: 'admin',
    role_name: 'Administracja',
    description: 'Pełne uprawnienia (*), RBAC, rotacja klucza AES-256-GCM, DefectDojo, Audit Log',
  },
  {
    username: 'operator',
    password: 'Operator123!',
    role_slug: 'operator',
    role_name: 'Dodawanie, usuwanie, modyfikacja',
    description: 'Uruchamianie skanów, import/eksport, edycja/usuwanie zasobów i DefectDojo push',
  },
  {
    username: 'analyst',
    password: 'Analyst123!',
    role_slug: 'analyst',
    role_name: 'Modyfikacja i odczyt',
    description: 'Edycja nadpisań (Overrides), sygnatury i notatki skanów bez usuwania/admina',
  },
  {
    username: 'viewer',
    password: 'Viewer123!',
    role_slug: 'viewer',
    role_name: 'Odczyt',
    description: 'Tylko podgląd Dashboardu, grafu, zasobów, diffów oraz eksport (403 na zapis)',
  },
];

export function LoginPage() {
  const { login, demoAccounts, health } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const accounts = demoAccounts.length > 0 ? demoAccounts : FALLBACK_DEMOS;

  const performLogin = async (u: string, p: string, label?: string) => {
    setError(null);
    setSubmitting(true);
    try {
      await login(u, p);
      toast.success('Zalogowano do AegisASI', label ? `Rola: ${label}` : `Użytkownik: ${u}`);
      navigate('/');
    } catch (err) {
      setError((err as Error).message || 'Nieprawidłowe dane logowania');
    } finally {
      setSubmitting(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) return;
    performLogin(username.trim(), password);
  };

  return (
    <div className="min-h-screen bg-bg-primary soc-grid-bg flex items-center justify-center p-4">
      <div className="w-full max-w-4xl grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Left: Login Form */}
        <div className="lg:col-span-5 rounded-2xl border border-border-subtle bg-bg-card/95 backdrop-blur-md p-7 shadow-2xl flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-3 mb-6">
              <div className="h-11 w-11 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/25">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold tracking-tight text-text-primary flex items-center gap-2">
                  AegisASI
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">
                    CBI AGH
                  </span>
                </h1>
                <p className="text-xs text-text-muted">Attack Surface Intelligence Platform</p>
              </div>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-text-secondary mb-1.5">
                  Nazwa użytkownika
                </label>
                <input
                  type="text"
                  autoComplete="username"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="np. admin"
                  className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3.5 py-2.5 text-sm text-text-primary focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-text-secondary mb-1.5">
                  Hasło
                </label>
                <input
                  type="password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3.5 py-2.5 text-sm text-text-primary focus:outline-none focus:border-cyan-500"
                />
              </div>

              {error && (
                <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={submitting}
                className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-sm py-2.5 transition-all shadow-lg shadow-cyan-500/20 disabled:opacity-50"
              >
                <KeyRound className="h-4 w-4" />
                {submitting ? 'Uwierzytelnianie...' : 'Zaloguj się'}
              </button>
            </form>
          </div>

          <div className="mt-6 pt-4 border-t border-border-subtle flex items-center justify-between text-[11px] text-text-muted">
            <span className="flex items-center gap-1.5">
              <Lock className="h-3.5 w-3.5 text-emerald-400" />
              AES-256-GCM Encryption At Rest
            </span>
            <span className="font-mono">{health?.version || 'v1.0'}</span>
          </div>
        </div>

        {/* Right: Quick Demo Role Switcher */}
        <div className="lg:col-span-7 rounded-2xl border border-border-subtle bg-bg-card/90 backdrop-blur-md p-7 shadow-2xl flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold uppercase tracking-wider mb-1.5">
              <UserCheck className="h-4 w-4" />
              Szybki Test RBAC (Konta Demo)
            </div>
            <h2 className="text-lg font-bold text-text-primary">
              Zaloguj jednym kliknięciem jako dowolna rola
            </h2>
            <p className="text-xs text-text-muted mt-1 mb-5">
              Każde konto prezentuje egzekwowanie uprawnień zarówno w interfejsie UI, jak i na
              poziomie API (<span className="font-mono">403 Forbidden</span> + wpis w Audit Log).
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {accounts.map((acc) => {
                const slug = acc.role_slug || acc.role || acc.username;
                const roleLabel = acc.role_name || acc.label || slug;
                return (
                  <button
                    key={acc.username}
                    type="button"
                    disabled={submitting}
                    onClick={() => performLogin(acc.username, acc.password, roleLabel)}
                    className="group text-left rounded-xl border border-border-subtle bg-bg-elevated/80 hover:bg-bg-hover hover:border-cyan-500/40 p-4 transition-all flex flex-col justify-between gap-3 disabled:opacity-50"
                  >
                    <div>
                      <div className="flex items-center justify-between gap-2 mb-2">
                        <span
                          className={`text-[11px] font-semibold px-2 py-0.5 rounded border ${getRoleBadgeClasses(
                            slug
                          )}`}
                        >
                          {roleLabel}
                        </span>
                        <ArrowRight className="h-4 w-4 text-text-muted group-hover:text-cyan-400 group-hover:translate-x-0.5 transition-all" />
                      </div>
                      <p className="text-xs text-text-muted leading-relaxed">
                        {acc.description || `Konto testowe roli ${roleLabel}`}
                      </p>
                    </div>
                    <div className="font-mono text-[11px] text-text-secondary bg-bg-card/80 rounded px-2 py-1 border border-border-subtle">
                      {acc.username} / {acc.password}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="mt-5 pt-4 border-t border-border-subtle text-[11px] text-text-muted">
            Centrum Bezpieczeństwa Informacji AGH · Continuous Discovery, Evidence-First
            Fingerprinting & DefectDojo v2 Integration
          </div>
        </div>
      </div>
    </div>
  );
}
