import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { RiArrowRightLine, RiLockLine } from '@remixicon/react';
import { AghBadge, AghEmblem } from '@/components/AghLogo';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/context/ToastContext';
import { getRoleBadgeClasses } from '@/lib/permissions';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';
import { Field, Notice } from '@/components/common';
import type { DemoAccount } from '@/types/api';

const FALLBACK_DEMOS: DemoAccount[] = [
  { username: 'admin', password: 'Admin123!', role_slug: 'admin', role_name: 'Administracja' },
  {
    username: 'operator',
    password: 'Operator123!',
    role_slug: 'operator',
    role_name: 'Dodawanie, usuwanie, modyfikacja',
  },
  { username: 'analyst', password: 'Analyst123!', role_slug: 'analyst', role_name: 'Modyfikacja i odczyt' },
  { username: 'viewer', password: 'Viewer123!', role_slug: 'viewer', role_name: 'Odczyt' },
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
      toast.success('Zalogowano', label || u);
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
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <div className="w-full max-w-sm space-y-8">
        <div className="flex items-center gap-3">
          <AghEmblem className="h-8" />
          <span className="text-lg font-bold tracking-widest uppercase">AegisASI</span>
          <AghBadge className="ml-auto" />
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          <Field label="Użytkownik" htmlFor="login-user">
            <Input
              id="login-user"
              autoComplete="username"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="admin"
            />
          </Field>
          <Field label="Hasło" htmlFor="login-pass">
            <Input
              id="login-pass"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
            />
          </Field>

          {error && <Notice tone="danger">{error}</Notice>}

          <Button type="submit" disabled={submitting} className="w-full">
            {submitting ? 'Logowanie…' : 'Zaloguj'}
          </Button>
        </form>

        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <Separator className="flex-1" />
            <span className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
              Demo RBAC
            </span>
            <Separator className="flex-1" />
          </div>
          <div className="grid grid-cols-2 gap-2">
            {accounts.map((acc) => {
              const slug = acc.role_slug || acc.role || acc.username;
              const roleLabel = acc.role_name || acc.label || slug;
              return (
                <button
                  key={acc.username}
                  type="button"
                  disabled={submitting}
                  title={roleLabel}
                  onClick={() => performLogin(acc.username, acc.password, roleLabel)}
                  className={cn(
                    'group flex h-9 items-center justify-between gap-2 border px-3 font-mono text-xs transition-opacity hover:opacity-80 disabled:opacity-50',
                    getRoleBadgeClasses(slug)
                  )}
                >
                  {acc.username}
                  <RiArrowRightLine className="size-3.5 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
                </button>
              );
            })}
          </div>
        </div>

        <div className="flex items-center justify-between text-[10px] tracking-wider text-muted-foreground uppercase">
          <span className="flex items-center gap-1.5">
            <RiLockLine className="size-3" />
            AES-256-GCM
          </span>
          <span className="font-mono normal-case">{health?.version || 'v1.0'}</span>
        </div>
      </div>
    </div>
  );
}
