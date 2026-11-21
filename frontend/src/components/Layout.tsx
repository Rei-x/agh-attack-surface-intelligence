import React, { useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  Activity,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  GitCompare,
  Lock,
  LogOut,
  Moon,
  Network,
  Radar,
  Server,
  Settings,
  Shield,
  Sparkles,
  Sun,
  UserCheck,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { useLiveEvents } from '../context/LiveEventsContext';
import { useToast } from '../context/ToastContext';
import {
  getRoleBadgeClasses,
  getRoleDisplayName,
  PERMISSIONS,
} from '../lib/permissions';

interface NavItem {
  to: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  perms: string[];
  end?: boolean;
}

const NAV_ITEMS: NavItem[] = [
  {
    to: '/',
    label: 'Dashboard',
    icon: Activity,
    perms: [PERMISSIONS.DASHBOARD_READ],
    end: true,
  },
  {
    to: '/graph',
    label: 'Graf Powierzchni',
    icon: Network,
    perms: [PERMISSIONS.ASSETS_READ],
  },
  {
    to: '/assets',
    label: 'Zasoby i Klastry',
    icon: Server,
    perms: [PERMISSIONS.ASSETS_READ],
  },
  {
    to: '/diff',
    label: 'Porównanie Skanów',
    icon: GitCompare,
    perms: [PERMISSIONS.SCANS_READ],
  },
  {
    to: '/scans',
    label: 'Skaner i Import',
    icon: Radar,
    perms: [PERMISSIONS.SCANS_READ],
  },
  {
    to: '/signatures',
    label: 'Signature Studio',
    icon: Sparkles,
    perms: [PERMISSIONS.SIGNATURES_READ],
  },
  {
    to: '/admin',
    label: 'DefectDojo i Admin',
    icon: Settings,
    perms: [
      PERMISSIONS.DEFECTDOJO_PUSH,
      PERMISSIONS.ADMIN_USERS,
      PERMISSIONS.ADMIN_ROLES,
      PERMISSIONS.ADMIN_SETTINGS,
      PERMISSIONS.ADMIN_AUDIT,
    ],
  },
];

export function Layout() {
  const { user, health, demoAccounts, login, logout, canAny } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const { connected, throttled } = useLiveEvents();
  const toast = useToast();
  const navigate = useNavigate();

  const [collapsed, setCollapsed] = useState(false);
  const [roleMenuOpen, setRoleMenuOpen] = useState(false);
  const [switchingRole, setSwitchingRole] = useState<string | null>(null);

  const visibleNav = NAV_ITEMS.filter((item) => canAny(item.perms));
  const roleSlug = user?.role_slug || user?.role || '';

  const handleQuickSwitch = async (username: string, password: string, label: string) => {
    setSwitchingRole(username);
    try {
      await login(username, password);
      setRoleMenuOpen(false);
      toast.success('Przełączono rolę RBAC', `Aktywna rola: ${label} (${username})`);
      navigate('/');
    } catch (err) {
      toast.error('Nie udało się przełączyć roli', (err as Error).message);
    } finally {
      setSwitchingRole(null);
    }
  };

  return (
    <div className="min-h-screen flex bg-bg-primary text-text-primary">
      {/* Sidebar */}
      <aside
        className={`${
          collapsed ? 'w-[72px]' : 'w-64'
        } shrink-0 border-r border-border-subtle bg-bg-secondary flex flex-col transition-all duration-200 sticky top-0 h-screen z-30`}
      >
        <div className="h-16 px-4 border-b border-border-subtle flex items-center justify-between gap-2">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 shrink-0">
              <Shield className="h-5 w-5 text-white" />
            </div>
            {!collapsed && (
              <div className="min-w-0">
                <div className="font-bold tracking-tight text-sm flex items-center gap-1.5">
                  <span>AegisASI</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">
                    CBI AGH
                  </span>
                </div>
                <p className="text-[11px] text-text-muted truncate">
                  Attack Surface Intelligence
                </p>
              </div>
            )}
          </div>
          <button
            type="button"
            onClick={() => setCollapsed((v) => !v)}
            className="p-1.5 rounded-md text-text-muted hover:text-text-primary hover:bg-bg-hover"
            title={collapsed ? 'Rozwiń menu' : 'Zwiń menu'}
          >
            {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          </button>
        </div>

        <nav className="flex-1 p-2.5 space-y-1 overflow-y-auto">
          {visibleNav.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 shadow-sm'
                      : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary border border-transparent'
                  }`
                }
                title={collapsed ? item.label : undefined}
              >
                <Icon className="h-4 w-4 shrink-0" />
                {!collapsed && <span className="truncate">{item.label}</span>}
              </NavLink>
            );
          })}
        </nav>

        {/* Bottom status box */}
        {!collapsed && (
          <div className="p-3 border-t border-border-subtle space-y-2 text-xs">
            <div className="flex items-center justify-between text-text-muted">
              <span className="flex items-center gap-1.5">
                <Lock className="h-3.5 w-3.5 text-emerald-400" />
                Encryption At Rest
              </span>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                {health?.key_version || 'AES-256-GCM'}
              </span>
            </div>
            <div className="flex items-center justify-between text-text-muted">
              <span>Nmap Engine</span>
              <span className="font-mono text-[11px] text-text-secondary">
                {health?.nmap_available === false ? 'TCP Fallback' : 'Active'}
              </span>
            </div>
          </div>
        )}
      </aside>

      {/* Main area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className="h-16 border-b border-border-subtle bg-bg-secondary/85 backdrop-blur-md sticky top-0 z-20 px-4 lg:px-6 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <div
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
                connected
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  : 'bg-slate-500/10 text-text-muted border-border-subtle'
              }`}
            >
              {connected ? (
                <>
                  <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                  <Wifi className="h-3 w-3" />
                  <span>Live SSE</span>
                </>
              ) : (
                <>
                  <WifiOff className="h-3 w-3" />
                  <span>SSE offline</span>
                </>
              )}
            </div>

            {throttled && (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-amber-500/15 text-amber-400 border border-amber-500/30">
                Noise Governor: ograniczono tempo
              </span>
            )}
          </div>

          <div className="flex items-center gap-2.5">
            {/* Theme toggle */}
            <button
              type="button"
              onClick={toggleTheme}
              className="p-2 rounded-lg border border-border-subtle bg-bg-elevated text-text-secondary hover:text-text-primary hover:bg-bg-hover transition-colors"
              title={theme === 'dark' ? 'Przełącz na jasny motyw' : 'Przełącz na ciemny motyw'}
            >
              {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>

            {/* Current role + Quick Demo Role Switcher */}
            <div className="relative">
              <button
                type="button"
                onClick={() => setRoleMenuOpen((v) => !v)}
                className="flex items-center gap-2.5 px-3 py-1.5 rounded-lg border border-border-subtle bg-bg-elevated hover:bg-bg-hover transition-colors"
              >
                <div className="text-right hidden sm:block">
                  <div className="text-xs font-semibold leading-tight text-text-primary">
                    {user?.username}
                  </div>
                  <div className="text-[10px] text-text-muted leading-tight">
                    {(user?.permissions || []).includes('*')
                      ? 'Pełne uprawnienia (*)'
                      : `${user?.permissions?.length || 0} uprawnień`}
                  </div>
                </div>
                <span
                  className={`text-xs font-medium px-2 py-0.5 rounded-md border ${getRoleBadgeClasses(
                    roleSlug
                  )}`}
                >
                  {getRoleDisplayName(user)}
                </span>
                <ChevronDown className="h-3.5 w-3.5 text-text-muted" />
              </button>

              {roleMenuOpen && (
                <>
                  <div
                    className="fixed inset-0 z-30"
                    onClick={() => setRoleMenuOpen(false)}
                  />
                  <div className="absolute right-0 mt-2 w-80 rounded-xl border border-border-strong bg-bg-card shadow-2xl z-40 p-2">
                    <div className="px-2.5 py-2 border-b border-border-subtle">
                      <div className="text-xs font-semibold text-text-primary flex items-center gap-1.5">
                        <UserCheck className="h-3.5 w-3.5 text-cyan-400" />
                        Szybkie przełączenie roli RBAC (Demo)
                      </div>
                      <p className="text-[11px] text-text-muted mt-0.5">
                        Przetestuj uprawnienia i blokady 403 jednym kliknięciem
                      </p>
                    </div>

                    <div className="py-1.5 space-y-1">
                      {demoAccounts.length > 0 ? (
                        demoAccounts.map((acc) => {
                          const slug = acc.role_slug || acc.role || acc.username;
                          const label = acc.role_name || acc.label || slug;
                          const isCurrent = user?.username === acc.username;
                          return (
                            <button
                              key={acc.username}
                              type="button"
                              disabled={switchingRole !== null}
                              onClick={() => handleQuickSwitch(acc.username, acc.password, label)}
                              className={`w-full text-left px-2.5 py-2 rounded-lg flex items-center justify-between gap-2 transition-colors ${
                                isCurrent
                                  ? 'bg-cyan-500/10 border border-cyan-500/30'
                                  : 'hover:bg-bg-hover border border-transparent'
                              }`}
                            >
                              <div className="min-w-0">
                                <div className="text-xs font-semibold text-text-primary truncate">
                                  {label}
                                </div>
                                <div className="text-[11px] font-mono text-text-muted">
                                  {acc.username}
                                </div>
                              </div>
                              <span
                                className={`text-[10px] px-1.5 py-0.5 rounded border shrink-0 ${getRoleBadgeClasses(
                                  slug
                                )}`}
                              >
                                {isCurrent
                                  ? 'Aktywna'
                                  : switchingRole === acc.username
                                    ? '...'
                                    : 'Przełącz'}
                              </span>
                            </button>
                          );
                        })
                      ) : (
                        <div className="px-2.5 py-2 text-xs text-text-muted">
                          Brak aktywnych kont demo.
                        </div>
                      )}
                    </div>

                    <div className="pt-1.5 border-t border-border-subtle">
                      <button
                        type="button"
                        onClick={() => {
                          setRoleMenuOpen(false);
                          logout();
                          navigate('/login');
                        }}
                        className="w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-xs font-medium text-rose-400 hover:bg-rose-500/10 transition-colors"
                      >
                        <LogOut className="h-3.5 w-3.5" />
                        Wyloguj się
                      </button>
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 p-4 lg:p-6 max-w-[1680px] w-full mx-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
