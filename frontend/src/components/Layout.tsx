import React, { useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  RiAddLine,
  RiArrowDownSLine,
  RiGitMergeLine,
  RiLayoutLeftLine,
  RiLockLine,
  RiLogoutBoxRLine,
  RiMoonLine,
  RiNodeTree,
  RiPulseLine,
  RiRadarLine,
  RiServerLine,
  RiSettings3Line,
  RiShieldCrossLine,
  RiSparklingLine,
  RiSunLine,
} from '@remixicon/react';
import { useAuth } from '@/context/AuthContext';
import { useTheme } from '@/context/ThemeContext';
import { useLiveEvents } from '@/context/LiveEventsContext';
import { useToast } from '@/context/ToastContext';
import { getRoleBadgeClasses, getRoleDisplayName, PERMISSIONS } from '@/lib/permissions';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Pill } from '@/components/common';
import { LiveIndicator } from '@/components/LiveIndicator';
import { WoodpeckerMark } from '@/components/Woodpecker';
import { QuickScanDialog } from '@/components/QuickScanDialog';
import { DojoStatusChip } from '@/components/DojoStatusChip';
import { rateChange, throttleReasonLabel } from '@/lib/scanTelemetry';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

interface NavItem {
  to: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  perms: string[];
  end?: boolean;
}

const NAV_ITEMS: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: RiPulseLine, perms: [PERMISSIONS.DASHBOARD_READ], end: true },
  { to: '/graph', label: 'Graph', icon: RiNodeTree, perms: [PERMISSIONS.ASSETS_READ] },
  { to: '/assets', label: 'Assets', icon: RiServerLine, perms: [PERMISSIONS.ASSETS_READ] },
  { to: '/diff', label: 'Diff', icon: RiGitMergeLine, perms: [PERMISSIONS.SCANS_READ] },
  { to: '/scans', label: 'Scans', icon: RiRadarLine, perms: [PERMISSIONS.SCANS_READ] },
  { to: '/policies', label: 'Policies', icon: RiShieldCrossLine, perms: [PERMISSIONS.ASSETS_READ] },
  { to: '/signatures', label: 'Signatures', icon: RiSparklingLine, perms: [PERMISSIONS.SIGNATURES_READ] },
  {
    to: '/admin',
    label: 'Admin',
    icon: RiSettings3Line,
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
  const { user, health, demoAccounts, login, logout, can, canAny } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const { throttled, lastThrottle } = useLiveEvents();
  const toast = useToast();
  const navigate = useNavigate();

  const [collapsed, setCollapsed] = useState(false);
  const [switchingRole, setSwitchingRole] = useState<string | null>(null);
  const [quickScanOpen, setQuickScanOpen] = useState(false);

  const visibleNav = NAV_ITEMS.filter((item) => canAny(item.perms));
  const roleSlug = user?.role_slug || user?.role || '';

  const handleQuickSwitch = async (username: string, password: string, label: string) => {
    setSwitchingRole(username);
    try {
      await login(username, password);
      toast.success('Role switched', label);
      navigate('/');
    } catch (err) {
      toast.error('Could not switch role', (err as Error).message);
    } finally {
      setSwitchingRole(null);
    }
  };

  return (
    <div className="flex min-h-screen bg-background text-foreground">
      {/* Sidebar */}
      <aside
        className={cn(
          'sticky top-0 z-30 flex h-screen shrink-0 flex-col border-r bg-sidebar transition-[width] duration-200',
          collapsed ? 'w-14' : 'w-52'
        )}
      >
        <div className={cn('flex h-14 items-center gap-2.5 border-b', collapsed ? 'justify-center px-0' : 'px-4')}>
          <WoodpeckerMark className="h-6" />
          {!collapsed && (
            <span className="flex min-w-0 flex-col leading-none">
              <span className="truncate text-base font-extrabold tracking-tight">
                Dzięcioł<span className="text-brand">.</span>
              </span>
              <span className="mt-1 truncate text-[9px] font-semibold tracking-[0.25em] text-muted-foreground uppercase">
                CBI AGH
              </span>
            </span>
          )}
        </div>

        <nav className="flex-1 space-y-0.5 overflow-y-auto p-2">
          {visibleNav.map((item) => {
            const Icon = item.icon;
            const link = (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  cn(
                    'flex h-9 items-center gap-3 px-2.5 text-xs font-semibold tracking-wider uppercase transition-colors',
                    isActive
                      ? 'bg-sidebar-accent text-foreground shadow-[inset_2px_0_0_var(--primary)]'
                      : 'text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground'
                  )
                }
              >
                <Icon className="size-4 shrink-0" />
                {!collapsed && <span className="truncate">{item.label}</span>}
              </NavLink>
            );
            return collapsed ? (
              <Tooltip key={item.to}>
                <TooltipTrigger render={<div />}>{link}</TooltipTrigger>
                <TooltipContent side="right">{item.label}</TooltipContent>
              </Tooltip>
            ) : (
              link
            );
          })}
        </nav>

        <div className="space-y-2 border-t p-3 text-[10px] tracking-wider text-muted-foreground uppercase">
          {!collapsed && (
            <>
              <div className="flex items-center justify-between gap-2">
                <span className="flex items-center gap-1.5">
                  <RiLockLine className="size-3 text-emerald-600 dark:text-emerald-400" />
                  At Rest
                </span>
                <span className="font-mono normal-case">{health?.key_version || 'AES-256-GCM'}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span>Nmap</span>
                <span className="font-mono normal-case">
                  {health?.nmap_available === false ? 'TCP Fallback' : 'Active'}
                </span>
              </div>
            </>
          )}
          <Button
            variant="ghost"
            size="icon-xs"
            onClick={() => setCollapsed((v) => !v)}
            aria-label={collapsed ? 'Expand menu' : 'Collapse menu'}
          >
            <RiLayoutLeftLine />
          </Button>
        </div>
      </aside>

      {/* Main */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex h-14 items-center justify-between gap-4 border-b bg-background/80 px-4 backdrop-blur-md lg:px-8">
          <div className="flex items-center gap-2">
            <LiveIndicator />
            {throttled && lastThrottle && (
              <Pill tone="warning" title={`Automatic backoff: ${throttleReasonLabel(lastThrottle.reason)}`}>
                Scan slowed down: {rateChange(lastThrottle.old_rate, lastThrottle.new_rate)}
              </Pill>
            )}
            {canAny([PERMISSIONS.DEFECTDOJO_PUSH, PERMISSIONS.ASSETS_READ]) && <DojoStatusChip />}
          </div>

          <div className="flex items-center gap-1.5">
            {can(PERMISSIONS.SCANS_RUN) && (
              <Button size="sm" variant="outline" onClick={() => setQuickScanOpen(true)} className="mr-1">
                <RiAddLine />
                Quick scan
              </Button>
            )}
            <Button
              variant="ghost"
              size="icon-sm"
              onClick={toggleTheme}
              aria-label={theme === 'dark' ? 'Light theme' : 'Dark theme'}
            >
              {theme === 'dark' ? <RiSunLine /> : <RiMoonLine />}
            </Button>

            <DropdownMenu>
              <DropdownMenuTrigger
                render={
                  <button
                    type="button"
                    className="flex h-8 items-center gap-2 border px-2.5 text-xs transition-colors hover:bg-muted"
                  />
                }
              >
                <span className="hidden font-mono sm:inline">{user?.username}</span>
                <Pill className={getRoleBadgeClasses(roleSlug)}>{getRoleDisplayName(user)}</Pill>
                <RiArrowDownSLine className="size-3.5 text-muted-foreground" />
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-72">
                <DropdownMenuGroup>
                  <DropdownMenuLabel>Switch demo role</DropdownMenuLabel>
                  {demoAccounts.length === 0 && (
                    <div className="px-3 py-2 text-xs text-muted-foreground">No demo accounts</div>
                  )}
                  {demoAccounts.map((acc) => {
                    const slug = acc.role_slug || acc.role || acc.username;
                    const label = acc.role_name || acc.label || slug;
                    const isCurrent = user?.username === acc.username;
                    return (
                      <DropdownMenuItem
                        key={acc.username}
                        disabled={switchingRole !== null || isCurrent}
                        onClick={() => handleQuickSwitch(acc.username, acc.password, label)}
                        className="justify-between normal-case tracking-normal"
                      >
                        <span className="min-w-0 truncate">
                          <span className="font-semibold">{label}</span>
                          <span className="ml-2 font-mono text-muted-foreground">{acc.username}</span>
                        </span>
                        {isCurrent ? (
                          <span className="size-1.5 shrink-0 bg-primary" />
                        ) : switchingRole === acc.username ? (
                          <span className="text-muted-foreground">…</span>
                        ) : null}
                      </DropdownMenuItem>
                    );
                  })}
                </DropdownMenuGroup>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  variant="destructive"
                  onClick={() => {
                    logout();
                    navigate('/login');
                  }}
                >
                  <RiLogoutBoxRLine />
                  Log out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1600px] flex-1 p-4 lg:p-8">
          {health?.status === 'degraded' && (
            <div role="alert" className="mb-4 rounded-md border border-red-500/50 bg-red-500/10 px-4 py-3 text-sm text-red-300">
              Data store problem: {health.db}
            </div>
          )}
          <Outlet />
        </main>
        {can(PERMISSIONS.SCANS_RUN) && (
          <QuickScanDialog open={quickScanOpen} onOpenChange={setQuickScanOpen} />
        )}
      </div>
    </div>
  );
}
