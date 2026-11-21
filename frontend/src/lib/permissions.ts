import type { User } from '../types/api';

export const PERMISSIONS = {
  DASHBOARD_READ: 'dashboard:read',
  ASSETS_READ: 'assets:read',
  ASSETS_WRITE: 'assets:write',
  ASSETS_DELETE: 'assets:delete',
  SCANS_READ: 'scans:read',
  SCANS_WRITE: 'scans:write',
  SCANS_DELETE: 'scans:delete',
  SCANS_RUN: 'scans:run',
  SIGNATURES_READ: 'signatures:read',
  SIGNATURES_WRITE: 'signatures:write',
  SIGNATURES_DELETE: 'signatures:delete',
  IMPORT_WRITE: 'import:write',
  EXPORT_READ: 'export:read',
  DEFECTDOJO_PUSH: 'defectdojo:push',
  ADMIN_USERS: 'admin:users',
  ADMIN_ROLES: 'admin:roles',
  ADMIN_SETTINGS: 'admin:settings',
  ADMIN_AUDIT: 'admin:audit',
} as const;

export const ALL_PERMISSIONS_META: Array<{
  slug: string;
  group: string;
  label: string;
}> = [
  { slug: 'dashboard:read', group: 'Dashboard', label: 'View the dashboard and KPIs' },
  { slug: 'assets:read', group: 'Assets & graph', label: 'Read hosts, services, clusters and the graph' },
  { slug: 'assets:write', group: 'Assets & graph', label: 'Edit analyst overrides and acknowledge changes' },
  { slug: 'assets:delete', group: 'Assets & graph', label: 'Delete assets' },
  { slug: 'scans:read', group: 'Scans & diff', label: 'Read scans, profiles, diffs and the coverage ledger' },
  { slug: 'scans:write', group: 'Scans & diff', label: 'Create and edit profiles, targets and scan notes' },
  { slug: 'scans:delete', group: 'Scans & diff', label: 'Delete scans, profiles and scope entries' },
  { slug: 'scans:run', group: 'Scans & diff', label: 'Start, pause and stop scans' },
  { slug: 'signatures:read', group: 'Signature Studio', label: 'Read signatures and run retroactive tests' },
  { slug: 'signatures:write', group: 'Signature Studio', label: 'Create, edit and import signatures' },
  { slug: 'signatures:delete', group: 'Signature Studio', label: 'Delete custom signatures' },
  { slug: 'import:write', group: 'Import / export', label: 'Manual entry and CSV/JSON/nmap import' },
  { slug: 'export:read', group: 'Import / export', label: 'Export data' },
  { slug: 'defectdojo:push', group: 'Integrations', label: 'Push findings and nmap XML to DefectDojo' },
  { slug: 'admin:users', group: 'Administration', label: 'Manage users' },
  { slug: 'admin:roles', group: 'Administration', label: 'Manage roles (dynamic RBAC)' },
  { slug: 'admin:settings', group: 'Administration', label: 'DefectDojo settings and encryption key rotation' },
  { slug: 'admin:audit', group: 'Administration', label: 'Read the audit log' },
];

export function hasPerm(user: User | null | undefined, perm: string): boolean {
  if (!user) return false;
  const perms = user.permissions || [];
  if (perms.includes('*')) return true;
  if (perms.includes(perm)) return true;
  const [prefix] = perm.split(':');
  if (prefix && perms.includes(`${prefix}:*`)) return true;
  return false;
}

export function hasAnyPerm(user: User | null | undefined, perms: string[]): boolean {
  return perms.some((p) => hasPerm(user, p));
}

export function getRoleDisplayName(user: User | null | undefined): string {
  if (!user) return '';
  if (user.role_name) return user.role_name;
  const slug = user.role_slug || user.role || '';
  switch (slug) {
    case 'admin':
      return 'Administration';
    case 'operator':
      return 'Add, delete, modify';
    case 'analyst':
      return 'Modify and read';
    case 'viewer':
      return 'Read only';
    default:
      return slug || 'User';
  }
}

export function getRoleBadgeClasses(slug?: string): string {
  switch (slug) {
    case 'admin':
      return 'bg-rose-500/10 text-rose-700 dark:text-rose-300 border-rose-500/25';
    case 'operator':
      return 'bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/25';
    case 'analyst':
      return 'bg-sky-500/10 text-sky-700 dark:text-sky-300 border-sky-500/25';
    case 'viewer':
      return 'bg-muted text-muted-foreground border-border';
    default:
      return 'bg-violet-500/10 text-violet-700 dark:text-violet-300 border-violet-500/25';
  }
}
