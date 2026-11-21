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
  { slug: 'dashboard:read', group: 'Dashboard', label: 'Podgląd Dashboardu i KPI' },
  { slug: 'assets:read', group: 'Zasoby & Graf', label: 'Odczyt hostów, usług, klastrów i grafu' },
  { slug: 'assets:write', group: 'Zasoby & Graf', label: 'Edycja nadpisań (Overrides) i potwierdzanie zmian' },
  { slug: 'assets:delete', group: 'Zasoby & Graf', label: 'Usuwanie zasobów' },
  { slug: 'scans:read', group: 'Skaner & Diff', label: 'Odczyt skanów, profili, diffów i Coverage Ledger' },
  { slug: 'scans:write', group: 'Skaner & Diff', label: 'Tworzenie/edycja profili, celów i notatek skanów' },
  { slug: 'scans:delete', group: 'Skaner & Diff', label: 'Usuwanie skanów, profili i zakresów' },
  { slug: 'scans:run', group: 'Skaner & Diff', label: 'Uruchamianie, pauzowanie i zatrzymywanie skanów' },
  { slug: 'signatures:read', group: 'Signature Studio', label: 'Odczyt sygnatur i test retroaktywny' },
  { slug: 'signatures:write', group: 'Signature Studio', label: 'Tworzenie, edycja i import sygnatur' },
  { slug: 'signatures:delete', group: 'Signature Studio', label: 'Usuwanie własnych sygnatur' },
  { slug: 'import:write', group: 'Import / Eksport', label: 'Formularz ręczny i import plików CSV/JSON' },
  { slug: 'export:read', group: 'Import / Eksport', label: 'Eksport danych do CSV/JSON' },
  { slug: 'defectdojo:push', group: 'Integracje', label: 'Wysyłanie znalezisk i Nmap XML do DefectDojo v2' },
  { slug: 'admin:users', group: 'Administracja', label: 'Zarządzanie użytkownikami' },
  { slug: 'admin:roles', group: 'Administracja', label: 'Dynamiczny RBAC — zarządzanie rolami' },
  { slug: 'admin:settings', group: 'Administracja', label: 'Konfiguracja DefectDojo i szyfrowanie (rotacja DEK)' },
  { slug: 'admin:audit', group: 'Administracja', label: 'Dziennik audytowy (Audit Log)' },
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
      return 'Administracja';
    case 'operator':
      return 'Dodawanie, usuwanie, modyfikacja';
    case 'analyst':
      return 'Modyfikacja i odczyt';
    case 'viewer':
      return 'Odczyt';
    default:
      return slug || 'Użytkownik';
  }
}

export function getRoleBadgeClasses(slug?: string): string {
  switch (slug) {
    case 'admin':
      return 'bg-rose-500/15 text-rose-400 border-rose-500/30';
    case 'operator':
      return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
    case 'analyst':
      return 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30';
    case 'viewer':
      return 'bg-slate-500/15 text-slate-300 border-slate-500/30';
    default:
      return 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30';
  }
}
