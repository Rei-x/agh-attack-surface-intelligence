import * as React from 'react';
import { Link } from 'react-router-dom';
import {
  RiBugLine,
  RiCpuLine,
  RiDatabase2Line,
  RiFireLine,
  RiFlaskLine,
  RiHourglassLine,
  RiLockUnlockLine,
  RiServerLine,
  RiShieldCheckLine,
  RiShieldCrossLine,
  RiShieldKeyholeLine,
  RiTerminalLine,
} from '@remixicon/react';
import { assetsLink, formatNumber } from '@/lib/format';
import { cn } from '@/lib/utils';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import type { OutdatedComponent, VulnHint } from '@/types/api';
import type { VerifiedFinding, VulnSummary } from '@/lib/vulnintel';

/**
 * Risk categories shown as compact icon badges (icon + tone + tooltip) instead of text pills.
 * Shared by the dashboard, asset list, inspector drawer and (later) the graph.
 */
export type CategoryKind =
  | 'admin'
  | 'staging'
  | 'iot'
  | 'bmc'
  | 'eol'
  | 'cve'
  | 'kev'
  | 'verified'
  | 'db'
  | 'cert'
  | 'cleartext'
  | 'policy';

type Icon = React.ComponentType<{ className?: string }>;

export const CATEGORY_META: Record<
  CategoryKind,
  { label: string; icon: Icon; tone: string; query: string; hint: string }
> = {
  // Woodpecker red is reserved for known CVEs; everything else is amber / neutral tones.
  verified: {
    label: 'Verified',
    icon: RiShieldCheckLine,
    tone: 'text-rose-700 dark:text-rose-300 border-rose-500/50 bg-rose-500/15',
    query: 'verified:true',
    hint: 'Exposure confirmed by a safe verification check, with evidence',
  },
  kev: {
    label: 'Exploited in the wild',
    icon: RiFireLine,
    tone: 'text-white border-rose-700 bg-rose-600 dark:bg-rose-500',
    query: 'kev:true',
    hint: 'A matched CVE is in the CISA Known Exploited Vulnerabilities catalog',
  },
  cve: {
    label: 'Known CVE',
    icon: RiBugLine,
    tone: 'text-rose-600 dark:text-rose-400 border-rose-500/30 bg-rose-500/10',
    query: 'vuln:true',
    hint: 'Version falls in a known CVE range (passive, version-only)',
  },
  eol: {
    label: 'End of life',
    icon: RiHourglassLine,
    tone: 'text-orange-700 dark:text-orange-300 border-orange-500/30 bg-orange-500/10',
    query: 'eol:true',
    hint: 'Version branch no longer receives security fixes',
  },
  admin: {
    label: 'Admin panel',
    icon: RiShieldKeyholeLine,
    tone: 'text-amber-700 dark:text-amber-300 border-amber-500/30 bg-amber-500/10',
    query: 'admin:true',
    hint: 'Management / login interface reachable from the scanner',
  },
  db: {
    label: 'Exposed database',
    icon: RiDatabase2Line,
    tone: 'text-amber-700 dark:text-amber-300 border-amber-500/30 bg-amber-500/10',
    query: 'db:true',
    hint: 'Database listener reachable over the network',
  },
  cleartext: {
    label: 'Cleartext admin protocol',
    icon: RiTerminalLine,
    tone: 'text-orange-700 dark:text-orange-300 border-orange-500/30 bg-orange-500/10',
    query: 'cleartext:true',
    hint: 'Telnet / FTP: credentials travel unencrypted',
  },
  cert: {
    label: 'Expired certificate',
    icon: RiLockUnlockLine,
    tone: 'text-orange-700 dark:text-orange-300 border-orange-500/30 bg-orange-500/10',
    query: 'cert:expired',
    hint: 'TLS certificate past its expiry date',
  },
  bmc: {
    label: 'Server BMC',
    icon: RiServerLine,
    tone: 'text-sky-700 dark:text-sky-300 border-sky-500/30 bg-sky-500/10',
    query: 'tech:bmc',
    hint: 'Out-of-band server management (iDRAC / iLO / IPMI)',
  },
  iot: {
    label: 'IoT device',
    icon: RiCpuLine,
    tone: 'text-cyan-700 dark:text-cyan-300 border-cyan-500/30 bg-cyan-500/10',
    query: 'iot:true',
    hint: 'Embedded device: camera, printer, router, NAS',
  },
  policy: {
    label: 'Policy violation',
    icon: RiShieldCrossLine,
    tone: 'text-foreground border-foreground/30 bg-foreground/5',
    query: 'violation:true',
    hint: 'Breaks the policy of its network zone',
  },
  staging: {
    label: 'Staging / dev',
    icon: RiFlaskLine,
    tone: 'text-violet-700 dark:text-violet-300 border-violet-500/30 bg-violet-500/10',
    query: 'staging:true',
    hint: 'Non-production environment exposed',
  },
};

/** Display order (most severe first). */
export const CATEGORY_ORDER: CategoryKind[] = ['policy', 'verified', 'kev', 'cve', 'eol', 'admin', 'db', 'cleartext', 'cert', 'bmc', 'iot', 'staging'];

export interface CategoryFlag {
  kind: CategoryKind;
  /** Extra tooltip lines (evidence). */
  detail?: string[];
}

interface FlaggableService {
  port?: number;
  service_name?: string;
  is_admin_panel?: boolean;
  is_staging_env?: boolean;
  is_iot?: boolean;
  outdated?: OutdatedComponent[];
  known_vulns?: VulnHint[];
  vulns?: VulnSummary[];
  verified?: VerifiedFinding[];
  matched_signatures?: string[];
  technologies?: Array<{ name: string }>;
  http?: { tls?: { is_expired?: boolean } | null; title?: string } | null;
  /** Open zone policy violations (derived by the backend on read). */
  policy_violations?: Array<{ zone_name: string; summary: string }>;
}

const DB_NAMES = new Set([
  'mysql', 'postgresql', 'postgres', 'ms-sql-s', 'mssql', 'oracle', 'oracle-tns', 'mongodb', 'mongod',
  'redis', 'elasticsearch', 'couchdb', 'memcache', 'memcached', 'cassandra', 'influxdb', 'clickhouse', 'neo4j',
]);
const DB_PORTS = new Set([3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984, 11211, 9042, 8086]);
const CLEARTEXT = new Set(['telnet', 'ftp', 'rlogin', 'login', 'shell', 'exec', 'tftp']);

function names(svc: FlaggableService): string[] {
  return [...(svc.matched_signatures || []), ...(svc.technologies || []).map((t) => t.name)].map((n) =>
    n.toLowerCase()
  );
}

/** Same rules as the backend quick filters (db:true, cleartext:true …). */
export function isDatabaseService(svc: FlaggableService): boolean {
  const n = (svc.service_name || '').toLowerCase();
  return DB_NAMES.has(n) || DB_PORTS.has(svc.port || 0) || names(svc).some((x) => x.includes('exposed database'));
}

export function isCleartextService(svc: FlaggableService): boolean {
  const n = (svc.service_name || '').toLowerCase();
  return CLEARTEXT.has(n) || (n === '' && (svc.port === 21 || svc.port === 23));
}

export function isBmcService(svc: FlaggableService): boolean {
  return names(svc).some((x) => /\bbmc\b|idrac|integrated lights-out|\bilo\b/.test(x));
}

export function outdatedDetail(o: OutdatedComponent): string {
  const parts = [
    `${o.product} ${o.version || o.branch}: branch ${o.branch} reached end of life on ${o.eol_date}` +
      (o.days_since_eol > 0 ? ` (${ageText(o.days_since_eol)} ago).` : '.'),
  ];
  if (o.latest_in_branch) parts.push(`Last release in branch: ${o.latest_in_branch}.`);
  if (o.supported_branch)
    parts.push(`Supported branch: ${o.supported_branch}${o.supported_track ? ` (${o.supported_track})` : ''}.`);
  if (o.distro_packaged) parts.push('Distro package: fixes may be backported, check the OS release.');
  parts.push(`Source: ${o.source} (data as of ${o.data_as_of}).`);
  return parts.join(' ');
}

export function vulnDetail(h: VulnHint): string {
  return (
    `${h.id} ${h.name}: ${h.product} ${h.version} is in the affected range (${h.affected}). ` +
    'Passive hint from the version only; nothing was sent to the service.' +
    (h.distro_packaged ? ' Distro build: the fix may be backported.' : '')
  );
}

export function ageText(days: number): string {
  if (days >= 365) {
    const y = Math.floor(days / 365);
    return `${y} year${y === 1 ? '' : 's'}`;
  }
  if (days >= 60) return `${Math.floor(days / 30)} months`;
  return `${days} days`;
}

/** Risk categories of one service, most severe first. */
export function serviceFlags(svc: FlaggableService): CategoryFlag[] {
  const out: CategoryFlag[] = [];
  if (svc.policy_violations?.length) out.push({ kind: 'policy', detail: svc.policy_violations.map((p) => p.summary) });
  if (svc.verified?.length) out.push({ kind: 'verified', detail: svc.verified.map((v) => `${v.severity}: ${v.name}`) });
  const kev = (svc.vulns || []).filter((v) => v.kev > 0);
  if (kev.length)
    out.push({
      kind: 'kev',
      detail: kev.flatMap((v) => v.top.filter((c) => c.kev).map((c) => `${c.id} (${v.product} ${v.version}), in KEV since ${c.kev_date_added}`)),
    });
  // Products whose every match the protocol probe ruled out (e.g. HTTP/2 off) are no finding.
  const liveV = (svc.vulns || []).filter((v) => v.total > 0);
  if (svc.known_vulns?.length || liveV.length)
    out.push({
      kind: 'cve',
      detail: [
        ...liveV.map(
          (v) => `${v.product} ${v.version}: ${v.total} CVEs, max CVSS ${v.max_cvss.toFixed(1)}, match confidence ${v.confidence}`
        ),
        ...(svc.known_vulns || []).map(vulnDetail),
      ],
    });
  if (svc.outdated?.length) out.push({ kind: 'eol', detail: svc.outdated.map(outdatedDetail) });
  if (svc.is_admin_panel) out.push({ kind: 'admin', detail: svc.http?.title ? [`“${svc.http.title}”`] : undefined });
  if (isDatabaseService(svc)) out.push({ kind: 'db', detail: [`${svc.service_name || 'database'} on port ${svc.port}`] });
  if (isCleartextService(svc)) out.push({ kind: 'cleartext', detail: [`${svc.service_name || 'service'} on port ${svc.port}`] });
  if (svc.http?.tls?.is_expired) out.push({ kind: 'cert' });
  const bmc = isBmcService(svc);
  if (bmc) out.push({ kind: 'bmc' });
  if (svc.is_iot && !bmc) out.push({ kind: 'iot' });
  if (svc.is_staging_env) out.push({ kind: 'staging' });
  return out;
}

/** Union of service categories for a host; detail lists the ports. */
export function hostFlags(services: Array<FlaggableService> | undefined): CategoryFlag[] {
  const by = new Map<CategoryKind, string[]>();
  for (const s of services || []) {
    for (const f of serviceFlags(s)) {
      const list = by.get(f.kind) || [];
      list.push(...(f.detail?.length ? f.detail.map((d) => `:${s.port} ${d}`) : [`port ${s.port}`]));
      by.set(f.kind, list);
    }
  }
  return CATEGORY_ORDER.filter((k) => by.has(k)).map((kind) => ({ kind, detail: by.get(kind) }));
}

/** One icon badge. With `link`, clicking lists every host in that category. */
export function CategoryBadge({
  kind,
  detail,
  link,
  size = 'sm',
  label,
  className,
}: {
  kind: CategoryKind;
  detail?: string[];
  link?: boolean;
  size?: 'xs' | 'sm';
  /** Show the label next to the icon (filter chips, legends). */
  label?: boolean;
  className?: string;
}) {
  const meta = CATEGORY_META[kind];
  const IconC = meta.icon;
  const cls = cn(
    'inline-flex shrink-0 items-center justify-center gap-1 border',
    size === 'xs' ? 'size-[18px]' : 'size-5',
    label && 'w-auto px-1.5 text-[10px] font-semibold tracking-wider uppercase',
    meta.tone,
    link && 'transition-opacity hover:opacity-80',
    className
  );
  const inner = (
    <>
      <IconC className={size === 'xs' ? 'size-3' : 'size-3.5'} />
      {label && meta.label}
    </>
  );
  const shown = (detail || []).slice(0, 4);
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          link ? (
            <Link
              to={assetsLink(meta.query)}
              onClick={(e) => e.stopPropagation()}
              aria-label={meta.label}
              className={cls}
            />
          ) : (
            <span role="img" aria-label={meta.label} className={cls} />
          )
        }
      >
        {inner}
      </TooltipTrigger>
      <TooltipContent className="max-w-sm flex-col items-start gap-0.5 text-left">
        <span className="font-semibold">{meta.label}</span>
        {shown.length === 0 ? (
          <span className="opacity-80">{meta.hint}</span>
        ) : (
          shown.map((d, i) => (
            <span key={i} className="opacity-80">
              {d}
            </span>
          ))
        )}
        {(detail?.length || 0) > shown.length && (
          <span className="opacity-60">+{formatNumber(detail!.length - shown.length)} more</span>
        )}
      </TooltipContent>
    </Tooltip>
  );
}

/** Row of badges for a list of flags. */
export function CategoryBadges({
  flags,
  link,
  size,
  max,
  className,
}: {
  flags: CategoryFlag[];
  link?: boolean;
  size?: 'xs' | 'sm';
  max?: number;
  className?: string;
}) {
  if (flags.length === 0) return null;
  const shown = max ? flags.slice(0, max) : flags;
  return (
    <span className={cn('inline-flex shrink-0 items-center gap-1', className)}>
      {shown.map((f) => (
        <CategoryBadge key={f.kind} kind={f.kind} detail={f.detail} link={link} size={size} />
      ))}
      {max && flags.length > max && (
        <span className="text-[10px] text-muted-foreground">+{flags.length - max}</span>
      )}
    </span>
  );
}
