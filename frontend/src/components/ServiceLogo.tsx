import * as React from 'react';
import type { SimpleIcon } from 'simple-icons';
import {
  siAdminer,
  siAngular,
  siApache,
  siApachetomcat,
  siCaddy,
  siCisco,
  siCloudflare,
  siDjango,
  siDocker,
  siDotnet,
  siDrupal,
  siElasticsearch,
  siExpress,
  siFlask,
  siGhost,
  siGitea,
  siGitlab,
  siGrafana,
  siGunicorn,
  siHaproxy,
  siHp,
  siJenkins,
  siJoomla,
  siJupyter,
  siKeycloak,
  siKibana,
  siKubernetes,
  siLaravel,
  siMariadb,
  siMikrotik,
  siMinio,
  siMongodb,
  siMoodle,
  siMysql,
  siNextcloud,
  siNextdotjs,
  siNginx,
  siNodedotjs,
  siOpensearch,
  siPhp,
  siPhpmyadmin,
  siPortainer,
  siPostgresql,
  siPrometheus,
  siProxmox,
  siPython,
  siRabbitmq,
  siReact,
  siRedis,
  siRoundcube,
  siSpring,
  siSpringboot,
  siSwagger,
  siSymfony,
  siSynology,
  siTraefikproxy,
  siTypo3,
  siUbiquiti,
  siVault,
  siVuedotjs,
  siWordpress,
} from 'simple-icons';
import {
  RiBook2Line,
  RiComputerLine,
  RiCpuLine,
  RiDatabase2Line,
  RiFlaskLine,
  RiFolderSharedLine,
  RiFolderTransferLine,
  RiGlobalLine,
  RiLockLine,
  RiMailLine,
  RiPrinterLine,
  RiRadarLine,
  RiRouterLine,
  RiServerLine,
  RiShieldKeyholeLine,
  RiSignalTowerLine,
  RiTerminalBoxLine,
  RiTerminalLine,
  RiWebcamLine,
  RiWindowsFill,
} from '@remixicon/react';
import { cn } from '@/lib/utils';

type RemixIcon = React.ComponentType<{ className?: string; style?: React.CSSProperties }>;

export interface ResolvedLogo {
  label: string;
  /** Brand / accent hex color (#RRGGBB). */
  color: string;
  /** simple-icons SVG path (24×24 viewBox) when a brand logo is available. */
  path?: string;
  /** Remix icon fallback. */
  Icon?: RemixIcon;
  /** Optional small accent dot (e.g. Hikvision red). */
  accent?: string;
  kind: 'brand' | 'icon';
}

interface Rule {
  keys: string[];
  si?: SimpleIcon;
  Icon?: RemixIcon;
  label?: string;
  color?: string;
  accent?: string;
}

/** Ordered: more specific products first (phpMyAdmin before PHP, Tomcat before Apache…). */
const BRAND_RULES: Rule[] = [
  // CMS / apps
  { keys: ['phpmyadmin'], si: siPhpmyadmin },
  { keys: ['wordpress', 'wp-admin', 'wp-login', 'woocommerce'], si: siWordpress },
  { keys: ['drupal'], si: siDrupal },
  { keys: ['joomla'], si: siJoomla },
  { keys: ['moodle'], si: siMoodle },
  { keys: ['mediawiki', 'wiki'], Icon: RiBook2Line, label: 'MediaWiki', color: '#3366CC' },
  { keys: ['ghost'], si: siGhost },
  { keys: ['typo3'], si: siTypo3 },
  { keys: ['keycloak'], si: siKeycloak },
  { keys: ['gitlab'], si: siGitlab },
  { keys: ['gitea'], si: siGitea },
  { keys: ['grafana'], si: siGrafana },
  { keys: ['zabbix'], Icon: RiServerLine, label: 'Zabbix', color: '#D40000' },
  { keys: ['jenkins'], si: siJenkins },
  { keys: ['prometheus'], si: siPrometheus },
  { keys: ['kibana'], si: siKibana },
  { keys: ['opensearch'], si: siOpensearch },
  { keys: ['elasticsearch', 'elastic'], si: siElasticsearch },
  { keys: ['portainer'], si: siPortainer },
  { keys: ['swagger', 'openapi', 'swagger-ui'], si: siSwagger },
  { keys: ['roundcube'], si: siRoundcube },
  { keys: ['adminer'], si: siAdminer },
  { keys: ['nextcloud'], si: siNextcloud },
  { keys: ['jupyter'], si: siJupyter },
  { keys: ['minio'], si: siMinio },
  { keys: ['vault'], si: siVault },
  { keys: ['rabbitmq'], si: siRabbitmq },
  { keys: ['proxmox'], si: siProxmox },
  // Frameworks / runtimes
  { keys: ['spring boot', 'spring-boot', 'springboot', 'whitelabel error'], si: siSpringboot },
  { keys: ['spring'], si: siSpring },
  { keys: ['flask', 'werkzeug'], si: siFlask },
  { keys: ['gunicorn'], si: siGunicorn },
  { keys: ['django', 'csrftoken'], si: siDjango },
  { keys: ['laravel', 'laravel_session'], si: siLaravel },
  { keys: ['symfony'], si: siSymfony },
  { keys: ['next.js', 'nextjs'], si: siNextdotjs },
  { keys: ['express'], si: siExpress },
  { keys: ['react'], si: siReact },
  { keys: ['angular'], si: siAngular },
  { keys: ['vue', 'vue.js', 'vuejs', 'nuxt'], si: siVuedotjs },
  { keys: ['node.js', 'nodejs', 'node'], si: siNodedotjs },
  { keys: ['asp.net', 'aspnet', '.net', 'dotnet', 'x-aspnet-version'], si: siDotnet },
  { keys: ['python', 'uvicorn', 'fastapi'], si: siPython },
  { keys: ['php', 'phpsessid'], si: siPhp },
  // Web servers / proxies / infra
  { keys: ['tomcat', 'coyote'], si: siApachetomcat },
  { keys: ['iis', 'microsoft-iis', 'microsoft iis'], Icon: RiWindowsFill, label: 'Microsoft IIS', color: '#0078D4' },
  { keys: ['nginx', 'openresty'], si: siNginx },
  { keys: ['apache', 'httpd'], si: siApache },
  { keys: ['caddy'], si: siCaddy },
  { keys: ['traefik'], si: siTraefikproxy },
  { keys: ['haproxy'], si: siHaproxy },
  { keys: ['cloudflare'], si: siCloudflare },
  { keys: ['docker', 'docker-registry'], si: siDocker },
  { keys: ['kubernetes', 'k8s', 'kubelet'], si: siKubernetes },
  // Databases
  { keys: ['postgresql', 'postgres'], si: siPostgresql },
  { keys: ['mariadb'], si: siMariadb },
  { keys: ['mysql'], si: siMysql },
  { keys: ['redis'], si: siRedis },
  { keys: ['mongodb', 'mongo'], si: siMongodb },
  // IoT / network brands
  { keys: ['hikvision', 'hik', 'dvr', 'nvr', 'ipcam', 'ip camera', 'rtsp'], Icon: RiWebcamLine, label: 'Hikvision', color: '#E60012', accent: '#E60012' },
  { keys: ['hp', 'laserjet', 'officejet', 'hewlett', 'jetdirect'], si: siHp },
  { keys: ['printer', 'ipp', 'cups'], Icon: RiPrinterLine, label: 'Drukarka', color: '#0EA5E9' },
  { keys: ['mikrotik', 'routeros', 'winbox'], si: siMikrotik },
  { keys: ['cisco'], si: siCisco },
  { keys: ['ubiquiti', 'unifi', 'edgeos'], si: siUbiquiti },
  { keys: ['synology', 'diskstation', 'dsm'], si: siSynology },
];

/** Generic protocol / tag fallbacks (only after brand rules miss). */
const GENERIC_RULES: Rule[] = [
  { keys: ['ssh', 'openssh', 'dropbear'], Icon: RiTerminalBoxLine, label: 'SSH', color: '#64748B' },
  { keys: ['telnet'], Icon: RiTerminalLine, label: 'Telnet', color: '#F97316' },
  { keys: ['ftp', 'sftp', 'vsftpd', 'proftpd'], Icon: RiFolderTransferLine, label: 'FTP', color: '#8B5CF6' },
  { keys: ['smtp', 'imap', 'pop3', 'mail', 'postfix', 'exim', 'dovecot'], Icon: RiMailLine, label: 'Mail', color: '#0EA5E9' },
  { keys: ['dns', 'bind', 'named'], Icon: RiSignalTowerLine, label: 'DNS', color: '#14B8A6' },
  { keys: ['rdp', 'ms-wbt-server', 'vnc'], Icon: RiComputerLine, label: 'Pulpit zdalny', color: '#0078D4' },
  { keys: ['smb', 'microsoft-ds', 'netbios', 'samba', 'nfs'], Icon: RiFolderSharedLine, label: 'Udział plików', color: '#6366F1' },
  { keys: ['snmp', 'router', 'mqtt', 'modbus', 'upnp'], Icon: RiRouterLine, label: 'Urządzenie sieciowe', color: '#06B6D4' },
  { keys: ['database', 'db', 'sql', 'mssql', 'oracle'], Icon: RiDatabase2Line, label: 'Baza danych', color: '#6366F1' },
  { keys: ['admin_panel', 'admin', 'panel', 'login', 'console', 'dashboard'], Icon: RiShieldKeyholeLine, label: 'Panel admina', color: '#F59E0B' },
  { keys: ['staging', 'stage', 'dev', 'test', 'qa', 'uat', 'debug'], Icon: RiFlaskLine, label: 'Staging', color: '#8B5CF6' },
  { keys: ['iot', 'embedded', 'firmware', 'camera'], Icon: RiCpuLine, label: 'IoT', color: '#06B6D4' },
  { keys: ['https', 'tls', 'ssl', 'https-alt'], Icon: RiLockLine, label: 'HTTPS', color: '#10B981' },
  { keys: ['http', 'http-alt', 'http-proxy', 'www', 'web'], Icon: RiGlobalLine, label: 'HTTP', color: '#3B82F6' },
  { keys: ['scope', 'cidr', 'subnet', 'network'], Icon: RiRadarLine, label: 'Zakres', color: '#3B82F6' },
  { keys: ['host', 'server'], Icon: RiServerLine, label: 'Host', color: '#78716C' },
];

const PORT_FALLBACK: Record<number, string> = {
  21: 'ftp',
  22: 'ssh',
  23: 'telnet',
  25: 'smtp',
  53: 'dns',
  80: 'http',
  110: 'pop3',
  143: 'imap',
  161: 'snmp',
  443: 'https',
  445: 'smb',
  554: 'rtsp',
  587: 'smtp',
  631: 'ipp',
  993: 'imap',
  1433: 'mssql',
  1883: 'mqtt',
  3000: 'http',
  3306: 'mysql',
  3389: 'rdp',
  5000: 'http',
  5432: 'postgresql',
  5672: 'rabbitmq',
  5900: 'vnc',
  6379: 'redis',
  8000: 'http',
  8008: 'http',
  8080: 'http',
  8081: 'http',
  8443: 'https',
  8888: 'http',
  9000: 'http',
  9090: 'prometheus',
  9100: 'printer',
  9200: 'elasticsearch',
  27017: 'mongodb',
};

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

interface CompiledRule extends Rule {
  re: RegExp;
}

function compile(rules: Rule[]): CompiledRule[] {
  return rules.map((r) => ({
    ...r,
    // Token-boundary match so "hp" doesn't hit "php" and "next" doesn't hit "nextcloud".
    re: new RegExp(`(^|[^a-z0-9])(${r.keys.map(escapeRe).join('|')})(?=$|[^a-z0-9])`, 'i'),
  }));
}

const BRAND = compile(BRAND_RULES);
const GENERIC = compile(GENERIC_RULES);

function toLogo(r: Rule): ResolvedLogo {
  if (r.si) {
    return {
      label: r.label || r.si.title,
      color: r.color || `#${r.si.hex}`,
      path: r.si.path,
      accent: r.accent,
      kind: 'brand',
    };
  }
  return {
    label: r.label || r.keys[0],
    color: r.color || '#78716C',
    Icon: r.Icon,
    accent: r.accent,
    kind: 'icon',
  };
}

const cache = new Map<string, ResolvedLogo>();

export interface LogoHints {
  port?: number;
  isAdmin?: boolean;
  isStaging?: boolean;
  isIoT?: boolean;
  tls?: boolean;
  /** Node kind hint, e.g. 'scope' | 'host'. */
  kind?: string;
}

/**
 * Resolve the best brand logo for any mix of service name / product / tech / title strings.
 * Case-insensitive, alias-aware; falls back to protocol / tag / port icons.
 */
export function resolveServiceLogo(
  candidates: Array<string | null | undefined> | string | null | undefined,
  hints: LogoHints = {}
): ResolvedLogo {
  const list = (Array.isArray(candidates) ? candidates : [candidates]).filter(
    (c): c is string => typeof c === 'string' && c.trim() !== ''
  );
  const key = `${list.join('|').toLowerCase()}#${hints.port ?? ''}${hints.isAdmin ? 'a' : ''}${hints.isStaging ? 's' : ''}${hints.isIoT ? 'i' : ''}${hints.tls ? 't' : ''}${hints.kind ?? ''}`;
  const hit = cache.get(key);
  if (hit) return hit;

  const resolve = (): ResolvedLogo => {
    if (hints.kind === 'scope') return toLogo(GENERIC_RULES.find((r) => r.keys[0] === 'scope')!);
    // Brand rules: walk candidates in priority order so `product` beats `service_name`.
    for (const c of list) {
      const s = c.toLowerCase().replace(/_/g, ' ');
      const r = BRAND.find((b) => b.re.test(s) || b.re.test(c.toLowerCase()));
      if (r) return toLogo(r);
    }
    if (hints.isIoT) return toLogo(GENERIC_RULES.find((r) => r.keys[0] === 'iot')!);
    if (hints.isAdmin) return toLogo(GENERIC_RULES.find((r) => r.keys[0] === 'admin_panel')!);
    if (hints.isStaging) return toLogo(GENERIC_RULES.find((r) => r.keys[0] === 'staging')!);
    for (const c of list) {
      const r = GENERIC.find((g) => g.re.test(c.toLowerCase()));
      if (r) return toLogo(r);
    }
    if (hints.port && PORT_FALLBACK[hints.port]) {
      const p = PORT_FALLBACK[hints.port];
      const r = BRAND.find((b) => b.re.test(p)) || GENERIC.find((g) => g.re.test(p));
      if (r) return toLogo(r);
    }
    if (hints.tls) return toLogo(GENERIC_RULES.find((r) => r.keys[0] === 'https')!);
    return toLogo(GENERIC_RULES.find((r) => r.keys[0] === (hints.kind === 'host' ? 'host' : 'http'))!);
  };

  const out = resolve();
  if (cache.size > 2000) cache.clear();
  cache.set(key, out);
  return out;
}

function isVeryDark(hex: string): boolean {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex);
  if (!m) return false;
  const n = parseInt(m[1], 16);
  const r = (n >> 16) & 255;
  const g = (n >> 8) & 255;
  const b = n & 255;
  return 0.2126 * r + 0.7152 * g + 0.0722 * b < 48;
}

const SIZES = { xs: 18, sm: 22, md: 28, lg: 32, xl: 40 } as const;

export interface ServiceLogoProps extends LogoHints {
  /** Primary strings to match: product, service name, technology, title, banner… */
  name?: string | null;
  names?: Array<string | null | undefined>;
  size?: keyof typeof SIZES | number;
  className?: string;
  /** Show the brand label as a native tooltip (default true). */
  title?: boolean;
}

interface ServiceLike {
  port?: number;
  product?: string;
  service_name?: string;
  is_admin_panel?: boolean;
  is_staging_env?: boolean;
  is_iot?: boolean;
  technologies?: Array<{ name: string; confidence?: number }>;
  matched_signatures?: string[];
  http?: { title?: string; server_header?: string; meta_generator?: string; tls?: unknown } | null;
}

/** Candidate strings for a Service, highest-signal first (product → techs → headers → name). */
export function serviceLogoNames(svc: ServiceLike): string[] {
  const techs = [...(svc.technologies || [])]
    .sort((a, b) => (b.confidence || 0) - (a.confidence || 0))
    .map((t) => t.name);
  return [
    svc.product,
    svc.http?.meta_generator,
    ...techs,
    ...(svc.matched_signatures || []),
    svc.http?.server_header,
    svc.http?.title,
    svc.service_name,
  ].filter((s): s is string => typeof s === 'string' && s.trim() !== '');
}

/** Convenience wrapper: <ServiceLogo/> from a Service object. */
export function ServiceLogoFor({
  service,
  size = 'sm',
  className,
}: {
  service: ServiceLike;
  size?: ServiceLogoProps['size'];
  className?: string;
}) {
  return (
    <ServiceLogo
      names={serviceLogoNames(service)}
      port={service.port}
      isAdmin={service.is_admin_panel}
      isStaging={service.is_staging_env}
      isIoT={service.is_iot}
      tls={Boolean(service.http?.tls)}
      size={size}
      className={className}
    />
  );
}

/** Crisp tinted square tile with an official brand SVG (or a Remix fallback icon). */
export const ServiceLogo = React.memo(function ServiceLogo({
  name,
  names,
  size = 'sm',
  className,
  title = true,
  ...hints
}: ServiceLogoProps) {
  const logo = resolveServiceLogo(names ?? [name], hints);
  const px = typeof size === 'number' ? size : SIZES[size];
  const glyph = Math.round(px * 0.6);
  const dark = isVeryDark(logo.color);
  const fg = dark ? 'var(--foreground)' : logo.color;
  const Icon = logo.Icon;

  return (
    <span
      role="img"
      aria-label={logo.label}
      title={title ? logo.label : undefined}
      className={cn('relative inline-flex shrink-0 items-center justify-center border', className)}
      style={{
        width: px,
        height: px,
        backgroundColor: dark ? 'var(--muted)' : `${logo.color}1A`,
        borderColor: dark ? 'var(--border)' : `${logo.color}40`,
      }}
    >
      {logo.path ? (
        <svg viewBox="0 0 24 24" width={glyph} height={glyph} aria-hidden style={{ fill: fg }}>
          <path d={logo.path} />
        </svg>
      ) : Icon ? (
        <Icon style={{ width: glyph, height: glyph, color: fg }} />
      ) : null}
      {logo.accent && (
        <span
          className="absolute top-0.5 right-0.5 size-1.5"
          style={{ backgroundColor: logo.accent }}
          aria-hidden
        />
      )}
    </span>
  );
});
