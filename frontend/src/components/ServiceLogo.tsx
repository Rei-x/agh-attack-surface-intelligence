import * as React from 'react';
import type { SimpleIcon } from 'simple-icons';
import {
  siAdminer,
  siAngular,
  siApache,
  siApachetomcat,
  siCaddy,
  siCentos,
  siCisco,
  siCloudflare,
  siDebian,
  siDell,
  siDjango,
  siDocker,
  siDotnet,
  siDovecot,
  siDrupal,
  siEclipsejetty,
  siElasticsearch,
  siExpress,
  siFlask,
  siFortinet,
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
  siLenovo,
  siLinux,
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
  siPaloaltonetworks,
  siPhp,
  siPhpmyadmin,
  siPortainer,
  siPostgresql,
  siPrometheus,
  siProxmox,
  siPython,
  siQnap,
  siRabbitmq,
  siReact,
  siRedis,
  siRoundcube,
  siSpring,
  siSpringboot,
  siSupermicro,
  siSwagger,
  siSymfony,
  siSynology,
  siTraefikproxy,
  siTruenas,
  siTypo3,
  siUbiquiti,
  siUbuntu,
  siVault,
  siVmware,
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
import { useTheme } from '@/context/ThemeContext';
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

/**
 * Tier 1 — applications, appliances and devices: what the analyst has to act on ("you run
 * phpMyAdmin"). Matched across ALL candidate strings before any web server / framework, so
 * WordPress on Apache shows WordPress and iDRAC built with Angular shows Dell.
 */
const APP_RULES: Rule[] = [
  // CMS / web apps
  { keys: ['phpmyadmin'], si: siPhpmyadmin },
  { keys: ['wordpress', 'wp-admin', 'wp-login', 'woocommerce'], si: siWordpress },
  { keys: ['drupal'], si: siDrupal },
  { keys: ['joomla'], si: siJoomla },
  { keys: ['moodle'], si: siMoodle },
  { keys: ['mediawiki'], Icon: RiBook2Line, label: 'MediaWiki', color: '#3366CC' },
  { keys: ['ghost'], si: siGhost },
  { keys: ['typo3'], si: siTypo3 },
  { keys: ['keycloak'], si: siKeycloak },
  { keys: ['gitlab'], si: siGitlab },
  { keys: ['gitea'], si: siGitea },
  { keys: ['grafana'], si: siGrafana },
  { keys: ['zabbix'], Icon: RiServerLine, label: 'Zabbix', color: '#D40000' },
  { keys: ['jenkins'], si: siJenkins },
  { keys: ['prometheus', 'node exporter', 'node-exporter'], si: siPrometheus },
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
  { keys: ['docker', 'docker-registry'], si: siDocker },
  { keys: ['kubernetes', 'k8s', 'kubelet'], si: siKubernetes },
  // Databases (the product is the listener itself)
  { keys: ['postgresql', 'postgres'], si: siPostgresql },
  { keys: ['mariadb'], si: siMariadb },
  { keys: ['mysql'], si: siMysql },
  { keys: ['redis'], si: siRedis },
  { keys: ['mongodb', 'mongo'], si: siMongodb },
  // Mail
  { keys: ['dovecot'], si: siDovecot },
  { keys: ['exim'], Icon: RiMailLine, label: 'Exim', color: '#0EA5E9' },
  { keys: ['postfix'], Icon: RiMailLine, label: 'Postfix', color: '#0EA5E9' },
  // Server management (BMC) and hardware vendors
  { keys: ['idrac', 'idrac9', 'idrac8', 'integrated dell remote access', 'dell'], si: siDell, label: 'Dell iDRAC' },
  { keys: ['ilo', 'hpe', 'integrated lights-out', 'lights-out', 'hp-ilo'], si: siHp, label: 'HPE iLO' },
  { keys: ['supermicro'], si: siSupermicro },
  { keys: ['lenovo', 'xclarity'], si: siLenovo },
  { keys: ['vmware', 'esxi', 'vcenter', 'vsphere'], si: siVmware },
  // Network / security appliances, NAS
  { keys: ['mikrotik', 'routeros', 'winbox'], si: siMikrotik },
  { keys: ['fortinet', 'fortigate', 'fortios'], si: siFortinet },
  { keys: ['palo alto', 'paloalto', 'pan-os', 'globalprotect'], si: siPaloaltonetworks },
  { keys: ['cisco'], si: siCisco },
  { keys: ['ubiquiti', 'unifi', 'edgeos'], si: siUbiquiti },
  { keys: ['synology', 'diskstation', 'dsm'], si: siSynology },
  { keys: ['qnap'], si: siQnap },
  { keys: ['truenas', 'freenas'], si: siTruenas },
  // Cameras / printers
  { keys: ['hikvision', 'hik', 'dvr', 'nvr', 'ipcam', 'ip camera', 'rtsp'], Icon: RiWebcamLine, label: 'Hikvision', color: '#E60012', accent: '#E60012' },
  { keys: ['brother'], Icon: RiPrinterLine, label: 'Brother printer', color: '#0D47A1' },
  { keys: ['laserjet', 'officejet', 'hewlett', 'jetdirect', 'hp'], si: siHp },
  { keys: ['cups'], Icon: RiPrinterLine, label: 'CUPS printing', color: '#0EA5E9' },
  { keys: ['printer', 'ipp'], Icon: RiPrinterLine, label: 'Printer', color: '#0EA5E9' },
  // Windows remote access
  { keys: ['microsoft terminal services', 'terminal services', 'ms-wbt-server', 'rdp'], Icon: RiWindowsFill, label: 'Windows RDP', color: '#0078D4' },
  // Operating systems visible from the outside (default pages, telnetd)
  { keys: ['ubuntu'], si: siUbuntu },
  { keys: ['debian'], si: siDebian },
  { keys: ['centos'], si: siCentos },
  { keys: ['linux telnetd', 'linux'], si: siLinux },
];

/** Tier 1b — device categories when no vendor is known (a BMC signature without a brand). */
const DEVICE_RULES: Rule[] = [
  { keys: ['server bmc', 'bmc', 'ipmi'], Icon: RiServerLine, label: 'Server BMC', color: '#0EA5E9' },
  { keys: ['camera', 'webcam'], Icon: RiWebcamLine, label: 'Camera', color: '#06B6D4' },
];

/** Tier 2 — frameworks / runtimes (more telling than the web server in front of them). */
const FRAMEWORK_RULES: Rule[] = [
  { keys: ['spring boot', 'spring-boot', 'springboot', 'whitelabel error'], si: siSpringboot },
  { keys: ['spring'], si: siSpring },
  { keys: ['flask', 'werkzeug'], si: siFlask },
  { keys: ['django', 'csrftoken', 'wsgiserver'], si: siDjango },
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
  { keys: ['gunicorn'], si: siGunicorn },
  { keys: ['php', 'phpsessid'], si: siPhp },
];

/** Tier 3 — generic web servers / proxies. */
const SERVER_RULES: Rule[] = [
  { keys: ['tomcat', 'coyote'], si: siApachetomcat },
  { keys: ['jetty'], si: siEclipsejetty },
  { keys: ['iis', 'microsoft-iis', 'microsoft iis'], Icon: RiWindowsFill, label: 'Microsoft IIS', color: '#0078D4' },
  { keys: ['nginx', 'openresty'], si: siNginx },
  { keys: ['apache', 'httpd'], si: siApache },
  { keys: ['caddy'], si: siCaddy },
  { keys: ['traefik'], si: siTraefikproxy },
  { keys: ['haproxy'], si: siHaproxy },
  { keys: ['cloudflare'], si: siCloudflare },
];

/** Generic protocol / tag fallbacks (only after every brand tier misses). */
const GENERIC_RULES: Rule[] = [
  { keys: ['ssh', 'openssh', 'dropbear'], Icon: RiTerminalBoxLine, label: 'SSH', color: '#64748B' },
  { keys: ['telnet'], Icon: RiTerminalLine, label: 'Telnet', color: '#F97316' },
  { keys: ['ftp', 'sftp', 'vsftpd', 'proftpd'], Icon: RiFolderTransferLine, label: 'FTP', color: '#8B5CF6' },
  { keys: ['smtp', 'imap', 'pop3', 'mail', 'smtpd'], Icon: RiMailLine, label: 'Mail', color: '#0EA5E9' },
  { keys: ['dns', 'bind', 'named', 'domain'], Icon: RiSignalTowerLine, label: 'DNS', color: '#14B8A6' },
  { keys: ['vnc'], Icon: RiComputerLine, label: 'Remote desktop', color: '#0078D4' },
  { keys: ['smb', 'microsoft-ds', 'netbios', 'netbios-ssn', 'msrpc', 'samba', 'nfs'], Icon: RiFolderSharedLine, label: 'File share / Windows RPC', color: '#6366F1' },
  { keys: ['snmp', 'router', 'mqtt', 'modbus', 'upnp'], Icon: RiRouterLine, label: 'Network device', color: '#06B6D4' },
  { keys: ['database', 'db', 'sql', 'mssql', 'ms-sql-s', 'oracle'], Icon: RiDatabase2Line, label: 'Database', color: '#6366F1' },
  { keys: ['admin_panel', 'admin', 'panel', 'login', 'console', 'dashboard'], Icon: RiShieldKeyholeLine, label: 'Admin panel', color: '#F59E0B' },
  { keys: ['staging', 'stage', 'dev', 'test', 'qa', 'uat', 'debug'], Icon: RiFlaskLine, label: 'Staging', color: '#8B5CF6' },
  { keys: ['iot', 'embedded', 'firmware'], Icon: RiCpuLine, label: 'IoT', color: '#06B6D4' },
  { keys: ['https', 'tls', 'ssl', 'https-alt'], Icon: RiLockLine, label: 'HTTPS', color: '#10B981' },
  { keys: ['http', 'http-alt', 'http-proxy', 'www', 'web'], Icon: RiGlobalLine, label: 'HTTP', color: '#3B82F6' },
  { keys: ['scope', 'cidr', 'subnet', 'network'], Icon: RiRadarLine, label: 'Scope', color: '#3B82F6' },
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
  135: 'msrpc',
  139: 'netbios',
  143: 'imap',
  161: 'snmp',
  443: 'https',
  445: 'smb',
  554: 'rtsp',
  587: 'smtp',
  623: 'ipmi',
  631: 'ipp',
  993: 'imap',
  995: 'pop3',
  1433: 'mssql',
  1883: 'mqtt',
  3000: 'http',
  3306: 'mysql',
  3389: 'rdp',
  5000: 'http',
  5432: 'postgresql',
  5601: 'kibana',
  5672: 'rabbitmq',
  5900: 'vnc',
  6379: 'redis',
  8000: 'http',
  8008: 'http',
  8080: 'http',
  8081: 'http',
  8291: 'winbox',
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

const TIERS: CompiledRule[][] = [APP_RULES, DEVICE_RULES, FRAMEWORK_RULES, SERVER_RULES].map(compile);
const ALL_BRANDS = TIERS.flat();
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

const genericByKey = (k: string) => toLogo(GENERIC_RULES.find((r) => r.keys[0] === k)!);

/**
 * Normalise one candidate string. The builtin BMC signature is named "Server BMC (Dell
 * iDRAC / HPE iLO)": its vendor list is a description, not evidence, so it is dropped and the
 * real vendor comes from the title / TLS / product candidates.
 */
function normalise(c: string): string {
  return c
    .toLowerCase()
    .replace(/\(dell idrac \/ hpe ilo\)/g, '')
    .replace(/_/g, ' ')
    .trim();
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
 * Resolve the best logo for any mix of product / tech / title / service-name strings.
 * Tiered: apps & devices (any candidate) → device categories → frameworks → web servers →
 * protocol / tag / port icons.
 */
export function resolveServiceLogo(
  candidates: Array<string | null | undefined> | string | null | undefined,
  hints: LogoHints = {}
): ResolvedLogo {
  const list = (Array.isArray(candidates) ? candidates : [candidates])
    .filter((c): c is string => typeof c === 'string' && c.trim() !== '')
    .map(normalise)
    .filter(Boolean);
  const key = `${list.join('|')}#${hints.port ?? ''}${hints.isAdmin ? 'a' : ''}${hints.isStaging ? 's' : ''}${hints.isIoT ? 'i' : ''}${hints.tls ? 't' : ''}${hints.kind ?? ''}`;
  const hit = cache.get(key);
  if (hit) return hit;

  const resolve = (): ResolvedLogo => {
    if (hints.kind === 'scope') return genericByKey('scope');
    for (const tier of TIERS) {
      for (const c of list) {
        const r = tier.find((b) => b.re.test(c));
        if (r) return toLogo(r);
      }
    }
    if (hints.isIoT) return genericByKey('iot');
    if (hints.isAdmin) return genericByKey('admin_panel');
    if (hints.isStaging) return genericByKey('staging');
    for (const c of list) {
      const r = GENERIC.find((g) => g.re.test(c));
      if (r) return toLogo(r);
    }
    if (hints.port && PORT_FALLBACK[hints.port]) {
      const p = PORT_FALLBACK[hints.port];
      const r = ALL_BRANDS.find((b) => b.re.test(p)) || GENERIC.find((g) => g.re.test(p));
      if (r) return toLogo(r);
    }
    if (hints.tls) return genericByKey('https');
    return genericByKey(hints.kind === 'host' ? 'host' : 'http');
  };

  const out = resolve();
  if (cache.size > 2000) cache.clear();
  cache.set(key, out);
  return out;
}

/* ---------- contrast against the actual theme surface ---------- */

const SURFACE = { light: '#ffffff', dark: '#111413' } as const; // --card in index.css

function hexRgb(hex: string): [number, number, number] | null {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex);
  if (!m) return null;
  const n = parseInt(m[1], 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function luminance([r, g, b]: [number, number, number]): number {
  const ch = (v: number) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b);
}

/** WCAG contrast of the brand colour on its own 10 % tint over the card surface. */
export function logoContrast(hex: string, theme: 'light' | 'dark'): number {
  const fg = hexRgb(hex);
  const surface = hexRgb(SURFACE[theme])!;
  if (!fg) return 21;
  const tile: [number, number, number] = [0, 1, 2].map((i) => Math.round(surface[i] * 0.9 + fg[i] * 0.1)) as [
    number,
    number,
    number,
  ];
  const a = luminance(fg);
  const b = luminance(tile);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
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
    svc.http?.title,
    svc.http?.server_header,
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
  const { theme } = useTheme();
  const logo = resolveServiceLogo(names ?? [name], hints);
  const px = typeof size === 'number' ? size : SIZES[size];
  const glyph = Math.round(px * 0.6);
  // Brand colours too close to the surface (MikroTik #293239, Keycloak #4D4D4D in dark mode,
  // pale brands in light mode) fall back to the foreground colour on a neutral tile.
  const lowContrast = logoContrast(logo.color, theme) < 3;
  const fg = lowContrast ? 'var(--foreground)' : logo.color;
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
        backgroundColor: lowContrast ? 'var(--muted)' : `${logo.color}1A`,
        borderColor: lowContrast ? 'var(--border)' : `${logo.color}40`,
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
