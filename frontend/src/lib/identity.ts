import type { Host, Service } from '@/types/api';

/**
 * Device identity derived from the fingerprints of a host's services: "what is this box?"
 * (vendor / product / version / OS / device kind). nmap OS detection is rarely available
 * (unprivileged scans), but product banners and page titles usually tell: a host with
 * "MikroTik router ftpd 7.14.3" is a MikroTik running RouterOS 7.14.3.
 */
export interface HostIdentity {
  vendor?: string;
  product?: string;
  version?: string;
  os?: string;
  kind?: string;
  /** Candidate strings for <ServiceLogo names=…/>. */
  logoNames: string[];
  /** Short evidence ("ftp/21 banner: MikroTik router ftpd 7.14.3"). */
  evidence?: string;
}

type Svc = Pick<Service, 'port' | 'service_name' | 'product' | 'version' | 'technologies' | 'matched_signatures' | 'http'>;

const APP_CATEGORY_RANK: Record<string, number> = { cms: 0, admin_panel: 1, iot: 2, framework: 3, server: 4 };

function texts(s: Svc): string {
  return [
    s.product,
    s.version,
    s.service_name,
    s.http?.title,
    s.http?.server_header,
    ...(s.technologies || []).map((t) => t.name),
    ...(s.matched_signatures || []),
  ]
    .filter(Boolean)
    .join(' | ');
}

const VERSION_RE = /\b(\d+(?:\.\d+){1,3}[a-z0-9]*)\b/i;

interface DeviceRule {
  test: RegExp;
  vendor: string;
  product: string | ((s: Svc) => string);
  kind: string;
  os?: string;
  logo: string;
}

const DEVICE_RULES: DeviceRule[] = [
  { test: /mikrotik|routeros|winbox/i, vendor: 'MikroTik', product: 'RouterOS', kind: 'Router', os: 'RouterOS', logo: 'mikrotik' },
  {
    test: /idrac|integrated dell remote access/i,
    vendor: 'Dell',
    product: (s) => /idrac\s?(\d+)/i.exec(texts(s))?.[0].replace(/\s/, '') || 'iDRAC',
    kind: 'Server BMC',
    logo: 'idrac',
  },
  {
    test: /\bilo\b|integrated lights-out|hp-ilo/i,
    vendor: 'HPE',
    product: (s) => (/\bilo\s?(\d+)/i.exec(texts(s))?.[0] || 'iLO').replace(/^ilo/i, 'iLO'),
    kind: 'Server BMC',
    logo: 'ilo',
  },
  { test: /hikvision/i, vendor: 'Hikvision', product: 'IP camera / NVR', kind: 'Camera', logo: 'hikvision' },
  {
    test: /brother/i,
    vendor: 'Brother',
    product: (s) => /brother\s+([A-Z]{2,4}-[A-Z0-9]+)/i.exec(texts(s))?.[1] || 'Printer',
    kind: 'Printer',
    logo: 'brother',
  },
  { test: /laserjet|officejet|hp printer|jetdirect/i, vendor: 'HP', product: 'Printer', kind: 'Printer', logo: 'hp' },
  { test: /canon/i, vendor: 'Canon', product: 'Printer', kind: 'Printer', logo: 'printer' },
  { test: /synology|diskstation/i, vendor: 'Synology', product: 'DiskStation (DSM)', kind: 'NAS', os: 'DSM', logo: 'synology' },
  { test: /fortigate|fortinet/i, vendor: 'Fortinet', product: 'FortiGate', kind: 'Firewall', os: 'FortiOS', logo: 'fortinet' },
  { test: /vmware|esxi/i, vendor: 'VMware', product: 'ESXi', kind: 'Hypervisor', logo: 'vmware' },
  { test: /\bbmc\b|ipmi/i, vendor: '', product: 'Server BMC', kind: 'Server BMC', logo: 'bmc' },
];

function osFrom(services: Svc[]): { os?: string; evidence?: string } {
  for (const s of services) {
    const t = texts(s);
    const m = /\b(Ubuntu|Debian|CentOS|Red Hat|RHEL|Fedora|FreeBSD|Alpine)\b/i.exec(t);
    if (m) {
      const name = m[1].toLowerCase() === 'rhel' ? 'Red Hat' : m[1].replace(/^./, (c) => c.toUpperCase());
      return { os: name === 'Centos' ? 'CentOS' : name, evidence: `${s.service_name || 'port'}/${s.port}: ${shorten(t)}` };
    }
  }
  for (const s of services) {
    const t = texts(s);
    if (/microsoft-iis|microsoft iis|iis httpd/i.test(t)) {
      return { os: 'Windows Server', evidence: `${s.service_name}/${s.port}: ${s.product || 'IIS'}` };
    }
  }
  for (const s of services) {
    const t = texts(s);
    if (/ms-wbt-server|terminal services|microsoft-ds|msrpc/i.test(t)) {
      return { os: 'Windows', evidence: `${s.service_name}/${s.port}` };
    }
  }
  for (const s of services) {
    if (/linux/i.test(texts(s))) return { os: 'Linux', evidence: `${s.service_name}/${s.port}: ${s.product || ''}` };
  }
  return {};
}

function shorten(s: string, n = 80): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

export function hostIdentity(host: Pick<Host, 'os_guess' | 'services'>): HostIdentity {
  const services = (host.services || []) as Svc[];
  let id: HostIdentity = { logoNames: [] };
  outer: for (const rule of DEVICE_RULES) {
    for (const s of services) {
      if (!rule.test.test(texts(s))) continue;
      // Version: from a service whose product names the device (e.g. "MikroTik router ftpd" 7.14.3).
      let version: string | undefined;
      for (const s2 of services) {
        if (s2.version && rule.test.test(`${s2.product || ''}`)) {
          version = VERSION_RE.exec(s2.version)?.[1];
          if (version) break;
        }
      }
      id = {
        vendor: rule.vendor || undefined,
        product: typeof rule.product === 'function' ? rule.product(s) : rule.product,
        version,
        kind: rule.kind,
        os: rule.os ? [rule.os, version].filter(Boolean).join(' ') : undefined,
        logoNames: [rule.logo],
        evidence: `${s.service_name || 'port'}/${s.port}: ${shorten(s.product || s.http?.title || texts(s))}`,
      };
      break outer;
    }
  }
  if (host.os_guess) {
    id.os = host.os_guess;
  } else if (!id.os) {
    const o = osFrom(services);
    if (o.os) {
      id.os = o.os;
      id.evidence = id.evidence || o.evidence;
    }
  }
  if (!id.product && !id.os) {
    // Nothing about the box itself: name it after its riskiest identified application.
    const ranked = [...(host.services || [])].sort((a, b) => (b.interestingness || 0) - (a.interestingness || 0));
    for (const s of ranked) {
      const tech = [...(s.technologies || [])]
        .filter((t) => t.category in APP_CATEGORY_RANK && !/admin panel|login portal/i.test(t.name))
        .sort((a, b) => (APP_CATEGORY_RANK[a.category] ?? 9) - (APP_CATEGORY_RANK[b.category] ?? 9))[0];
      const name = tech?.name || s.product;
      if (name) {
        id.product = name;
        id.version = tech?.version || undefined;
        id.logoNames = [name];
        id.evidence = `${s.service_name || 'port'}/${s.port}`;
        break;
      }
    }
  }
  if (!id.kind && services.length > 0) {
    const hasWeb = services.some((s) => s.http || /http/i.test(s.service_name || ''));
    id.kind = hasWeb ? 'Server' : undefined;
  }
  if (id.logoNames.length === 0 && id.os) id.logoNames = [id.os];
  return id;
}

/** "MikroTik RouterOS 7.14.3" style one-liner (empty when nothing is known). */
export function identityLabel(id: HostIdentity): string {
  return [id.vendor, id.product, id.version].filter(Boolean).join(' ');
}
