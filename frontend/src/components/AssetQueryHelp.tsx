import { Pill } from '@/components/common';
import type { TriageInfo } from '@/types/api';
import { formatDateTime } from '@/lib/format';

const KEYS: Array<{ key: string; desc: string }> = [
  { key: 'tech:wordpress', desc: 'technology / signature / product' },
  { key: 'tech:"server bmc"', desc: 'quote values with spaces' },
  { key: 'port:3389', desc: 'port (list: port:80,443)' },
  { key: 'version:1.18', desc: 'product or technology version' },
  { key: 'owner:wi.agh', desc: 'owner (CIDR rules or override)' },
  { key: 'cidr:10.66.0.0/24', desc: 'address range (or a single IP)' },
  { key: 'state:new', desc: 'host lifecycle state' },
  { key: 'env:staging', desc: 'environment' },
  { key: 'tag:wi', desc: 'host or service tag' },
  { key: 'title:"admin"', desc: 'HTTP page title' },
  { key: 'cert:expired', desc: 'TLS: expired, expiring, selfsigned, valid' },
  { key: 'eol:true', desc: 'end-of-life version (offline table)' },
  { key: 'vuln:true', desc: 'known CVE hint (by version, passive)' },
  { key: 'admin:true', desc: 'admin / management panel' },
  { key: 'db:true', desc: 'exposed database' },
  { key: 'cleartext:true', desc: 'telnet / ftp management' },
  { key: 'iot:true', desc: 'IoT device, BMC, printer, camera' },
  { key: 'violation:true', desc: 'breaks its zone policy (Policies page)' },
  { key: 'policy:"server zone"', desc: 'zone name, rule or category (policy:database)' },
  { key: 'triage:accepted_risk', desc: 'new, triaged, accepted_risk, false_positive' },
  { key: 'score:>=70', desc: 'minimum score' },
];

const EXAMPLES = [
  'tech:nginx eol:true',
  'port:3389 -env:prod',
  'tech:wordpress cidr:10.66.0.0/22',
  'admin:true state:new',
  'cert:expired,expiring',
];

/** Short syntax help for the Shodan-like asset query (evaluated server-side). */
export function AssetQueryHelp({ onPick }: { onPick: (q: string) => void }) {
  return (
    <div className="mb-4 border border-border bg-card p-4 text-xs">
      <p className="mb-3 text-muted-foreground">
        <span className="font-mono text-foreground">key:value</span> terms are combined with AND, a comma means
        OR, a leading <span className="font-mono text-foreground">-</span> negates, quotes allow spaces. Other
        words search IP, hostname, banners and notes. Service terms (port, tech, version, title, cert, admin, eol…)
        must all hold for the same service: <span className="font-mono text-foreground">tech:wordpress port:443</span>{' '}
        means WordPress on 443.
      </p>
      <div className="grid gap-x-6 gap-y-1 sm:grid-cols-2 xl:grid-cols-3">
        {KEYS.map((k) => (
          <div key={k.key} className="flex min-w-0 items-baseline gap-2">
            <button
              type="button"
              onClick={() => onPick(k.key)}
              className="shrink-0 font-mono text-foreground underline decoration-border underline-offset-2 hover:decoration-foreground"
            >
              {k.key}
            </button>
            <span className="truncate text-muted-foreground">{k.desc}</span>
          </div>
        ))}
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-1.5">
        <span className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">Examples</span>
        {EXAMPLES.map((ex) => (
          <button
            key={ex}
            type="button"
            onClick={() => onPick(ex)}
            className="border border-border px-1.5 py-0.5 font-mono text-[11px] text-foreground transition-colors hover:border-foreground/40"
          >
            {ex}
          </button>
        ))}
      </div>
    </div>
  );
}

const TRIAGE_LABEL: Record<string, string> = {
  accepted_risk: 'Risk accepted',
  false_positive: 'False positive',
};

/** Compact badge for an analyst risk decision (shows expiry state in the tooltip). */
export function TriageBadge({ triage }: { triage?: TriageInfo | null }) {
  if (!triage || !TRIAGE_LABEL[triage.status]) return null;
  const title = [
    triage.reason,
    `${triage.by || 'unknown'} · ${formatDateTime(triage.at)}`,
    triage.expires_at ? `Expires: ${formatDateTime(triage.expires_at)}` : 'No expiry',
  ].join('\n');
  if (triage.expired) {
    return (
      <Pill tone="warning" title={title}>
        Acceptance expired
      </Pill>
    );
  }
  return (
    <Pill tone={triage.status === 'false_positive' ? 'neutral' : 'violet'} title={title}>
      {TRIAGE_LABEL[triage.status]}
    </Pill>
  );
}
