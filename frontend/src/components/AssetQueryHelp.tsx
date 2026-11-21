import { Pill } from '@/components/common';
import type { TriageInfo } from '@/types/api';
import { formatDateTime } from '@/lib/format';

const KEYS: Array<{ key: string; desc: string }> = [
  { key: 'port:3389', desc: 'port (lista: port:80,443)' },
  { key: 'tech:wordpress', desc: 'technologia / sygnatura / produkt' },
  { key: 'tag:wi', desc: 'tag hosta lub usługi' },
  { key: 'state:new', desc: 'stan cyklu życia hosta' },
  { key: 'cidr:10.66.0.0/24', desc: 'zakres adresów (lub pojedynczy IP)' },
  { key: 'env:staging', desc: 'środowisko' },
  { key: 'title:"admin"', desc: 'tytuł strony HTTP' },
  { key: 'cert:expired', desc: 'TLS: expired, expiring, selfsigned, valid' },
  { key: 'owner:wi.agh', desc: 'właściciel' },
  { key: 'triage:accepted_risk', desc: 'decyzja: new, triaged, accepted_risk, false_positive' },
  { key: 'admin:true', desc: 'panel administracyjny' },
  { key: 'eol:true', desc: 'wersja po końcu wsparcia (EOL, tabela offline)' },
  { key: 'vuln:true', desc: 'pasywna wskazówka znanego CVE (po wersji)' },
  { key: 'score:>=70', desc: 'minimalny score' },
];

const EXAMPLES = [
  'port:3389 -env:prod',
  'tech:wordpress cidr:10.66.0.0/22',
  'cert:expired,expiring',
  'admin:true state:new',
  'eol:true',
];

/** Short syntax help for the Shodan-like asset query (evaluated server-side). */
export function AssetQueryHelp({ onPick }: { onPick: (q: string) => void }) {
  return (
    <div className="mb-4 border border-border bg-card p-4 text-xs">
      <p className="mb-3 text-muted-foreground">
        Warunki <span className="font-mono text-foreground">klucz:wartość</span> łączone są przez AND,
        przecinek to OR, <span className="font-mono text-foreground">-</span> neguje warunek, cudzysłów
        pozwala na spacje. Pozostałe słowa to wyszukiwanie pełnotekstowe (IP, hostname, banner, notatki).
        Warunki usługi (port, tech, title, cert, admin) muszą być spełnione przez tę samą usługę.
      </p>
      <div className="grid gap-x-6 gap-y-1 sm:grid-cols-2">
        {KEYS.map((k) => (
          <div key={k.key} className="flex items-baseline gap-2">
            <button
              type="button"
              onClick={() => onPick(k.key)}
              className="shrink-0 font-mono text-primary hover:underline"
            >
              {k.key}
            </button>
            <span className="truncate text-muted-foreground">{k.desc}</span>
          </div>
        ))}
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-1.5">
        <span className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
          Przykłady
        </span>
        {EXAMPLES.map((ex) => (
          <button
            key={ex}
            type="button"
            onClick={() => onPick(ex)}
            className="border border-border px-1.5 py-0.5 font-mono text-[11px] text-foreground transition-colors hover:border-primary hover:text-primary"
          >
            {ex}
          </button>
        ))}
      </div>
    </div>
  );
}

const TRIAGE_LABEL: Record<string, string> = {
  accepted_risk: 'Ryzyko zaakceptowane',
  false_positive: 'False positive',
};

/** Compact badge for an analyst risk decision (shows expiry state in the tooltip). */
export function TriageBadge({ triage }: { triage?: TriageInfo | null }) {
  if (!triage || !TRIAGE_LABEL[triage.status]) return null;
  const title = [
    triage.reason,
    `${triage.by || '—'} · ${formatDateTime(triage.at)}`,
    triage.expires_at ? `Wygasa: ${formatDateTime(triage.expires_at)}` : 'Bez daty wygaśnięcia',
  ].join('\n');
  if (triage.expired) {
    return (
      <Pill tone="warning" title={title}>
        Akceptacja wygasła
      </Pill>
    );
  }
  return (
    <Pill tone={triage.status === 'false_positive' ? 'neutral' : 'violet'} title={title}>
      {TRIAGE_LABEL[triage.status]}
    </Pill>
  );
}
