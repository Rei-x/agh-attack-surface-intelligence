import { Pill } from '@/components/common';
import type { Service } from '@/types/api';

type EolService = Pick<Service, 'outdated' | 'known_vulns'>;

/**
 * Badges for end-of-life versions ("nginx 1.14 – gałąź EOL od 2019-04") and passive CVE
 * hints. The full evidence (source, data date, distro caveat) is in the tooltip.
 */
export function EolBadges({ service }: { service: EolService }) {
  const outdated = service.outdated || [];
  const hints = service.known_vulns || [];
  if (outdated.length === 0 && hints.length === 0) return null;
  return (
    <>
      {outdated.map((o) => (
        <Pill
          key={`${o.product}-${o.branch}`}
          tone="orange"
          className="normal-case tracking-normal"
          title={o.evidence}
        >
          EOL · {o.label}
        </Pill>
      ))}
      {hints.map((h) => (
        <Pill key={h.id} tone="danger" className="normal-case tracking-normal" title={h.evidence}>
          {h.id} (pasywnie)
        </Pill>
      ))}
    </>
  );
}

/** Evidence block for the expanded service view. */
export function EolEvidence({ service }: { service: EolService }) {
  const outdated = service.outdated || [];
  const hints = service.known_vulns || [];
  if (outdated.length === 0 && hints.length === 0) return null;
  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold tracking-widest text-muted-foreground uppercase">
        Wersje EOL i wskazówki CVE
      </h4>
      <ul className="space-y-1.5 text-xs">
        {outdated.map((o) => (
          <li key={`${o.product}-${o.branch}`} className="border-l-2 border-orange-500/60 pl-2">
            <span className="font-medium text-foreground">{o.label}</span>
            <span className="text-muted-foreground"> — {o.evidence} </span>
            <a href={o.source} target="_blank" rel="noreferrer" className="underline">
              źródło
            </a>
          </li>
        ))}
        {hints.map((h) => (
          <li key={h.id} className="border-l-2 border-rose-500/60 pl-2">
            <span className="font-medium text-foreground">
              {h.id}: {h.name}
            </span>
            <span className="text-muted-foreground"> — {h.evidence} </span>
            {h.references[0] && (
              <a href={h.references[0]} target="_blank" rel="noreferrer" className="underline">
                źródło
              </a>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Owner stamped on a change event by the backend (CIDR rules), if any. */
export function changeOwner(after?: Record<string, unknown>): string {
  const o = after?.owner;
  return typeof o === 'string' ? o : '';
}
