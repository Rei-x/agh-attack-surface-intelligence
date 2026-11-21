import { CategoryBadge, outdatedDetail, vulnDetail } from '@/components/CategoryBadge';
import { eolLabel } from '@/lib/format';
import type { Service } from '@/types/api';

type EolService = Pick<Service, 'outdated' | 'known_vulns'>;

/**
 * Compact icon badges for end-of-life versions and passive CVE hints; the evidence (branch,
 * EOL date, source, distro caveat) is in the tooltip.
 */
export function EolBadges({ service, size }: { service: EolService; size?: 'xs' | 'sm' }) {
  const outdated = service.outdated || [];
  const hints = service.known_vulns || [];
  if (outdated.length === 0 && hints.length === 0) return null;
  return (
    <>
      {hints.length > 0 && <CategoryBadge kind="cve" size={size} detail={hints.map(vulnDetail)} />}
      {outdated.length > 0 && <CategoryBadge kind="eol" size={size} detail={outdated.map(outdatedDetail)} />}
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
        End-of-life versions and CVE hints
      </h4>
      <ul className="space-y-1.5 text-xs">
        {outdated.map((o) => (
          <li key={`${o.product}-${o.branch}`} className="border-l-2 border-orange-500/60 pl-2">
            <span className="font-medium text-foreground">{eolLabel(o.label)}</span>
            <span className="text-muted-foreground"> — {outdatedDetail(o)} </span>
            <a href={o.source} target="_blank" rel="noopener noreferrer" className="underline">
              source
            </a>
          </li>
        ))}
        {hints.map((h) => (
          <li key={h.id} className="border-l-2 border-rose-500/60 pl-2">
            <span className="font-medium text-foreground">
              {h.id}: {h.name}
            </span>
            <span className="text-muted-foreground"> — {vulnDetail(h)} </span>
            {h.references[0] && (
              <a href={h.references[0]} target="_blank" rel="noopener noreferrer" className="underline">
                reference
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
