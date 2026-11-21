import { Link } from 'react-router-dom';
import { RiShieldCrossLine } from '@remixicon/react';
import { Pill } from '@/components/common';
import { policySeverityTone, ruleLabel } from '@/lib/policies';

interface Hit {
  zone_id: string;
  zone_name: string;
  rules: string[];
  severity: string;
  summary: string;
}

/** Open zone policy violations of one service (host drawer). Renders nothing when clean. */
export function PolicyViolationNotice({ hits }: { hits?: Hit[] }) {
  if (!hits?.length) return null;
  return (
    <div className="space-y-2 border border-foreground/20 bg-card px-3 py-2.5">
      {hits.map((h) => (
        <div key={h.zone_id} className="flex items-start gap-2 text-xs">
          <RiShieldCrossLine className="mt-0.5 size-3.5 shrink-0" />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="font-semibold">Breaks zone policy</span>
              <Link to="/policies" className="underline underline-offset-2">
                {h.zone_name}
              </Link>
              <Pill tone={policySeverityTone(h.severity)}>{h.severity}</Pill>
            </div>
            <div className="mt-0.5 text-muted-foreground">{h.rules.map((r) => ruleLabel(r)).join(' · ')}</div>
          </div>
        </div>
      ))}
    </div>
  );
}
