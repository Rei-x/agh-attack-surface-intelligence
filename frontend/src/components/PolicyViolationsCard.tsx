import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { RiArrowRightUpLine } from '@remixicon/react';
import { formatNumber } from '@/lib/format';
import { policiesApi, policySeverityTone, type ViolationsResponse } from '@/lib/policies';
import { Pill } from '@/components/common';
import { Card, CardAction, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

const SEV = ['critical', 'high', 'medium', 'low'];

/** Dashboard card: open zone policy violations per zone. Hidden when no zones exist. */
export function PolicyViolationsCard({ titleClassName }: { titleClassName?: string }) {
  const [data, setData] = useState<ViolationsResponse | null>(null);
  const [zones, setZones] = useState<number | null>(null);

  useEffect(() => {
    let alive = true;
    Promise.all([policiesApi.violations('open'), policiesApi.list()])
      .then(([v, p]) => {
        if (!alive) return;
        setData(v);
        setZones(p.zones.length);
      })
      .catch(() => alive && setZones(0));
    return () => {
      alive = false;
    };
  }, []);

  if (!data || !zones) return null;
  const total = data.violations.length;
  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle className={titleClassName}>Policy violations</CardTitle>
        <CardAction>
          <Link
            to="/policies"
            className="inline-flex items-center gap-1 text-[11px] font-semibold tracking-wider text-muted-foreground uppercase hover:text-foreground"
          >
            Policies <RiArrowRightUpLine className="size-3.5" />
          </Link>
        </CardAction>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-baseline gap-3">
          <span className="font-heading text-2xl font-semibold tabular-nums">{formatNumber(total)}</span>
          <span className="text-xs text-muted-foreground">open in {formatNumber(data.by_zone.length)} of {formatNumber(zones)} zones</span>
        </div>
        {total > 0 && (
          <ul className="divide-y divide-border border-y border-border">
            {data.by_zone.slice(0, 4).map((g) => (
              <li key={g.key} className="flex items-center justify-between gap-2 py-1.5 text-xs">
                <span className="truncate">{g.label}</span>
                <span className="flex shrink-0 items-center gap-1">
                  {SEV.filter((s) => g.severity[s]).map((s) => (
                    <Pill key={s} tone={policySeverityTone(s)}>
                      {g.severity[s]} {s}
                    </Pill>
                  ))}
                </span>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
