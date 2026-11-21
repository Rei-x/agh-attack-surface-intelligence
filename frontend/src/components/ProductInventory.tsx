import { useMemo, useState } from 'react';
import { RiSearchLine } from '@remixicon/react';
import { CategoryBadge } from '@/components/CategoryBadge';
import { Empty, Pill } from '@/components/common';
import { ServiceLogo } from '@/components/ServiceLogo';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { PeckLoader } from '@/components/Woodpecker';
import { formatNumber, scoreColor } from '@/lib/format';
import { cn } from '@/lib/utils';
import type { InventoryProduct } from '@/types/api';

const CATEGORY_LABEL: Record<string, string> = {
  cms: 'CMS',
  framework: 'Framework',
  server: 'Server',
  iot: 'Device',
};

/**
 * One row per product: logo, version spread, host count and risk counts. Every number is a
 * drill-down into the host list (`onQuery` sets the asset query).
 */
export function ProductInventory({
  products,
  loading,
  onQuery,
}: {
  products: InventoryProduct[] | null;
  loading: boolean;
  onQuery: (q: string) => void;
}) {
  const [filter, setFilter] = useState('');
  const rows = useMemo(() => {
    const f = filter.trim().toLowerCase();
    const list = products || [];
    return f ? list.filter((p) => p.name.toLowerCase().includes(f) || (p.category || '').includes(f)) : list;
  }, [products, filter]);

  const countCell = (n: number, q: string, kind: 'eol' | 'admin' | 'cve') => (
    <TableCell className="text-right">
      {n > 0 ? (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onQuery(q);
          }}
          className="inline-flex items-center gap-1.5 font-mono text-xs tabular-nums hover:underline"
        >
          <CategoryBadge kind={kind} size="xs" />
          {n}
        </button>
      ) : (
        <span className="sr-only">none</span>
      )}
    </TableCell>
  );

  return (
    <div>
      <div className="mb-4 flex items-center gap-3">
        <div className="relative w-72">
          <RiSearchLine className="pointer-events-none absolute top-1/2 left-0 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter products, e.g. nginx, wordpress"
            className="pl-6"
          />
        </div>
        <span className="text-xs text-muted-foreground">
          Click a row to list its hosts; click a risk count to list only those.
        </span>
      </div>
      <div className="border border-border bg-card">
        <Table className="table-fixed">
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="w-[30%] pl-4">Product</TableHead>
              <TableHead>Versions</TableHead>
              <TableHead className="w-20 text-right">Hosts</TableHead>
              <TableHead className="w-20 text-right">EOL</TableHead>
              <TableHead className="w-20 text-right">CVE</TableHead>
              <TableHead className="w-20 text-right">Admin</TableHead>
              <TableHead className="w-24 pr-4 text-right">Max score</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading && !products ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={7}>
                  <PeckLoader />
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={7}>
                  <Empty bird>No products identified yet</Empty>
                </TableCell>
              </TableRow>
            ) : (
              rows.map((p) => {
                const shown = p.versions.slice(0, 4);
                const rest = p.versions.length - shown.length;
                return (
                  <TableRow key={p.name} className="cursor-pointer" onClick={() => onQuery(p.query)}>
                    <TableCell className="pl-4">
                      <div className="flex min-w-0 items-center gap-2.5">
                        <ServiceLogo names={p.logo_names} size="md" />
                        <div className="min-w-0">
                          <div className="truncate text-sm font-medium text-foreground" title={p.name}>
                            {p.name}
                          </div>
                          <div className="truncate font-mono text-[11px] text-muted-foreground">
                            {[CATEGORY_LABEL[p.category || ''] || p.category, p.ports.map((x) => `:${x}`).join(' ')]
                              .filter(Boolean)
                              .join(' · ')}
                          </div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      {shown.length === 0 ? (
                        <span className="text-xs text-muted-foreground">version unknown</span>
                      ) : (
                        <div className="flex flex-wrap items-center gap-1">
                          {shown.map((v) => (
                            <button
                              key={v.version}
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                onQuery(`${p.query} version:${v.version.replace(/\s/g, '')}`);
                              }}
                              className="inline-flex h-5 items-center gap-1 border border-border bg-muted/40 px-1.5 font-mono text-[11px] text-foreground transition-colors hover:border-foreground/40"
                              title={`${v.count} service${v.count === 1 ? '' : 's'} on ${v.version}`}
                            >
                              {v.version}
                              <span className="text-muted-foreground">×{v.count}</span>
                            </button>
                          ))}
                          {rest > 0 && <span className="text-[11px] text-muted-foreground">+{rest} more</span>}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="text-right font-mono text-sm tabular-nums">
                      {formatNumber(p.host_count)}
                      {p.new_count > 0 && (
                        <Pill tone="info" className="ml-1.5" title={`${p.new_count} new since last scan`}>
                          +{p.new_count}
                        </Pill>
                      )}
                    </TableCell>
                    {countCell(p.eol_count, `${p.query} eol:true`, 'eol')}
                    {countCell(p.vuln_count, `${p.query} vuln:true`, 'cve')}
                    {countCell(p.admin_count, `${p.query} admin:true`, 'admin')}
                    <TableCell className="pr-4 text-right">
                      <Pill className={cn('font-mono tabular-nums', scoreColor(p.max_score))}>{p.max_score}</Pill>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
