import { useCallback, useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  RiCameraOffLine,
  RiCloseLine,
  RiLayoutGridLine,
  RiPagesLine,
  RiRefreshLine,
  RiSearchLine,
} from '@remixicon/react';
import { cn } from '@/lib/utils';
import { formatNumber, plural } from '@/lib/format';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Empty, Notice, PageHeader } from '@/components/common';
import { PeckLoader } from '@/components/Woodpecker';
import { CATEGORY_META } from '@/components/CategoryBadge';
import { ScreenshotGrid, ScreenshotPreview } from '@/components/ScreenshotGallery';
import { useLiveRefresh } from '@/context/LiveEventsContext';
import { ApiError } from '@/lib/api';
import {
  listScreenshots,
  type GalleryItem,
  type GalleryKind,
  type GalleryResponse,
} from '@/lib/screenshots';

const PAGE = 60;

const CHIPS: Array<{ kind: GalleryKind | ''; label: string; icon: React.ComponentType<{ className?: string }>; tone?: string; hint: string }> = [
  { kind: '', label: 'All', icon: RiLayoutGridLine, hint: 'Every web service with a screenshot' },
  { kind: 'admin', label: 'Admin panels', icon: CATEGORY_META.admin.icon, tone: CATEGORY_META.admin.tone, hint: CATEGORY_META.admin.hint },
  { kind: 'iot', label: 'IoT / BMC', icon: CATEGORY_META.bmc.icon, tone: CATEGORY_META.bmc.tone, hint: 'Cameras, printers, routers, iDRAC / iLO' },
  { kind: 'default', label: 'Default pages', icon: RiPagesLine, tone: 'text-violet-700 dark:text-violet-300', hint: 'Out-of-the-box server pages: nobody configured this' },
  { kind: 'eol', label: 'End of life', icon: CATEGORY_META.eol.icon, tone: CATEGORY_META.eol.tone, hint: CATEGORY_META.eol.hint },
];

export function GalleryPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [q, setQ] = useState(searchParams.get('q') || '');
  const [debouncedQ, setDebouncedQ] = useState(q.trim());
  const kindParam = searchParams.get('kind') || '';
  const kind = (CHIPS.some((c) => c.kind === kindParam) ? kindParam : '') as GalleryKind | '';
  const [data, setData] = useState<GalleryResponse | null>(null);
  const [items, setItems] = useState<GalleryItem[]>([]);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [open, setOpen] = useState<GalleryItem | null>(null);
  const reqSeq = useRef(0);

  const patch = useCallback(
    (p: Record<string, string | null>) =>
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          for (const [k, v] of Object.entries(p)) {
            if (!v) next.delete(k);
            else next.set(k, v);
          }
          return next;
        },
        { replace: true }
      ),
    [setSearchParams]
  );

  useEffect(() => {
    const t = window.setTimeout(() => setDebouncedQ(q.trim()), 300);
    return () => window.clearTimeout(t);
  }, [q]);
  useEffect(() => {
    if (debouncedQ !== (searchParams.get('q') || '')) patch({ q: debouncedQ || null });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedQ]);

  const load = useCallback(
    async (nextPage: number, silent = false) => {
      const seq = ++reqSeq.current;
      if (!silent) setLoading(true);
      try {
        const res = await listScreenshots({ q: debouncedQ || undefined, kind, page: nextPage, limit: PAGE });
        if (seq !== reqSeq.current) return;
        setError('');
        setData(res);
        setPage(nextPage);
        setItems((prev) => (nextPage === 1 ? res.items : [...prev, ...res.items]));
      } catch (err) {
        if (seq !== reqSeq.current) return;
        setError(err instanceof ApiError && err.status === 400 ? err.message : `Could not load screenshots: ${(err as Error).message}`);
        if (nextPage === 1) setItems([]);
      } finally {
        if (seq === reqSeq.current) setLoading(false);
      }
    },
    [debouncedQ, kind]
  );

  useEffect(() => {
    load(1);
  }, [load]);

  useLiveRefresh(() => {
    if (page === 1) load(1, true);
  });

  const status = data?.status;
  const counts = data?.counts || {};
  const total = data?.total ?? 0;

  return (
    <div>
      <PageHeader
        title="Gallery"
        meta={<span className="font-mono tabular-nums">{plural(total, 'web service')}</span>}
        actions={
          <Button variant="outline" size="icon-sm" onClick={() => load(1)} aria-label="Refresh">
            <RiRefreshLine className={cn(loading && 'animate-spin')} />
          </Button>
        }
      />

      {status && !status.available && (
        <Notice tone="warning" icon={RiCameraOffLine} className="mb-4">
          <span className="font-medium">This server cannot take screenshots:</span> {status.detail}. Install Chromium on
          the scanning host (or set DZIECIOL_CHROME_PATH). Agents with Chromium still send theirs.
        </Notice>
      )}

      <div className="mb-3 flex flex-wrap items-center gap-1.5">
        {CHIPS.map((c) => {
          const active = kind === c.kind;
          const count = c.kind ? counts[c.kind] : counts.all;
          const Icon = c.icon;
          return (
            <button
              key={c.label}
              type="button"
              title={c.hint}
              aria-pressed={active}
              onClick={() => patch({ kind: active || !c.kind ? null : c.kind })}
              disabled={!active && c.kind !== '' && count === 0}
              className={cn(
                'inline-flex h-7 items-center gap-1.5 border px-2 text-[11px] font-medium transition-colors disabled:opacity-40',
                active
                  ? 'border-foreground bg-foreground text-background'
                  : 'border-border bg-card text-foreground hover:border-foreground/40'
              )}
            >
              <Icon className={cn('size-3.5', !active && c.tone?.split(' ').slice(0, 2).join(' '))} />
              {c.label}
              {count !== undefined && (
                <span className={cn('font-mono tabular-nums', active ? 'opacity-70' : 'text-muted-foreground')}>
                  {formatNumber(count)}
                </span>
              )}
            </button>
          );
        })}
      </div>

      <div className="relative mb-4">
        <RiSearchLine className="pointer-events-none absolute top-1/2 left-0 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="IP, title, or tech:jenkins port:8443 cidr:10.0.0.0/16"
          className="pr-8 pl-6 font-mono"
          aria-invalid={error ? true : undefined}
        />
        {q && (
          <button
            type="button"
            onClick={() => setQ('')}
            className="absolute top-1/2 right-0 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            aria-label="Clear search"
          >
            <RiCloseLine className="size-4" />
          </button>
        )}
      </div>
      {error && <p className="-mt-2 mb-3 font-mono text-xs text-destructive">{error}</p>}

      {loading && items.length === 0 ? (
        <PeckLoader />
      ) : items.length === 0 ? (
        <Empty bird>
          {q || kind
            ? 'No screenshot matches this filter'
            : status?.store === false
              ? 'Screenshot storage is off on this server'
              : 'No screenshots yet. Run a scan with "Capture screenshots" on.'}
        </Empty>
      ) : (
        <>
          <ScreenshotGrid items={items} onOpen={setOpen} />
          {data && page < data.total_pages && (
            <div className="mt-4 flex justify-center">
              <Button variant="outline" size="sm" onClick={() => load(page + 1)} disabled={loading}>
                Show more
              </Button>
            </div>
          )}
        </>
      )}

      <ScreenshotPreview item={open} onClose={() => setOpen(null)} />
    </div>
  );
}
