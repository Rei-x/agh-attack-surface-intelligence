import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { RiCameraOffLine, RiExternalLinkLine, RiImageLine } from '@remixicon/react';
import { cn } from '@/lib/utils';
import { formatDateTime, formatRelativeTime } from '@/lib/format';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog';
import { ServiceLogoFor } from '@/components/ServiceLogo';
import { CategoryBadges, serviceFlags } from '@/components/CategoryBadge';
import {
  hostScreenshots,
  useScreenshotImage,
  type GalleryItem,
  type ScreenshotEntry,
} from '@/lib/screenshots';

/** Lazy-loaded authenticated image (thumbnail or full) in a fixed 16:10 frame. */
export function ScreenshotImage({
  id,
  alt,
  lazy = true,
  className,
}: {
  id?: string;
  alt: string;
  lazy?: boolean;
  className?: string;
}) {
  const [ref, url, failed] = useScreenshotImage<HTMLDivElement>(id, lazy);
  return (
    <div ref={ref} className={cn('relative aspect-[16/10] overflow-hidden bg-muted', className)}>
      {url ? (
        <img src={url} alt={alt} className="absolute inset-0 size-full object-cover object-top" draggable={false} />
      ) : (
        <div className="absolute inset-0 flex items-center justify-center text-muted-foreground/50">
          {failed ? <RiCameraOffLine className="size-5" /> : <RiImageLine className="size-5 animate-pulse" />}
        </div>
      )}
    </div>
  );
}

function hostPort(item: GalleryItem): string {
  return `${item.host_ip}:${item.key.port}`;
}

export function GalleryTile({ item, onOpen }: { item: GalleryItem; onOpen: (item: GalleryItem) => void }) {
  const title = item.shot.title || item.service.http?.title || '';
  const flags = serviceFlags(item.service);
  return (
    <button
      type="button"
      onClick={() => onOpen(item)}
      className="group flex min-w-0 flex-col border border-border bg-card text-left transition-colors hover:border-foreground/40 focus-visible:border-foreground focus-visible:outline-none"
    >
      <ScreenshotImage id={item.shot.thumb} alt={`${hostPort(item)} ${title}`} className="border-b border-border" />
      <div className="flex min-w-0 flex-col gap-1 p-2">
        <div className="flex min-w-0 items-center gap-1.5">
          <ServiceLogoFor service={item.service} size="xs" />
          <span className="truncate font-mono text-xs text-foreground tabular-nums">{hostPort(item)}</span>
          <CategoryBadges flags={flags} size="xs" max={3} className="ml-auto" />
        </div>
        <div className="truncate text-xs text-muted-foreground" title={title}>
          {title || <span className="opacity-60">No title</span>}
        </div>
      </div>
    </button>
  );
}

/** Large preview with the service's earlier screenshots and a link to the host. */
export function ScreenshotPreview({ item, onClose }: { item: GalleryItem | null; onClose: () => void }) {
  const navigate = useNavigate();
  const [history, setHistory] = useState<ScreenshotEntry[]>([]);
  const [shown, setShown] = useState<ScreenshotEntry | null>(null);

  useEffect(() => {
    setShown(item?.shot || null);
    setHistory([]);
    if (!item || item.versions < 2) return;
    let alive = true;
    hostScreenshots(item.host_id)
      .then((res) => {
        const svc = res.services.find((s) => s.key.port === item.key.port && s.key.protocol === item.key.protocol);
        if (alive && svc) setHistory(svc.entries);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [item]);

  if (!item) return null;
  const cur = shown || item.shot;
  const title = cur.title || item.service.http?.title || '';
  return (
    <Dialog open={Boolean(item)} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="gap-4 p-4 sm:max-w-5xl">
        <div className="flex min-w-0 items-center gap-2 pr-10">
          <ServiceLogoFor service={item.service} size="sm" />
          <div className="min-w-0">
            <DialogTitle className="truncate font-mono text-sm">{hostPort(item)}</DialogTitle>
            <div className="truncate text-xs text-muted-foreground" title={title}>
              {title || 'No title'}
              {item.hostname ? ` · ${item.hostname}` : ''}
            </div>
          </div>
          <CategoryBadges flags={serviceFlags(item.service)} className="ml-auto" />
        </div>

        <ScreenshotImage id={cur.id} alt={`${hostPort(item)} ${title}`} lazy={false} className="border border-border" />

        {history.length > 1 && (
          <div className="flex items-center gap-2 overflow-x-auto">
            <span className="shrink-0 text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
              Versions
            </span>
            {history.map((h) => (
              <button
                key={h.id}
                type="button"
                onClick={() => setShown(h)}
                title={`Captured ${formatDateTime(h.captured_at)}`}
                className={cn(
                  'w-28 shrink-0 border transition-colors',
                  h.id === cur.id ? 'border-foreground' : 'border-border hover:border-foreground/40'
                )}
              >
                <ScreenshotImage id={h.thumb} alt="" />
                <div className="truncate px-1 py-0.5 text-[10px] text-muted-foreground">{formatRelativeTime(h.captured_at)}</div>
              </button>
            ))}
          </div>
        )}

        <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <span title={formatDateTime(cur.captured_at)}>Captured {formatRelativeTime(cur.captured_at)}</span>
          {cur.first_seen !== cur.captured_at && (
            <span title={formatDateTime(cur.first_seen)}>· unchanged since {formatRelativeTime(cur.first_seen)}</span>
          )}
          <div className="ml-auto flex items-center gap-2">
            {/^https?:\/\//i.test(cur.url) && (
              <Button variant="outline" size="sm" nativeButton={false} render={<a href={cur.url} target="_blank" rel="noopener noreferrer" />}>
                <RiExternalLinkLine data-icon="inline-start" /> Open page
              </Button>
            )}
            <Button size="sm" onClick={() => navigate(`/assets?host=${encodeURIComponent(item.host_id)}`)}>
              Open host
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

/** Dense, lazy-loading grid of service screenshots. */
export function ScreenshotGrid({ items, onOpen }: { items: GalleryItem[]; onOpen: (item: GalleryItem) => void }) {
  return (
    <div className="grid grid-cols-[repeat(auto-fill,minmax(220px,1fr))] gap-3">
      {items.map((it) => (
        <GalleryTile key={`${it.key.ip}|${it.key.port}|${it.key.protocol}`} item={it} onOpen={onOpen} />
      ))}
    </div>
  );
}

