import { useEffect, useState } from 'react';
import { formatDateTime, formatRelativeTime } from '@/lib/format';
import { hostScreenshots, type GalleryItem, type ScreenshotEntry } from '@/lib/screenshots';
import { ScreenshotImage, ScreenshotPreview } from '@/components/ScreenshotGallery';
import type { Host, Service } from '@/types/api';

/**
 * Screenshot of one HTTP service, shown at the top of its evidence in the host drawer.
 * Renders nothing when the service has no screenshot.
 */
export function ServiceScreenshot({ host, service }: { host: Host; service: Service }) {
  const [entries, setEntries] = useState<ScreenshotEntry[]>([]);
  const [open, setOpen] = useState<GalleryItem | null>(null);
  const protocol = (service.protocol || 'tcp').toLowerCase();

  useEffect(() => {
    let alive = true;
    setEntries([]);
    hostScreenshots(host.id)
      .then((res) => {
        const svc = res.services.find((s) => s.key.port === service.port && s.key.protocol === protocol);
        if (alive && svc) setEntries(svc.entries);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [host.id, service.port, protocol]);

  const shot = entries[0];
  if (!shot) return null;
  const item: GalleryItem = {
    host_id: host.id,
    host_ip: host.ip,
    hostname: host.hostname,
    service,
    shot,
    versions: entries.length,
    key: { ip: host.ip, port: service.port, protocol },
  };
  return (
    <div className="space-y-1">
      <button
        type="button"
        onClick={() => setOpen(item)}
        className="block w-full max-w-xl border border-border transition-colors hover:border-foreground/40"
        title="Open larger"
      >
        <ScreenshotImage id={shot.id} alt={`Screenshot of ${host.ip}:${service.port}`} />
      </button>
      <div className="text-[11px] text-muted-foreground" title={formatDateTime(shot.captured_at)}>
        Screenshot {formatRelativeTime(shot.captured_at)}
        {entries.length > 1 && ` · ${entries.length} versions`}
      </div>
      <ScreenshotPreview item={open} onClose={() => setOpen(null)} />
    </div>
  );
}
