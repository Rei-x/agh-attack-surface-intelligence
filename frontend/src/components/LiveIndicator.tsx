import { useState } from 'react';
import { RiDeleteBinLine, RiPulseLine } from '@remixicon/react';
import { describeEvent, useLiveEvents } from '@/context/LiveEventsContext';
import { formatClock } from '@/lib/format';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { PeckSpinner } from '@/components/Woodpecker';

const TONE_TEXT = {
  danger: 'text-rose-600 dark:text-rose-400',
  warning: 'text-amber-600 dark:text-amber-400',
  success: 'text-emerald-600 dark:text-emerald-400',
  info: 'text-primary',
} as const;

/** Emerald ping dot that also flashes once per incoming SSE event. */
export function LiveDot({ live, className }: { live: boolean; className?: string }) {
  const { pulseTick } = useLiveEvents();
  return (
    <span className={cn('relative inline-flex size-2 shrink-0', className)} aria-hidden>
      {live && (
        <>
          <span className="absolute inline-flex size-full animate-ping bg-emerald-500 opacity-60" />
          <span key={pulseTick} className="absolute inline-flex size-full animate-live-flash bg-emerald-400" />
        </>
      )}
      <span className={cn('relative inline-flex size-2', live ? 'bg-emerald-500' : 'bg-muted-foreground/50')} />
    </span>
  );
}

export function LiveIndicator() {
  const { connected, clients, liveFeed, lastEventAt, clearEvents, activeScan } = useLiveEvents();
  const [open, setOpen] = useState(false);
  // A scan is knocking right now: show the pecking bird next to the live dot.
  const pecking = connected && !!activeScan && (activeScan.status === 'RUNNING' || activeScan.status === 'CALIBRATING');

  return (
    <>
      <Tooltip>
        <TooltipTrigger
          render={
            <button
              type="button"
              onClick={() => setOpen(true)}
              className={cn(
                'inline-flex h-6 items-center gap-2 border px-2 font-mono text-[10px] font-semibold tracking-widest uppercase transition-colors hover:bg-muted',
                connected
                  ? 'border-emerald-500/30 text-emerald-700 dark:text-emerald-400'
                  : 'text-muted-foreground'
              )}
              aria-label="Live Stream"
            />
          }
        >
          <LiveDot live={connected} />
          {connected ? 'Live' : 'Offline'}
          {pecking && <PeckSpinner className="h-3.5" />}
          <span className="border-l border-current/20 pl-2 tabular-nums text-muted-foreground">
            {liveFeed.length}
          </span>
        </TooltipTrigger>
        <TooltipContent>
          {pecking && 'Knock, knock · scan in progress · '}
          {formatClock(lastEventAt)}
          {clients > 0 && ` · ${clients} client${clients === 1 ? '' : 's'}`}
        </TooltipContent>
      </Tooltip>

      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent side="right" className="w-full gap-0 sm:max-w-md">
          <SheetHeader className="border-b">
            <SheetTitle className="flex items-center gap-2 text-xs font-semibold tracking-widest uppercase">
              <RiPulseLine className="size-4 text-primary" />
              Live Stream
              <LiveDot live={connected} className="ml-1" />
            </SheetTitle>
          </SheetHeader>
          <div className="flex items-center justify-between border-b px-4 py-1.5 font-mono text-[10px] text-muted-foreground tabular-nums">
            <span>
              {liveFeed.length} · {clients} client{clients === 1 ? '' : 's'}
            </span>
            {liveFeed.length > 0 && (
              <Button variant="ghost" size="icon-xs" onClick={clearEvents} aria-label="Clear">
                <RiDeleteBinLine />
              </Button>
            )}
          </div>
          <div className="flex-1 overflow-y-auto font-mono text-[11px]">
            {liveFeed.length === 0 ? (
              <div className="py-10 text-center text-muted-foreground">Quiet in the woods</div>
            ) : (
              liveFeed.map((ev, idx) => {
                const d = describeEvent(ev);
                return (
                  <div
                    key={`${ev.timestamp}-${ev.type}-${liveFeed.length - idx}`}
                    className={cn(
                      'flex items-baseline gap-2 border-b border-border/60 px-4 py-1.5',
                      idx === 0 && 'animate-live-row'
                    )}
                  >
                    <span className="shrink-0 text-muted-foreground tabular-nums">
                      {formatClock(ev.timestamp)}
                    </span>
                    <span className={cn('w-12 shrink-0 font-semibold', d.tone ? TONE_TEXT[d.tone] : 'text-foreground')}>
                      {d.tag}
                    </span>
                    <span className="min-w-0 truncate" title={d.text}>
                      {d.text}
                    </span>
                  </div>
                );
              })
            )}
          </div>
        </SheetContent>
      </Sheet>
    </>
  );
}
