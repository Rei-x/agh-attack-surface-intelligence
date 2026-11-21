import { useId } from 'react';
import { cn } from '@/lib/utils';

/** AGH tricolour: green · slate (zinc-900 / zinc-200 in dark) · crimson. */
export const AGH_COLORS = {
  green: '#00693C',
  crimson: '#A71930',
} as const;

const SHIELD = 'M1 1H23V14.5C23 20.6 18.2 24.9 12 27C5.8 24.9 1 20.6 1 14.5Z';

/** Tricolour shield emblem (three vertical bars clipped to a shield). */
export function AghEmblem({ className, title = 'AGH' }: { className?: string; title?: string }) {
  const clipId = `agh-shield-${useId().replace(/:/g, '')}`;
  return (
    <svg
      viewBox="0 0 24 28"
      role="img"
      aria-label={title}
      className={cn('h-6 w-auto shrink-0', className)}
    >
      <defs>
        <clipPath id={clipId}>
          <path d={SHIELD} />
        </clipPath>
      </defs>
      <g clipPath={`url(#${clipId})`}>
        <rect x="0" y="0" width="7.4" height="28" fill={AGH_COLORS.green} />
        <rect x="8.3" y="0" width="7.4" height="28" className="fill-zinc-900 dark:fill-zinc-200" />
        <rect x="16.6" y="0" width="7.4" height="28" fill={AGH_COLORS.crimson} />
      </g>
      <path d={SHIELD} fill="none" className="stroke-foreground/15" strokeWidth="0.75" />
    </svg>
  );
}

/** Compact `CBI AGH` badge: emblem + geometric wordmark. */
export function AghBadge({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex h-5 shrink-0 items-center gap-1.5 border px-1.5 text-[9px] font-bold tracking-[0.2em] text-muted-foreground uppercase',
        className
      )}
    >
      <span className="flex h-2.5 gap-px" aria-hidden>
        <span className="w-[3px]" style={{ backgroundColor: AGH_COLORS.green }} />
        <span className="w-[3px] bg-zinc-900 dark:bg-zinc-200" />
        <span className="w-[3px]" style={{ backgroundColor: AGH_COLORS.crimson }} />
      </span>
      CBI AGH
    </span>
  );
}
