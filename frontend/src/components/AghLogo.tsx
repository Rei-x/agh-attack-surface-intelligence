import { cn } from '@/lib/utils';

/** AGH tricolour: green · slate (zinc-900 / zinc-200 in dark) · crimson. */
export const AGH_COLORS = {
  green: '#00693C',
  crimson: '#A71930',
} as const;

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
