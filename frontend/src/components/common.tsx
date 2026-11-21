import * as React from 'react';
import { cn } from '@/lib/utils';
import { TONE, type Tone } from '@/lib/format';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

/** Page title row: title on the left, actions on the right. No subtitles. */
export function PageHeader({
  title,
  meta,
  actions,
  className,
}: {
  title: React.ReactNode;
  meta?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('flex flex-wrap items-end justify-between gap-4 pb-6', className)}>
      <div className="flex min-w-0 items-baseline gap-3">
        <h1 className="font-heading text-xl font-semibold tracking-wider uppercase">{title}</h1>
        {meta && <div className="text-xs text-muted-foreground">{meta}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/** Small section heading inside a page/card. */
export function SectionTitle({
  children,
  actions,
  className,
}: {
  children: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('flex items-center justify-between gap-3', className)}>
      <h2 className="text-xs font-semibold tracking-widest text-muted-foreground uppercase">
        {children}
      </h2>
      {actions}
    </div>
  );
}

/** Quiet status pill with a semantic tone (or custom tint classes via className). */
export function Pill({
  tone = 'neutral',
  dot,
  pulse,
  className,
  children,
  ...props
}: React.ComponentProps<'span'> & { tone?: Tone; dot?: boolean; pulse?: boolean }) {
  return (
    <span
      className={cn(
        'inline-flex h-5 shrink-0 items-center gap-1.5 border px-1.5 text-[10px] font-semibold tracking-wider whitespace-nowrap uppercase',
        TONE[tone],
        className
      )}
      {...props}
    >
      {dot && (
        <span className={cn('size-1.5 bg-current', pulse && 'animate-pulse')} aria-hidden />
      )}
      {children}
    </span>
  );
}

/** KPI cell for a horizontal strip: label + big number. */
export function Stat({
  label,
  value,
  hint,
  tone,
  className,
}: {
  label: React.ReactNode;
  value: React.ReactNode;
  hint?: React.ReactNode;
  tone?: 'danger' | 'warning' | 'success';
  className?: string;
}) {
  const toneText =
    tone === 'danger'
      ? 'text-rose-600 dark:text-rose-400'
      : tone === 'warning'
        ? 'text-amber-600 dark:text-amber-400'
        : tone === 'success'
          ? 'text-emerald-600 dark:text-emerald-400'
          : '';
  return (
    <div className={cn('flex min-w-0 flex-col gap-1.5 px-5 py-4', className)}>
      <span className="truncate text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
        {label}
      </span>
      <span className={cn('font-heading text-2xl font-semibold tabular-nums', toneText)}>
        {value}
      </span>
      {hint && <span className="truncate text-xs text-muted-foreground">{hint}</span>}
    </div>
  );
}

/** Wrapper for a row of <Stat/> separated by 1px dividers. */
export function StatStrip({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        'grid grid-cols-2 divide-x divide-y divide-border bg-card ring-1 ring-foreground/5 sm:divide-y-0 md:grid-flow-col md:auto-cols-fr',
        className
      )}
    >
      {children}
    </div>
  );
}

/** One-line empty state. */
export function Empty({
  icon: Icon,
  children,
  className,
}: {
  icon?: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-2 py-10 text-center text-xs text-muted-foreground',
        className
      )}
    >
      {Icon && <Icon className="size-5 opacity-50" />}
      <span>{children}</span>
    </div>
  );
}

/** Label + control stacked. */
export function Field({
  label,
  htmlFor,
  hint,
  className,
  children,
}: {
  label: React.ReactNode;
  htmlFor?: string;
  hint?: React.ReactNode;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={cn('flex min-w-0 flex-col gap-1.5', className)}>
      <Label
        htmlFor={htmlFor}
        className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase"
      >
        {label}
      </Label>
      {children}
      {hint && <span className="text-[11px] text-muted-foreground">{hint}</span>}
    </div>
  );
}

export interface SelectOption {
  value: string;
  label: React.ReactNode;
}

/** Simple controlled select built on shadcn <Select> (Base UI). */
export function SimpleSelect({
  value,
  onValueChange,
  options,
  placeholder,
  className,
  disabled,
  size = 'default',
  id,
}: {
  value: string;
  onValueChange: (value: string) => void;
  options: SelectOption[];
  placeholder?: string;
  className?: string;
  disabled?: boolean;
  size?: 'sm' | 'default';
  id?: string;
}) {
  return (
    <Select
      value={value}
      onValueChange={(v) => onValueChange((v as string | null) ?? '')}
      items={options}
      disabled={disabled}
    >
      <SelectTrigger id={id} size={size} className={cn('w-full min-w-0', className)}>
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value}>
            {o.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

/** Monospace inline code chip. */
export function Code({ className, ...props }: React.ComponentProps<'code'>) {
  return (
    <code
      className={cn('bg-muted px-1.5 py-0.5 font-mono text-[11px] text-foreground', className)}
      {...props}
    />
  );
}

/** Inline alert row for errors / warnings. */
export function Notice({
  tone = 'neutral',
  icon: Icon,
  className,
  children,
}: {
  tone?: Tone;
  icon?: React.ComponentType<{ className?: string }>;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={cn('flex items-start gap-2 border px-3 py-2 text-xs', TONE[tone], className)}>
      {Icon && <Icon className="mt-0.5 size-3.5 shrink-0" />}
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );
}
