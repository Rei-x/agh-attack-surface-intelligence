import { useEffect, useRef, useState } from 'react';
import { RiCalendarLine } from '@remixicon/react';
import { cn } from '@/lib/utils';
import { isIsoDay } from '@/lib/format';
import { Input } from '@/components/ui/input';

/**
 * Date field that always shows the day as YYYY-MM-DD, whatever the browser locale (a native
 * date input renders "12/22/2026" in an en-US browser). The calendar button opens the
 * browser's picker on a hidden native input; its value is ISO in every locale.
 */
export function IsoDateInput({
  id,
  value,
  onChange,
  className,
  inputClassName,
  'aria-label': ariaLabel,
}: {
  id?: string;
  value: string;
  /** Called with a valid YYYY-MM-DD day, or '' when cleared. */
  onChange: (day: string) => void;
  className?: string;
  inputClassName?: string;
  'aria-label'?: string;
}) {
  const picker = useRef<HTMLInputElement>(null);
  const [text, setText] = useState(value);
  useEffect(() => setText(value), [value]);
  const invalid = text !== '' && !isIsoDay(text);

  const openPicker = () => {
    const el = picker.current;
    if (!el) return;
    try {
      el.showPicker();
    } catch {
      el.focus();
    }
  };

  return (
    <div className={cn('relative flex items-center', className)}>
      <Input
        id={id}
        value={text}
        inputMode="numeric"
        placeholder="YYYY-MM-DD"
        maxLength={10}
        aria-label={ariaLabel}
        aria-invalid={invalid || undefined}
        title={invalid ? 'Use YYYY-MM-DD, for example 2026-12-22' : undefined}
        onChange={(e) => {
          const v = e.target.value.trim();
          setText(v);
          if (v === '' || isIsoDay(v)) onChange(v);
        }}
        className={cn('pr-7 font-mono tabular-nums', inputClassName)}
      />
      <button
        type="button"
        onClick={openPicker}
        aria-label="Pick a date"
        className="absolute right-0 flex size-6 items-center justify-center text-muted-foreground hover:text-foreground"
      >
        <RiCalendarLine className="size-4" />
      </button>
      <input
        ref={picker}
        type="date"
        tabIndex={-1}
        aria-hidden
        value={isIsoDay(text) ? text : ''}
        onChange={(e) => {
          setText(e.target.value);
          onChange(e.target.value);
        }}
        className="pointer-events-none absolute right-0 bottom-0 h-px w-px opacity-0"
      />
    </div>
  );
}
