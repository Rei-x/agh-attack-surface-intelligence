import { useEffect, useRef, useState } from 'react';
import { RiCheckLine, RiInformationLine } from '@remixicon/react';
import type { TriagePatch } from '@/lib/api';
import type { TriageInfo } from '@/types/api';
import { formatDateTime } from '@/lib/format';
import { cn } from '@/lib/utils';
import { SimpleSelect } from '@/components/common';
import { TriageBadge } from '@/components/AssetQueryHelp';
import { Input } from '@/components/ui/input';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

const RISK = ['accepted_risk', 'false_positive'];
const NONE = '__none__';

const WORKFLOW_OPTIONS = [
  { value: 'new', label: 'New' },
  { value: 'triaged', label: 'Triaged' },
  { value: 'accepted_risk', label: 'Accepted risk' },
  { value: 'false_positive', label: 'False positive' },
];
const HOST_OPTIONS = [
  { value: NONE, label: 'No decision' },
  { value: 'accepted_risk', label: 'Accepted risk' },
  { value: 'false_positive', label: 'False positive' },
];

type SaveState = 'idle' | 'saving' | 'saved';

/**
 * Inline triage decision that saves on change. Accepted risk / false positive need a reason,
 * saved on Enter or when the field loses focus.
 */
export function TriageEditor({
  status,
  triage,
  workflow,
  canWrite,
  onSave,
}: {
  status?: string;
  triage?: TriageInfo;
  /** Services also have the new/triaged workflow statuses; hosts only the risk decision. */
  workflow: boolean;
  canWrite: boolean;
  onSave: (patch: TriagePatch | null) => Promise<void>;
}) {
  const active = triage && !triage.expired ? triage : undefined;
  const initialStatus = active?.status || (workflow ? status || 'new' : NONE);
  const [sel, setSel] = useState(initialStatus);
  const [reason, setReason] = useState(active?.reason || '');
  const [expires, setExpires] = useState(active?.expires_at ? active.expires_at.slice(0, 10) : '');
  const [state, setState] = useState<SaveState>('idle');
  const [error, setError] = useState('');
  const savedTimer = useRef<number | undefined>(undefined);

  useEffect(() => {
    setSel(initialStatus);
    setReason(active?.reason || '');
    setExpires(active?.expires_at ? active.expires_at.slice(0, 10) : '');
    setError('');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status, triage?.status, triage?.reason, triage?.expires_at, triage?.expired]);

  useEffect(() => () => window.clearTimeout(savedTimer.current), []);

  const isRisk = RISK.includes(sel);

  const save = async (nextSel: string, nextReason: string, nextExpires: string) => {
    setError('');
    if (RISK.includes(nextSel) && !nextReason.trim()) return; // waits for the reason
    setState('saving');
    try {
      if (RISK.includes(nextSel)) {
        await onSave({ status: nextSel, reason: nextReason.trim(), expires_at: nextExpires || undefined });
      } else if (nextSel === NONE) {
        await onSave(null);
      } else {
        await onSave({ status: nextSel });
      }
      setState('saved');
      window.clearTimeout(savedTimer.current);
      savedTimer.current = window.setTimeout(() => setState('idle'), 2000);
    } catch (err) {
      setError((err as Error).message);
      setState('idle');
    }
  };

  const reasonChanged = reason.trim() !== (active?.reason || '') || expires !== (active?.expires_at?.slice(0, 10) || '');

  return (
    <div className="space-y-1.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">Decision</span>
        {canWrite ? (
          <SimpleSelect
            size="sm"
            className="h-7 w-40"
            value={sel}
            onValueChange={(v) => {
              setSel(v);
              save(v, reason, expires);
            }}
            options={workflow ? WORKFLOW_OPTIONS : HOST_OPTIONS}
          />
        ) : (
          <span className="text-xs text-foreground">
            {(workflow ? WORKFLOW_OPTIONS : HOST_OPTIONS).find((o) => o.value === sel)?.label || sel}
          </span>
        )}
        <TriageBadge triage={triage} />
        <span
          className={cn(
            'inline-flex items-center gap-1 text-[11px] text-muted-foreground transition-opacity',
            state === 'idle' && 'opacity-0'
          )}
          aria-live="polite"
        >
          {state === 'saving' ? 'Saving…' : (
            <>
              <RiCheckLine className="size-3.5 text-emerald-600 dark:text-emerald-400" /> Saved
            </>
          )}
        </span>
        <Tooltip>
          <TooltipTrigger
            render={<span className="ml-auto inline-flex text-muted-foreground" aria-label="About triage decisions" />}
          >
            <RiInformationLine className="size-3.5" />
          </TooltipTrigger>
          <TooltipContent className="max-w-xs">
            Saved as soon as you pick it and kept across scans. Accepted risk and false positive hide the finding from
            top findings and alerts, and are synced to DefectDojo on the next push.
          </TooltipContent>
        </Tooltip>
      </div>
      {triage && (
        <p className="text-[11px] text-muted-foreground">
          {triage.expired ? 'Expired acceptance: ' : ''}“{triage.reason}”, {triage.by || 'unknown'},{' '}
          {formatDateTime(triage.at)}
          {triage.expires_at ? `, until ${formatDateTime(triage.expires_at)}` : ', no expiry'}
        </p>
      )}
      {canWrite && isRisk && (
        <div className="flex flex-wrap items-center gap-2">
          <Input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                save(sel, reason, expires);
              }
            }}
            onBlur={() => reasonChanged && save(sel, reason, expires)}
            placeholder="Reason (required), e.g. jump host behind VPN, ticket SOC-123"
            className="h-7 min-w-[16rem] flex-1 text-xs"
            aria-invalid={!reason.trim() ? true : undefined}
          />
          <label className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
            Expires
            <Input
              type="date"
              value={expires}
              onChange={(e) => {
                setExpires(e.target.value);
                if (reason.trim()) save(sel, reason, e.target.value);
              }}
              className="h-7 w-36 text-xs"
            />
          </label>
        </div>
      )}
      {canWrite && isRisk && !reason.trim() && (
        <p className="text-[11px] text-amber-700 dark:text-amber-400">Add a reason and press Enter to save.</p>
      )}
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}
