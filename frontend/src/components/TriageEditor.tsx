import { useEffect, useState } from 'react';
import { RiSaveLine } from '@remixicon/react';
import type { TriagePatch } from '@/lib/api';
import type { TriageInfo } from '@/types/api';
import { formatDateTime } from '@/lib/format';
import { SimpleSelect } from '@/components/common';
import { TriageBadge } from '@/components/AssetQueryHelp';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';

const RISK = ['accepted_risk', 'false_positive'];
const NONE = '__none__';

const WORKFLOW_OPTIONS = [
  { value: 'new', label: 'new' },
  { value: 'triaged', label: 'triaged' },
  { value: 'accepted_risk', label: 'accepted_risk (akceptacja ryzyka)' },
  { value: 'false_positive', label: 'false_positive' },
];
const HOST_OPTIONS = [
  { value: NONE, label: 'Brak decyzji' },
  { value: 'accepted_risk', label: 'accepted_risk (akceptacja ryzyka)' },
  { value: 'false_positive', label: 'false_positive' },
];

/**
 * Triage decision editor. accepted_risk / false_positive require a reason and may expire;
 * the decision is stored as an encrypted override, preserved across scans, and hides the
 * finding from "most important findings" and alerts until it expires.
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
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    setSel(initialStatus);
    setReason(active?.reason || '');
    setExpires(active?.expires_at ? active.expires_at.slice(0, 10) : '');
    setError('');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status, triage?.status, triage?.reason, triage?.expires_at, triage?.expired]);

  const isRisk = RISK.includes(sel);

  const save = async () => {
    setError('');
    if (isRisk && !reason.trim()) {
      setError('Uzasadnienie jest wymagane');
      return;
    }
    setSaving(true);
    try {
      if (isRisk) {
        await onSave({ status: sel, reason: reason.trim(), expires_at: expires || undefined });
      } else if (sel === NONE) {
        await onSave(null);
      } else {
        await onSave({ status: sel });
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-2 border border-border bg-card px-4 py-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
          Decyzja (triage)
        </span>
        <TriageBadge triage={triage} />
      </div>
      {triage && (
        <p className="text-[11px] text-muted-foreground">
          {triage.expired ? 'Wygasła akceptacja: ' : ''}
          „{triage.reason}” · {triage.by || '—'} · {formatDateTime(triage.at)}
          {triage.expires_at ? ` · do ${formatDateTime(triage.expires_at)}` : ' · bezterminowo'}
        </p>
      )}
      {canWrite && (
        <>
          <SimpleSelect value={sel} onValueChange={setSel} options={workflow ? WORKFLOW_OPTIONS : HOST_OPTIONS} />
          {isRisk && (
            <>
              <Textarea
                rows={2}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Uzasadnienie (wymagane), np. jump host dostępny tylko z VPN, ticket SOC-123"
              />
              <label className="flex items-center gap-2 text-[11px] text-muted-foreground">
                Wygasa
                <Input
                  type="date"
                  value={expires}
                  onChange={(e) => setExpires(e.target.value)}
                  className="w-44"
                />
                <span>(puste = bezterminowo)</span>
              </label>
            </>
          )}
          {error && <p className="text-xs text-destructive">{error}</p>}
          <div className="flex justify-end">
            <Button type="button" size="xs" disabled={saving} onClick={save}>
              <RiSaveLine data-icon="inline-start" />
              {saving ? 'Zapisywanie…' : 'Zapisz decyzję'}
            </Button>
          </div>
        </>
      )}
    </div>
  );
}
