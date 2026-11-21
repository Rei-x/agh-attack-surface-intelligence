import { useCallback, useEffect, useState } from 'react';
import { RiAddLine, RiDeleteBinLine, RiPriceTag3Line, RiRefreshLine, RiSaveLine } from '@remixicon/react';
import { api } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/context/ToastContext';
import { PERMISSIONS } from '@/lib/permissions';
import type { TagRule } from '@/types/api';
import { Empty } from '@/components/common';
import { Button } from '@/components/ui/button';
import { Card, CardAction, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';

interface Row {
  id?: string;
  cidr: string;
  tags: string;
  owner: string;
  environment: string;
  enabled: boolean;
}

const toRow = (r: TagRule): Row => ({
  id: r.id,
  cidr: r.cidr,
  tags: (r.tags || []).join(', '),
  owner: r.owner || '',
  environment: r.environment || '',
  enabled: r.enabled,
});

const toRule = (r: Row): TagRule => ({
  id: r.id,
  cidr: r.cidr.trim(),
  tags: r.tags
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean),
  owner: r.owner.trim() || undefined,
  environment: r.environment.trim() || undefined,
  enabled: r.enabled,
});

/**
 * Ownership by CIDR: rules mapping a network range to tags / owner / environment, applied
 * automatically on every ingest (analyst overrides still win). Lives next to scan targets.
 */
export function TagRulesPanel() {
  const { can } = useAuth();
  const toast = useToast();
  const canWrite = can(PERMISSIONS.ASSETS_WRITE);
  const [rows, setRows] = useState<Row[]>([]);
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const rules = await api.listTagRules();
      setRows(rules.map(toRow));
      setDirty(false);
    } catch (err) {
      toast.error('Reguły tagów', (err as Error).message);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const update = (idx: number, patch: Partial<Row>) => {
    setRows((prev) => prev.map((r, i) => (i === idx ? { ...r, ...patch } : r)));
    setDirty(true);
  };

  const save = async () => {
    setBusy(true);
    try {
      const saved = await api.saveTagRules(rows.filter((r) => r.cidr.trim()).map(toRule));
      setRows(saved.map(toRow));
      setDirty(false);
      toast.success('Zapisano reguły', 'Zastosowane przy kolejnym skanie każdego hosta');
    } catch (err) {
      toast.error('Błąd zapisu reguł', (err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const applyNow = async () => {
    setBusy(true);
    try {
      const res = await api.applyTagRules();
      toast.success('Zastosowano reguły', `${res.updated} z ${res.checked} hostów zaktualizowano`);
    } catch (err) {
      toast.error('Błąd', (err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm">
          <RiPriceTag3Line className="size-4 text-muted-foreground" />
          Właściciele i tagi wg CIDR · {rows.length}
        </CardTitle>
        {canWrite && (
          <CardAction className="flex items-center gap-2">
            <Button variant="outline" size="xs" disabled={busy || dirty || rows.length === 0} onClick={applyNow}>
              <RiRefreshLine data-icon="inline-start" /> Zastosuj do istniejących
            </Button>
            <Button size="xs" disabled={busy || !dirty} onClick={save}>
              <RiSaveLine data-icon="inline-start" /> Zapisz
            </Button>
          </CardAction>
        )}
      </CardHeader>
      <CardContent className="space-y-3">
        {rows.length === 0 ? (
          <Empty className="py-6">Brak reguł · np. 10.66.0.0/22 → wydzial-wi, admin@wi.agh.edu.pl</Empty>
        ) : (
          <div className="divide-y divide-border border-y border-border">
            <div className="grid grid-cols-[minmax(8rem,1fr)_minmax(8rem,1fr)_minmax(8rem,1fr)_6rem_2.5rem_2rem] gap-2 py-1.5 text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
              <span>CIDR</span>
              <span>Tagi</span>
              <span>Właściciel</span>
              <span>Środ.</span>
              <span>Aktywna</span>
              <span />
            </div>
            {rows.map((r, idx) => (
              <div
                key={r.id || `new-${idx}`}
                className="grid grid-cols-[minmax(8rem,1fr)_minmax(8rem,1fr)_minmax(8rem,1fr)_6rem_2.5rem_2rem] items-center gap-2 py-1.5"
              >
                <Input
                  value={r.cidr}
                  disabled={!canWrite}
                  onChange={(e) => update(idx, { cidr: e.target.value })}
                  placeholder="10.66.0.0/22"
                  className="font-mono"
                />
                <Input
                  value={r.tags}
                  disabled={!canWrite}
                  onChange={(e) => update(idx, { tags: e.target.value })}
                  placeholder="wydzial-wi, krytyczny"
                />
                <Input
                  value={r.owner}
                  disabled={!canWrite}
                  onChange={(e) => update(idx, { owner: e.target.value })}
                  placeholder="admin@wi.agh.edu.pl"
                />
                <Input
                  value={r.environment}
                  disabled={!canWrite}
                  onChange={(e) => update(idx, { environment: e.target.value })}
                  placeholder="prod"
                />
                <Switch
                  checked={r.enabled}
                  disabled={!canWrite}
                  onCheckedChange={(checked) => update(idx, { enabled: checked })}
                />
                {canWrite ? (
                  <Button
                    variant="ghost"
                    size="icon-xs"
                    aria-label="Usuń regułę"
                    className="text-muted-foreground hover:text-destructive"
                    onClick={() => {
                      setRows((prev) => prev.filter((_, i) => i !== idx));
                      setDirty(true);
                    }}
                  >
                    <RiDeleteBinLine />
                  </Button>
                ) : (
                  <span />
                )}
              </div>
            ))}
          </div>
        )}
        {canWrite && (
          <Button
            variant="outline"
            size="xs"
            onClick={() => {
              setRows((prev) => [...prev, { cidr: '', tags: '', owner: '', environment: '', enabled: true }]);
              setDirty(true);
            }}
          >
            <RiAddLine data-icon="inline-start" /> Dodaj regułę
          </Button>
        )}
      </CardContent>
    </Card>
  );
}
