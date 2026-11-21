import { useCallback, useEffect, useState } from 'react';
import {
  RiAlertLine,
  RiArrowLeftRightLine,
  RiCheckboxCircleLine,
  RiRefreshLine,
  RiTimeLine,
} from '@remixicon/react';
import { api } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/context/ToastContext';
import { useLiveRefresh } from '@/context/LiveEventsContext';
import { PERMISSIONS } from '@/lib/permissions';
import { TONE, formatDateTime, formatShortTime, severityMeta } from '@/lib/format';
import { cn } from '@/lib/utils';
import { AssetInspectorDrawer } from '@/components/AssetInspectorDrawer';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Empty,
  Field,
  PageHeader,
  Pill,
  SimpleSelect,
  Stat,
  StatStrip,
} from '@/components/common';
import type { ChangeEvent, ChangedServiceDiff, ScanDiffResponse, ScanRun } from '@/types/api';

type BeforeAfter = { before?: Record<string, unknown>; after?: Record<string, unknown> };

const hasBeforeAfter = (ch: BeforeAfter) =>
  Object.keys(ch.before || {}).length > 0 || Object.keys(ch.after || {}).length > 0;

export function DiffPage() {
  const { can } = useAuth();
  const toast = useToast();

  const [scans, setScans] = useState<ScanRun[]>([]);
  const [fromId, setFromId] = useState('');
  const [toId, setToId] = useState('');
  const [diff, setDiff] = useState<ScanDiffResponse | null>(null);
  const [allChanges, setAllChanges] = useState<ChangeEvent[]>([]);
  const [anomalyOnly, setAnomalyOnly] = useState(false);
  const [loading, setLoading] = useState(true);
  const [diffLoading, setDiffLoading] = useState(false);
  const [ackingId, setAckingId] = useState<string | null>(null);
  const [inspectHostId, setInspectHostId] = useState<string | null>(null);

  const canWrite = can(PERMISSIONS.ASSETS_WRITE);

  const loadInitial = useCallback(async (silent?: boolean) => {
    if (!silent) setLoading(true);
    try {
      const [scanList, changeList] = await Promise.all([
        api.listScans(),
        api.listChanges({ anomaly_only: anomalyOnly || undefined }),
      ]);
      setScans(scanList);
      setAllChanges(changeList);

      if (scanList.length >= 2 && !fromId && !toId) {
        // Default: second newest vs newest
        setFromId(scanList[1].id);
        setToId(scanList[0].id);
      } else if (scanList.length === 1 && !toId) {
        setFromId(scanList[0].id);
        setToId(scanList[0].id);
      }
    } catch (err) {
      if (!silent) toast.error('Błąd ładowania', (err as Error).message);
    } finally {
      if (!silent) setLoading(false);
    }
  }, [anomalyOnly, fromId, toId, toast]);

  useEffect(() => {
    loadInitial();
  }, [loadInitial]);

  const runDiff = useCallback(async (silent?: boolean) => {
    if (!fromId || !toId) return;
    if (!silent) setDiffLoading(true);
    try {
      const res = await api.diffScans(fromId, toId);
      setDiff(res);
    } catch (err) {
      if (!silent) toast.error('Błąd porównania', (err as Error).message);
    } finally {
      if (!silent) setDiffLoading(false);
    }
  }, [fromId, toId, toast]);

  // Silent background refresh on live data changes
  useLiveRefresh(() => {
    loadInitial(true);
    runDiff(true);
  });

  useEffect(() => {
    if (fromId && toId) {
      runDiff();
    }
  }, [fromId, toId, runDiff]);

  const handleAck = async (ch: ChangeEvent) => {
    setAckingId(ch.id);
    try {
      await api.acknowledgeChange(ch.id);
      toast.success('Potwierdzono', ch.summary);
      await Promise.all([runDiff(), loadInitial()]);
    } catch (err) {
      toast.error('Błąd potwierdzenia', (err as Error).message);
    } finally {
      setAckingId(null);
    }
  };

  const newHosts = diff?.new_hosts || [];
  const missingHosts = diff?.missing_hosts || [];
  const newServices = diff?.new_services || [];
  const closedServices = diff?.closed_services || [];
  const changedServices = diff?.changed_services || [];
  const timeAnomalies = diff?.time_anomalies || [];

  const addedCount = newHosts.length + newServices.length;
  const removedCount = missingHosts.length + closedServices.length;
  const changedCount = changedServices.length + timeAnomalies.length;

  const scanOptions = scans.map((s) => ({
    value: s.id,
    label: `${s.name} · ${formatShortTime(s.started_at)} · ${s.active_hosts} hostów`,
  }));

  const renderBeforeAfter = (ch: BeforeAfter) => {
    const before = ch.before || {};
    const after = ch.after || {};
    const keys = Array.from(new Set([...Object.keys(before), ...Object.keys(after)]));
    if (keys.length === 0) return null;

    return (
      <div className="grid grid-cols-1 gap-2 font-mono text-[11px] md:grid-cols-2">
        <div className={cn('border p-2.5', TONE.danger)}>
          <div className="mb-1 text-[10px] font-semibold tracking-widest uppercase">Przed · A</div>
          {keys.map((k) => (
            <div key={k} className="break-all whitespace-normal">
              <span className="text-muted-foreground">{k}: </span>
              <span className="text-foreground">
                {before[k] !== undefined ? JSON.stringify(before[k]) : '—'}
              </span>
            </div>
          ))}
        </div>
        <div className={cn('border p-2.5', TONE.success)}>
          <div className="mb-1 text-[10px] font-semibold tracking-widest uppercase">Po · B</div>
          {keys.map((k) => (
            <div key={k} className="break-all whitespace-normal">
              <span className="text-muted-foreground">{k}: </span>
              <span className="text-foreground">
                {after[k] !== undefined ? JSON.stringify(after[k]) : '—'}
              </span>
            </div>
          ))}
        </div>
      </div>
    );
  };

  const hostLink = (hostId: string, ip: string, port?: number) => (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        setInspectHostId(hostId);
      }}
      className="font-mono text-xs font-semibold text-primary hover:underline"
    >
      {ip}
      {port ? `:${port}` : ''}
    </button>
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Diff skanów"
        actions={
          <div className="flex flex-wrap items-end gap-2">
            <Field label="Scan A" className="w-64">
              <SimpleSelect
                value={fromId}
                onValueChange={setFromId}
                options={scanOptions}
                placeholder="Skan bazowy"
                size="sm"
              />
            </Field>
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label="Zamień A ↔ B"
              title="Zamień A ↔ B"
              onClick={() => {
                setFromId(toId);
                setToId(fromId);
              }}
            >
              <RiArrowLeftRightLine />
            </Button>
            <Field label="Scan B" className="w-64">
              <SimpleSelect
                value={toId}
                onValueChange={setToId}
                options={scanOptions}
                placeholder="Skan docelowy"
                size="sm"
              />
            </Field>
            <Button size="sm" disabled={!fromId || !toId || diffLoading} onClick={() => runDiff()}>
              <RiRefreshLine className={cn(diffLoading && 'animate-spin')} />
              Porównaj
            </Button>
          </div>
        }
      />

      {diff && (
        <StatStrip>
          <Stat
            label="Nowe hosty"
            value={diff.summary?.new_hosts ?? newHosts.length}
            tone="success"
          />
          <Stat
            label="Znikające hosty"
            value={diff.summary?.missing_hosts ?? missingHosts.length}
            tone="danger"
          />
          <Stat
            label="Nowe usługi"
            value={diff.summary?.new_services ?? newServices.length}
            tone="success"
          />
          <Stat
            label="Zamknięte usługi"
            value={diff.summary?.closed_services ?? closedServices.length}
            tone="danger"
          />
          <Stat
            label="Zmienione usługi"
            value={diff.summary?.changed_services ?? changedServices.length}
            tone="warning"
          />
          <Stat
            label="Anomalie pory dnia"
            value={diff.summary?.time_anomalies ?? timeAnomalies.length}
            tone="danger"
          />
        </StatStrip>
      )}

      <Tabs defaultValue="added">
        <TabsList variant="line">
          <TabsTrigger value="added">Dodane ({addedCount})</TabsTrigger>
          <TabsTrigger value="removed">Usunięte ({removedCount})</TabsTrigger>
          <TabsTrigger value="changed">Zmienione ({changedCount})</TabsTrigger>
          <TabsTrigger value="log">Dziennik ({allChanges.length})</TabsTrigger>
        </TabsList>

        {/* Added */}
        <TabsContent value="added" className="pt-4">
          <Card size="sm" className="py-0">
            {addedCount === 0 ? (
              <Empty>Brak nowych zasobów</Empty>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-24">Typ</TableHead>
                    <TableHead>Adres</TableHead>
                    <TableHead>Szczegóły</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {newHosts.map((h) => (
                    <TableRow
                      key={h.id}
                      onClick={() => setInspectHostId(h.id)}
                      className="cursor-pointer"
                    >
                      <TableCell>
                        <Pill tone="success">+ Host</Pill>
                      </TableCell>
                      <TableCell className="font-mono text-xs font-semibold">
                        {h.ip} {h.hostname ? `(${h.hostname})` : ''}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {h.lifecycle_state}
                      </TableCell>
                    </TableRow>
                  ))}
                  {newServices.map((s) => (
                    <TableRow
                      key={s.id}
                      onClick={() => setInspectHostId(s.host_id)}
                      className="cursor-pointer"
                    >
                      <TableCell>
                        <Pill tone="success">+ Usługa</Pill>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {s.host_ip || ''}:{s.port}/{s.protocol} ({s.service_name})
                      </TableCell>
                      <TableCell className="max-w-[240px] truncate text-xs text-muted-foreground">
                        {s.http?.title || s.product || ''}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Card>
        </TabsContent>

        {/* Removed */}
        <TabsContent value="removed" className="pt-4">
          <Card size="sm" className="py-0">
            {removedCount === 0 ? (
              <Empty>Brak usuniętych zasobów</Empty>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-24">Typ</TableHead>
                    <TableHead>Adres</TableHead>
                    <TableHead>Stan</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {missingHosts.map((h) => (
                    <TableRow
                      key={h.id}
                      onClick={() => setInspectHostId(h.id)}
                      className="cursor-pointer"
                    >
                      <TableCell>
                        <Pill tone="danger">− Host</Pill>
                      </TableCell>
                      <TableCell className="font-mono text-xs font-semibold">
                        {h.ip} {h.hostname ? `(${h.hostname})` : ''}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {h.lifecycle_state}
                      </TableCell>
                    </TableRow>
                  ))}
                  {closedServices.map((s) => (
                    <TableRow
                      key={s.id}
                      onClick={() => setInspectHostId(s.host_id)}
                      className="cursor-pointer"
                    >
                      <TableCell>
                        <Pill tone="danger">− Usługa</Pill>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {s.host_ip || ''}:{s.port}/{s.protocol} ({s.service_name})
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">zamknięta</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Card>
        </TabsContent>

        {/* Changed + time anomalies */}
        <TabsContent value="changed" className="pt-4">
          <Card size="sm" className="py-0">
            {changedCount === 0 ? (
              <Empty>Brak zmian</Empty>
            ) : (
              <div className="divide-y divide-border">
                {[...timeAnomalies, ...changedServices].map((ch: ChangedServiceDiff, idx) => {
                  const sev = severityMeta(ch.severity || (ch.is_time_anomaly ? 'high' : 'medium'));
                  return (
                    <div
                      key={ch.id || `${ch.host_id}-${ch.port}-${idx}`}
                      className="space-y-3 px-5 py-4"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex min-w-0 flex-wrap items-center gap-2">
                          <Pill className={sev.badge}>{sev.label}</Pill>
                          {hostLink(ch.host_id, ch.host_ip, ch.port)}
                          <span className="text-xs">{ch.summary}</span>
                          {ch.is_time_anomaly && (
                            <Pill tone="danger">
                              <RiAlertLine className="size-3" /> Anomalia {ch.time_slot}
                            </Pill>
                          )}
                          {ch.is_expected_schedule && (
                            <Pill tone="neutral">
                              <RiTimeLine className="size-3" /> Harmonogram
                            </Pill>
                          )}
                        </div>

                        {ch.acknowledged_at ? (
                          <Pill tone="success">
                            <RiCheckboxCircleLine className="size-3" /> {ch.acknowledged_by}
                          </Pill>
                        ) : canWrite && ch.id ? (
                          <Button
                            variant="outline"
                            size="xs"
                            disabled={ackingId === ch.id}
                            onClick={() => handleAck(ch as ChangeEvent)}
                          >
                            {ackingId === ch.id ? '…' : 'Acknowledge'}
                          </Button>
                        ) : null}
                      </div>
                      {renderBeforeAfter(ch)}
                    </div>
                  );
                })}
              </div>
            )}
          </Card>
        </TabsContent>

        {/* Full change log */}
        <TabsContent value="log" className="space-y-3 pt-4">
          <div className="flex items-center justify-end gap-2">
            <Switch
              id="anomaly-only"
              size="sm"
              checked={anomalyOnly}
              onCheckedChange={(checked) => setAnomalyOnly(checked)}
            />
            <Label htmlFor="anomaly-only" className="text-xs text-muted-foreground">
              Tylko TIME_ANOMALY
            </Label>
          </div>
          <Card size="sm" className="py-0">
            {loading && allChanges.length === 0 ? (
              <Empty>Ładowanie…</Empty>
            ) : allChanges.length === 0 ? (
              <Empty>Brak zdarzeń</Empty>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Waga</TableHead>
                    <TableHead>Typ</TableHead>
                    <TableHead>Host</TableHead>
                    <TableHead>Zmiana</TableHead>
                    <TableHead>Czas</TableHead>
                    <TableHead className="text-right">Ack</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {allChanges.slice(0, 40).map((ch) => {
                    const sev = severityMeta(ch.severity);
                    const showBA = hasBeforeAfter(ch);
                    return [
                      <TableRow key={ch.id} className={cn(showBA && 'border-b-0')}>
                        <TableCell>
                          <Pill className={sev.badge}>{sev.label}</Pill>
                        </TableCell>
                        <TableCell className="font-mono text-[11px] text-muted-foreground">
                          {ch.event_type}
                        </TableCell>
                        <TableCell>{hostLink(ch.host_id, ch.host_ip, ch.port)}</TableCell>
                        <TableCell className="max-w-[420px] truncate text-xs">{ch.summary}</TableCell>
                        <TableCell className="font-mono text-[11px] text-muted-foreground">
                          {formatDateTime(ch.created_at)}
                        </TableCell>
                        <TableCell className="text-right">
                          {ch.acknowledged_at ? (
                            <Pill tone="success">
                              <RiCheckboxCircleLine className="size-3" /> Ack
                            </Pill>
                          ) : canWrite ? (
                            <Button
                              variant="outline"
                              size="xs"
                              disabled={ackingId === ch.id}
                              onClick={() => handleAck(ch)}
                            >
                              Acknowledge
                            </Button>
                          ) : null}
                        </TableCell>
                      </TableRow>,
                      showBA ? (
                        <TableRow key={`${ch.id}-ba`} className="hover:bg-transparent">
                          <TableCell colSpan={6} className="pt-0 whitespace-normal">
                            {renderBeforeAfter(ch)}
                          </TableCell>
                        </TableRow>
                      ) : null,
                    ];
                  })}
                </TableBody>
              </Table>
            )}
          </Card>
        </TabsContent>
      </Tabs>

      <AssetInspectorDrawer
        hostId={inspectHostId}
        onClose={() => setInspectHostId(null)}
        onUpdated={loadInitial}
      />
    </div>
  );
}
