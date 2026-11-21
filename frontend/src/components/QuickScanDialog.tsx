import { useEffect, useMemo, useState } from 'react';
import type React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  RiArrowDownSLine,
  RiFlashlightLine,
  RiPlayFill,
  RiRadarLine,
} from '@remixicon/react';
import { api } from '@/lib/api';
import { useToast } from '@/context/ToastContext';
import { formatDurationSeconds, formatNumber } from '@/lib/format';
import { cn } from '@/lib/utils';
import type { TargetEstimate } from '@/types/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Field, Notice } from '@/components/common';
import { PeckSpinner } from '@/components/Woodpecker';

const PRESETS = [
  { label: 'Lab AGH', hint: '172.28.0.10-14', value: '172.28.0.10-14' },
  { label: 'Subnet /24', hint: '256 IP', value: '172.28.0.0/24' },
  { label: 'Scale 16,384 IP', hint: '10.0.0.0/18', value: '10.0.0.0/18' },
];

const DEFAULT_PORTS = '21,22,23,25,53,80,110,143,443,445,554,631,3000,3306,3389,5000,5432,6379,8000,8080,8081,8443,8888,9000,9090,9100,9200,27017';

function parseTargets(text: string): string[] {
  return text
    .split(/[\n,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function EstimateCell({ label, value, tone }: { label: string; value: React.ReactNode; tone?: 'warning' }) {
  return (
    <div className="flex min-w-0 flex-col gap-1 px-3 py-2.5">
      <span className="truncate text-[9px] font-semibold tracking-widest text-muted-foreground uppercase">
        {label}
      </span>
      <span
        className={cn(
          'font-mono text-sm font-semibold tabular-nums',
          tone === 'warning' && 'text-amber-600 dark:text-amber-400'
        )}
      >
        {value}
      </span>
    </div>
  );
}

export function QuickScanDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const toast = useToast();
  const navigate = useNavigate();

  const [targetsText, setTargetsText] = useState('');
  const [ports, setPorts] = useState(DEFAULT_PORTS);
  const [rate, setRate] = useState(1000);
  const [windowEnabled, setWindowEnabled] = useState(false);
  const [windowStart, setWindowStart] = useState('22:00');
  const [windowEnd, setWindowEnd] = useState('06:00');
  const [advancedOpen, setAdvancedOpen] = useState(false);

  const [estimate, setEstimate] = useState<TargetEstimate | null>(null);
  const [estimating, setEstimating] = useState(false);
  const [estimateError, setEstimateError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const targets = useMemo(() => parseTargets(targetsText), [targetsText]);

  // Debounced live estimator
  useEffect(() => {
    if (!open) return;
    if (targets.length === 0) {
      setEstimate(null);
      setEstimateError(null);
      return;
    }
    let cancelled = false;
    const t = window.setTimeout(async () => {
      setEstimating(true);
      try {
        const res = await api.estimateTargets({
          targets,
          ports,
          allowed_ports: ports,
          max_rate_pps: rate,
          window_enabled: windowEnabled,
          window_start: windowStart,
          window_end: windowEnd,
          timezone: 'Europe/Warsaw',
        });
        if (!cancelled) {
          setEstimate(res);
          setEstimateError(null);
        }
      } catch (err) {
        if (!cancelled) {
          setEstimate(null);
          setEstimateError((err as Error).message);
        }
      } finally {
        if (!cancelled) setEstimating(false);
      }
    }, 350);
    return () => {
      cancelled = true;
      window.clearTimeout(t);
    };
  }, [open, targets, ports, rate, windowEnabled, windowStart, windowEnd]);

  const handleSubmit = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (targets.length === 0 || submitting) return;
    setSubmitting(true);
    try {
      const run = await api.startScan({
        name: `Quick scan: ${targets.slice(0, 2).join(', ')}${targets.length > 2 ? ` +${targets.length - 2}` : ''}`,
        targets,
        allowed_ports: ports,
        max_rate_pps: rate,
        window_enabled: windowEnabled,
        window_start: windowStart,
        window_end: windowEnd,
        timezone: 'Europe/Warsaw',
      });
      toast.success(
        'Scan started',
        `${run?.name || 'Quick scan'} · ${formatNumber(estimate?.effective_ips ?? run?.total_ips)} IP`
      );
      onOpenChange(false);
    } catch (err) {
      toast.error('Could not start scan', (err as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => onOpenChange(o)}>
      <DialogContent className="gap-5 sm:max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <RiRadarLine className="size-5 text-primary" />
            New scan
          </DialogTitle>
          <DialogDescription>IP, CIDR, range or domain. One per line or comma separated.</DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div className="flex flex-wrap gap-1.5">
            {PRESETS.map((p) => {
              const active = targetsText.trim() === p.value;
              return (
                <button
                  key={p.value}
                  type="button"
                  onClick={() => setTargetsText(p.value)}
                  className={cn(
                    'inline-flex h-7 items-center gap-1.5 border px-2.5 text-[11px] font-semibold transition-colors',
                    active
                      ? 'border-primary bg-primary/10 text-primary'
                      : 'border-border text-muted-foreground hover:bg-muted hover:text-foreground'
                  )}
                >
                  <RiFlashlightLine className="size-3" />
                  {p.label}
                  <span className="font-mono font-normal opacity-70">({p.hint})</span>
                </button>
              );
            })}
          </div>

          <Field label="Targets" htmlFor="qs-targets">
            <Textarea
              id="qs-targets"
              value={targetsText}
              onChange={(e) => setTargetsText(e.target.value)}
              rows={3}
              placeholder={'10.66.0.0/24\n10.0.0.1-50, intranet.agh.edu.pl'}
              className="font-mono text-xs"
              autoFocus
              onKeyDown={(e) => {
                if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) handleSubmit();
              }}
            />
          </Field>

          {/* Live estimator strip */}
          <div className="relative grid grid-cols-4 divide-x divide-border border border-border bg-muted/30">
            <EstimateCell label="Effective IPs" value={estimate ? formatNumber(estimate.effective_ips) : 'n/a'} />
            <EstimateCell label="Chunks" value={estimate ? formatNumber(estimate.chunk_count) : 'n/a'} />
            <EstimateCell
              label="Chunk size"
              value={estimate ? formatNumber(estimate.recommended_chunk_size) : 'n/a'}
            />
            <EstimateCell
              label="ETA"
              value={estimate ? formatDurationSeconds(estimate.estimated_seconds) : 'n/a'}
              tone={estimate && windowEnabled && !estimate.fits_in_window ? 'warning' : undefined}
            />
            {estimating && (
              <PeckSpinner className="absolute top-1.5 right-1.5 h-3" />
            )}
          </div>
          {estimate && estimate.excluded_ips > 0 && (
            <span className="-mt-2 text-[11px] text-muted-foreground tabular-nums">
              {formatNumber(estimate.excluded_ips)} IPs excluded out of {formatNumber(estimate.total_ips)}
            </span>
          )}
          {estimateError && <Notice tone="danger">{estimateError}</Notice>}

          {/* Advanced */}
          <div className="border border-border">
            <button
              type="button"
              onClick={() => setAdvancedOpen((v) => !v)}
              className="flex w-full items-center justify-between px-3 py-2 text-[10px] font-semibold tracking-widest text-muted-foreground uppercase hover:text-foreground"
              aria-expanded={advancedOpen}
            >
              Parameters and time window
              <RiArrowDownSLine className={cn('size-4 transition-transform', advancedOpen && 'rotate-180')} />
            </button>
            {advancedOpen && (
              <div className="grid grid-cols-2 gap-3 border-t border-border p-3">
                <Field label="Ports" htmlFor="qs-ports" className="col-span-2">
                  <Input
                    id="qs-ports"
                    value={ports}
                    onChange={(e) => setPorts(e.target.value)}
                    className="font-mono text-xs"
                  />
                </Field>
                <Field label="Max PPS" htmlFor="qs-rate">
                  <Input
                    id="qs-rate"
                    type="number"
                    min={10}
                    max={100000}
                    value={rate}
                    onChange={(e) => setRate(Math.max(1, Number(e.target.value) || 0))}
                    className="font-mono tabular-nums"
                  />
                </Field>
                <Field label="Time window">
                  <div className="flex h-8 items-center gap-2">
                    <Switch size="sm" checked={windowEnabled} onCheckedChange={(c) => setWindowEnabled(c)} />
                    <Input
                      type="time"
                      value={windowStart}
                      disabled={!windowEnabled}
                      onChange={(e) => setWindowStart(e.target.value)}
                      className="h-8 font-mono text-xs tabular-nums"
                      aria-label="Window start"
                    />
                    <span className="text-muted-foreground">to</span>
                    <Input
                      type="time"
                      value={windowEnd}
                      disabled={!windowEnabled}
                      onChange={(e) => setWindowEnd(e.target.value)}
                      className="h-8 font-mono text-xs tabular-nums"
                      aria-label="Window end"
                    />
                  </div>
                </Field>
              </div>
            )}
          </div>

          <DialogFooter className="items-center sm:justify-between">
            <Button
              type="button"
              variant="link"
              size="sm"
              className="px-0 text-muted-foreground"
              onClick={() => {
                onOpenChange(false);
                navigate('/scans');
              }}
            >
              Full scanner setup →
            </Button>
            <Button type="submit" disabled={targets.length === 0 || submitting}>
              {submitting ? <PeckSpinner className="h-3.5" /> : <RiPlayFill />}
              Start scan
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
