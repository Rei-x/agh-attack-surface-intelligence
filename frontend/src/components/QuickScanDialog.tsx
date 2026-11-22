import { useEffect, useMemo, useState } from 'react';
import type React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  RiArrowDownSLine,
  RiArrowLeftLine,
  RiFlashlightLine,
  RiFlaskLine,
  RiHome4Line,
  RiPlayFill,
  RiRadarLine,
  RiTerminalBoxLine,
} from '@remixicon/react';
import { api } from '@/lib/api';
import { useToast } from '@/context/ToastContext';
import { formatDurationSeconds, formatNumber, plural } from '@/lib/format';
import { cn } from '@/lib/utils';
import type { QuickScanInfo, ScanRun, TargetEstimate } from '@/types/api';
import { OwnNetworkView, useAgentSetupState } from '@/components/QuickScanAgent';
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
  { label: 'This machine', hint: '127.0.0.1', value: '127.0.0.1' },
  { label: 'Lab AGH', hint: '172.28.0.10-14', value: '172.28.0.10-14' },
  { label: 'Subnet /24', hint: '256 IP', value: '172.28.0.0/24' },
  { label: 'Scale 16,384 IP', hint: '10.0.0.0/18', value: '10.0.0.0/18' },
];

// "auto" lets the server size the list to the scope: all 65535 ports for 1-4 IPs, the top
// 1000 + common alternative web/admin/db/mq ports up to 1024 IPs, a compact list above.
const DEFAULT_PORTS = 'auto';

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

/** "Enter targets yourself": any IP, CIDR, range or domain from this server. */
function CustomTargetsView({
  open,
  onBack,
  onStarted,
  onFullSetup,
}: {
  open: boolean;
  onBack: () => void;
  onStarted: (run: ScanRun) => void;
  onFullSetup: () => void;
}) {
  const toast = useToast();

  const [targetsText, setTargetsText] = useState('');
  const [ports, setPorts] = useState(DEFAULT_PORTS);
  // null = automatic (server default; raised for a full-range scan of 1-4 hosts)
  const [rate, setRate] = useState<number | null>(null);
  const [windowEnabled, setWindowEnabled] = useState(false);
  const [windowStart, setWindowStart] = useState('22:00');
  const [windowEnd, setWindowEnd] = useState('06:00');
  const [advancedOpen, setAdvancedOpen] = useState(false);

  const [estimate, setEstimate] = useState<TargetEstimate | null>(null);
  const [estimating, setEstimating] = useState(false);
  const [estimateError, setEstimateError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const targets = useMemo(() => parseTargets(targetsText), [targetsText]);

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
          max_rate_pps: rate ?? undefined,
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
        max_rate_pps: rate ?? undefined,
        window_enabled: windowEnabled,
        window_start: windowStart,
        window_end: windowEnd,
        timezone: 'Europe/Warsaw',
      });
      toast.success(
        'Scan started',
        `${run?.name || 'Quick scan'} · ${formatNumber(estimate?.effective_ips ?? run?.total_ips)} IP`
      );
      onStarted(run);
    } catch (err) {
      toast.error('Could not start scan', (err as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
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
          {estimate?.ports_label && (
            <span className="-mt-2 text-[11px] text-muted-foreground tabular-nums">
              Ports: {estimate.ports_label}
              {estimate.port_count ? ` (${formatNumber(estimate.port_count)})` : ''}
              {estimate.max_rate_pps ? `, ${formatNumber(estimate.max_rate_pps)} pps` : ''}
            </span>
          )}
          {estimate && estimate.excluded_ips > 0 && (
            <Notice tone={estimate.effective_ips === 0 ? 'danger' : 'warning'}>
              {formatNumber(estimate.excluded_ips)} of {formatNumber(estimate.total_ips)} IPs are covered by exclusions
              (Scans, Scope tab) and will not be scanned.
            </Notice>
          )}
          {estimateError && <Notice tone="danger">{estimateError}</Notice>}

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
                    placeholder="auto, or e.g. 22,80,443,8000-8100"
                    className="font-mono text-xs"
                  />
                </Field>
                <Field label="Max PPS" htmlFor="qs-rate">
                  <Input
                    id="qs-rate"
                    type="number"
                    min={10}
                    max={100000}
                    value={rate ?? ''}
                    placeholder="auto"
                    onChange={(e) => setRate(e.target.value === '' ? null : Math.max(1, Number(e.target.value) || 0))}
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
            <div className="flex items-center gap-3">
              <Button type="button" variant="ghost" size="sm" onClick={onBack}>
                <RiArrowLeftLine data-icon="inline-start" /> Back
              </Button>
              <Button type="button" variant="link" size="sm" className="px-0 text-muted-foreground" onClick={onFullSetup}>
                Full scanner setup →
              </Button>
            </div>
            <Button type="submit" disabled={targets.length === 0 || submitting}>
              {submitting ? <PeckSpinner className="h-3.5" /> : <RiPlayFill />}
              Start scan
            </Button>
          </DialogFooter>
        </form>
    </>
  );
}

type View = 'choose' | 'agent' | 'custom';

/** One big choice per option: the option body explains it, the button starts it. */
function OptionCard({
  icon: Icon,
  title,
  children,
  action,
  highlight,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  children: React.ReactNode;
  action: React.ReactNode;
  highlight?: boolean;
}) {
  return (
    <div className={cn('flex flex-col gap-3 border p-4', highlight ? 'border-primary/50 bg-primary/5' : 'border-border')}>
      <div className="flex items-center gap-2 text-sm font-semibold">
        <Icon className={cn('size-4', highlight ? 'text-primary' : 'text-muted-foreground')} />
        {title}
      </div>
      <div className="space-y-1.5 text-xs text-muted-foreground">{children}</div>
      <div>{action}</div>
    </div>
  );
}

function ChooseView({
  info,
  infoError,
  startingLab,
  onLab,
  onAgent,
  onCustom,
  onFullSetup,
}: {
  info: QuickScanInfo | null;
  infoError: string | null;
  startingLab: boolean;
  onLab: () => void;
  onAgent: () => void;
  onCustom: () => void;
  onFullSetup: () => void;
}) {
  const lab = info?.lab;
  return (
    <>
      <DialogHeader>
        <DialogTitle className="flex items-center gap-2">
          <RiRadarLine className="size-5 text-primary" />
          Quick scan
        </DialogTitle>
        <DialogDescription>
          Pick a network. You land on a live view where hosts and services appear while the scan runs.
        </DialogDescription>
      </DialogHeader>

      <div className="grid gap-3">
        <OptionCard
          icon={RiFlaskLine}
          title="Our lab network"
          highlight
          action={
            <Button onClick={onLab} disabled={!lab?.available || startingLab}>
              {startingLab ? <PeckSpinner className="h-3.5" /> : <RiPlayFill data-icon="inline-start" />}
              {lab?.active_run_id ? 'Watch the lab scan' : 'Scan the lab'}
            </Button>
          }
        >
          {!info && !infoError && (
            <span className="inline-flex items-center gap-2">
              <PeckSpinner className="h-3" /> Checking the lab
            </span>
          )}
          {infoError && <Notice tone="danger">{infoError}</Notice>}
          {lab && lab.available && (
            <>
              <p>
                A test range built like a campus network, with web apps, admin panels, databases and devices.
                Hosts show up block by block; the whole run takes a few minutes.
              </p>
              <p className="font-mono text-[11px] text-foreground/80">
                {lab.targets?.join(', ')} · {plural(lab.total_ips ?? 0, 'address', 'addresses')}
                {lab.port_count ? ` · ${formatNumber(lab.port_count)} ports` : ''}
                {lab.agent_name ? ` · agent ${lab.agent_name}` : ''}
              </p>
              {lab.active_run_id && <p>A lab scan is already running. You will join it.</p>}
            </>
          )}
          {lab && !lab.available && (
            <Notice tone="warning">The lab scan is not available right now: {lab.reason}.</Notice>
          )}
        </OptionCard>

        <OptionCard
          icon={RiHome4Line}
          title="Your own network"
          action={
            <Button variant="outline" onClick={onAgent}>
              <RiTerminalBoxLine data-icon="inline-start" /> Set up an agent
            </Button>
          }
        >
          <p>
            Paste one command on a computer in your network. A small agent connects out to this server, so nothing
            has to be opened in your firewall, and it only scans the private networks that computer is on.
          </p>
        </OptionCard>
      </div>

      <DialogFooter className="items-center sm:justify-between">
        <Button variant="link" size="sm" className="px-0 text-muted-foreground" onClick={onCustom}>
          Enter targets yourself
        </Button>
        <Button variant="link" size="sm" className="px-0 text-muted-foreground" onClick={onFullSetup}>
          Full scanner setup →
        </Button>
      </DialogFooter>
    </>
  );
}

export function QuickScanDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const toast = useToast();
  const navigate = useNavigate();
  const [view, setView] = useState<View>('choose');
  const [info, setInfo] = useState<QuickScanInfo | null>(null);
  const [infoError, setInfoError] = useState<string | null>(null);
  const [startingLab, setStartingLab] = useState(false);
  // Kept while the dialog is closed, so reopening it still waits for the same agent.
  const agentSetup = useAgentSetupState();

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setInfoError(null);
    api
      .quickScanInfo()
      .then((res) => !cancelled && setInfo(res))
      .catch((err) => !cancelled && setInfoError((err as Error).message));
    return () => {
      cancelled = true;
    };
  }, [open]);

  const goLive = (run: ScanRun) => {
    onOpenChange(false);
    setView('choose');
    navigate(`/scans?scan=${encodeURIComponent(run.id)}`);
  };

  const startLab = async () => {
    setStartingLab(true);
    try {
      const res = await api.quickScanLab();
      if (res.joined) toast.success('Joined the running lab scan', res.run.name);
      else toast.success('Lab scan started', res.run.name);
      goLive(res.run);
    } catch (err) {
      toast.error('Could not start the lab scan', (err as Error).message);
    } finally {
      setStartingLab(false);
    }
  };

  const fullSetup = () => {
    onOpenChange(false);
    navigate('/scans');
  };

  return (
    <Dialog open={open} onOpenChange={(o) => onOpenChange(o)}>
      <DialogContent className="gap-5 sm:max-w-2xl">
        {view === 'choose' && (
          <ChooseView
            info={info}
            infoError={infoError}
            startingLab={startingLab}
            onLab={startLab}
            onAgent={() => setView('agent')}
            onCustom={() => setView('custom')}
            onFullSetup={fullSetup}
          />
        )}
        {view === 'agent' && (
          <OwnNetworkView
            state={agentSetup}
            serverURL={info?.server_url}
            tokenAdmins={info?.token_admins}
            onBack={() => setView('choose')}
            onStarted={goLive}
          />
        )}
        {view === 'custom' && (
          <CustomTargetsView
            open={open}
            onBack={() => setView('choose')}
            onStarted={goLive}
            onFullSetup={fullSetup}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}
