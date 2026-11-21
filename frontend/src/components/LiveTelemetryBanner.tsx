import { useState, type ReactNode } from 'react';
import { RiPauseLine, RiPlayLine, RiStopLine } from '@remixicon/react';
import { api } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import { useLiveEvents } from '@/context/LiveEventsContext';
import { useToast } from '@/context/ToastContext';
import { PERMISSIONS } from '@/lib/permissions';
import { formatDurationSeconds, formatNumber, scanStatusMeta } from '@/lib/format';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { Pill } from '@/components/common';
import { LiveDot } from '@/components/LiveIndicator';
import type { ScanRun } from '@/types/api';

interface Props {
  activeScan: ScanRun | null | undefined;
  onScanUpdated?: () => void;
}

const ACTIVE = new Set(['RUNNING', 'CALIBRATING', 'QUEUED']);
const PAUSED = new Set(['PAUSED_WINDOW', 'PAUSED_USER']);

function ControlButton({
  label,
  onClick,
  disabled,
  destructive,
  children,
}: {
  label: string;
  onClick: () => void;
  disabled?: boolean;
  destructive?: boolean;
  children: ReactNode;
}) {
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <Button
            variant={destructive ? 'destructive' : 'outline'}
            size="icon-xs"
            aria-label={label}
            disabled={disabled}
            onClick={onClick}
          />
        }
      >
        {children}
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
}

function Metric({ label, children }: { label: string; children: ReactNode }) {
  return (
    <span className="flex items-baseline gap-1">
      <span className="text-foreground">{children}</span>
      <span className="text-[10px] tracking-wider uppercase">{label}</span>
    </span>
  );
}

export function LiveTelemetryBanner({ activeScan, onScanUpdated }: Props) {
  const { can } = useAuth();
  const { activeScan: live, throttled } = useLiveEvents();
  const toast = useToast();
  const [busyAction, setBusyAction] = useState<string | null>(null);

  // Live SSE state wins when it refers to the same run (or the server hasn't caught up yet).
  const liveMatches =
    !!live && (!activeScan || !live.scan_run_id || live.scan_run_id === activeScan.id);
  const L = liveMatches ? live : null;

  const scanId = activeScan?.id || L?.scan_run_id;
  const name = activeScan?.name || L?.name || '—';
  const status = L?.status || activeScan?.status || 'IDLE';

  const pick = (liveVal: number | undefined, serverVal: number | undefined) =>
    L && typeof liveVal === 'number' && (liveVal > 0 || !serverVal) ? liveVal : serverVal ?? 0;

  const completedChunks = pick(L?.completed_chunks, activeScan?.completed_chunks);
  const totalChunks = pick(L?.total_chunks, activeScan?.total_chunks);
  const scannedIPs = pick(L?.scanned_ips, activeScan?.scanned_ips);
  const totalIPs = pick(L?.total_ips, activeScan?.total_ips);
  const hostsPerSec = L ? L.hosts_per_sec : activeScan?.hosts_per_sec ?? 0;
  const etaSeconds = L ? L.eta_seconds : activeScan?.eta_seconds ?? 0;
  const latestHost = L?.latestHost;

  const isRunning = ACTIVE.has(status);
  const isPaused = PAUSED.has(status);
  if (!scanId || !(isRunning || isPaused)) return null;

  const pct =
    totalIPs > 0
      ? Math.min(100, (scannedIPs / totalIPs) * 100)
      : totalChunks > 0
        ? Math.min(100, (completedChunks / totalChunks) * 100)
        : 0;

  const meta = scanStatusMeta(status);
  const canControl = can(PERMISSIONS.SCANS_RUN);

  const handleControl = async (action: 'pause' | 'resume' | 'stop') => {
    setBusyAction(action);
    try {
      if (action === 'pause') {
        await api.pauseScan(scanId);
        toast.info('Skan wstrzymany', name);
      } else if (action === 'resume') {
        await api.resumeScan(scanId);
        toast.success('Skan wznowiony', name);
      } else {
        await api.stopScan(scanId);
        toast.warning('Emergency Stop', name);
      }
      onScanUpdated?.();
    } catch (err) {
      toast.error('Błąd sterowania skanem', (err as Error).message);
    } finally {
      setBusyAction(null);
    }
  };

  return (
    <div className="relative bg-card ring-1 ring-foreground/5">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2">
          <LiveDot live={isRunning} />
          <Pill className={meta.badge}>{meta.label}</Pill>
          <span className="max-w-48 truncate text-sm font-medium">{name}</span>
          {throttled && <Pill tone="warning">Governor</Pill>}
        </div>

        <div className="flex shrink-0 items-center gap-4 font-mono text-[11px] text-muted-foreground tabular-nums">
          <Metric label="%">{Math.floor(pct)}</Metric>
          <Metric label="IP/s">{hostsPerSec.toFixed(1)}</Metric>
          <Metric label="ETA">{formatDurationSeconds(etaSeconds)}</Metric>
          <Metric label="chunks">
            {completedChunks}/{totalChunks || '—'}
          </Metric>
          <span className="hidden lg:inline">
            {formatNumber(scannedIPs)}/{formatNumber(totalIPs)}
          </span>
        </div>

        <div className="hidden min-w-0 flex-1 items-center gap-1.5 font-mono text-[11px] text-muted-foreground md:flex">
          {latestHost && (
            <span key={latestHost.ip + latestHost.at} className="min-w-0 truncate animate-in fade-in slide-in-from-bottom-1 duration-300">
              Last discovered:{' '}
              <span className="text-foreground">{latestHost.ip}</span>
              {latestHost.ports.length > 0 && (
                <> ({latestHost.ports.slice(0, 4).map((p) => `:${p}`).join(', ')})</>
              )}
            </span>
          )}
        </div>

        {canControl && (
          <div className="ml-auto flex shrink-0 items-center gap-1">
            {isRunning && (
              <ControlButton label="Pause" disabled={busyAction !== null} onClick={() => handleControl('pause')}>
                <RiPauseLine />
              </ControlButton>
            )}
            {isPaused && (
              <ControlButton label="Resume" disabled={busyAction !== null} onClick={() => handleControl('resume')}>
                <RiPlayLine />
              </ControlButton>
            )}
            <ControlButton
              label="Emergency Stop"
              destructive
              disabled={busyAction !== null}
              onClick={() => handleControl('stop')}
            >
              <RiStopLine />
            </ControlButton>
          </div>
        )}
      </div>

      {/* Progress rail */}
      <div className="h-0.5 w-full bg-muted">
        <div
          className={cn(
            'h-full transition-[width] duration-700 ease-out',
            status === 'PAUSED_WINDOW' || status === 'PAUSED_USER' ? 'bg-amber-500' : 'bg-primary'
          )}
          style={{ width: `${Math.max(pct, isRunning ? 1 : 0)}%` }}
        />
      </div>
    </div>
  );
}
