import React, { useState } from 'react';
import {
  ChevronDown,
  ChevronUp,
  Clock,
  Gauge,
  Pause,
  Play,
  Radio,
  Square,
  Terminal,
  Trash2,
} from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../context/AuthContext';
import { useLiveEvents } from '../context/LiveEventsContext';
import { useToast } from '../context/ToastContext';
import { PERMISSIONS } from '../lib/permissions';
import { formatDurationSeconds, formatNumber, formatShortTime, scanStatusMeta } from '../lib/format';
import type { ScanRun } from '../types/api';

interface Props {
  activeScan: ScanRun | null | undefined;
  onScanUpdated?: () => void;
}

export function LiveTelemetryBanner({ activeScan, onScanUpdated }: Props) {
  const { can } = useAuth();
  const { connected, events, throttled, clearEvents } = useLiveEvents();
  const toast = useToast();
  const [consoleOpen, setConsoleOpen] = useState(false);
  const [busyAction, setBusyAction] = useState<string | null>(null);

  const canControl = can(PERMISSIONS.SCANS_RUN);

  const handleControl = async (action: 'pause' | 'resume' | 'stop') => {
    if (!activeScan) return;
    setBusyAction(action);
    try {
      if (action === 'pause') {
        await api.pauseScan(activeScan.id);
        toast.info('Skan wstrzymany', `Skan "${activeScan.name}" zatrzymany na granicy chunka.`);
      } else if (action === 'resume') {
        await api.resumeScan(activeScan.id);
        toast.success('Wznowiono skan', `Skan "${activeScan.name}" wznowiony od checkpointu.`);
      } else {
        await api.stopScan(activeScan.id);
        toast.warning('Emergency Stop', `Zatrzymano skan "${activeScan.name}".`);
      }
      onScanUpdated?.();
    } catch (err) {
      toast.error('Błąd sterowania skanem', (err as Error).message);
    } finally {
      setBusyAction(null);
    }
  };

  // Derive live overlay metrics from latest SSE scan.progress event if matching
  const latestProgress = events.find(
    (e) =>
      (e.type === 'scan.progress' || e.type === 'scan.chunk' || e.type === 'scan.paused_window') &&
      (!activeScan || !e.scan_run_id || e.scan_run_id === activeScan.id)
  );
  const p = latestProgress?.payload || {};

  const status = (p.status as string) || activeScan?.status || 'IDLE';
  const completedChunks =
    typeof p.completed_chunks === 'number'
      ? p.completed_chunks
      : activeScan?.completed_chunks ?? 0;
  const totalChunks =
    typeof p.total_chunks === 'number' ? p.total_chunks : activeScan?.total_chunks ?? 0;
  const scannedIPs =
    typeof p.scanned_ips === 'number' ? p.scanned_ips : activeScan?.scanned_ips ?? 0;
  const totalIPs = typeof p.total_ips === 'number' ? p.total_ips : activeScan?.total_ips ?? 0;
  const hostsPerSec =
    typeof p.hosts_per_sec === 'number' ? p.hosts_per_sec : activeScan?.hosts_per_sec ?? 0;
  const etaSeconds =
    typeof p.eta_seconds === 'number' ? p.eta_seconds : activeScan?.eta_seconds ?? 0;

  const pct =
    totalChunks > 0
      ? Math.min(100, Math.round((completedChunks / totalChunks) * 100))
      : totalIPs > 0
        ? Math.min(100, Math.round((scannedIPs / totalIPs) * 100))
        : 0;

  const meta = scanStatusMeta(status);
  const isPaused = status === 'PAUSED_WINDOW' || status === 'PAUSED_USER';
  const isRunning = status === 'RUNNING' || status === 'CALIBRATING' || status === 'QUEUED';

  return (
    <div className="rounded-xl border border-border-subtle bg-bg-card overflow-hidden shadow-sm">
      <div className="p-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="flex items-start gap-3 min-w-0 flex-1">
          <div
            className={`h-10 w-10 rounded-lg flex items-center justify-center shrink-0 border ${
              isRunning
                ? 'bg-cyan-500/15 border-cyan-500/35 text-cyan-400'
                : isPaused
                  ? 'bg-amber-500/15 border-amber-500/35 text-amber-400'
                  : 'bg-bg-elevated border-border-subtle text-text-muted'
            }`}
          >
            <Radio className={`h-5 w-5 ${isRunning ? 'animate-pulse' : ''}`} />
          </div>

          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-sm font-semibold text-text-primary">
                {activeScan ? `Aktywny Skan: ${activeScan.name}` : 'Telemetria Skanera (SSE)'}
              </h2>
              {activeScan ? (
                <span
                  className={`text-[11px] font-mono px-2 py-0.5 rounded border ${meta.badge}`}
                >
                  {meta.label}
                </span>
              ) : (
                <span className="text-[11px] font-mono px-2 py-0.5 rounded border bg-bg-elevated text-text-muted border-border-subtle">
                  OCZEKIWANIE
                </span>
              )}

              {/* Time-Window Status Pill */}
              {activeScan && (
                <span
                  className={`inline-flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded border ${
                    status === 'PAUSED_WINDOW'
                      ? 'bg-amber-500/15 text-amber-300 border-amber-500/40'
                      : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  }`}
                >
                  <Clock className="h-3 w-3" />
                  {status === 'PAUSED_WINDOW' ? 'Poza oknem (PAUSED_WINDOW)' : 'W oknie czasowym'}
                </span>
              )}

              {throttled && (
                <span className="text-[11px] px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/35">
                  Noise Governor: backoff aktywny
                </span>
              )}
            </div>

            {activeScan ? (
              <div className="mt-2.5 space-y-1.5">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-text-secondary">
                  <span className="font-mono">
                    Chunki: <strong className="text-text-primary">{completedChunks}/{totalChunks || 1}</strong>{' '}
                    ({pct}%) · IP: <strong className="text-text-primary">{formatNumber(scannedIPs)}/{formatNumber(totalIPs)}</strong>
                  </span>
                  <div className="flex items-center gap-4 font-mono text-xs">
                    <span className="flex items-center gap-1 text-cyan-400">
                      <Gauge className="h-3.5 w-3.5" />
                      {hostsPerSec.toFixed(1)} IP/s
                    </span>
                    <span className="flex items-center gap-1 text-text-muted">
                      <Clock className="h-3.5 w-3.5" />
                      ETA: {formatDurationSeconds(etaSeconds)}
                    </span>
                  </div>
                </div>
                <div className="h-2 rounded-full bg-bg-elevated overflow-hidden border border-border-subtle">
                  <div
                    className={`h-full transition-all duration-500 ${
                      status === 'PAUSED_WINDOW'
                        ? 'bg-amber-500'
                        : 'bg-gradient-to-r from-cyan-500 to-blue-500'
                    }`}
                    style={{ width: `${Math.max(pct, isRunning ? 4 : 0)}%` }}
                  />
                </div>
              </div>
            ) : (
              <p className="text-xs text-text-muted mt-1">
                Brak aktywnie działającego skanu. Strumień SSE ({connected ? 'połączony' : 'rozłączony'}) nasłuchuje zdarzeń skanera, zmian powierzchni ataku oraz Noise Governora.
              </p>
            )}
          </div>
        </div>

        {/* Actions */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {activeScan && canControl && (
            <>
              {isRunning && (
                <button
                  type="button"
                  disabled={busyAction !== null}
                  onClick={() => handleControl('pause')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-amber-500/15 text-amber-300 border border-amber-500/35 hover:bg-amber-500/25 disabled:opacity-50"
                >
                  <Pause className="h-3.5 w-3.5" />
                  Pause
                </button>
              )}
              {isPaused && (
                <button
                  type="button"
                  disabled={busyAction !== null}
                  onClick={() => handleControl('resume')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-500/15 text-emerald-300 border border-emerald-500/35 hover:bg-emerald-500/25 disabled:opacity-50"
                >
                  <Play className="h-3.5 w-3.5" />
                  Resume
                </button>
              )}
              {(isRunning || isPaused) && (
                <button
                  type="button"
                  disabled={busyAction !== null}
                  onClick={() => handleControl('stop')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-rose-500/15 text-rose-300 border border-rose-500/35 hover:bg-rose-500/25 disabled:opacity-50"
                >
                  <Square className="h-3.5 w-3.5" />
                  Emergency Stop
                </button>
              )}
            </>
          )}

          <button
            type="button"
            onClick={() => setConsoleOpen((v) => !v)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-border-subtle bg-bg-elevated text-text-secondary hover:text-text-primary hover:bg-bg-hover"
          >
            <Terminal className="h-3.5 w-3.5 text-cyan-400" />
            Konsola Live ({events.length})
            {consoleOpen ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
          </button>
        </div>
      </div>

      {/* Expandable Live Event Console */}
      {consoleOpen && (
        <div className="border-t border-border-subtle bg-bg-primary/90 p-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-mono uppercase tracking-wider text-text-muted">
              SSE Stream · /api/v1/events/stream
            </span>
            {events.length > 0 && (
              <button
                type="button"
                onClick={clearEvents}
                className="inline-flex items-center gap-1 text-[11px] text-text-muted hover:text-text-primary"
              >
                <Trash2 className="h-3 w-3" /> Wyczyść
              </button>
            )}
          </div>
          <div className="max-h-52 overflow-y-auto font-mono text-[11px] space-y-1">
            {events.length === 0 ? (
              <div className="text-text-muted py-3 text-center">
                Oczekiwanie na zdarzenia SSE ze skanera...
              </div>
            ) : (
              events.map((ev, idx) => (
                <div
                  key={`${ev.timestamp}-${idx}`}
                  className="flex items-start gap-2 px-2 py-1 rounded bg-bg-card/70 border border-border-subtle/50"
                >
                  <span className="text-text-muted shrink-0">{formatShortTime(ev.timestamp)}</span>
                  <span className="text-cyan-400 shrink-0 font-semibold">{ev.type}</span>
                  <span className="text-text-secondary break-all">
                    {JSON.stringify(ev.payload || {})}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
