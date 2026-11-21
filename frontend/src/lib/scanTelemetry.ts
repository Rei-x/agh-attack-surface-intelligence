/** Helpers for scan rate-control telemetry and nmap command display. */

/** Human label for a noise-governor backoff reason ("http_429", "timeout_burst_host", ...). */
export function throttleReasonLabel(reason: string): string {
  const hostOnly = reason.endsWith('_host');
  const base = hostOnly ? reason.slice(0, -5) : reason;
  const label =
    base === 'http_429'
      ? 'HTTP 429/503 from the target'
      : base === 'timeout_burst'
        ? 'burst of timeouts'
        : base === 'rst_burst'
          ? 'burst of TCP resets'
          : base.replace(/_/g, ' ');
  return hostOnly ? `${label} (that host only)` : label;
}

/** "80 → 40 req/s" */
export function rateChange(oldRate: number, newRate: number, unit = 'req/s'): string {
  const f = (n: number) => (n >= 10 ? Math.round(n).toString() : n.toFixed(1));
  return `${f(oldRate)} → ${f(newRate)} ${unit}`;
}

export interface CommandLine {
  cmd: string;
  /** How many times the same command ran back to back (re-probe retries). */
  times: number;
}

/** Collapses consecutive identical commands (re-probe retries) into one line with a count. */
export function collapseCommands(cmds: string[]): CommandLine[] {
  const out: CommandLine[] = [];
  for (const cmd of cmds) {
    const last = out[out.length - 1];
    if (last && last.cmd === cmd) last.times += 1;
    else out.push({ cmd, times: 1 });
  }
  return out;
}
