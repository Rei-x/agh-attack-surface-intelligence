import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  RiArrowLeftLine,
  RiCheckboxCircleLine,
  RiFileCopyLine,
  RiPlayFill,
} from '@remixicon/react';
import { api } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/context/ToastContext';
import { formatClock, formatNumber } from '@/lib/format';
import { PERMISSIONS } from '@/lib/permissions';
import { cn } from '@/lib/utils';
import type { Agent, CreatedAgentToken, LocalSubnet, ScanRun } from '@/types/api';
import { Button } from '@/components/ui/button';
import { DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Code, Notice } from '@/components/common';
import { PeckSpinner } from '@/components/Woodpecker';

const POLL_MS = 2500;
const TOKEN_TTL_HOURS = 2;

/** Agent setup state, kept by the dialog so closing and reopening it keeps waiting. */
export interface AgentSetupState {
  created: CreatedAgentToken | null;
  setCreated: (t: CreatedAgentToken | null) => void;
  agentId: string | null;
  setAgentId: (id: string | null) => void;
}

export function useAgentSetupState(): AgentSetupState {
  const [created, setCreated] = useState<CreatedAgentToken | null>(null);
  const [agentId, setAgentId] = useState<string | null>(null);
  return { created, setCreated, agentId, setAgentId };
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function parseCidr(cidr: string): { base: number; bits: number } | null {
  const [ip, b] = cidr.split('/');
  const base = ipv4ToInt(ip);
  const bits = Number(b ?? 32);
  if (base === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  return { base, bits };
}

function cidrContains(outer: string, inner: string): boolean {
  const o = parseCidr(outer);
  const i = parseCidr(inner);
  if (!o || !i || o.bits > i.bits) return false;
  const mask = o.bits === 0 ? 0 : (~0 << (32 - o.bits)) >>> 0;
  return ((o.base & mask) >>> 0) === ((i.base & mask) >>> 0);
}

interface Suggestion {
  target: string;
  ips: number;
  subnet: LocalSubnet;
  /** Set when the target is a /24 inside a wider network. */
  partOf?: string;
}

/**
 * One-click targets from the agent's own networks: IPv4 only, a network wider than /22 is
 * narrowed to the /24 around the agent, single-host prefixes are skipped. With an explicit
 * --allow-cidr only targets inside it are offered.
 */
function suggestions(agent: Agent): Suggestion[] {
  const caps = agent.capabilities ?? { nmap: false, privileged: false };
  const allow = caps.allow_cidrs ?? [];
  const out: Suggestion[] = [];
  for (const s of caps.local_subnets ?? []) {
    const p = parseCidr(s.cidr);
    if (!p || p.bits >= 31) continue;
    let target = s.cidr;
    let partOf: string | undefined;
    if (p.bits < 22) {
      const parts = (s.address || s.cidr.split('/')[0]).split('.');
      target = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
      partOf = s.cidr;
    }
    if (!caps.allow_from_interfaces && allow.length > 0 && !allow.some((a) => cidrContains(a, target))) continue;
    if (out.some((x) => x.target === target)) continue;
    const bits = parseCidr(target)?.bits ?? 32;
    out.push({ target, ips: 2 ** (32 - bits), subnet: s, partOf });
  }
  return out;
}

function CommandBox({ text, primary }: { text: string; primary: boolean }) {
  const toast = useToast();
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success('Command copied', 'Paste it into a terminal on a computer in your network.');
    } catch {
      toast.error('Could not copy', 'Select the command and copy it by hand.');
    }
  };
  return (
    <div className="flex items-stretch gap-2">
      <pre className="min-w-0 flex-1 overflow-x-auto border border-border bg-muted px-3 py-2.5 font-mono text-[11px] leading-relaxed break-all whitespace-pre-wrap select-all">
        {text}
      </pre>
      <Button variant={primary ? 'default' : 'outline'} className="h-auto shrink-0" onClick={copy}>
        <RiFileCopyLine data-icon="inline-start" /> Copy
      </Button>
    </div>
  );
}

/**
 * "Your own network": creates a one-time agent token, shows the install one-liner for this
 * server, waits for the agent to connect, then offers the agent's networks as one-click
 * targets.
 */
export function OwnNetworkView({
  state,
  serverURL,
  tokenAdmins,
  onBack,
  onStarted,
}: {
  state: AgentSetupState;
  serverURL?: string;
  tokenAdmins?: string[];
  onBack: () => void;
  onStarted: (run: ScanRun) => void;
}) {
  const { can } = useAuth();
  const toast = useToast();
  const canEnroll = can(PERMISSIONS.ADMIN_SETTINGS);
  const { created, setCreated, agentId, setAgentId } = state;
  const [tab, setTab] = useState<'linux' | 'mac'>('linux');
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [agent, setAgent] = useState<Agent | null>(null);
  const [target, setTarget] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);

  const expired = created ? new Date(created.enroll_token.expires_at).getTime() <= Date.now() : false;

  const createToken = useCallback(async () => {
    setCreating(true);
    setCreateError(null);
    try {
      const res = await api.createAgentToken({ site: 'Quick scan', ttl_hours: TOKEN_TTL_HOURS });
      setCreated(res);
      setAgentId(null);
      setAgent(null);
    } catch (err) {
      setCreateError((err as Error).message);
    } finally {
      setCreating(false);
    }
  }, [setCreated, setAgentId]);

  // A fresh token when there is none yet, or the last one expired before an agent used it.
  useEffect(() => {
    if (!canEnroll || creating || createError) return;
    if (!created || (expired && !agentId)) void createToken();
  }, [canEnroll, created, expired, agentId, creating, createError, createToken]);

  // Wait for the agent: the token records which agent used it, the agent list says when it
  // is online and which networks it found.
  const online = agent?.status === 'online';
  useEffect(() => {
    if (!canEnroll || !created || online) return;
    let cancelled = false;
    const tick = async () => {
      try {
        let id = agentId;
        if (!id) {
          const tokens = await api.listAgentTokens();
          id = tokens.find((t) => t.id === created.enroll_token.id)?.agent_id ?? null;
          if (id && !cancelled) setAgentId(id);
        }
        if (id) {
          const { agents } = await api.listAgents();
          const found = agents.find((a) => a.id === id) ?? null;
          if (!cancelled) setAgent(found);
        }
      } catch {
        // keep polling
      }
    };
    void tick();
    const t = window.setInterval(tick, POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(t);
    };
  }, [canEnroll, created, agentId, online, setAgentId]);

  const options = useMemo(() => (agent ? suggestions(agent) : []), [agent]);
  useEffect(() => {
    if (options.length > 0 && !options.some((o) => o.target === target)) setTarget(options[0].target);
  }, [options, target]);

  const start = async () => {
    if (!agent || !target) return;
    setStarting(true);
    try {
      const res = await api.quickScanAgent({ agent_id: agent.id, target });
      toast.success('Scan started', res.run.name);
      onStarted(res.run);
    } catch (err) {
      toast.error('Could not start the scan', (err as Error).message);
    } finally {
      setStarting(false);
    }
  };

  const caps = agent?.capabilities;
  const command = created ? (tab === 'linux' ? created.install_command : created.foreground_command) : '';

  return (
    <>
      <DialogHeader>
        <DialogTitle>Scan your own network</DialogTitle>
        <DialogDescription>
          Run this command on a computer in the network you want to scan. The agent connects out to{' '}
          {serverURL || 'this server'}, so nothing has to be opened in your firewall.
        </DialogDescription>
      </DialogHeader>

      {!canEnroll ? (
        <Notice tone="warning">
          Creating the agent command needs the admin:settings permission (the Administration role).{' '}
          {tokenAdmins && tokenAdmins.length > 0
            ? `Ask ${tokenAdmins.join(', ')} to open Quick scan and create it for you.`
            : 'Ask an administrator to open Quick scan and create it for you.'}
        </Notice>
      ) : (
        <div className="flex flex-col gap-3">
          <Tabs value={tab} onValueChange={(v) => setTab(v as 'linux' | 'mac')}>
            <TabsList variant="line">
              <TabsTrigger value="linux">Linux</TabsTrigger>
              <TabsTrigger value="mac">macOS or no root</TabsTrigger>
            </TabsList>
          </Tabs>
          {createError && (
            <Notice tone="danger">
              Could not create the command: {createError}{' '}
              <button type="button" className="underline underline-offset-2" onClick={() => void createToken()}>
                Try again
              </button>
            </Notice>
          )}
          {!created ? (
            !createError && (
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <PeckSpinner className="h-3" /> Creating a one-time command
              </div>
            )
          ) : (
            <>
              <CommandBox text={command} primary={!online} />
              <p className="text-[11px] leading-relaxed text-muted-foreground">
                {tab === 'linux'
                  ? 'Needs sudo and systemd (for example Ubuntu, Debian or Fedora, on amd64 or arm64). Installs dzieciol and starts the dzieciol-agent service, which also starts after a reboot.'
                  : 'For macOS, or Linux without root or systemd. The agent runs in the terminal until you press Ctrl+C; run the command again to resume.'}{' '}
                The command works once, until {formatClock(created.enroll_token.expires_at)}. Without{' '}
                <Code>--allow-cidr</Code> the agent only scans the private networks its computer is on.
              </p>
            </>
          )}

          {created && !online && (
            <div className="flex items-center gap-2.5 border border-dashed px-3 py-3 text-xs text-muted-foreground">
              <PeckSpinner className="h-3.5" />
              {agent ? `Agent ${agent.name} is ${agent.status}. Waiting for it to come back.` : 'Waiting for the agent to connect.'}
            </div>
          )}

          {agent && online && (
            <div className="flex flex-col gap-3">
              <Notice tone="success" icon={RiCheckboxCircleLine}>
                Connected: {agent.name} ({caps?.os}/{caps?.arch}
                {caps?.nmap ? ', nmap' : ', built-in scanner'})
              </Notice>
              {options.length === 0 ? (
                <Notice tone="warning">
                  The agent found no private IPv4 network to offer. Start it again with{' '}
                  <Code>--allow-cidr</Code> and the network to scan, for example <Code>--allow-cidr 192.168.1.0/24</Code>.
                </Notice>
              ) : (
                <div className="flex flex-col gap-1.5">
                  <span className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
                    Network to scan
                  </span>
                  {options.map((o) => (
                    <button
                      key={o.target}
                      type="button"
                      onClick={() => setTarget(o.target)}
                      aria-pressed={target === o.target}
                      className={cn(
                        'flex items-center justify-between gap-3 border px-3 py-2 text-left text-xs transition-colors',
                        target === o.target ? 'border-primary bg-primary/10' : 'border-border hover:bg-muted'
                      )}
                    >
                      <span className="flex min-w-0 items-center gap-2">
                        <span
                          className={cn(
                            'size-2.5 shrink-0 border',
                            target === o.target ? 'border-primary bg-primary' : 'border-muted-foreground'
                          )}
                        />
                        <span className="font-mono font-semibold">{o.target}</span>
                        <span className="truncate text-muted-foreground">
                          {o.subnet.interface}
                          {o.subnet.virtual ? ' (container or VM network)' : ''}
                          {o.subnet.address ? `, agent at ${o.subnet.address}` : ''}
                          {o.partOf ? `, part of ${o.partOf}` : ''}
                        </span>
                      </span>
                      <span className="shrink-0 font-mono text-[11px] text-muted-foreground tabular-nums">
                        {formatNumber(o.ips)} IP
                      </span>
                    </button>
                  ))}
                  <span className="text-[11px] text-muted-foreground">
                    Gentle settings for a network we do not know: 150 packets/s, 32 common ports. Hosts appear in
                    the live view block by block.
                  </span>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      <DialogFooter className="items-center sm:justify-between">
        <Button variant="ghost" size="sm" onClick={onBack}>
          <RiArrowLeftLine data-icon="inline-start" /> Back
        </Button>
        {online && options.length > 0 && (
          <Button onClick={start} disabled={!target || starting}>
            {starting ? <PeckSpinner className="h-3.5" /> : <RiPlayFill data-icon="inline-start" />}
            Scan {target}
          </Button>
        )}
      </DialogFooter>
    </>
  );
}
