import React, { useCallback, useEffect, useState } from 'react';
import {
  RiAddLine,
  RiDeleteBinLine,
  RiFileCopyLine,
  RiForbidLine,
  RiPlayLine,
  RiRadarLine,
  RiShieldCheckLine,
} from '@remixicon/react';
import { api } from '@/lib/api';
import { useToast } from '@/context/ToastContext';
import { formatDateTime, formatRelativeTime, type Tone } from '@/lib/format';
import type { Agent, AgentEnrollToken, CreatedAgentToken } from '@/types/api';
import { Code, Empty, Field, Notice, Pill, SectionTitle } from '@/components/common';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { PeckLoader } from '@/components/Woodpecker';

const STATUS: Record<string, { label: string; tone: Tone }> = {
  online: { label: 'online', tone: 'success' },
  offline: { label: 'offline', tone: 'danger' },
  disabled: { label: 'disabled', tone: 'neutral' },
};

function CopyBlock({ label, text }: { label: string; text: string }) {
  const toast = useToast();
  return (
    <Field label={label}>
      <div className="flex items-start gap-2">
        <pre className="min-w-0 flex-1 overflow-x-auto border bg-muted px-2 py-1.5 font-mono text-[11px] whitespace-pre-wrap break-all">
          {text}
        </pre>
        <Button
          type="button"
          variant="outline"
          size="icon-xs"
          aria-label="Copy"
          title="Copy"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(text);
              toast.success('Copied');
            } catch {
              toast.error('Could not copy', 'Select the text manually.');
            }
          }}
        >
          <RiFileCopyLine />
        </Button>
      </div>
    </Field>
  );
}

/**
 * Remote scanning agents (dzieciol agent): a lightweight scanner inside another network segment
 * that connects OUT to this server over HTTPS, pulls jobs and uploads results. Everyone with
 * scans:read sees the list; admins (admin:settings) add, disable and remove agents.
 */
export function AgentsPanel({ canManage }: { canManage: boolean }) {
  const toast = useToast();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [offlineAfter, setOfflineAfter] = useState(90);
  const [tokens, setTokens] = useState<AgentEnrollToken[]>([]);
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState({ name: '', site: '', ttl_hours: 24 });
  const [created, setCreated] = useState<CreatedAgentToken | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await api.listAgents();
      setAgents(res.agents);
      setOfflineAfter(res.offline_after_sec);
      if (canManage) setTokens(await api.listAgentTokens());
    } catch (err) {
      toast.error('Agents', (err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [canManage, toast]);

  useEffect(() => {
    load();
    const t = window.setInterval(load, 10000);
    return () => window.clearInterval(t);
  }, [load]);

  const createToken = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const res = await api.createAgentToken({
        name: form.name.trim(),
        site: form.site.trim(),
        ttl_hours: form.ttl_hours,
      });
      setCreated(res);
      setForm({ name: '', site: '', ttl_hours: 24 });
      load();
    } catch (err) {
      toast.error('Could not create token', (err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const toggle = async (a: Agent) => {
    try {
      await api.updateAgent(a.id, { disabled: !a.disabled });
      load();
    } catch (err) {
      toast.error('Agent', (err as Error).message);
    }
  };

  const remove = async (a: Agent) => {
    if (!window.confirm(`Remove agent "${a.name}"? Its credential will stop working and any active scan will be stopped.`)) return;
    try {
      await api.deleteAgent(a.id);
      toast.success('Agent removed', a.name);
      load();
    } catch (err) {
      toast.error('Agent', (err as Error).message);
    }
  };

  const pendingTokens = tokens.filter((t) => !t.used_at && new Date(t.expires_at).getTime() > Date.now());

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
      <div className={canManage ? 'space-y-6 xl:col-span-8' : 'space-y-6 xl:col-span-12'}>
        <Card size="sm" className="py-0">
          {loading ? (
            <PeckLoader />
          ) : agents.length === 0 ? (
            <Empty icon={RiRadarLine}>
              No agents yet. An agent is a small scanner in another network (VLAN, department, behind NAT)
              that only makes outbound connections to this server.
            </Empty>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Agent</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Version / scanner</TableHead>
                  <TableHead>Allowed networks</TableHead>
                  <TableHead className="text-right" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {agents.map((a) => {
                  const st = STATUS[a.status] ?? { label: a.status, tone: 'neutral' as Tone };
                  const allow = a.capabilities?.allow_cidrs ?? [];
                  return (
                    <TableRow key={a.id}>
                      <TableCell className="max-w-[240px] whitespace-normal">
                        <div className="text-sm font-medium">{a.name}</div>
                        <div className="font-mono text-[11px] text-muted-foreground">
                          {[a.site, a.capabilities?.hostname, a.remote_ip].filter(Boolean).join(' · ')}
                        </div>
                      </TableCell>
                      <TableCell className="whitespace-normal">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <Pill tone={st.tone} dot pulse={a.status === 'online'}>
                            {st.label}
                          </Pill>
                          {a.current_run_id && <Pill tone="info">scanning</Pill>}
                        </div>
                        <div className="mt-1 text-[11px] text-muted-foreground" title={formatDateTime(a.last_seen_at)}>
                          {a.last_seen_at ? `last seen ${formatRelativeTime(a.last_seen_at)}` : 'not connected yet'}
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-muted-foreground">
                        <div>v{a.version || '?'} · {a.capabilities?.os}/{a.capabilities?.arch}</div>
                        <div>
                          {a.capabilities?.nmap ? 'nmap' : 'TCP connect (no nmap)'}
                          {a.capabilities?.privileged ? ' · root' : ''}
                        </div>
                      </TableCell>
                      <TableCell className="max-w-[200px] whitespace-normal font-mono text-[11px]">
                        {allow.length > 0 ? (
                          <span className="inline-flex items-center gap-1 text-emerald-700 dark:text-emerald-300">
                            <RiShieldCheckLine className="size-3.5" />
                            {allow.join(', ')}
                          </span>
                        ) : (
                          <span className="text-amber-700 dark:text-amber-300">no restriction</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {canManage && (
                          <div className="flex items-center justify-end gap-1">
                            <Button variant="outline" size="xs" onClick={() => toggle(a)}>
                              {a.disabled ? (
                                <>
                                  <RiPlayLine data-icon="inline-start" /> Enable
                                </>
                              ) : (
                                <>
                                  <RiForbidLine data-icon="inline-start" /> Disable
                                </>
                              )}
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon-xs"
                              aria-label="Remove agent"
                              title="Remove agent"
                              className="text-muted-foreground hover:text-destructive"
                              onClick={() => remove(a)}
                            >
                              <RiDeleteBinLine />
                            </Button>
                          </div>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </Card>
        <p className="text-[11px] text-muted-foreground">
          An agent silent for {Math.round(offlineAfter)} s is marked offline. Its running scan is paused and
          resumes from the last checkpoint when the agent is back. Assign a profile to an agent in the Profiles
          tab.
        </p>
      </div>

      {canManage && (
        <div className="space-y-6 xl:col-span-4">
          <Card size="sm">
            <form onSubmit={createToken} className="flex flex-col gap-5">
              <CardHeader>
                <CardTitle className="text-sm">Add agent</CardTitle>
              </CardHeader>
              <CardContent className="grid grid-cols-1 gap-4">
                <Field label="Name" htmlFor="ag-name">
                  <Input
                    id="ag-name"
                    value={form.name}
                    placeholder="e.g. dept-eaiib"
                    onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                  />
                </Field>
                <Field label="Location / segment" htmlFor="ag-site">
                  <Input
                    id="ag-site"
                    value={form.site}
                    placeholder="e.g. VLAN 120, building D-17"
                    onChange={(e) => setForm((f) => ({ ...f, site: e.target.value }))}
                  />
                </Field>
                <Field label="Token valid for (hours)" htmlFor="ag-ttl" hint="The token can be used once.">
                  <Input
                    id="ag-ttl"
                    type="number"
                    min={1}
                    max={720}
                    value={form.ttl_hours}
                    onChange={(e) => setForm((f) => ({ ...f, ttl_hours: Number(e.target.value) }))}
                    className="font-mono"
                  />
                </Field>
              </CardContent>
              <CardFooter className="justify-end">
                <Button type="submit" size="sm" disabled={busy}>
                  <RiAddLine data-icon="inline-start" /> Create token
                </Button>
              </CardFooter>
            </form>
          </Card>

          {created && (
            <Card size="sm">
              <CardHeader>
                <CardTitle className="text-sm">Install the agent</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <Notice tone="warning">
                  The token is shown only now (the server keeps only its hash). Valid until{' '}
                  {formatDateTime(created.enroll_token.expires_at)}, single use.
                </Notice>
                <CopyBlock label="Linux + systemd (root)" text={created.install_command} />
                <CopyBlock label="Manual (any OS)" text={created.run_command} />
                <p className="text-[11px] text-muted-foreground">
                  The agent only needs outbound access to <Code>{created.server_url}</Code> (HTTPS). Add{' '}
                  <Code>--allow-cidr 10.20.0.0/16</Code> so the agent rejects targets outside its network.
                </p>
              </CardContent>
            </Card>
          )}

          {pendingTokens.length > 0 && (
            <div className="space-y-2">
              <SectionTitle>Unused tokens</SectionTitle>
              {pendingTokens.map((t) => (
                <div key={t.id} className="flex items-center justify-between gap-2 border px-3 py-2 text-xs">
                  <div className="min-w-0">
                    <div className="truncate font-medium">{t.name || 'unnamed'}</div>
                    <div className="font-mono text-[11px] text-muted-foreground">
                      {t.prefix}… · until {formatDateTime(t.expires_at)}
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon-xs"
                    aria-label="Revoke token"
                    title="Revoke token"
                    className="text-muted-foreground hover:text-destructive"
                    onClick={async () => {
                      await api.revokeAgentToken(t.id);
                      load();
                    }}
                  >
                    <RiDeleteBinLine />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
