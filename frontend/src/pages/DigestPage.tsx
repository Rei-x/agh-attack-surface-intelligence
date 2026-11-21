import React, { useCallback, useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { RiArrowDownSLine, RiDownloadLine, RiHammerLine, RiSendPlaneLine } from '@remixicon/react';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/context/ToastContext';
import { PERMISSIONS } from '@/lib/permissions';
import { formatDateTime } from '@/lib/format';
import { cn } from '@/lib/utils';
import {
  kindCategory,
  remediationApi,
  type Digest,
  type DigestRisk,
  type DigestSettings,
  type DigestSummary,
} from '@/lib/remediation';
import { Empty, Field, Notice, PageHeader, Pill, SectionTitle, SimpleSelect, Stat, StatStrip } from '@/components/common';
import { CategoryBadge } from '@/components/CategoryBadge';
import { FORMAT_OPTIONS } from '@/components/DeliveryChannelsPanel';
import { AssetInspectorDrawer } from '@/components/AssetInspectorDrawer';
import { PeckLoader } from '@/components/Woodpecker';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';

function RiskRow({ r, onOpen }: { r: DigestRisk; onOpen: (id: string) => void }) {
  const cat = kindCategory(r.kind);
  return (
    <button
      type="button"
      onClick={() => onOpen(r.host_id)}
      className="flex w-full items-center gap-3 px-5 py-2.5 text-left text-xs transition-colors hover:bg-muted/40"
    >
      {cat ? <CategoryBadge kind={cat} size="xs" /> : <span className="size-[18px] shrink-0" />}
      <span className="min-w-0 flex-1 truncate text-foreground">{r.title}</span>
      {r.ticket_status && <Pill tone="info">{r.ticket_status.replace('_', ' ')}</Pill>}
      <span className="w-48 shrink-0 truncate text-right text-muted-foreground">{r.owner || 'Unassigned'}</span>
      <span className="w-8 shrink-0 text-right font-mono tabular-nums text-muted-foreground">{r.score}</span>
    </button>
  );
}

function Section({ title, children, count }: { title: string; count?: number; children: React.ReactNode }) {
  return (
    <Card size="sm" className="gap-0 py-0">
      <div className="px-5 py-3">
        <SectionTitle>
          {title}
          {count !== undefined && <span className="ml-2 font-mono text-muted-foreground">{count}</span>}
        </SectionTitle>
      </div>
      <div className="divide-y divide-border border-t border-border">{children}</div>
    </Card>
  );
}

function SettingsPanel() {
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [s, setS] = useState<DigestSettings | null>(null);
  const [recipients, setRecipients] = useState('');
  const [webhook, setWebhook] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    remediationApi
      .digestSettings()
      .then((r) => {
        setS(r.settings);
        setRecipients((r.settings.recipients || []).join(', '));
      })
      .catch(() => undefined);
  }, []);

  const save = async () => {
    if (!s) return;
    setBusy(true);
    try {
      const r = await remediationApi.saveDigestSettings({
        enabled: s.enabled,
        recipients: recipients.split(/[,\s]+/).filter(Boolean),
        webhook_url: webhook || undefined,
        webhook_format: s.webhook_format,
        send_at: s.send_at,
        timezone: s.timezone,
        only_scheduled: s.only_scheduled,
        app_url: s.app_url,
      });
      setS(r.settings);
      setWebhook('');
      toast.success('Digest settings saved');
    } catch (err) {
      toast.error('Could not save', (err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (!s) return null;
  return (
    <Card size="sm" className="gap-0 py-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between gap-3 px-5 py-3 text-left"
        aria-expanded={open}
      >
        <span className="flex items-center gap-2">
          <span className="text-xs font-semibold tracking-widest text-muted-foreground uppercase">Digest settings</span>
          <Pill tone={s.enabled ? 'success' : 'neutral'}>{s.enabled ? `sent at ${s.send_at || 'scan end'}` : 'delivery off'}</Pill>
        </span>
        <RiArrowDownSLine className={cn('size-4 text-muted-foreground transition-transform', open && 'rotate-180')} />
      </button>
      {open && (
        <div className="space-y-4 border-t border-border px-5 py-4">
          <label className="flex items-center gap-2 text-xs">
            <Switch size="sm" checked={s.enabled} onCheckedChange={(c) => setS({ ...s, enabled: c })} />
            Send the digest every morning
          </label>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
            <Field label="Recipients" className="md:col-span-2" hint="Comma separated. Needs SMTP; otherwise the webhook is used.">
              <Input value={recipients} onChange={(e) => setRecipients(e.target.value)} placeholder="cbi@agh.edu.pl" />
            </Field>
            <Field label="Send at">
              <Input type="time" value={s.send_at} onChange={(e) => setS({ ...s, send_at: e.target.value })} />
            </Field>
            <Field label="Timezone">
              <Input value={s.timezone} onChange={(e) => setS({ ...s, timezone: e.target.value })} />
            </Field>
            <Field
              label="Webhook URL"
              className="md:col-span-2"
              hint={s.has_webhook_url ? `Stored: ${s.webhook_masked}` : 'Empty: the remediation or alert webhook'}
            >
              <Input value={webhook} onChange={(e) => setWebhook(e.target.value)} placeholder="https://..." />
            </Field>
            <Field label="Format">
              <SimpleSelect
                value={s.webhook_format || 'slack'}
                onValueChange={(v) => setS({ ...s, webhook_format: v })}
                options={FORMAT_OPTIONS}
              />
            </Field>
            <Field label="Link base URL" hint="Optional, for the link in messages">
              <Input value={s.app_url || ''} onChange={(e) => setS({ ...s, app_url: e.target.value })} placeholder="https://dzieciol.agh.edu.pl" />
            </Field>
          </div>
          <label className="flex items-center gap-2 text-xs">
            <Switch size="sm" checked={s.only_scheduled} onCheckedChange={(c) => setS({ ...s, only_scheduled: c })} />
            Build only after scheduled runs (off: after every completed scan)
          </label>
          <div className="flex justify-end">
            <Button variant="outline" size="sm" disabled={busy} onClick={save}>
              Save settings
            </Button>
          </div>
        </div>
      )}
    </Card>
  );
}

export function DigestPage() {
  const { can } = useAuth();
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const id = params.get('id');
  const [d, setD] = useState<Digest | null>(null);
  const [history, setHistory] = useState<DigestSummary[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [hostId, setHostId] = useState<string | null>(null);
  const canWrite = can(PERMISSIONS.ASSETS_WRITE);

  const load = useCallback(async () => {
    try {
      const [digest, list] = await Promise.all([
        id ? remediationApi.getDigest(id) : remediationApi.latestDigest(),
        remediationApi.listDigests(),
      ]);
      setD(digest);
      setHistory(list.digests);
    } catch (err) {
      toast.error('Could not load the digest', (err as Error).message);
    }
  }, [id, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const build = async () => {
    setBusy('build');
    try {
      const nd = await remediationApi.buildDigest(false);
      setParams({ id: nd.id });
      toast.success('Digest built', nd.headline);
    } catch (err) {
      toast.error('Build failed', (err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const send = async () => {
    if (!d || d.preview) return;
    setBusy('send');
    try {
      const nd = await remediationApi.deliverDigest(d.id);
      setD(nd);
      if (nd.delivered) toast.success('Digest sent', (nd.delivery || []).join('; '));
      else toast.warning('Not sent', (nd.delivery || []).join('; '));
    } catch (err) {
      toast.error('Send failed', (err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const download = async () => {
    try {
      await remediationApi.downloadDigestMarkdown(d && !d.preview ? d.id : 'latest');
    } catch (err) {
      toast.error('Download failed', (err as Error).message);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        className="pb-0"
        title="Digest"
        meta={d ? (d.preview ? 'preview of the last 24 hours' : formatDateTime(d.created_at)) : undefined}
        actions={
          <>
            <Button variant="outline" size="sm" onClick={download} disabled={!d}>
              <RiDownloadLine />
              Markdown
            </Button>
            {canWrite && d && !d.preview && (
              <Button variant="outline" size="sm" onClick={send} disabled={!!busy}>
                <RiSendPlaneLine />
                Send now
              </Button>
            )}
            {canWrite && (
              <Button size="sm" onClick={build} disabled={!!busy}>
                <RiHammerLine />
                Build now
              </Button>
            )}
          </>
        }
      />

      {!d ? (
        <PeckLoader />
      ) : (
        <>
          <Card size="sm">
            <CardContent className="flex flex-wrap items-center justify-between gap-3">
              <p className="text-base font-medium">{d.headline}</p>
              <span className="text-xs text-muted-foreground">
                {formatDateTime(d.since)} to {formatDateTime(d.created_at)}
                {d.scan_name ? ` · after ${d.scan_name}` : ''}
                {d.delivered ? ' · sent' : ''}
              </span>
            </CardContent>
          </Card>
          {d.delivery && d.delivery.length > 0 && !d.delivered && <Notice tone="warning">{d.delivery.join('; ')}</Notice>}

          <StatStrip>
            <Stat label="Risky" value={d.counts.risky} tone={d.counts.risky ? 'warning' : undefined} />
            <Stat label="New services" value={d.counts.new_services} />
            <Stat label="Closed" value={d.counts.closed_services} />
            <Stat label="Hosts new / gone" value={`${d.counts.new_hosts} / ${d.counts.gone_hosts}`} />
            <Stat label="Fixed" value={d.counts.fixed} tone={d.counts.fixed ? 'success' : undefined} />
            <Stat label="Overdue" value={d.counts.overdue} tone={d.counts.overdue ? 'warning' : undefined} to="/remediation?status=overdue" />
          </StatStrip>

          <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
            <div className="flex flex-col gap-6 xl:col-span-8">
              <Section title="Top risks" count={d.top_risks.length}>
                {d.top_risks.length === 0 ? (
                  <Empty>No open risks</Empty>
                ) : (
                  d.top_risks.map((r) => <RiskRow key={`${r.service_id}-${r.kind}`} r={r} onOpen={setHostId} />)
                )}
              </Section>
              <Section title="New risky exposures" count={d.risky.length}>
                {d.risky.length === 0 ? (
                  <Empty>Nothing new and risky</Empty>
                ) : (
                  d.risky.map((r) => <RiskRow key={`${r.service_id}-${r.kind}-${r.title}`} r={r} onOpen={setHostId} />)
                )}
              </Section>
              <Section title="Remediation" count={d.fixed.length + d.overdue.length}>
                {d.fixed.length + d.overdue.length === 0 ? (
                  <Empty>No fixes or overdue tickets in this window</Empty>
                ) : (
                  <>
                    {d.fixed.map((t) => (
                      <Link key={t.id} to={`/remediation?status=fixed&ticket=${t.id}`} className="flex items-center gap-3 px-5 py-2.5 text-xs hover:bg-muted/40">
                        <Pill tone="success">Fixed</Pill>
                        <span className="min-w-0 flex-1 truncate">{t.title}</span>
                        <span className="truncate text-muted-foreground">{t.note}</span>
                      </Link>
                    ))}
                    {d.overdue.map((t) => (
                      <Link key={t.id} to={`/remediation?status=overdue&ticket=${t.id}`} className="flex items-center gap-3 px-5 py-2.5 text-xs hover:bg-muted/40">
                        <Pill tone="warning">Overdue</Pill>
                        <span className="min-w-0 flex-1 truncate">{t.title}</span>
                        <span className="w-48 truncate text-right text-muted-foreground">{t.owner || 'Unassigned'}</span>
                      </Link>
                    ))}
                  </>
                )}
              </Section>
            </div>

            <div className="flex flex-col gap-6 xl:col-span-4">
              <Section title="By owner" count={d.owners.length}>
                {d.owners.length === 0 ? (
                  <Empty>Nothing to route</Empty>
                ) : (
                  d.owners.map((g) => (
                    <div key={g.owner} className="px-5 py-3 text-xs">
                      <div className="truncate font-semibold text-foreground">{g.owner}</div>
                      <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-muted-foreground">
                        {(g.risky?.length || 0) > 0 && <span>{g.risky!.length} risky</span>}
                        {(g.new_services?.length || 0) > 0 && <span>{g.new_services!.length} new services</span>}
                        {(g.new_hosts?.length || 0) > 0 && <span>{g.new_hosts!.length} new hosts</span>}
                        {(g.gone_hosts?.length || 0) > 0 && <span>{g.gone_hosts!.length} gone</span>}
                        {(g.fixed?.length || 0) > 0 && <span>{g.fixed!.length} fixed</span>}
                        {(g.overdue?.length || 0) > 0 && <span className="text-amber-700 dark:text-amber-400">{g.overdue!.length} overdue</span>}
                      </div>
                    </div>
                  ))
                )}
              </Section>
              {history.length > 0 && (
                <Section title="Earlier digests" count={history.length}>
                  {history.slice(0, 10).map((h) => (
                    <button
                      key={h.id}
                      type="button"
                      onClick={() => setParams({ id: h.id })}
                      className={cn('block w-full px-5 py-2 text-left text-xs hover:bg-muted/40', h.id === d.id && 'bg-muted/50')}
                    >
                      <div className="font-mono text-[11px] text-muted-foreground">{formatDateTime(h.created_at)}</div>
                      <div className="truncate">{h.headline}</div>
                    </button>
                  ))}
                </Section>
              )}
            </div>
          </div>
          {can(PERMISSIONS.ADMIN_SETTINGS) && <SettingsPanel />}
        </>
      )}
      <AssetInspectorDrawer hostId={hostId} onClose={() => setHostId(null)} />
    </div>
  );
}
