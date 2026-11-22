import { useEffect, useState } from 'react';
import { RiArrowDownSLine } from '@remixicon/react';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/context/ToastContext';
import { PERMISSIONS } from '@/lib/permissions';
import { cn } from '@/lib/utils';
import {
  LANGUAGE_LABEL,
  SEVERITY_LABEL,
  remediationApi,
  type Channels,
  type DeliverySettings,
  type NoticeSettings,
} from '@/lib/remediation';
import { Field, Notice, Pill, SimpleSelect } from '@/components/common';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';

const SLA_KEYS = ['critical', 'high', 'medium', 'low'];

export const FORMAT_OPTIONS = [
  { value: 'slack', label: 'Slack / Mattermost / Discord' },
  { value: 'teams', label: 'Microsoft Teams' },
  { value: 'generic', label: 'Generic JSON' },
];

/**
 * How owner notifications and the digest leave the system (SMTP, webhook, or manual), and
 * how notices read: language, timezone of every date, and SLA days per severity.
 */
export function DeliveryChannelsPanel() {
  const { can } = useAuth();
  const toast = useToast();
  const isAdmin = can(PERMISSIONS.ADMIN_SETTINGS);
  const [open, setOpen] = useState(false);
  const [available, setAvailable] = useState<Channels | null>(null);
  const [s, setS] = useState<DeliverySettings | null>(null);
  const [password, setPassword] = useState('');
  const [webhook, setWebhook] = useState('');
  const [testTo, setTestTo] = useState('');
  const [busy, setBusy] = useState(false);
  const [notices, setNotices] = useState<NoticeSettings | null>(null);
  const [sla, setSla] = useState<Record<string, string>>({});

  const applyNotices = (n?: NoticeSettings) => {
    if (!n) return;
    setNotices(n);
    setSla(Object.fromEntries(SLA_KEYS.map((k) => [k, String(n.sla_days[k] ?? n.default_sla_days[k] ?? '')])));
  };

  const load = async () => {
    try {
      const res = await remediationApi.channels();
      setAvailable(res.available);
      applyNotices(res.notices);
      if (res.settings) setS({ ...res.settings, notice_language: res.notices?.notice_language, timezone: res.notices?.timezone });
    } catch {
      // read-only roles still see the summary line
    }
  };
  useEffect(() => {
    load();
  }, []);

  const save = async () => {
    if (!s) return;
    // Only days that differ from DefectDojo's defaults are stored; equal ones stay defaults.
    const slaDays: Record<string, number> = {};
    for (const k of SLA_KEYS) {
      const v = Number(sla[k]);
      if (!Number.isInteger(v) || v < 1 || v > 3650) {
        toast.error('Could not save', `SLA days for ${SEVERITY_LABEL[k]} must be a whole number from 1 to 3650.`);
        return;
      }
      if (v !== notices?.default_sla_days[k]) slaDays[k] = v;
    }
    setBusy(true);
    try {
      const res = await remediationApi.saveChannels({
        smtp: { ...s.smtp, password: password || undefined },
        webhook_url: webhook || undefined,
        webhook_format: s.webhook_format,
        use_alert_webhook: s.use_alert_webhook,
        notice_language: s.notice_language,
        timezone: s.timezone?.trim() || undefined,
        sla_days: slaDays,
      } as Partial<DeliverySettings>);
      setAvailable(res.available);
      applyNotices(res.notices);
      if (res.settings) setS({ ...res.settings, notice_language: res.notices?.notice_language, timezone: res.notices?.timezone });
      setPassword('');
      setWebhook('');
      toast.success('Delivery channels saved');
    } catch (err) {
      toast.error('Could not save', (err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const test = async () => {
    setBusy(true);
    try {
      const r = await remediationApi.testChannels(testTo || undefined);
      if (r.delivered) toast.success('Test sent', `${r.channel} ${r.target || ''}`);
      else toast.warning('Nothing sent', r.error || 'No email or webhook is configured');
    } catch (err) {
      toast.error('Test failed', (err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const summary = available
    ? [
        available.email ? 'email' : null,
        available.webhook ? `webhook (${available.webhook_source === 'alert' ? 'alert webhook' : 'dedicated'})` : null,
      ].filter(Boolean)
    : [];

  return (
    <Card size="sm" className="gap-0 py-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between gap-3 px-5 py-3 text-left"
        aria-expanded={open}
      >
        <span className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-semibold tracking-widest text-muted-foreground uppercase">Delivery channels</span>
          {summary.length ? (
            summary.map((x) => (
              <Pill key={x as string} tone="success">
                {x}
              </Pill>
            ))
          ) : (
            <Pill tone="neutral">manual only</Pill>
          )}
          {notices && (
            <Pill tone="neutral" title={`Notice language and the timezone of every date in notices, ticket history and the digest`}>
              {LANGUAGE_LABEL[notices.notice_language] || notices.notice_language} · {notices.timezone}
            </Pill>
          )}
        </span>
        <RiArrowDownSLine className={cn('size-4 text-muted-foreground transition-transform', open && 'rotate-180')} />
      </button>
      {open && (
        <div className="space-y-4 border-t border-border px-5 py-4">
          <p className="text-xs text-muted-foreground">
            Email goes to the owner contact when SMTP is set. Otherwise messages go to the webhook. With neither, you copy
            the message or open it in your mail app.
          </p>
          {!isAdmin || !s ? (
            <Notice tone="neutral">Only administrators can change delivery channels.</Notice>
          ) : (
            <>
              <div className="grid grid-cols-1 gap-3 md:grid-cols-5">
                <Field label="SMTP host" className="md:col-span-2">
                  <Input
                    value={s.smtp.host}
                    disabled={s.smtp_from_env}
                    onChange={(e) => setS({ ...s, smtp: { ...s.smtp, host: e.target.value } })}
                    placeholder="smtp.agh.edu.pl"
                  />
                </Field>
                <Field label="Port">
                  <Input
                    type="number"
                    value={s.smtp.port || ''}
                    disabled={s.smtp_from_env}
                    onChange={(e) => setS({ ...s, smtp: { ...s.smtp, port: Number(e.target.value) || 0 } })}
                    placeholder="587"
                  />
                </Field>
                <Field label="Sender" className="md:col-span-2">
                  <Input
                    value={s.smtp.from}
                    disabled={s.smtp_from_env}
                    onChange={(e) => setS({ ...s, smtp: { ...s.smtp, from: e.target.value } })}
                    placeholder="CBI AGH <cbi@agh.edu.pl>"
                  />
                </Field>
                <Field label="Username" className="md:col-span-2">
                  <Input
                    value={s.smtp.username || ''}
                    disabled={s.smtp_from_env}
                    onChange={(e) => setS({ ...s, smtp: { ...s.smtp, username: e.target.value } })}
                  />
                </Field>
                <Field label="Password" className="md:col-span-3" hint={s.smtp.has_password ? 'Stored. Leave empty to keep it.' : undefined}>
                  <Input type="password" value={password} disabled={s.smtp_from_env} onChange={(e) => setPassword(e.target.value)} />
                </Field>
              </div>
              {s.smtp_from_env && <p className="text-[11px] text-muted-foreground">SMTP comes from DZIECIOL_SMTP_* environment variables.</p>}
              <div className="grid grid-cols-1 gap-3 md:grid-cols-5">
                <Field
                  label="Webhook URL"
                  className="md:col-span-3"
                  hint={s.has_webhook_url ? `Stored: ${s.webhook_masked}. Leave empty to keep it.` : undefined}
                >
                  <Input value={webhook} onChange={(e) => setWebhook(e.target.value)} placeholder="https://..." />
                </Field>
                <Field label="Format" className="md:col-span-2">
                  <SimpleSelect
                    value={s.webhook_format}
                    onValueChange={(v) => setS({ ...s, webhook_format: v })}
                    options={FORMAT_OPTIONS}
                  />
                </Field>
              </div>
              <label className="flex items-center gap-2 text-xs">
                <Switch size="sm" checked={s.use_alert_webhook} onCheckedChange={(c) => setS({ ...s, use_alert_webhook: c })} />
                Use the alert webhook when no webhook is set here
              </label>
              <div className="space-y-3 border-t border-border pt-4">
                <div className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">Notices</div>
                <div className="grid grid-cols-1 gap-3 md:grid-cols-5">
                  <Field label="Notice language" htmlFor="notice-language" className="md:col-span-2" hint="Default for new messages; the analyst can switch per message.">
                    <SimpleSelect
                      id="notice-language"
                      value={s.notice_language || 'pl'}
                      onValueChange={(v) => setS({ ...s, notice_language: v })}
                      options={(notices?.languages || ['pl', 'en']).map((l) => ({ value: l, label: LANGUAGE_LABEL[l] || l }))}
                    />
                  </Field>
                  <Field label="Timezone" htmlFor="notice-timezone" className="md:col-span-3" hint="Every date in notices, ticket history and the digest, as YYYY-MM-DD.">
                    <Input
                      id="notice-timezone"
                      value={s.timezone || ''}
                      onChange={(e) => setS({ ...s, timezone: e.target.value })}
                      placeholder="Europe/Warsaw"
                    />
                  </Field>
                </div>
                <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                  {SLA_KEYS.map((k) => (
                    <Field key={k} label={`${SEVERITY_LABEL[k]} (days)`} htmlFor={`sla-${k}`}>
                      <Input
                        id={`sla-${k}`}
                        type="number"
                        min={1}
                        max={3650}
                        value={sla[k] ?? ''}
                        onChange={(e) => setSla({ ...sla, [k]: e.target.value })}
                      />
                    </Field>
                  ))}
                </div>
                <p className="text-[11px] text-muted-foreground">
                  Days to fix by severity. They set the default ticket due date and the date in the notice, counted from the
                  DefectDojo finding date, and must match DefectDojo&apos;s SLA configuration (its defaults:{' '}
                  {notices ? SLA_KEYS.map((k) => notices.default_sla_days[k]).join(' / ') : '7 / 30 / 90 / 120'} days). Existing
                  tickets keep their due dates.
                </p>
              </div>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Input value={testTo} onChange={(e) => setTestTo(e.target.value)} placeholder="test recipient (optional)" className="h-8 w-56 text-xs" />
                  <Button variant="ghost" size="xs" disabled={busy} onClick={test}>
                    Send test
                  </Button>
                </div>
                <Button variant="outline" size="sm" disabled={busy} onClick={save}>
                  Save channels
                </Button>
              </div>
            </>
          )}
        </div>
      )}
    </Card>
  );
}
