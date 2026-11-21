import { useCallback, useEffect, useState } from 'react';
import { RiNotification3Line, RiSaveLine, RiSendPlaneLine } from '@remixicon/react';
import { api } from '@/lib/api';
import { useToast } from '@/context/ToastContext';
import type { WebhookConfig } from '@/types/api';
import { formatDateTime } from '@/lib/format';
import { Field, Notice, Pill, SimpleSelect } from '@/components/common';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';

const SEVERITY_OPTIONS = [
  { value: 'high', label: 'high (nowe RDP/SMB/DB/panele admina)' },
  { value: 'medium', label: 'medium i wyżej' },
  { value: 'low', label: 'low i wyżej' },
  { value: 'info', label: 'wszystkie' },
];

/**
 * Outbound alert webhook (admin:settings). One JSON payload compatible with Slack, Discord
 * and Teams incoming webhooks, sent after each scan for new high-severity exposures and host
 * state changes. The URL is a secret: stored encrypted, never sent back to the browser.
 */
export function WebhookPanel() {
  const toast = useToast();
  const [cfg, setCfg] = useState<WebhookConfig | null>(null);
  const [url, setUrl] = useState('');
  const [enabled, setEnabled] = useState(false);
  const [minSeverity, setMinSeverity] = useState('high');
  const [stateChanges, setStateChanges] = useState(true);
  const [busy, setBusy] = useState(false);

  const apply = (c: WebhookConfig) => {
    setCfg(c);
    setEnabled(c.enabled);
    setMinSeverity(c.min_severity || 'high');
    setStateChanges(c.notify_state_changes);
    setUrl('');
  };

  const load = useCallback(async () => {
    try {
      apply(await api.getWebhook());
    } catch (err) {
      toast.error('Webhook', (err as Error).message);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      apply(
        await api.saveWebhook({
          url: url.trim() || undefined,
          enabled,
          min_severity: minSeverity,
          notify_state_changes: stateChanges,
        })
      );
      toast.success('Zapisano webhook');
    } catch (err) {
      toast.error('Błąd zapisu', (err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const test = async () => {
    setBusy(true);
    try {
      await api.testWebhook(url.trim() || undefined);
      toast.success('Webhook działa', 'Wysłano wiadomość testową');
    } catch (err) {
      toast.error('Test nieudany', (err as Error).message);
    } finally {
      setBusy(false);
      load();
    }
  };

  return (
    <Card size="sm" className="max-w-2xl">
      <form onSubmit={save} className="flex flex-col gap-(--card-spacing)">
        <CardHeader className="border-b">
          <CardTitle className="flex items-center gap-2 text-sm">
            <RiNotification3Line className="size-4 text-muted-foreground" />
            Webhook alertów (Slack / Discord / Teams)
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <Field
            label="URL webhooka"
            htmlFor="wh-url"
            hint={
              cfg?.has_url
                ? `Zapisany: ${cfg.url_masked} (zaszyfrowany). Zostaw puste, aby zachować.`
                : 'Np. https://hooks.slack.com/services/…, https://discord.com/api/webhooks/…'
            }
          >
            <Input
              id="wh-url"
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder={cfg?.has_url ? cfg.url_masked : 'https://'}
              className="font-mono"
              autoComplete="off"
            />
          </Field>
          <Field label="Minimalna ważność">
            <SimpleSelect value={minSeverity} onValueChange={setMinSeverity} options={SEVERITY_OPTIONS} />
          </Field>
          <label className="flex cursor-pointer items-center gap-2 text-xs select-none">
            <Switch checked={stateChanges} onCheckedChange={setStateChanges} />
            Zmiany stanu hostów (zniknął / nieaktywny / reaktywowany / anomalia czasowa)
          </label>
          <label className="flex cursor-pointer items-center gap-2 text-xs select-none">
            <Switch checked={enabled} onCheckedChange={setEnabled} />
            Włączony
          </label>
          {cfg?.last_status && (
            <Notice>
              Ostatnia wysyłka:{' '}
              <Pill tone={cfg.last_status === 'ok' ? 'success' : 'danger'}>{cfg.last_status}</Pill>{' '}
              {cfg.last_sent_at && formatDateTime(cfg.last_sent_at)}
              {cfg.last_error && <span className="ml-1 font-mono text-[11px]">{cfg.last_error}</span>}
            </Notice>
          )}
          <p className="text-[11px] text-muted-foreground">
            Pomijane są hosty i usługi z aktywną akceptacją ryzyka / false positive.
          </p>
          <div className="flex justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={busy || (!cfg?.has_url && !url.trim())}
              onClick={test}
            >
              <RiSendPlaneLine data-icon="inline-start" /> Testuj webhook
            </Button>
            <Button type="submit" size="sm" disabled={busy}>
              <RiSaveLine data-icon="inline-start" /> Zapisz
            </Button>
          </div>
        </CardContent>
      </form>
    </Card>
  );
}
