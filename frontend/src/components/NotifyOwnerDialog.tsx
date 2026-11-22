import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  RiCheckboxCircleLine,
  RiFileCopyLine,
  RiInformationLine,
  RiMailLine,
  RiMailSendLine,
  RiSendPlaneLine,
} from '@remixicon/react';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/context/ToastContext';
import { PERMISSIONS } from '@/lib/permissions';
import { cn } from '@/lib/utils';
import { isIsoDay } from '@/lib/format';
import {
  ACTION_LABEL,
  KIND_LABEL,
  LANGUAGE_LABEL,
  SEVERITY_LABEL,
  STATUS_META,
  fixLabel,
  invalidateTickets,
  isActive,
  kindCategory,
  remediationApi,
  ticketForService,
  useTicketIndex,
  type Delivery,
  type Draft,
  type Ticket,
} from '@/lib/remediation';
import { Field, Notice, Pill, SimpleSelect } from '@/components/common';
import { CategoryBadge } from '@/components/CategoryBadge';
import { IsoDateInput } from '@/components/IsoDateInput';
import { PeckLoader } from '@/components/Woodpecker';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  hostId: string;
  serviceId?: string;
  issueKey?: string;
  onSent?: (t: Ticket) => void;
}

function channelLine(d: Draft, to: string): { text: string; ready: boolean } {
  if (d.channels.email && to) return { text: `Sends an email to ${to}.`, ready: true };
  if (d.channels.webhook) {
    const fmt = d.channels.webhook_format === 'teams' ? 'Teams' : d.channels.webhook_format === 'generic' ? 'JSON' : 'Slack';
    const src = d.channels.webhook_source === 'alert' ? 'the alert webhook' : 'the remediation webhook';
    return { text: `Posts to ${src} (${fmt} format)${d.channels.email ? ' because no contact email is set' : ''}.`, ready: true };
  }
  return {
    text: 'No email or webhook is set up. Copy the message or open it in your mail app; the ticket is tracked either way.',
    ready: false,
  };
}

/** text with every occurrence of the ISO day from replaced by to. */
function withDue(text: string, from: string, to: string): string {
  if (!from || !to || from === to) return text;
  return text.split(from).join(to);
}

/** Where the default due date comes from, in one line. */
function slaLine(d: Draft): string {
  const zone = d.timezone ? ` Dates in ${d.timezone}.` : '';
  if (d.existing?.due_at) return `Due date kept from the open ticket.${zone}`;
  const sev = SEVERITY_LABEL[d.sla.severity] || d.sla.severity;
  if (d.sla.expired) {
    return `DefectDojo SLA for this ${sev} finding (${d.sla.days} days from ${d.sla.start}) ended on ${d.sla.expires}; the owner gets ${d.sla.days} days from today.${zone}`;
  }
  if (d.sla.from_defectdojo) {
    return `Same day as the DefectDojo SLA: ${sev}, ${d.sla.days} days from the finding date ${d.sla.start}.${zone}`;
  }
  return `${sev} severity: ${d.sla.days} days to fix.${zone}`;
}

/** "Notify owner": prefilled, editable message plus a remediation ticket. */
export function NotifyOwnerDialog({ open, onOpenChange, hostId, serviceId, issueKey, onSent }: Props) {
  const toast = useToast();
  const [draft, setDraft] = useState<Draft | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [key, setKey] = useState(issueKey || '');
  const [to, setTo] = useState('');
  const [due, setDue] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [sending, setSending] = useState<string | null>(null);
  const [result, setResult] = useState<Delivery | null>(null);
  /** Notice language of this message ('' until the first draft: the instance default). */
  const [lang, setLang] = useState('');
  const [switching, setSwitching] = useState(false);

  /** Loads a draft; keepDue keeps the analyst's due day (and writes it into the message). */
  const load = async (k?: string, l?: string, keep?: { contact?: boolean; due?: string }) => {
    setError(null);
    try {
      const d = await remediationApi.draft(hostId, serviceId, k, l);
      const day = keep?.due && isIsoDay(keep.due) ? keep.due : d.due_date;
      setDraft(d);
      setKey(d.issue_key);
      setLang(d.language);
      if (!keep?.contact) setTo(d.owner_email || '');
      setDue(day);
      setSubject(withDue(d.subject, d.due_date, day));
      setBody(withDue(d.body, d.due_date, day));
    } catch (err) {
      setError((err as Error).message);
    }
  };

  useEffect(() => {
    if (!open) return;
    setDraft(null);
    setResult(null);
    setLang('');
    load(issueKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, hostId, serviceId, issueKey]);

  /** The ticket due day and the message's "by" date stay the same day. */
  const changeDue = (day: string) => {
    if (due && isIsoDay(day)) {
      setSubject((s) => withDue(s, due, day));
      setBody((b) => withDue(b, due, day));
    }
    setDue(day);
  };

  const edited =
    !!draft && (subject !== withDue(draft.subject, draft.due_date, due) || body !== withDue(draft.body, draft.due_date, due));
  const switchLanguage = async (l: string) => {
    if (!draft || l === lang) return;
    if (edited && !window.confirm('Switching the language rewrites the subject and message. Your edits will be lost.')) return;
    setSwitching(true);
    await load(key, l, { contact: true, due });
    setSwitching(false);
  };

  const send = async (channel: string) => {
    if (!draft) return;
    setSending(channel);
    try {
      const res = await remediationApi.create({
        host_id: hostId,
        service_id: serviceId,
        issue_key: key,
        owner_email: to.trim(),
        subject,
        body,
        language: lang || undefined,
        due_date: due || undefined,
        channel,
      });
      invalidateTickets();
      onSent?.(res.ticket);
      if (res.delivery.delivered) {
        toast.success(
          channel === 'manual' ? 'Ticket marked as notified' : 'Owner notified',
          res.delivery.target ? `Sent to ${res.delivery.target}` : res.ticket.title
        );
        onOpenChange(false);
      } else {
        setResult(res.delivery);
      }
    } catch (err) {
      toast.error('Could not notify the owner', (err as Error).message);
    } finally {
      setSending(null);
    }
  };

  const copyAndMark = async () => {
    try {
      await navigator.clipboard.writeText(`Subject: ${subject}\n\n${body}`);
    } catch {
      // clipboard can be blocked; the ticket is still recorded
    }
    await send('manual');
  };

  const mailto = () => {
    const q = new URLSearchParams({ subject, body: body.length > 1800 ? `${body.slice(0, 1800)}\n...` : body });
    window.location.href = `mailto:${to.trim()}?${q.toString().replace(/\+/g, '%20')}`;
    send('manual');
  };

  const issue = draft?.issues.find((i) => i.key === key);
  const line = draft ? channelLine(draft, to.trim()) : null;
  const existing = draft?.existing;
  const cat = issue ? kindCategory(issue.kind) : undefined;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="z-[60]! gap-4 sm:max-w-2xl" overlayClassName="z-[60]!">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <RiMailSendLine className="size-5 text-muted-foreground" />
            Notify owner
          </DialogTitle>
          <DialogDescription>
            {draft
              ? `${draft.host_ip}${draft.port ? `:${draft.port}/${draft.protocol}` : ''}${draft.service ? ` · ${draft.service}` : ''}`
              : 'Loading the finding'}
          </DialogDescription>
        </DialogHeader>

        {error ? (
          <Notice tone="danger">{error}</Notice>
        ) : !draft ? (
          <PeckLoader />
        ) : (
          <div className="flex max-h-[65vh] flex-col gap-4 overflow-y-auto pr-1">
            {existing && (
              <Notice tone="info" icon={RiInformationLine}>
                A ticket for this already exists ({STATUS_META[existing.status].label.toLowerCase()}, opened by{' '}
                {existing.created_by}). Sending again adds a reminder to it.
              </Notice>
            )}

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="Owner">
                <Input readOnly value={draft.owner || 'Not assigned'} className={cn(!draft.owner && 'text-muted-foreground')} />
              </Field>
              <Field label="Contact email" htmlFor="no-to">
                <Input
                  id="no-to"
                  type="email"
                  value={to}
                  onChange={(e) => setTo(e.target.value)}
                  placeholder="owner@agh.edu.pl"
                />
              </Field>
            </div>
            {!draft.owner && (
              <span className="-mt-2 text-[11px] text-muted-foreground">
                Nobody owns this range yet. Add a CIDR owner rule in Assets so the next finding is routed automatically.
              </span>
            )}

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_9rem]">
              <Field label="Finding">
                {draft.issues.length > 1 ? (
                  <SimpleSelect
                    value={key}
                    onValueChange={(v) => load(v, lang, { contact: true })}
                    options={draft.issues.map((i) => ({ value: i.key, label: `${KIND_LABEL[i.kind] || i.kind}: ${i.title}` }))}
                  />
                ) : (
                  <Input readOnly value={issue?.title || ''} />
                )}
              </Field>
              <Field label="Due" htmlFor="no-due">
                <IsoDateInput id="no-due" value={due} onChange={changeDue} />
              </Field>
            </div>
            <span className="-mt-2 text-[11px] text-muted-foreground">{slaLine(draft)}</span>
            {issue && (
              <div className="-mt-1 flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                {cat && <CategoryBadge kind={cat} size="xs" />}
                <Pill tone="neutral">{ACTION_LABEL[issue.action] || issue.action}</Pill>
                <span className="min-w-0 flex-1">{issue.evidence}</span>
              </div>
            )}

            <div className="flex items-center justify-between gap-3">
              <span className="text-[11px] text-muted-foreground">
                Notice language{draft.default_language && draft.default_language !== lang ? ` (default ${LANGUAGE_LABEL[draft.default_language] || draft.default_language})` : ''}
              </span>
              <div className="flex gap-1" role="group" aria-label="Notice language">
                {(draft.languages?.length ? draft.languages : ['pl', 'en']).map((l) => (
                  <button
                    key={l}
                    type="button"
                    disabled={switching || !!sending}
                    aria-pressed={l === lang}
                    onClick={() => switchLanguage(l)}
                    className={cn(
                      'h-7 border px-2.5 text-[11px] font-semibold transition-colors disabled:opacity-50',
                      l === lang
                        ? 'border-foreground/40 bg-muted text-foreground'
                        : 'border-border text-muted-foreground hover:bg-muted hover:text-foreground'
                    )}
                  >
                    {LANGUAGE_LABEL[l] || l.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>

            <Field label="Subject" htmlFor="no-subject">
              <Input id="no-subject" value={subject} onChange={(e) => setSubject(e.target.value)} />
            </Field>
            <Field label="Message" htmlFor="no-body">
              <Textarea
                id="no-body"
                rows={12}
                value={body}
                onChange={(e) => setBody(e.target.value)}
                className="font-mono text-xs leading-relaxed md:text-xs"
              />
            </Field>

            {result && !result.delivered && (
              <Notice tone="warning">
                {result.error ? `Delivery failed: ${result.error}. ` : 'Nothing was sent. '}
                Copy the message or open it in your mail app.
              </Notice>
            )}
            {line && !result && (
              <p className={cn('text-[11px]', line.ready ? 'text-muted-foreground' : 'text-amber-700 dark:text-amber-400')}>
                {line.text}
              </p>
            )}
          </div>
        )}

        <DialogFooter className="items-center gap-2 sm:justify-between">
          <div className="flex items-center gap-1">
            <Button variant="ghost" size="sm" disabled={!draft || !!sending} onClick={copyAndMark}>
              <RiFileCopyLine data-icon="inline-start" />
              Copy text
            </Button>
            <Button variant="ghost" size="sm" disabled={!draft || !!sending} onClick={mailto}>
              <RiMailLine data-icon="inline-start" />
              Mail app
            </Button>
          </div>
          {(!draft || line?.ready) && !result ? (
            <Button size="sm" disabled={!draft || !!sending || !subject.trim() || !body.trim()} onClick={() => send('auto')}>
              <RiSendPlaneLine data-icon="inline-start" />
              {sending === 'auto' ? 'Sending' : 'Send'}
            </Button>
          ) : (
            <Button size="sm" disabled={!draft || !!sending} onClick={copyAndMark}>
              <RiCheckboxCircleLine data-icon="inline-start" />
              Copy and mark notified
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** Button that opens the dialog; hidden for read-only roles. */
export function NotifyOwnerButton({
  hostId,
  serviceId,
  issueKey,
  icon,
  className,
  onSent,
}: {
  hostId: string;
  serviceId?: string;
  issueKey?: string;
  /** Icon-only variant for dense tables. */
  icon?: boolean;
  className?: string;
  onSent?: (t: Ticket) => void;
}) {
  const { can } = useAuth();
  const [open, setOpen] = useState(false);
  if (!can(PERMISSIONS.ASSETS_WRITE)) return null;
  return (
    <span onClick={(e) => e.stopPropagation()} className="inline-flex">
      {icon ? (
        <Tooltip>
          <TooltipTrigger
            render={
              <Button
                variant="ghost"
                size="icon-xs"
                className={cn('text-muted-foreground', className)}
                aria-label="Notify owner"
                onClick={() => setOpen(true)}
              />
            }
          >
            <RiMailSendLine />
          </TooltipTrigger>
          <TooltipContent>Notify owner</TooltipContent>
        </Tooltip>
      ) : (
        <Button variant="ghost" size="xs" className={className} onClick={() => setOpen(true)}>
          <RiMailSendLine data-icon="inline-start" />
          Notify owner
        </Button>
      )}
      {open && (
        <NotifyOwnerDialog
          open={open}
          onOpenChange={setOpen}
          hostId={hostId}
          serviceId={serviceId}
          issueKey={issueKey}
          onSent={onSent}
        />
      )}
    </span>
  );
}

/** Small badge on a service that has a remediation ticket (open, overdue or verified fixed). */
export function TicketBadge({ serviceId }: { serviceId: string }) {
  const { can } = useAuth();
  const tickets = useTicketIndex(can(PERMISSIONS.ASSETS_READ));
  const t = ticketForService(tickets, serviceId);
  if (!t) return null;
  const overdue = isActive(t.status) && (t.overdue || t.past_due);
  const meta = STATUS_META[t.status];
  const fixed = t.status === 'fixed' ? fixLabel(t) : '';
  const label = overdue ? 'Overdue' : fixed ? (t.fixed_reason === 'upgraded' ? 'Fixed: upgraded' : fixed) : meta.label;
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <Link
            to={`/remediation?ticket=${t.id}`}
            onClick={(e) => e.stopPropagation()}
            className="inline-flex"
          />
        }
      >
        <Pill tone={overdue ? 'warning' : meta.tone}>
          <RiMailSendLine className="size-3" />
          {label}
        </Pill>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs flex-col items-start gap-0.5 text-left">
        <span className="font-semibold">Remediation ticket</span>
        <span className="opacity-80">{t.title}</span>
        {fixed && <span className="opacity-80">{fixed}</span>}
        {t.owner && <span className="opacity-80">Owner: {t.owner}</span>}
        {(t.due_date || t.due_at) && isActive(t.status) && (
          <span className="opacity-80">Due {t.due_date || t.due_at?.slice(0, 10)}</span>
        )}
        {t.last_check_note && <span className="opacity-60">Last check: {t.last_check_note}</span>}
      </TooltipContent>
    </Tooltip>
  );
}
