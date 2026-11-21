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
import {
  ACTION_LABEL,
  KIND_LABEL,
  STATUS_META,
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

  const load = async (k?: string) => {
    setError(null);
    try {
      const d = await remediationApi.draft(hostId, serviceId, k);
      setDraft(d);
      setKey(d.issue_key);
      setTo(d.owner_email || '');
      setDue(d.due_at.slice(0, 10));
      setSubject(d.subject);
      setBody(d.body);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  useEffect(() => {
    if (!open) return;
    setDraft(null);
    setResult(null);
    load(issueKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, hostId, serviceId, issueKey]);

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
        due_at: due ? new Date(`${due}T23:59:00Z`).toISOString() : undefined,
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
      <DialogContent className="gap-4 sm:max-w-2xl">
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
                <div className="flex h-9 items-center truncate border border-border bg-muted/30 px-3 text-sm">
                  {draft.owner || <span className="text-muted-foreground">Not assigned</span>}
                </div>
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
                    onValueChange={(v) => load(v)}
                    options={draft.issues.map((i) => ({ value: i.key, label: `${KIND_LABEL[i.kind] || i.kind}: ${i.title}` }))}
                  />
                ) : (
                  <div className="flex h-9 items-center truncate border border-border px-3 text-sm">{issue?.title}</div>
                )}
              </Field>
              <Field label="Due" htmlFor="no-due">
                <Input id="no-due" type="date" value={due} onChange={(e) => setDue(e.target.value)} />
              </Field>
            </div>
            {issue && (
              <div className="-mt-1 flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                {cat && <CategoryBadge kind={cat} size="xs" />}
                <Pill tone="neutral">{ACTION_LABEL[issue.action] || issue.action}</Pill>
                <span className="min-w-0 flex-1">{issue.evidence}</span>
              </div>
            )}

            <Field label="Subject" htmlFor="no-subject">
              <Input id="no-subject" value={subject} onChange={(e) => setSubject(e.target.value)} />
            </Field>
            <Field label="Message" htmlFor="no-body">
              <Textarea
                id="no-body"
                rows={12}
                value={body}
                onChange={(e) => setBody(e.target.value)}
                className="font-mono text-xs leading-relaxed"
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
          {line?.ready && !result ? (
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
  const label = overdue ? 'Overdue' : t.status === 'fixed' ? (t.verified ? 'Fix verified' : 'Fixed') : meta.label;
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
        {t.owner && <span className="opacity-80">Owner: {t.owner}</span>}
        {t.due_at && isActive(t.status) && <span className="opacity-80">Due {t.due_at.slice(0, 10)}</span>}
        {t.last_check_note && <span className="opacity-60">Last check: {t.last_check_note}</span>}
      </TooltipContent>
    </Tooltip>
  );
}
