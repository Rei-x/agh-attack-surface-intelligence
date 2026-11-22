import * as React from 'react';
import { Link } from 'react-router-dom';
import {
  RiExternalLinkLine,
  RiFireLine,
  RiLoader4Line,
  RiShieldCheckLine,
  RiShieldFlashLine,
  RiSkull2Line,
} from '@remixicon/react';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { ServiceLogo } from '@/components/ServiceLogo';
import { useToast } from '@/context/ToastContext';
import { assetsLink, formatRelativeTime } from '@/lib/format';
import { cn } from '@/lib/utils';
import {
  applicabilityLabel,
  checkedTime,
  cvssSeverity,
  liveVulns,
  pct,
  severityTone,
  suppressedCount,
  vulnApi,
  worstVuln,
  type CVERef,
  type VerifiedFinding,
  type VerifyHostScope,
  type VerifyProfileView,
  type VulnSummary,
} from '@/lib/vulnintel';

type VulnService = { vulns?: VulnSummary[]; verified?: VerifiedFinding[] };

function Heading({ children, aside }: { children: React.ReactNode; aside?: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-2">
      <h4 className="text-xs font-semibold tracking-widest text-muted-foreground uppercase">{children}</h4>
      {aside && <span className="text-[10px] text-muted-foreground">{aside}</span>}
    </div>
  );
}

/** Compact "23 CVE 9.8" chip for the service row; tone follows the worst CVSS. */
export function VulnChip({ service }: { service: VulnService }) {
  const v = worstVuln(service.vulns);
  const suppressed = suppressedCount(service.vulns);
  if (!v) {
    if (suppressed === 0) return null;
    return (
      <Tooltip>
        <TooltipTrigger
          render={
            <span className="inline-flex h-[18px] items-center border border-dashed border-muted-foreground/40 px-1 font-mono text-[10px] leading-none text-muted-foreground line-through decoration-muted-foreground/60" />
          }
        >
          {suppressed} CVE
        </TooltipTrigger>
        <TooltipContent className="max-w-sm text-left">
          Version matches ruled out by the protocol probe: {suppressedLine(service.vulns)}
        </TooltipContent>
      </Tooltip>
    );
  }
  const live = liveVulns(service.vulns);
  const total = live.reduce((n, x) => n + x.total, 0);
  const possibleOnly = live.every((x) => x.confidence === 'low' || x.possible === x.total);
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <Link
            to={assetsLink(`cve:${v.top[0]?.id || 'true'}`)}
            onClick={(e) => e.stopPropagation()}
            className={cn(
              'inline-flex h-[18px] items-center gap-1 border px-1 font-mono text-[10px] leading-none font-semibold tabular-nums',
              severityTone(cvssSeverity(v.max_cvss)),
              possibleOnly && 'border-dashed opacity-80'
            )}
          />
        }
      >
        {total} CVE
        <span className="opacity-60">|</span>
        {v.max_cvss.toFixed(1)}
      </TooltipTrigger>
      <TooltipContent className="max-w-sm flex-col items-start gap-0.5 text-left">
        {live.map((x) => (
          <span key={x.product}>
            <span className="font-semibold">
              {x.product} {x.version}
            </span>
            : {x.total} CVEs ({x.critical} critical, {x.high} high), max CVSS {x.max_cvss.toFixed(1)}
            {x.kev > 0 && `, ${x.kev} exploited in the wild`}
            {x.confidence === 'low' && ', possible (distro backport)'}
          </span>
        ))}
        {suppressed > 0 && <span className="opacity-80">{suppressed} suppressed: {suppressedLine(service.vulns)}</span>}
      </TooltipContent>
    </Tooltip>
  );
}

/** "CVE-2023-44487, CVE-2019-9513 (not applicable: HTTP/2 off)". */
function suppressedLine(vulns: VulnSummary[] | undefined): string {
  const refs = (vulns || []).flatMap((v) => v.suppressed || []);
  if (!refs.length) return 'see the host drawer';
  const ids = refs.slice(0, 4).map((c) => c.id).join(', ') + (refs.length > 4 ? ` +${refs.length - 4}` : '');
  return `${ids} (${applicabilityLabel(refs[0])})`;
}

/** Applicability of a protocol-dependent CVE that still counts (on, or not checked). */
function ApplicabilityTag({ c }: { c: CVERef }) {
  if (!c.applicability || c.applicability === 'not_applicable') return null;
  const on = c.applicability === 'applicable';
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <span
            className={cn(
              'shrink-0 border px-1 text-[10px]',
              on ? 'border-foreground/30 text-foreground' : 'border-dashed border-muted-foreground/50 text-muted-foreground'
            )}
          />
        }
      >
        {applicabilityLabel(c)}
      </TooltipTrigger>
      <TooltipContent className="max-w-sm text-left">
        {c.applicability_note}
        {c.checked_at && ` Checked ${checkedTime(c.checked_at)}.`}
      </TooltipContent>
    </Tooltip>
  );
}

/** Version matches ruled out by the protocol probe: kept visible, struck through, with why. */
function SuppressedList({ refs }: { refs: CVERef[] }) {
  if (!refs.length) return null;
  return (
    <ul className="space-y-0.5 border-t border-dashed border-border pt-1.5" aria-label="Not applicable CVEs">
      {refs.map((c) => (
        <li key={c.id} className="flex items-baseline gap-1.5 text-[11px] text-muted-foreground">
          <a
            href={c.url}
            target="_blank"
            rel="noopener noreferrer"
            className="shrink-0 font-mono line-through decoration-muted-foreground/60 underline-offset-2 hover:underline"
          >
            {c.id}
          </a>
          {c.kev && (
            <span className="shrink-0 text-[10px] opacity-70" title={`In CISA KEV since ${c.kev_date_added}, not applicable here`}>
              KEV
            </span>
          )}
          <Tooltip>
            <TooltipTrigger render={<span className="min-w-0 flex-1 truncate" />}>
              · {applicabilityLabel(c)}
              {c.checked_at && ` (checked ${checkedTime(c.checked_at)})`}
            </TooltipTrigger>
            <TooltipContent className="max-w-sm text-left">{c.applicability_note}</TooltipContent>
          </Tooltip>
        </li>
      ))}
    </ul>
  );
}

function SeverityBar({ v }: { v: VulnSummary }) {
  const parts: Array<[string, number]> = [
    ['critical', v.critical],
    ['high', v.high],
    ['medium', v.medium],
    ['low', v.low],
  ];
  return (
    <span className="inline-flex items-center gap-px" aria-label="CVEs by severity">
      {parts.map(([sev, n]) => (
        <span
          key={sev}
          title={`${n} ${sev}`}
          className={cn(
            'inline-flex h-5 min-w-6 items-center justify-center border px-1 font-mono text-[10px] font-semibold tabular-nums',
            n > 0 ? severityTone(sev) : 'border-border text-muted-foreground/50'
          )}
        >
          {n}
          <span className="ml-0.5 font-sans text-[9px] font-normal uppercase opacity-70">{sev[0]}</span>
        </span>
      ))}
    </span>
  );
}

function ConfidenceBadge({ v }: { v: VulnSummary }) {
  const label =
    v.confidence === 'high' ? 'Exact version' : v.confidence === 'low' ? 'Possible, distro backport' : 'Likely';
  const tone =
    v.confidence === 'high'
      ? 'border-foreground/30 text-foreground'
      : v.confidence === 'low'
        ? 'border-dashed border-muted-foreground/50 text-muted-foreground'
        : 'border-amber-500/40 text-amber-700 dark:text-amber-300';
  return (
    <Tooltip>
      <TooltipTrigger render={<span className={cn('inline-flex h-5 items-center border px-1.5 text-[10px] font-medium', tone)} />}>
        {label}
      </TooltipTrigger>
      <TooltipContent className="max-w-sm text-left">{v.confidence_note}</TooltipContent>
    </Tooltip>
  );
}

export function KevBadge({ count, ransomware }: { count: number; ransomware?: boolean }) {
  return (
    <span className="inline-flex h-5 items-center gap-1 border border-rose-700 bg-rose-600 px-1.5 text-[10px] font-semibold text-white dark:bg-rose-500">
      <RiFireLine className="size-3" />
      Exploited in the wild{count > 1 ? ` (${count})` : ''}
      {ransomware && <RiSkull2Line className="size-3" aria-label="used by ransomware" />}
    </span>
  );
}

/** Known-vulnerability evidence of a service (expanded view in the host drawer). */
export function VulnEvidence({ service }: { service: VulnService }) {
  const vulns = service.vulns || [];
  if (vulns.length === 0) return null;
  const suppressed = suppressedCount(vulns);
  return (
    <div className="space-y-2">
      <Heading aside={`NVD, CISA KEV, FIRST EPSS as of ${vulns[0].data_as_of}`}>
        Known vulnerabilities
        {suppressed > 0 && (
          <Tooltip>
            <TooltipTrigger
              render={
                <span className="ml-2 inline-flex h-4 items-center border border-dashed border-muted-foreground/50 px-1 align-middle text-[10px] font-medium tracking-normal normal-case" />
              }
            >
              {suppressed} suppressed
            </TooltipTrigger>
            <TooltipContent className="max-w-sm text-left">
              Version matches whose precondition the scan ruled out (HTTP/2 off on this port). Kept for the record;
              not counted in the score, the KEV badge, queries or DefectDojo.
            </TooltipContent>
          </Tooltip>
        )}
      </Heading>
      {vulns.map((v) =>
        v.total === 0 ? (
          <div key={v.product} className="space-y-1.5 border border-dashed border-border bg-card/50 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <ServiceLogo name={v.product} size="sm" />
              <span className="text-sm font-semibold text-muted-foreground">
                {v.product} <span className="font-mono text-xs font-normal">{v.version}</span>
              </span>
              <span className="text-[11px] text-muted-foreground">
                every match is not applicable on this port
              </span>
            </div>
            <SuppressedList refs={v.suppressed || []} />
          </div>
        ) : (
        <div key={v.product} className="space-y-2 border border-border bg-card p-3">
          <div className="flex flex-wrap items-center gap-2">
            <ServiceLogo name={v.product} size="sm" />
            <span className="text-sm font-semibold text-foreground">
              {v.product} <span className="font-mono text-xs font-normal">{v.version}</span>
            </span>
            <ConfidenceBadge v={v} />
            {v.kev > 0 && <KevBadge count={v.kev} ransomware={v.ransomware} />}
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
            <SeverityBar v={v} />
            <span className="text-muted-foreground">
              <span className="font-mono font-semibold text-foreground tabular-nums">{v.total}</span> CVEs
              {v.possible > 0 && <> ({v.possible} possible)</>}
            </span>
            <span className="text-muted-foreground">
              max CVSS{' '}
              <span className={cn('border px-1 font-mono font-semibold tabular-nums', severityTone(cvssSeverity(v.max_cvss)))}>
                {v.max_cvss.toFixed(1)}
              </span>
            </span>
            <span className="text-muted-foreground" title="Highest EPSS percentile among the matched CVEs">
              EPSS{' '}
              <span className="font-mono font-semibold text-foreground tabular-nums">{pct(v.max_epss, 1)}</span>
              {' '}(top {Math.max(0.1, 100 - v.max_epss_percentile * 100).toFixed(1)}%)
            </span>
          </div>
          <ul className="divide-y divide-border border-t border-border">
            {v.top.map((c) => (
              <li key={c.id} className="flex items-start gap-2 py-1.5 text-xs">
                <a
                  href={c.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex shrink-0 items-center gap-0.5 font-mono font-semibold text-foreground underline-offset-2 hover:underline"
                >
                  {c.id}
                  <RiExternalLinkLine className="size-3 opacity-60" />
                </a>
                <span className={cn('shrink-0 border px-1 font-mono text-[10px] tabular-nums', severityTone(cvssSeverity(c.cvss)))}>
                  {c.cvss.toFixed(1)}
                </span>
                {c.kev && (
                  <Tooltip>
                    <TooltipTrigger render={<span className="inline-flex shrink-0 text-rose-600 dark:text-rose-400" />}>
                      <RiFireLine className="size-3.5" aria-label="CISA KEV" />
                    </TooltipTrigger>
                    <TooltipContent>In CISA KEV since {c.kev_date_added}</TooltipContent>
                  </Tooltip>
                )}
                <span className="shrink-0 font-mono text-[10px] text-muted-foreground tabular-nums" title="EPSS probability of exploitation in 30 days">
                  EPSS {pct(c.epss, 1)}
                </span>
                {c.possible && <span className="shrink-0 border border-dashed px-1 text-[10px] text-muted-foreground">possible</span>}
                <ApplicabilityTag c={c} />
                <span className="min-w-0 flex-1 truncate text-muted-foreground" title={`${c.summary}${c.range ? ` (affected: ${c.range})` : ''}`}>
                  {c.summary}
                </span>
              </li>
            ))}
          </ul>
          {v.total > v.top.length && v.top[0] && (
            <p className="text-[11px] text-muted-foreground">
              +{v.total - v.top.length} more, ordered by KEV, EPSS and CVSS.{' '}
              <Link to={assetsLink(`cve:${v.top[0].id}`)} className="underline">
                Other hosts with {v.top[0].id}
              </Link>
            </p>
          )}
          <SuppressedList refs={v.suppressed || []} />
        </div>
        )
      )}
    </div>
  );
}

/** Findings confirmed by safe checks, with request / response evidence. */
export function VerifiedEvidence({ service }: { service: VulnService }) {
  const list = service.verified || [];
  if (list.length === 0) return null;
  return (
    <div className="space-y-2">
      <Heading aside={`checked ${formatRelativeTime(list[0].checked_at)}`}>Verified exposures</Heading>
      {list.map((f) => (
        <details key={f.check_id} className="group border border-border bg-card">
          <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 text-xs">
            <RiShieldCheckLine className="size-4 shrink-0 text-rose-600 dark:text-rose-400" />
            <span className={cn('shrink-0 border px-1 text-[10px] font-semibold uppercase', severityTone(f.severity))}>{f.severity}</span>
            <span className="min-w-0 flex-1 font-medium text-foreground">{f.name}</span>
            {f.default_creds && (
              <span className="shrink-0 border border-amber-500/40 px-1 text-[10px] text-amber-700 dark:text-amber-300">default credential</span>
            )}
            <span className="shrink-0 font-mono text-[10px] text-muted-foreground">{f.check_id}</span>
          </summary>
          <div className="space-y-2 border-t border-border px-3 py-2 text-xs">
            <div>
              <div className="mb-0.5 text-[10px] font-semibold tracking-wider text-muted-foreground uppercase">Request</div>
              <pre className="overflow-x-auto bg-muted/50 p-2 font-mono text-[11px] whitespace-pre-wrap">{f.request}</pre>
            </div>
            <div>
              <div className="mb-0.5 text-[10px] font-semibold tracking-wider text-muted-foreground uppercase">
                Response (secrets redacted)
              </div>
              <pre className="max-h-48 overflow-auto bg-muted/50 p-2 font-mono text-[11px] whitespace-pre-wrap">{f.evidence}</pre>
            </div>
            <p className="text-muted-foreground">
              <span className="font-semibold text-foreground">Fix: </span>
              {f.remediation}
            </p>
            {f.references?.[0] && (
              <a href={f.references[0]} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-0.5 underline">
                reference <RiExternalLinkLine className="size-3" />
              </a>
            )}
          </div>
        </details>
      ))}
    </div>
  );
}

/** Verify status for a host with a "Verify now" action (secondary button). */
export function VerifyHostBar({ hostId, canRun, onDone }: { hostId: string; canRun: boolean; onDone: () => void }) {
  const toast = useToast();
  const [scope, setScope] = React.useState<VerifyHostScope | null>(null);
  const [running, setRunning] = React.useState(false);
  React.useEffect(() => {
    let alive = true;
    vulnApi
      .hostScope(hostId)
      .then((s) => alive && setScope(s))
      .catch(() => alive && setScope(null));
    return () => {
      alive = false;
    };
  }, [hostId]);
  if (!scope) return null;
  const on = scope.profiles.filter((p) => p.config.enabled);
  const last = on.map((p) => p.last_run).filter(Boolean).sort((a, b) => (b!.finished_at > a!.finished_at ? 1 : -1))[0];
  const run = async () => {
    setRunning(true);
    try {
      const sum = await vulnApi.runHost(hostId, on[0]?.profile_id);
      const n = sum.stats.findings;
      toast.success(n > 0 ? `Verify confirmed ${n} exposure${n === 1 ? '' : 's'}` : 'Verify found nothing to confirm', `${sum.stats.checks_run} safe checks on ${sum.stats.targets} services`);
      onDone();
    } catch (err) {
      toast.error('Verify failed', (err as Error).message);
    } finally {
      setRunning(false);
    }
  };
  return (
    <div className="mb-3 flex flex-wrap items-center gap-2 border border-border bg-muted/30 px-3 py-2 text-xs">
      <RiShieldFlashLine className="size-4 shrink-0 text-muted-foreground" />
      {on.length === 0 ? (
        <span className="text-muted-foreground">
          Verify (safe checks) is off for this host.{' '}
          <Link to="/scans" className="underline">
            Enable it in a scan profile
          </Link>{' '}
          that covers {scope.ip}.
        </span>
      ) : (
        <>
          <span className="min-w-0 flex-1 text-muted-foreground">
            <span className="font-medium text-foreground">Verify</span> on in {on.map((p) => p.profile_name).join(', ')}
            {on.some((p) => p.config.default_creds) && ', default credentials included'}
            {last ? `. Last run ${formatRelativeTime(last.finished_at)}: ${last.stats.findings} confirmed.` : '. Not run yet.'}
          </span>
          {canRun && (
            <Button type="button" size="xs" variant="outline" disabled={running} onClick={run}>
              {running ? <RiLoader4Line data-icon="inline-start" className="animate-spin" /> : <RiShieldCheckLine data-icon="inline-start" />}
              {running ? 'Verifying' : 'Verify now'}
            </Button>
          )}
        </>
      )}
    </div>
  );
}

/**
 * Per-profile opt-in for Verify (deep mode) and default credentials. Saved immediately and
 * audited; off by default. New profiles must be saved first.
 */
export function VerifyProfileSettings({ profileId }: { profileId: string | null }) {
  const toast = useToast();
  const [view, setView] = React.useState<VerifyProfileView | null>(null);
  const [saving, setSaving] = React.useState(false);
  React.useEffect(() => {
    if (!profileId) {
      setView(null);
      return;
    }
    let alive = true;
    vulnApi
      .profiles()
      .then((list) => alive && setView(list.find((p) => p.profile_id === profileId) || null))
      .catch(() => alive && setView(null));
    return () => {
      alive = false;
    };
  }, [profileId]);
  const save = async (enabled: boolean, defaultCreds: boolean) => {
    if (!profileId) return;
    setSaving(true);
    try {
      const v = await vulnApi.saveProfile(profileId, { enabled, default_creds: enabled && defaultCreds });
      setView((prev) => ({ ...(prev || v), config: v.config }));
      toast.success(enabled ? 'Verify enabled for this profile' : 'Verify disabled for this profile');
    } catch (err) {
      toast.error('Could not save Verify settings', (err as Error).message);
    } finally {
      setSaving(false);
    }
  };
  const cfg = view?.config || { enabled: false, default_creds: false };
  return (
    <div className="space-y-2 border border-dashed border-border p-3 sm:col-span-2">
      <div className="flex items-center gap-3">
        <Switch
          id="verify-on"
          checked={cfg.enabled}
          disabled={!profileId || saving}
          onCheckedChange={(checked) => save(checked, cfg.default_creds)}
        />
        <Label htmlFor="verify-on" className="text-xs">
          <RiShieldCheckLine className="size-3.5" /> Verify (deep mode): confirm exposures with safe checks
        </Label>
      </div>
      <div className="flex items-center gap-3 pl-11">
        <Switch
          id="verify-creds"
          checked={cfg.enabled && cfg.default_creds}
          disabled={!profileId || saving || !cfg.enabled}
          onCheckedChange={(checked) => save(true, checked)}
        />
        <Label htmlFor="verify-creds" className="text-xs">
          Check well-known default credentials (e.g. RabbitMQ guest), each attempt audited
        </Label>
      </div>
      <p className="text-[11px] text-muted-foreground">
        {profileId
          ? 'Off by default. Runs after each completed scan, only against this profile’s targets, through the same rate governor. Read-only requests: no exploitation, no brute force. Saved immediately.'
          : 'Save the profile first, then enable Verify here.'}
        {view?.last_run && ` Last run ${formatRelativeTime(view.last_run.finished_at)}: ${view.last_run.stats.findings} confirmed on ${view.last_run.stats.targets} services.`}
      </p>
    </div>
  );
}
