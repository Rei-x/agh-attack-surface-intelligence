import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  RiAddLine,
  RiArrowDownSLine,
  RiArrowRightSLine,
  RiCalculatorLine,
  RiCheckLine,
  RiDeleteBinLine,
  RiDownload2Line,
  RiEditLine,
  RiFileUploadLine,
  RiForbidLine,
  RiPauseLine,
  RiPlayLine,
  RiSaveLine,
  RiStopLine,
  RiTimeLine,
  RiUploadCloud2Line,
} from '@remixicon/react';
import { api, ApiError, type ExportFormat } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/context/ToastContext';
import { useLiveEvents, useLiveRefresh } from '@/context/LiveEventsContext';
import { PERMISSIONS } from '@/lib/permissions';
import {
  formatDateTime,
  formatShortTime,
  formatDurationSeconds,
  formatNumber,
  scanStatusMeta,
} from '@/lib/format';
import { cn } from '@/lib/utils';
import { TagRulesPanel } from '@/components/TagRulesPanel';
import { AgentsPanel } from '@/components/AgentsPanel';
import { Button } from '@/components/ui/button';
import { ChunkMatrix } from '@/components/ChunkMatrix';
import { NmapCommandsPanel } from '@/components/NmapCommandsPanel';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Code,
  Empty,
  Field,
  Notice,
  PageHeader,
  Pill,
  SectionTitle,
  SimpleSelect,
  Stat,
  StatStrip,
} from '@/components/common';
import type {
  Agent,
  ProfileSchedule,
  ScanChunk,
  ScanProfile,
  ScanRun,
  Target,
  TargetEstimate,
  TargetExclusion,
} from '@/types/api';
import { PeckLoader } from '@/components/Woodpecker';
import { rateChange, throttleReasonLabel } from '@/lib/scanTelemetry';

type ScansTab = 'runs' | 'profiles' | 'scopes' | 'ingest' | 'agents';

const LOCAL_AGENT = '__local__';

const ALL = '__all__';

const EMPTY_PROFILE_FORM = {
  name: '',
  description: '',
  targetsText: '',
  allowed_ports: '21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,8080,8443',
  max_rate_pps: 300,
  http_rps: 10,
  concurrency: 16,
  chunk_target_sec: 30,
  window_enabled: false,
  window_start: '22:00',
  window_end: '06:00',
  timezone: 'Europe/Warsaw',
  schedule_cron: '',
  missing_threshold: 2,
  grace_period_hours: 24,
  retry_unstable_count: 2,
  enable_http_fingerprint: true,
  agent_id: LOCAL_AGENT,
};
type ProfileFormState = typeof EMPTY_PROFILE_FORM;


/**
 * Scan profile presets (SecureCodeBox-style scan types). They only prefill the form;
 * rate limits stay conservative (shared university network).
 */
const PROFILE_PRESETS = [
  {
    id: 'discovery',
    label: 'Quick discovery',
    hint: 'Live hosts + top ports, no HTTP',
    values: {
      description: 'Quick discovery: top ports, no HTTP fingerprinting',
      allowed_ports: '22,80,443,3389,8080,8443',
      max_rate_pps: 200,
      http_rps: 5,
      concurrency: 16,
      chunk_target_sec: 30,
      enable_http_fingerprint: false,
    },
  },
  {
    id: 'standard',
    label: 'Standard',
    hint: 'Service ports + HTTP/TLS fingerprint',
    values: {
      description: 'Standard: common network services + HTTP/TLS fingerprint',
      allowed_ports: '21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,8080,8443',
      max_rate_pps: 300,
      http_rps: 10,
      concurrency: 16,
      chunk_target_sec: 30,
      enable_http_fingerprint: true,
    },
  },
  {
    id: 'web',
    label: 'Full web',
    hint: 'Web ports + HTTP/TLS + safe paths',
    values: {
      description: 'Full web: HTTP(S) ports, HTTP/TLS fingerprint and safe paths from signatures',
      allowed_ports: '80,443,3000,5000,8000,8008,8080,8081,8443,8888,9000,9090,9443',
      max_rate_pps: 200,
      http_rps: 10,
      concurrency: 8,
      chunk_target_sec: 45,
      enable_http_fingerprint: true,
    },
  },
] as const;

export function ScansPage() {
  const { can } = useAuth();
  const toast = useToast();

  const [activeTab, setActiveTab] = useState<ScansTab>('runs');
  const [targets, setTargets] = useState<Target[]>([]);
  const [exclusions, setExclusions] = useState<TargetExclusion[]>([]);
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [scans, setScans] = useState<ScanRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [launchProfileId, setLaunchProfileId] = useState('');

  // Target & exclusion forms
  const [newTarget, setNewTarget] = useState('');
  const [newTargetLabel, setNewTargetLabel] = useState('');
  const [newExclusion, setNewExclusion] = useState('');
  const [newExclusionReason, setNewExclusionReason] = useState('');

  // Estimator state
  const [estTargets, setEstTargets] = useState('172.28.0.0/24\n10.0.0.0/18');
  const [estExclusions, setEstExclusions] = useState('10.0.0.1/32');
  const [estPorts, setEstPorts] = useState('22,80,443,8080,8443');
  const [estRate, setEstRate] = useState(500);
  const [estConcurrency] = useState(32);
  const [estWindowStart, setEstWindowStart] = useState('22:00');
  const [estWindowEnd, setEstWindowEnd] = useState('06:00');
  const [estimate, setEstimate] = useState<TargetEstimate | null>(null);
  const [estimating, setEstimating] = useState(false);

  // Profile editor (create, or edit when editingProfileId is set)
  const [profileForm, setProfileForm] = useState<ProfileFormState>(EMPTY_PROFILE_FORM);
  const [editingProfileId, setEditingProfileId] = useState<string | null>(null);
  const profileFormRef = useRef<HTMLDivElement>(null);
  // Defaults for a new profile come from the configured scope and an online agent, once.
  const defaultsApplied = useRef(false);

  // Coverage Ledger selected scan & metadata editor
  const [expandedScanId, setExpandedScanId] = useState<string | null>(null);
  const [scanDetail, setScanDetail] = useState<ScanRun | null>(null);
  const [editingScanId, setEditingScanId] = useState<string | null>(null);
  const [editScanName, setEditScanName] = useState('');
  const [editScanNotes, setEditScanNotes] = useState('');

  // Manual Ingest Form
  const [manualForm, setManualForm] = useState({
    scan_name: 'Analyst manual entry',
    ip: '',
    hostname: '',
    environment: 'prod',
    tags: 'manual, cbi-agh',
    notes: '',
    port: 443,
    protocol: 'tcp',
    service_name: 'https',
    product: 'nginx',
    version: '1.24.0',
    http_title: '',
    status_code: 200,
    headers_text: 'Server: nginx/1.24.0\nX-Powered-By: Express',
    cookies_text: 'session_id=demo; Path=/',
  });
  const [submittingManual, setSubmittingManual] = useState(false);

  // File Import state
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importFormat, setImportFormat] = useState<'csv' | 'json' | 'nmap' | 'scb'>('csv');
  const [importScanName, setImportScanName] = useState('');
  const [importPreview, setImportPreview] = useState<string>('');
  const [importing, setImporting] = useState(false);

  // Export state
  const [exportScanId, setExportScanId] = useState('');
  const [exportState, setExportState] = useState('');
  const [exportTag, setExportTag] = useState('');

  const canWriteScans = can(PERMISSIONS.SCANS_WRITE);
  const canDeleteScans = can(PERMISSIONS.SCANS_DELETE);
  const canRunScans = can(PERMISSIONS.SCANS_RUN);
  const canImport = can(PERMISSIONS.IMPORT_WRITE);
  const canExport = can(PERMISSIONS.EXPORT_READ);

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const [t, ex, pr, sc] = await Promise.all([
        api.listTargets(),
        api.listExclusions(),
        api.listProfiles(),
        api.listScans(),
      ]);
      setTargets(t);
      setExclusions(ex);
      setProfiles(pr);
      setScans(sc);
      api
        .listAgents()
        .then((res) => setAgents(res.agents))
        .catch(() => setAgents([]));
    } catch (err) {
      toast.error('Could not load scans', (err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  // Live: silently refresh runs + the open Coverage Ledger as SSE data arrives
  const { liveChunks, activeScan: liveScan } = useLiveEvents();
  const expandedRef = useRef(expandedScanId);
  expandedRef.current = expandedScanId;
  useLiveRefresh(async () => {
    try {
      const sc = await api.listScans();
      setScans(sc);
      const openId = expandedRef.current;
      if (openId) {
        const detail = await api.getScan(openId);
        if (expandedRef.current === openId) setScanDetail(detail);
      }
    } catch {
      // background refresh: ignore
    }
  });

  const handleEstimate = async () => {
    setEstimating(true);
    try {
      const res = await api.estimateTargets({
        targets: estTargets
          .split(/[\n,]+/)
          .map((s) => s.trim())
          .filter(Boolean),
        exclusions: estExclusions
          .split(/[\n,]+/)
          .map((s) => s.trim())
          .filter(Boolean),
        ports: estPorts,
        allowed_ports: estPorts,
        max_rate_pps: estRate,
        concurrency: estConcurrency,
        window_enabled: true,
        window_start: estWindowStart,
        window_end: estWindowEnd,
        timezone: 'Europe/Warsaw',
      });
      setEstimate(res);
    } catch (err) {
      toast.error('Estimate failed', (err as Error).message);
    } finally {
      setEstimating(false);
    }
  };

  const handleAddTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTarget.trim()) return;
    try {
      await api.createTarget({ value: newTarget.trim(), label: newTargetLabel.trim(), enabled: true });
      setNewTarget('');
      setNewTargetLabel('');
      toast.success('Target added');
      loadAll();
    } catch (err) {
      toast.error('Could not add target', (err as Error).message);
    }
  };

  const handleAddExclusion = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newExclusion.trim()) return;
    try {
      await api.createExclusion({
        value: newExclusion.trim(),
        reason: newExclusionReason.trim() || 'Excluded by CBI AGH',
      });
      setNewExclusion('');
      setNewExclusionReason('');
      toast.success('Exclusion added');
      loadAll();
    } catch (err) {
      toast.error('Could not add exclusion', (err as Error).message);
    }
  };

  const defaultNewProfile = useCallback((): ProfileFormState => {
    const scope = targets.filter((t) => t.enabled).map((t) => t.value);
    const online = agents.find((a) => a.status === 'online' && !a.disabled);
    return {
      ...EMPTY_PROFILE_FORM,
      targetsText: scope.join('\n'),
      agent_id: online ? online.id : LOCAL_AGENT,
    };
  }, [targets, agents]);

  useEffect(() => {
    if (defaultsApplied.current || loading || editingProfileId) return;
    if (targets.length === 0 && agents.length === 0) return;
    defaultsApplied.current = true;
    setProfileForm((p) => (p.name || p.targetsText ? p : defaultNewProfile()));
  }, [loading, targets, agents, editingProfileId, defaultNewProfile]);

  const resetProfileForm = () => {
    setEditingProfileId(null);
    setProfileForm(defaultNewProfile());
  };

  const startEditProfile = (p: ScanProfile) => {
    setEditingProfileId(p.id);
    setProfileForm({
      name: p.name,
      description: p.description || '',
      targetsText: (p.targets || []).join('\n'),
      allowed_ports: p.allowed_ports,
      max_rate_pps: p.max_rate_pps,
      http_rps: p.http_rps,
      concurrency: p.concurrency,
      chunk_target_sec: p.chunk_target_sec,
      window_enabled: p.window_enabled,
      window_start: p.window_start || '22:00',
      window_end: p.window_end || '06:00',
      timezone: p.timezone || 'Europe/Warsaw',
      schedule_cron: p.schedule_cron || '',
      missing_threshold: p.missing_threshold,
      grace_period_hours: p.grace_period_hours,
      retry_unstable_count: p.retry_unstable_count,
      enable_http_fingerprint: p.enable_http_fingerprint,
      agent_id: p.agent_id || LOCAL_AGENT,
    });
    requestAnimationFrame(() => profileFormRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }));
  };

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!profileForm.name.trim()) return;
    const payload = {
        name: profileForm.name.trim(),
        description: profileForm.description.trim(),
        targets: profileForm.targetsText
          .split(/[\n,]+/)
          .map((s) => s.trim())
          .filter(Boolean),
        allowed_ports: profileForm.allowed_ports,
        max_rate_pps: profileForm.max_rate_pps,
        http_rps: profileForm.http_rps,
        concurrency: profileForm.concurrency,
        chunk_target_sec: profileForm.chunk_target_sec,
        window_enabled: profileForm.window_enabled,
        window_start: profileForm.window_start,
        window_end: profileForm.window_end,
        timezone: profileForm.timezone,
        schedule_cron: profileForm.schedule_cron.trim(),
        missing_threshold: profileForm.missing_threshold,
        grace_period_hours: profileForm.grace_period_hours,
        retry_unstable_count: profileForm.retry_unstable_count,
        enable_http_fingerprint: profileForm.enable_http_fingerprint,
        agent_id: profileForm.agent_id === LOCAL_AGENT ? '' : profileForm.agent_id,
        enabled: true,
    };
    try {
      if (editingProfileId) {
        await api.updateProfile(editingProfileId, payload);
        toast.success('Profile saved', payload.name);
      } else {
        await api.createProfile(payload);
        toast.success('Profile created', payload.name);
      }
      setEditingProfileId(null);
      setProfileForm(defaultNewProfile());
      loadAll();
    } catch (err) {
      toast.error(editingProfileId ? 'Could not save the profile' : 'Could not create the profile', (err as Error).message);
    }
  };

  const handleStartProfileScan = async (profile: ScanProfile) => {
    try {
      const run = await api.runProfile(profile.id);
      toast.success('Scan started', run.name);
      setActiveTab('runs');
      loadAll();
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        toast.error('This profile already has an active run', 'Wait for it to finish or stop it.');
      } else {
        toast.error('Could not start the scan', (err as Error).message);
      }
    }
  };

  // Deep link from the dashboard: /scans?scan=<id> opens that run expanded.
  const [searchParams] = useSearchParams();
  const deepLinked = useRef(false);
  useEffect(() => {
    const id = searchParams.get('scan');
    if (!id || deepLinked.current || scans.length === 0) return;
    deepLinked.current = true;
    setActiveTab('runs');
    setExpandedScanId(id);
    api
      .getScan(id)
      .then(setScanDetail)
      .catch(() => undefined);
  }, [searchParams, scans.length]);

  const handleToggleScanDetail = async (scanId: string) => {
    if (expandedScanId === scanId) {
      setExpandedScanId(null);
      setScanDetail(null);
      return;
    }
    setExpandedScanId(scanId);
    try {
      const detail = await api.getScan(scanId);
      setScanDetail(detail);
    } catch (err) {
      toast.error('Could not load the run', (err as Error).message);
    }
  };

  const handleSaveScanMeta = async (scanId: string) => {
    try {
      await api.updateScan(scanId, { name: editScanName, notes: editScanNotes });
      toast.success('Saved');
      setEditingScanId(null);
      loadAll();
    } catch (err) {
      toast.error('Save failed', (err as Error).message);
    }
  };

  const handleScanControl = async (scanId: string, action: 'pause' | 'resume' | 'stop' | 'delete') => {
    try {
      if (action === 'pause') await api.pauseScan(scanId);
      else if (action === 'resume') await api.resumeScan(scanId);
      else if (action === 'stop') await api.stopScan(scanId);
      else if (action === 'delete') {
        if (!window.confirm('Delete this scan run?')) return;
        await api.deleteScan(scanId);
      }
      toast.success('Done');
      loadAll();
    } catch (err) {
      toast.error('Action failed', (err as Error).message);
    }
  };

  const handleManualSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualForm.ip.trim()) return;
    setSubmittingManual(true);
    try {
      const headers: Record<string, string> = {};
      for (const line of manualForm.headers_text.split('\n')) {
        const idx = line.indexOf(':');
        if (idx > 0) {
          headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
        }
      }

      const cookies = manualForm.cookies_text
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean)
        .map((line) => {
          const [pair, ...attrs] = line.split(';').map((p) => p.trim());
          const eq = pair.indexOf('=');
          const name = eq > 0 ? pair.slice(0, eq) : pair;
          const value = eq > 0 ? pair.slice(eq + 1) : '';
          const lowerAttrs = attrs.map((a) => a.toLowerCase());
          return {
            name,
            value,
            http_only: lowerAttrs.includes('httponly'),
            secure: lowerAttrs.includes('secure'),
          };
        });

      const tags = manualForm.tags
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);

      await api.ingestManual({
        scan_name: manualForm.scan_name || 'Manual entry',
        ip: manualForm.ip.trim(),
        hostname: manualForm.hostname.trim(),
        environment: manualForm.environment,
        tags,
        notes: manualForm.notes.trim(),
        is_alive: true,
        services: [
          {
            port: Number(manualForm.port),
            protocol: manualForm.protocol,
            state: 'open',
            service_name: manualForm.service_name,
            product: manualForm.product,
            version: manualForm.version,
            tags,
            http: manualForm.http_title || Object.keys(headers).length > 0
              ? {
                  status_code: Number(manualForm.status_code) || 200,
                  title: manualForm.http_title,
                  headers,
                  cookies,
                  scheme: Number(manualForm.port) === 443 ? 'https' : 'http',
                }
              : undefined,
          },
        ],
      });

      toast.success('Host added', manualForm.ip);
      setManualForm((m) => ({ ...m, ip: '', hostname: '', http_title: '', notes: '' }));
      loadAll();
    } catch (err) {
      toast.error('Manual entry failed', (err as Error).message);
    } finally {
      setSubmittingManual(false);
    }
  };

  const handleFileChange = (file: File | null) => {
    setImportFile(file);
    if (!file) {
      setImportPreview('');
      return;
    }
    const lower = file.name.toLowerCase();
    if (lower.endsWith('.json')) setImportFormat('json');
    else if (lower.endsWith('.xml')) setImportFormat('nmap');
    else setImportFormat('csv');

    const reader = new FileReader();
    reader.onload = () => {
      const text = String(reader.result || '');
      setImportPreview(text.split('\n').slice(0, 14).join('\n'));
    };
    reader.readAsText(file);
  };

  const handleImportSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!importFile) return;
    setImporting(true);
    try {
      await api.ingestImportFile(
        importFile,
        importFormat,
        importScanName.trim() || `Import ${importFormat.toUpperCase()}: ${importFile.name}`
      );
      toast.success('Imported', importFile.name);
      setImportFile(null);
      setImportPreview('');
      setImportScanName('');
      loadAll();
    } catch (err) {
      toast.error('Import failed', (err as Error).message);
    } finally {
      setImporting(false);
    }
  };

  const launchProfile = profiles.find((p) => p.id === launchProfileId) || profiles[0];

  const runExport = (format: ExportFormat) =>
    api
      .exportData({
        format,
        scan_id: exportScanId || undefined,
        state: exportState || undefined,
        tag: exportTag || undefined,
      })
      .catch((err) => toast.error('Export failed', (err as Error).message));

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scans"
        meta={`${scans.length} runs · ${profiles.length} profiles`}
        actions={
          activeTab === 'runs' && canRunScans && profiles.length > 0 ? (
            <>
              <SimpleSelect
                value={launchProfile?.id ?? ''}
                onValueChange={setLaunchProfileId}
                options={profiles.map((p) => ({ value: p.id, label: p.name }))}
                placeholder="Profile"
                size="sm"
                className="w-56"
              />
              <Button
                size="sm"
                disabled={!launchProfile}
                onClick={() => launchProfile && handleStartProfileScan(launchProfile)}
              >
                <RiPlayLine data-icon="inline-start" />
                Run scan
              </Button>
            </>
          ) : undefined
        }
      />

      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as ScansTab)}>
        <TabsList variant="line">
          <TabsTrigger value="runs">Runs ({scans.length})</TabsTrigger>
          <TabsTrigger value="profiles">Profiles ({profiles.length})</TabsTrigger>
          <TabsTrigger value="scopes">Scope</TabsTrigger>
          <TabsTrigger value="ingest">Import / export</TabsTrigger>
          <TabsTrigger value="agents">Agents ({agents.length})</TabsTrigger>
        </TabsList>

        {/* ───────────── RUNS & COVERAGE LEDGER ───────────── */}
        <TabsContent value="runs" className="pt-4">
          <Card size="sm" className="py-0">
            {scans.length === 0 ? (
              loading ? (
                <PeckLoader />
              ) : (
                <Empty bird>No runs yet · Dzięcioł hasn't knocked</Empty>
              )
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="w-28">Chunks</TableHead>
                    <TableHead className="hidden text-right min-[1400px]:table-cell">IPs</TableHead>
                    <TableHead className="text-right">Hosts</TableHead>
                    <TableHead className="text-right">Services</TableHead>
                    <TableHead className="hidden text-right min-[1400px]:table-cell">Changes</TableHead>
                    <TableHead className="text-right">Duration</TableHead>
                    <TableHead className="text-right">Rate</TableHead>
                    <TableHead>Started</TableHead>
                    <TableHead className="text-right" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {scans.map((scan) => {
                    const meta = scanStatusMeta(scan.status);
                    const isExpanded = expandedScanId === scan.id;
                    const isEditing = editingScanId === scan.id;
                    const chunks: ScanChunk[] = isExpanded
                      ? scanDetail?.chunks || scan.chunks || []
                      : [];
                    const pct =
                      scan.total_chunks > 0
                        ? Math.round((scan.completed_chunks / scan.total_chunks) * 100)
                        : scan.status === 'COMPLETED'
                          ? 100
                          : 0;
                    const isActive =
                      scan.status === 'RUNNING' ||
                      scan.status === 'PAUSED_USER' ||
                      scan.status === 'PAUSED_WINDOW';
                    const isPaused =
                      scan.status === 'PAUSED_USER' || scan.status === 'PAUSED_WINDOW';

                    return (
                      <React.Fragment key={scan.id}>
                        <TableRow className={cn((isExpanded || isEditing) && 'border-b-0 bg-muted/30')}>
                          <TableCell className="max-w-[300px]">
                            <button
                              type="button"
                              onClick={() => handleToggleScanDetail(scan.id)}
                              className="flex w-full min-w-0 items-center gap-1.5 text-left"
                            >
                              {isExpanded ? (
                                <RiArrowDownSLine className="size-4 shrink-0 text-muted-foreground" />
                              ) : (
                                <RiArrowRightSLine className="size-4 shrink-0 text-muted-foreground" />
                              )}
                              <span className="truncate text-sm font-medium" title={scan.name}>
                                {scan.name}
                              </span>
                            </button>
                            <div className="mt-0.5 truncate pl-5.5 text-xs text-muted-foreground" title={scan.notes}>
                              <span className="font-mono text-[10px] tracking-wider uppercase">
                                {runTypeLabel(scan.run_type)}
                              </span>
                              {scan.notes ? ` · ${scan.notes}` : ''}
                            </div>
                          </TableCell>
                          <TableCell>
                            <Pill className={meta.badge} dot pulse={meta.pulse}>
                              {meta.label}
                            </Pill>
                          </TableCell>
                          <TableCell>
                            <div className="flex flex-col gap-1.5">
                              <span className="font-mono text-[11px] text-muted-foreground">
                                {scan.completed_chunks}/{scan.total_chunks || 1} · {pct}%
                              </span>
                              <Progress value={pct} />
                            </div>
                          </TableCell>
                          <TableCell className="hidden text-right font-mono text-xs min-[1400px]:table-cell">
                            {scan.scanned_ips}/{scan.total_ips}
                          </TableCell>
                          <TableCell className="text-right font-mono text-xs">
                            {scan.active_hosts}
                          </TableCell>
                          <TableCell className="text-right font-mono text-xs">
                            {scan.services_found}
                          </TableCell>
                          <TableCell className="hidden text-right font-mono text-xs min-[1400px]:table-cell">
                            {scan.changes_detected}
                          </TableCell>
                          <TableCell className="text-right font-mono text-xs whitespace-nowrap">
                            {scan.duration_ms >= 1000 ? formatDurationSeconds(scan.duration_ms / 1000) : scan.duration_ms > 0 ? "<1s" : ''}
                          </TableCell>
                          <TableCell className="text-right font-mono text-xs whitespace-nowrap">
                            <div>{scan.hosts_per_sec > 0 ? `${scan.hosts_per_sec < 1 ? scan.hosts_per_sec.toFixed(2) : scan.hosts_per_sec.toFixed(1)} IP/s` : ''}</div>
                            {(scan.telemetry?.throttle_count ?? 0) > 0 && (
                              <div
                                className="text-[10px] text-amber-600 dark:text-amber-400"
                                title="The noise governor slowed this run down. Expand the row for details."
                              >
                                slowed ×{scan.telemetry!.throttle_count}
                              </div>
                            )}
                          </TableCell>
                          <TableCell className="font-mono text-xs whitespace-nowrap text-muted-foreground">
                            <span title={formatDateTime(scan.started_at)}>{formatShortTime(scan.started_at)}</span>
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center justify-end gap-0.5">
                              {canWriteScans && (
                                <Button
                                  variant="ghost"
                                  size="icon-xs"
                                  aria-label="Edit"
                                  title="Edit name and notes"
                                  onClick={() => {
                                    setEditingScanId(isEditing ? null : scan.id);
                                    setEditScanName(scan.name);
                                    setEditScanNotes(scan.notes || '');
                                  }}
                                >
                                  <RiEditLine />
                                </Button>
                              )}
                              {canRunScans && scan.status === 'RUNNING' && (
                                <Button
                                  variant="ghost"
                                  size="icon-xs"
                                  aria-label="Pause"
                                  title="Pause"
                                  onClick={() => handleScanControl(scan.id, 'pause')}
                                >
                                  <RiPauseLine />
                                </Button>
                              )}
                              {canRunScans && isPaused && (
                                <Button
                                  variant="ghost"
                                  size="icon-xs"
                                  aria-label="Resume"
                                  title="Resume"
                                  onClick={() => handleScanControl(scan.id, 'resume')}
                                >
                                  <RiPlayLine />
                                </Button>
                              )}
                              {canRunScans && isActive && (
                                <Button
                                  variant="ghost"
                                  size="icon-xs"
                                  aria-label="Stop"
                                  title="Stop"
                                  onClick={() => handleScanControl(scan.id, 'stop')}
                                >
                                  <RiStopLine />
                                </Button>
                              )}
                              {canDeleteScans && (
                                <Button
                                  variant="ghost"
                                  size="icon-xs"
                                  aria-label="Delete"
                                  title="Delete run"
                                  className="text-muted-foreground hover:text-destructive"
                                  onClick={() => handleScanControl(scan.id, 'delete')}
                                >
                                  <RiDeleteBinLine />
                                </Button>
                              )}
                            </div>
                          </TableCell>
                        </TableRow>

                        {/* Inline metadata editor (any status) */}
                        {isEditing && canWriteScans && (
                          <TableRow
                            className={cn('bg-muted/30 hover:bg-muted/30', isExpanded && 'border-b-0')}
                          >
                            <TableCell colSpan={11} className="whitespace-normal">
                              <div className="flex flex-col items-end gap-4 px-5.5 pb-2 sm:flex-row">
                                <Field label="Name" className="w-full sm:flex-1">
                                  <Input
                                    value={editScanName}
                                    onChange={(e) => setEditScanName(e.target.value)}
                                  />
                                </Field>
                                <Field label="Notes" className="w-full sm:flex-[2]">
                                  <Input
                                    value={editScanNotes}
                                    onChange={(e) => setEditScanNotes(e.target.value)}
                                  />
                                </Field>
                                <div className="flex shrink-0 gap-2">
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => setEditingScanId(null)}
                                  >
                                    Cancel
                                  </Button>
                                  <Button size="sm" onClick={() => handleSaveScanMeta(scan.id)}>
                                    <RiSaveLine data-icon="inline-start" /> Save
                                  </Button>
                                </div>
                              </div>
                            </TableCell>
                          </TableRow>
                        )}

                        {/* Coverage Ledger chunk grid */}
                        {isExpanded && (
                          <TableRow className="bg-muted/30 hover:bg-muted/30">
                            <TableCell colSpan={11} className="whitespace-normal">
                              <div className="space-y-3 px-5.5 pb-2">
                                <SectionTitle>Coverage Ledger · {chunks.length}</SectionTitle>

                                {chunks.length === 0 ? (
                                  <Empty className="py-4">No chunks</Empty>
                                ) : (
                                  <ChunkMatrix
                                    chunks={chunks.map((raw) => {
                                      const lc =
                                        (raw.id && liveChunks[raw.id]) ||
                                        (liveScan?.scan_run_id === scan.id
                                          ? liveChunks[`#${raw.chunk_index}`]
                                          : undefined);
                                      const ch: ScanChunk = lc
                                        ? {
                                            ...raw,
                                            status: lc.status || raw.status,
                                            active_hosts: lc.active_hosts ?? raw.active_hosts,
                                            services_found: lc.services ?? raw.services_found,
                                          }
                                        : raw;
                                      return ch;
                                    })}
                                    throttles={(scanDetail?.id === scan.id ? scanDetail.telemetry : scan.telemetry)?.throttles}
                                  />
                                )}
                                <RateControlPanel
                                  scan={scanDetail?.id === scan.id ? scanDetail : scan}
                                  chunks={chunks}
                                />
                                <NmapCommandsPanel scan={scanDetail ?? scan} chunks={chunks} />
                              </div>
                            </TableCell>
                          </TableRow>
                        )}
                      </React.Fragment>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </Card>
        </TabsContent>

        {/* ───────────── PROFILES ───────────── */}
        <TabsContent value="profiles" className="pt-4">
          <div className="grid grid-cols-1 gap-6 2xl:grid-cols-12">
            <Card size="sm" className={cn('py-0', canWriteScans ? '2xl:col-span-7' : '2xl:col-span-12')}>
              {loading ? (
                <PeckLoader />
              ) : profiles.length === 0 ? (
                <Empty>No profiles yet</Empty>
              ) : (
                <Table className="table-fixed">
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[34%]">Profile</TableHead>
                      <TableHead className="w-[30%]">Ports and intensity</TableHead>
                      <TableHead>Schedule</TableHead>
                      <TableHead className="w-36 text-right" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {profiles.map((p) => {
                      const agent = agents.find((a) => a.id === p.agent_id);
                      return (
                        <TableRow key={p.id} className={cn(editingProfileId === p.id && 'bg-muted/40')}>
                          <TableCell className="whitespace-normal">
                            <div className="flex min-w-0 flex-wrap items-center gap-1.5">
                              <span className="truncate text-sm font-medium" title={p.name}>
                                {p.name}
                              </span>
                              {p.agent_id && (
                                <Pill
                                  tone={agent?.status === 'online' ? 'violet' : 'warning'}
                                  title="Scanned by a remote agent"
                                >
                                  agent: {agent?.name ?? 'deleted'}
                                </Pill>
                              )}
                              {p.window_enabled && (
                                <Pill tone="neutral" title="Scans only inside this daily time window">
                                  <RiTimeLine className="size-3" />
                                  {p.window_start} to {p.window_end}
                                </Pill>
                              )}
                            </div>
                            <div
                              className="mt-1 truncate font-mono text-[11px] text-muted-foreground"
                              title={(p.targets || []).join(', ')}
                            >
                              {(p.targets || []).join(', ') || 'global scope'}
                            </div>
                          </TableCell>
                          <TableCell className="whitespace-normal">
                            <PortChips ports={p.allowed_ports} />
                            <div className="mt-1 text-[11px] text-muted-foreground">
                              {formatNumber(p.max_rate_pps)} PPS · HTTP {p.http_rps} req/s per host
                            </div>
                            <div className="text-[11px] text-muted-foreground">
                              missing after {p.missing_threshold} scan{p.missing_threshold === 1 ? '' : 's'} /{' '}
                              {p.grace_period_hours} h grace
                            </div>
                          </TableCell>
                          <TableCell className="whitespace-normal font-mono text-[11px] text-muted-foreground">
                            <ScheduleCell schedule={p.schedule} cron={p.schedule_cron} />
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center justify-end gap-1 whitespace-nowrap">
                              {canRunScans && (
                                <Button variant="outline" size="xs" onClick={() => handleStartProfileScan(p)}>
                                  <RiPlayLine data-icon="inline-start" />
                                  Run
                                </Button>
                              )}
                              {canWriteScans && (
                                <Button
                                  variant="ghost"
                                  size="icon-xs"
                                  aria-label="Edit profile"
                                  title="Edit profile"
                                  onClick={() => startEditProfile(p)}
                                >
                                  <RiEditLine />
                                </Button>
                              )}
                              {canDeleteScans && (
                                <Button
                                  variant="ghost"
                                  size="icon-xs"
                                  aria-label="Delete profile"
                                  title="Delete profile"
                                  className="text-muted-foreground hover:text-destructive"
                                  onClick={async () => {
                                    if (!window.confirm(`Delete profile "${p.name}"?`)) return;
                                    await api.deleteProfile(p.id);
                                    toast.success('Profile deleted');
                                    if (editingProfileId === p.id) resetProfileForm();
                                    loadAll();
                                  }}
                                >
                                  <RiDeleteBinLine />
                                </Button>
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              )}
            </Card>

            {canWriteScans && (
              <Card size="sm" className="2xl:col-span-5" ref={profileFormRef}>
                <form onSubmit={handleSaveProfile} className="flex flex-col gap-5">
                  <CardHeader>
                    <CardTitle className="text-sm">
                      {editingProfileId ? `Edit profile: ${profileForm.name || 'unnamed'}` : 'New profile'}
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="grid grid-cols-1 gap-5 sm:grid-cols-2">
                    {!editingProfileId && (
                      <Field label="Start from a preset" className="sm:col-span-2">
                        <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                          {PROFILE_PRESETS.map((preset) => {
                            const active =
                              profileForm.allowed_ports === preset.values.allowed_ports &&
                              profileForm.enable_http_fingerprint === preset.values.enable_http_fingerprint;
                            return (
                              <button
                                key={preset.id}
                                type="button"
                                onClick={() => setProfileForm((p) => ({ ...p, ...preset.values }))}
                                className={cn(
                                  'border px-3 py-2 text-left transition-colors hover:bg-muted/50',
                                  active ? 'border-foreground/60 bg-muted/60' : 'border-border'
                                )}
                              >
                                <div className="text-xs font-semibold">{preset.label}</div>
                                <div className="text-[11px] text-muted-foreground">{preset.hint}</div>
                              </button>
                            );
                          })}
                        </div>
                      </Field>
                    )}
                    <Field label="Name" htmlFor="pf-name" className="sm:col-span-2">
                      <Input
                        id="pf-name"
                        required
                        value={profileForm.name}
                        onChange={(e) => setProfileForm((p) => ({ ...p, name: e.target.value }))}
                        placeholder="Night scan, faculty networks"
                      />
                    </Field>
                    <Field
                      label="Targets"
                      htmlFor="pf-targets"
                      className="sm:col-span-2"
                      hint="IPs, CIDRs, ranges (a-b) or domains, one per line or comma separated."
                    >
                      <Textarea
                        id="pf-targets"
                        rows={2}
                        required
                        value={profileForm.targetsText}
                        placeholder="10.66.0.0/22"
                        onChange={(e) => setProfileForm((p) => ({ ...p, targetsText: e.target.value }))}
                        className="font-mono text-xs"
                      />
                    </Field>
                    <Field
                      label="Scanner"
                      htmlFor="pf-agent"
                      className="sm:col-span-2"
                      hint="A remote agent scans from inside its own network; results go through the same pipeline."
                    >
                      <SimpleSelect
                        id="pf-agent"
                        value={profileForm.agent_id}
                        onValueChange={(v) => setProfileForm((p) => ({ ...p, agent_id: v || LOCAL_AGENT }))}
                        options={[
                          { value: LOCAL_AGENT, label: 'This server' },
                          ...agents
                            .filter((a) => !a.disabled)
                            .map((a) => ({
                              value: a.id,
                              label: `Agent ${a.name}${a.site ? ` (${a.site})` : ''} · ${a.status}`,
                            })),
                        ]}
                      />
                    </Field>
                    <Field label="Ports" htmlFor="pf-ports" className="sm:col-span-2" hint="Comma-separated TCP ports.">
                      <Input
                        id="pf-ports"
                        value={profileForm.allowed_ports}
                        onChange={(e) => setProfileForm((p) => ({ ...p, allowed_ports: e.target.value }))}
                        className="font-mono"
                      />
                    </Field>

                    <div className="sm:col-span-2">
                      <SectionTitle>Intensity</SectionTitle>
                    </div>
                    <Field label="Max packets/s (whole scan)" htmlFor="pf-pps" hint="Split across nmap workers.">
                      <Input
                        id="pf-pps"
                        type="number"
                        min={1}
                        value={profileForm.max_rate_pps}
                        onChange={(e) => setProfileForm((p) => ({ ...p, max_rate_pps: Number(e.target.value) }))}
                        className="font-mono"
                      />
                    </Field>
                    <Field label="HTTP requests/s per host" htmlFor="pf-rps">
                      <Input
                        id="pf-rps"
                        type="number"
                        min={1}
                        value={profileForm.http_rps}
                        onChange={(e) => setProfileForm((p) => ({ ...p, http_rps: Number(e.target.value) }))}
                        className="font-mono"
                      />
                    </Field>
                    <Field label="Concurrency (max workers)" htmlFor="pf-conc">
                      <Input
                        id="pf-conc"
                        type="number"
                        min={1}
                        value={profileForm.concurrency}
                        onChange={(e) => setProfileForm((p) => ({ ...p, concurrency: Number(e.target.value) }))}
                        className="font-mono"
                      />
                    </Field>
                    <Field label="Chunk size (target seconds)" htmlFor="pf-chunk" hint="Checkpoint granularity.">
                      <Input
                        id="pf-chunk"
                        type="number"
                        min={5}
                        value={profileForm.chunk_target_sec}
                        onChange={(e) => setProfileForm((p) => ({ ...p, chunk_target_sec: Number(e.target.value) }))}
                        className="font-mono"
                      />
                    </Field>
                    <Field
                      label="Re-probe retries"
                      htmlFor="pf-retry"
                      hint="Extra ping sweeps for known hosts that did not answer."
                    >
                      <Input
                        id="pf-retry"
                        type="number"
                        min={0}
                        max={5}
                        value={profileForm.retry_unstable_count}
                        onChange={(e) =>
                          setProfileForm((p) => ({ ...p, retry_unstable_count: Number(e.target.value) }))
                        }
                        className="font-mono"
                      />
                    </Field>
                    <div className="flex items-center gap-3 self-end pb-2">
                      <Switch
                        id="http_fp"
                        checked={profileForm.enable_http_fingerprint}
                        onCheckedChange={(checked) => setProfileForm((p) => ({ ...p, enable_http_fingerprint: checked }))}
                      />
                      <Label htmlFor="http_fp" className="text-xs">
                        HTTP/TLS fingerprint + safe paths
                      </Label>
                    </div>
                    <p className="text-[11px] text-muted-foreground sm:col-span-2">
                      Automatic backoff is always on: bursts of timeouts, HTTP 429/503 or TCP resets halve the rate
                      (only for the affected host when a single host misbehaves) and it recovers after a quiet period.
                      nmap timing, host timeout and retries are derived from the packet rate. Every slowdown is kept on
                      the run.
                    </p>

                    <div className="sm:col-span-2">
                      <SectionTitle>Schedule</SectionTitle>
                    </div>
                    <Field label="Cron (5 fields)" htmlFor="pf-cron" className="sm:col-span-2" hint={describeCron(profileForm.schedule_cron)}>
                      <Input
                        id="pf-cron"
                        value={profileForm.schedule_cron}
                        placeholder="e.g. 0 22 * * * (empty = manual only)"
                        onChange={(e) => setProfileForm((p) => ({ ...p, schedule_cron: e.target.value }))}
                        className="font-mono"
                      />
                    </Field>
                    <div className="flex items-center gap-3 sm:col-span-2">
                      <Switch
                        id="win_en"
                        checked={profileForm.window_enabled}
                        onCheckedChange={(checked) => setProfileForm((p) => ({ ...p, window_enabled: checked }))}
                      />
                      <Label htmlFor="win_en" className="text-xs">
                        Daily time window (pause outside, resume inside)
                      </Label>
                    </div>
                    {profileForm.window_enabled && (
                      <>
                        <Field label="From (HH:MM)" htmlFor="pf-ws">
                          <Input
                            id="pf-ws"
                            value={profileForm.window_start}
                            onChange={(e) => setProfileForm((p) => ({ ...p, window_start: e.target.value }))}
                            className="font-mono"
                          />
                        </Field>
                        <Field label="To (HH:MM)" htmlFor="pf-we">
                          <Input
                            id="pf-we"
                            value={profileForm.window_end}
                            onChange={(e) => setProfileForm((p) => ({ ...p, window_end: e.target.value }))}
                            className="font-mono"
                          />
                        </Field>
                        <Field label="Time zone" htmlFor="pf-tz" className="sm:col-span-2">
                          <Input
                            id="pf-tz"
                            value={profileForm.timezone}
                            onChange={(e) => setProfileForm((p) => ({ ...p, timezone: e.target.value }))}
                            className="font-mono"
                          />
                        </Field>
                      </>
                    )}
                    <div className="sm:col-span-2">
                      <WindowBar
                        enabled={profileForm.window_enabled}
                        start={profileForm.window_start}
                        end={profileForm.window_end}
                      />
                    </div>

                    <div className="sm:col-span-2">
                      <SectionTitle>Host lifecycle</SectionTitle>
                    </div>
                    <Field label="Missing after N scans" htmlFor="pf-miss">
                      <Input
                        id="pf-miss"
                        type="number"
                        min={1}
                        value={profileForm.missing_threshold}
                        onChange={(e) => setProfileForm((p) => ({ ...p, missing_threshold: Number(e.target.value) }))}
                        className="font-mono"
                      />
                    </Field>
                    <Field label="Grace period (hours)" htmlFor="pf-grace">
                      <Input
                        id="pf-grace"
                        type="number"
                        min={0}
                        value={profileForm.grace_period_hours}
                        onChange={(e) => setProfileForm((p) => ({ ...p, grace_period_hours: Number(e.target.value) }))}
                        className="font-mono"
                      />
                    </Field>
                    <p className="text-[11px] text-muted-foreground sm:col-span-2">
                      A host is reported gone only after it missed {profileForm.missing_threshold} scan
                      {profileForm.missing_threshold === 1 ? '' : 's'} in a row and {profileForm.grace_period_hours} h
                      passed since it last answered.
                    </p>

                    <div className="sm:col-span-2">
                      <SectionTitle className="mb-2">Exclusions</SectionTitle>
                      {exclusions.length === 0 ? (
                        <p className="text-[11px] text-muted-foreground">
                          No exclusions. Add never-scan ranges in the Scope tab; they apply to every profile.
                        </p>
                      ) : (
                        <div className="space-y-1">
                          <div className="flex flex-wrap gap-1">
                            {exclusions.map((ex) => (
                              <span
                                key={ex.id}
                                className="border border-border bg-muted px-1 font-mono text-[10px]"
                                title={ex.reason}
                              >
                                {ex.value}
                              </span>
                            ))}
                          </div>
                          <p className="text-[11px] text-muted-foreground">
                            Never scanned by any profile (manage them in the Scope tab).
                          </p>
                        </div>
                      )}
                    </div>
                  </CardContent>
                  <CardFooter className="justify-end gap-2">
                    {editingProfileId && (
                      <Button type="button" variant="ghost" size="sm" onClick={resetProfileForm}>
                        Cancel
                      </Button>
                    )}
                    <Button type="submit" size="sm">
                      <RiSaveLine data-icon="inline-start" /> {editingProfileId ? 'Save changes' : 'Create profile'}
                    </Button>
                  </CardFooter>
                </form>
              </Card>
            )}
          </div>
        </TabsContent>

        {/* ───────────── SCOPES: targets, exclusions, estimator ───────────── */}
        <TabsContent value="scopes" className="space-y-6 pt-4">
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Targets */}
            <Card size="sm">
              <CardHeader>
                <CardTitle className="text-sm">Targets · {targets.length}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {canWriteScans && (
                  <form onSubmit={handleAddTarget} className="flex items-end gap-3">
                    <Input
                      value={newTarget}
                      onChange={(e) => setNewTarget(e.target.value)}
                      placeholder="10.66.0.0/24 or agh.edu.pl"
                      aria-label="Target"
                      className="flex-1 font-mono"
                    />
                    <Input
                      value={newTargetLabel}
                      onChange={(e) => setNewTargetLabel(e.target.value)}
                      placeholder="Label"
                      aria-label="Label"
                      className="w-32"
                    />
                    <Button type="submit" size="sm" variant="outline">
                      <RiAddLine data-icon="inline-start" /> Add
                    </Button>
                  </form>
                )}
                {targets.length === 0 ? (
                  <Empty className="py-6">No targets</Empty>
                ) : (
                  <div className="max-h-64 divide-y divide-border overflow-y-auto border-y border-border">
                    {targets.map((t) => (
                      <div key={t.id} className="flex items-center justify-between gap-2 py-2 text-xs">
                        <div className="min-w-0 truncate">
                          <span className="font-mono font-medium">{t.value}</span>
                          {t.label && <span className="ml-2 text-muted-foreground">{t.label}</span>}
                        </div>
                        {canDeleteScans && (
                          <Button
                            variant="ghost"
                            size="icon-xs"
                            aria-label="Delete target"
                            className="text-muted-foreground hover:text-destructive"
                            onClick={async () => {
                              await api.deleteTarget(t.id);
                              loadAll();
                            }}
                          >
                            <RiDeleteBinLine />
                          </Button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Exclusions */}
            <Card size="sm">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-sm">
                  <RiForbidLine className="size-4 text-destructive" />
                  Exclusions · {exclusions.length}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {canWriteScans && (
                  <form onSubmit={handleAddExclusion} className="flex items-end gap-3">
                    <Input
                      value={newExclusion}
                      onChange={(e) => setNewExclusion(e.target.value)}
                      placeholder="10.0.0.1/32"
                      aria-label="Exclusion"
                      className="flex-1 font-mono"
                    />
                    <Input
                      value={newExclusionReason}
                      onChange={(e) => setNewExclusionReason(e.target.value)}
                      placeholder="Reason"
                      aria-label="Reason"
                      className="w-40"
                    />
                    <Button type="submit" size="sm" variant="outline">
                      <RiForbidLine data-icon="inline-start" /> Exclude
                    </Button>
                  </form>
                )}
                {exclusions.length === 0 ? (
                  <Empty className="py-6">No exclusions</Empty>
                ) : (
                  <div className="max-h-64 divide-y divide-border overflow-y-auto border-y border-border">
                    {exclusions.map((ex) => (
                      <div key={ex.id} className="flex items-center justify-between gap-2 py-2 text-xs">
                        <div className="flex min-w-0 items-center gap-2">
                          <Pill tone="neutral" className="font-mono">{ex.value}</Pill>
                          {ex.reason && (
                            <span className="truncate text-muted-foreground">{ex.reason}</span>
                          )}
                        </div>
                        {canDeleteScans && (
                          <Button
                            variant="ghost"
                            size="icon-xs"
                            aria-label="Delete exclusion"
                            className="text-muted-foreground hover:text-destructive"
                            onClick={async () => {
                              await api.deleteExclusion(ex.id);
                              loadAll();
                            }}
                          >
                            <RiDeleteBinLine />
                          </Button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Ownership by CIDR (tag rules applied on ingest) */}
          <TagRulesPanel />

          {/* Estimator */}
          <Card size="sm">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <RiCalculatorLine className="size-4 text-muted-foreground" />
                Scan time estimate
              </CardTitle>
            </CardHeader>
            <CardContent className="grid grid-cols-1 gap-5 lg:grid-cols-12">
              <Field label="Ranges" htmlFor="est-targets" className="lg:col-span-4">
                <Textarea
                  id="est-targets"
                  rows={3}
                  value={estTargets}
                  onChange={(e) => setEstTargets(e.target.value)}
                  className="font-mono text-xs"
                />
              </Field>
              <Field label="Exclusions" htmlFor="est-excl" className="lg:col-span-3">
                <Textarea
                  id="est-excl"
                  rows={3}
                  value={estExclusions}
                  onChange={(e) => setEstExclusions(e.target.value)}
                  className="font-mono text-xs"
                />
              </Field>
              <div className="grid grid-cols-2 gap-5 sm:grid-cols-3 lg:col-span-5">
                <Field label="Ports" htmlFor="est-ports" className="col-span-2 sm:col-span-3">
                  <Input
                    id="est-ports"
                    value={estPorts}
                    onChange={(e) => setEstPorts(e.target.value)}
                    className="font-mono"
                  />
                </Field>
                <Field label="Max PPS" htmlFor="est-pps">
                  <Input
                    id="est-pps"
                    type="number"
                    value={estRate}
                    onChange={(e) => setEstRate(Number(e.target.value))}
                    className="font-mono"
                  />
                </Field>
                <Field label="Window from" htmlFor="est-ws">
                  <Input
                    id="est-ws"
                    value={estWindowStart}
                    onChange={(e) => setEstWindowStart(e.target.value)}
                    className="font-mono"
                  />
                </Field>
                <Field label="Window to" htmlFor="est-we">
                  <Input
                    id="est-we"
                    value={estWindowEnd}
                    onChange={(e) => setEstWindowEnd(e.target.value)}
                    className="font-mono"
                  />
                </Field>
              </div>
            </CardContent>
            <CardFooter className="justify-end">
              <Button size="sm" variant="outline" disabled={estimating} onClick={handleEstimate}>
                <RiCalculatorLine data-icon="inline-start" />
                {estimating ? 'Estimating…' : 'Estimate'}
              </Button>
            </CardFooter>
          </Card>

          {estimate && (
            <StatStrip>
              <Stat label="All IPs" value={formatNumber(estimate.total_ips)} />
              <Stat label="Excluded" value={formatNumber(estimate.excluded_ips)} />
              <Stat label="To scan" value={formatNumber(estimate.effective_ips)} />
              <Stat
                label="Chunk size / count"
                value={`${estimate.recommended_chunk_size} / ${estimate.chunk_count}`}
              />
              <Stat label="ETA" value={formatDurationSeconds(estimate.estimated_seconds)} />
              <Stat
                label="Time window"
                tone={estimate.fits_in_window ? 'success' : 'warning'}
                value={
                  <span className="text-sm">
                    {estimate.fits_in_window
                      ? 'Fits in one window'
                      : `Pauses and resumes over ${estimate.estimated_windows || 2} windows`}
                  </span>
                }
              />
            </StatStrip>
          )}
        </TabsContent>

        {/* ───────────── IMPORT / EXPORT ───────────── */}
        <TabsContent value="ingest" className="pt-4">
          <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
            {/* Manual form */}
            <Card size="sm" className="xl:col-span-7">
              <form onSubmit={handleManualSubmit} className="flex flex-col gap-5">
                <CardHeader>
                  <CardTitle className="text-sm">Manual entry</CardTitle>
                </CardHeader>
                {!canImport ? (
                  <CardContent>
                    <Notice tone="warning">
                      Requires the <Code>import:write</Code> permission
                    </Notice>
                  </CardContent>
                ) : (
                  <>
                    <CardContent className="grid grid-cols-1 gap-5 sm:grid-cols-3">
                      <Field label="Run name" htmlFor="m-name" className="sm:col-span-2">
                        <Input
                          id="m-name"
                          value={manualForm.scan_name}
                          onChange={(e) => setManualForm((m) => ({ ...m, scan_name: e.target.value }))}
                        />
                      </Field>
                      <Field label="Environment">
                        <SimpleSelect
                          value={manualForm.environment}
                          onValueChange={(v) => setManualForm((m) => ({ ...m, environment: v }))}
                          options={['prod', 'staging', 'dev', 'test'].map((v) => ({
                            value: v,
                            label: v,
                          }))}
                        />
                      </Field>
                      <Field label="IP *" htmlFor="m-ip">
                        <Input
                          id="m-ip"
                          required
                          value={manualForm.ip}
                          onChange={(e) => setManualForm((m) => ({ ...m, ip: e.target.value }))}
                          placeholder="172.28.0.55"
                          className="font-mono"
                        />
                      </Field>
                      <Field label="Hostname" htmlFor="m-host">
                        <Input
                          id="m-host"
                          value={manualForm.hostname}
                          onChange={(e) => setManualForm((m) => ({ ...m, hostname: e.target.value }))}
                          placeholder="admin-dev.agh.edu.pl"
                          className="font-mono"
                        />
                      </Field>
                      <Field label="Tags" htmlFor="m-tags">
                        <Input
                          id="m-tags"
                          value={manualForm.tags}
                          onChange={(e) => setManualForm((m) => ({ ...m, tags: e.target.value }))}
                        />
                      </Field>
                      <Field label="Port" htmlFor="m-port">
                        <Input
                          id="m-port"
                          type="number"
                          value={manualForm.port}
                          onChange={(e) =>
                            setManualForm((m) => ({ ...m, port: Number(e.target.value) }))
                          }
                          className="font-mono"
                        />
                      </Field>
                      <Field label="Product" htmlFor="m-product">
                        <Input
                          id="m-product"
                          value={manualForm.product}
                          onChange={(e) => setManualForm((m) => ({ ...m, product: e.target.value }))}
                        />
                      </Field>
                      <Field label="Version" htmlFor="m-version">
                        <Input
                          id="m-version"
                          value={manualForm.version}
                          onChange={(e) => setManualForm((m) => ({ ...m, version: e.target.value }))}
                          className="font-mono"
                        />
                      </Field>
                      <Field label="HTTP title" htmlFor="m-title" className="sm:col-span-2">
                        <Input
                          id="m-title"
                          value={manualForm.http_title}
                          onChange={(e) => setManualForm((m) => ({ ...m, http_title: e.target.value }))}
                          placeholder="Staging Admin Console"
                        />
                      </Field>
                      <Field label="HTTP status" htmlFor="m-code">
                        <Input
                          id="m-code"
                          type="number"
                          value={manualForm.status_code}
                          onChange={(e) =>
                            setManualForm((m) => ({ ...m, status_code: Number(e.target.value) }))
                          }
                          className="font-mono"
                        />
                      </Field>
                      <Field label="Headers" htmlFor="m-headers" className="sm:col-span-3">
                        <Textarea
                          id="m-headers"
                          rows={2}
                          value={manualForm.headers_text}
                          onChange={(e) =>
                            setManualForm((m) => ({ ...m, headers_text: e.target.value }))
                          }
                          className="font-mono text-xs"
                        />
                      </Field>
                      <Field label="Set-Cookie" htmlFor="m-cookies" className="sm:col-span-3">
                        <Input
                          id="m-cookies"
                          value={manualForm.cookies_text}
                          onChange={(e) =>
                            setManualForm((m) => ({ ...m, cookies_text: e.target.value }))
                          }
                          className="font-mono"
                        />
                      </Field>
                      <Field label="Notes" htmlFor="m-notes" className="sm:col-span-3">
                        <Input
                          id="m-notes"
                          value={manualForm.notes}
                          onChange={(e) => setManualForm((m) => ({ ...m, notes: e.target.value }))}
                        />
                      </Field>
                    </CardContent>
                    <CardFooter className="justify-end">
                      <Button type="submit" size="sm" variant="outline" disabled={submittingManual}>
                        <RiCheckLine data-icon="inline-start" />
                        {submittingManual ? 'Saving…' : 'Add host'}
                      </Button>
                    </CardFooter>
                  </>
                )}
              </form>
            </Card>

            <div className="space-y-6 xl:col-span-5">
              {/* File import */}
              <Card size="sm">
                <form onSubmit={handleImportSubmit} className="flex flex-col gap-5">
                  <CardHeader>
                    <CardTitle className="text-sm">Import a file</CardTitle>
                  </CardHeader>
                  {!canImport ? (
                    <CardContent>
                      <Notice tone="warning">
                        Requires the <Code>import:write</Code> permission
                      </Notice>
                    </CardContent>
                  ) : (
                    <>
                      <CardContent className="space-y-5">
                        <label
                          onDragOver={(e) => e.preventDefault()}
                          onDrop={(e) => {
                            e.preventDefault();
                            handleFileChange(e.dataTransfer.files?.[0] || null);
                          }}
                          className="flex cursor-pointer flex-col items-center gap-2 border border-dashed border-border px-4 py-6 text-center transition-colors hover:bg-muted/50"
                        >
                          <RiUploadCloud2Line className="size-5 text-muted-foreground" />
                          <span className="text-xs text-muted-foreground">
                            {importFile ? importFile.name : 'Drop a .csv / .json / nmap .xml (-oX) file'}
                          </span>
                          <input
                            type="file"
                            accept=".csv,.json,.xml,text/csv,application/json,application/xml,text/xml"
                            onChange={(e) => handleFileChange(e.target.files?.[0] || null)}
                            className="text-xs text-muted-foreground file:mr-2 file:border file:border-border file:bg-transparent file:px-3 file:py-1 file:text-[10px] file:font-semibold file:tracking-widest file:text-foreground file:uppercase hover:file:bg-muted"
                          />
                        </label>

                        <div className="grid grid-cols-2 gap-5">
                          <Field label="Format">
                            <SimpleSelect
                              value={importFormat}
                              onValueChange={(v) => setImportFormat(v as 'csv' | 'json' | 'nmap' | 'scb')}
                              options={[
                                { value: 'csv', label: 'CSV' },
                                { value: 'json', label: 'JSON' },
                                { value: 'nmap', label: 'nmap XML (-oX)' },
                                { value: 'scb', label: 'secureCodeBox findings.json' },
                              ]}
                            />
                          </Field>
                          <Field label="Import name" htmlFor="imp-name">
                            <Input
                              id="imp-name"
                              value={importScanName}
                              onChange={(e) => setImportScanName(e.target.value)}
                              placeholder="optional"
                            />
                          </Field>
                        </div>

                        {importPreview && (
                          <div className="border border-border bg-muted/40 p-3">
                            <div className="mb-1.5 text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
                              Preview · {importFile?.name}
                            </div>
                            <pre className="max-h-36 overflow-auto font-mono text-[11px] text-foreground">
                              {importPreview}
                            </pre>
                          </div>
                        )}
                      </CardContent>
                      <CardFooter className="justify-end">
                        <Button type="submit" size="sm" disabled={!importFile || importing}>
                          <RiFileUploadLine data-icon="inline-start" />
                          {importing ? 'Importing…' : 'Import'}
                        </Button>
                      </CardFooter>
                    </>
                  )}
                </form>
              </Card>

              {/* Export */}
              <Card size="sm">
                <CardHeader>
                  <CardTitle className="text-sm">Export</CardTitle>
                </CardHeader>
                <CardContent className="grid grid-cols-1 gap-5 sm:grid-cols-3">
                  <Field label="Run">
                    <SimpleSelect
                      value={exportScanId || ALL}
                      onValueChange={(v) => setExportScanId(v === ALL ? '' : v)}
                      options={[
                        { value: ALL, label: 'All runs' },
                        ...scans.map((s) => ({ value: s.id, label: s.name })),
                      ]}
                    />
                  </Field>
                  <Field label="State">
                    <SimpleSelect
                      value={exportState || ALL}
                      onValueChange={(v) => setExportState(v === ALL ? '' : v)}
                      options={[
                        { value: ALL, label: 'All states' },
                        { value: 'ACTIVE', label: 'ACTIVE' },
                        { value: 'INTERMITTENT', label: 'INTERMITTENT' },
                        { value: 'MISSING', label: 'MISSING' },
                      ]}
                    />
                  </Field>
                  <Field label="Tag" htmlFor="exp-tag">
                    <Input
                      id="exp-tag"
                      value={exportTag}
                      onChange={(e) => setExportTag(e.target.value)}
                      placeholder="any"
                    />
                  </Field>
                </CardContent>
                <CardFooter className="flex-wrap justify-end gap-2">
                  {canExport ? (
                    <>
                      <Button variant="outline" size="sm" onClick={() => runExport('csv')}>
                        <RiDownload2Line data-icon="inline-start" /> CSV
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => runExport('json')}>
                        <RiDownload2Line data-icon="inline-start" /> JSON
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        title="nmap XML (-oX): DefectDojo, Metasploit db_import"
                        onClick={() => runExport('nmap')}
                      >
                        <RiDownload2Line data-icon="inline-start" /> nmap XML
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        title="One URL per line: httpx, nuclei, gowitness"
                        onClick={() => runExport('urls')}
                      >
                        <RiDownload2Line data-icon="inline-start" /> URLs
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        title="NDJSON in Elastic Common Schema: ELK / Splunk"
                        onClick={() => runExport('ecs')}
                      >
                        <RiDownload2Line data-icon="inline-start" /> ECS (ELK)
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        title="OWASP secureCodeBox findings.json (Host / Open Port + TLS/SSH)"
                        onClick={() => runExport('scb')}
                      >
                        <RiDownload2Line data-icon="inline-start" /> secureCodeBox
                      </Button>
                    </>
                  ) : (
                    <Notice tone="neutral" className="w-full">
                      Requires the <Code>export:read</Code> permission
                    </Notice>
                  )}
                </CardFooter>
              </Card>
            </div>
          </div>
        </TabsContent>
        {/* REMOTE AGENTS */}
        <TabsContent value="agents" className="pt-4">
          <AgentsPanel canManage={can(PERMISSIONS.ADMIN_SETTINGS)} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

/** Recurring schedule summary: when it runs (in words), next run (window-adjusted), last run. */
function ScheduleCell({ schedule, cron }: { schedule?: ProfileSchedule; cron?: string }) {
  const expr = schedule?.cron || cron || '';
  if (!expr) return <span>manual only</span>;
  if (schedule?.cron_error) {
    return <span className="text-rose-500">invalid cron: {schedule.cron_error}</span>;
  }
  return (
    <div className="space-y-0.5">
      <div className="text-foreground" title={expr}>
        {describeCron(expr)}
      </div>
      {schedule?.next_run_at && (
        <div>
          next: {formatDateTime(schedule.next_run_at)}
          {schedule.deferred_by_window && (
            <Pill tone="warning" className="ml-1">
              when the window opens
            </Pill>
          )}
          {schedule.pending_catch_up && (
            <Pill tone="violet" className="ml-1">
              catch-up
            </Pill>
          )}
        </div>
      )}
      {schedule?.active_run && (
        <div className="text-amber-600 dark:text-amber-300">
          running ({schedule.active_run.status}); the next slot will be skipped
        </div>
      )}
      {schedule?.last_run && (
        <div>
          last: {formatDateTime(schedule.last_run.started_at)} · {schedule.last_run.status}
        </div>
      )}
      {schedule?.last_skip_reason && (
        <div className="truncate" title={schedule.last_skip_reason}>
          skipped: {schedule.last_skip_reason}
        </div>
      )}
    </div>
  );
}

function runTypeLabel(t: string): string {
  switch (t) {
    case 'ACTIVE':
      return 'active scan';
    case 'MANUAL':
      return 'manual entry';
    case 'IMPORT_CSV':
      return 'CSV import';
    case 'IMPORT_JSON':
      return 'JSON import';
    case 'IMPORT_NMAP':
      return 'nmap XML import';
    case 'PASSIVE':
      return 'passive import';
    default:
      return t.toLowerCase().replace(/_/g, ' ');
  }
}

const WEEKDAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

function pad2(n: number) {
  return String(n).padStart(2, '0');
}

/** Plain-English summary of common 5-field cron expressions ("every day at 22:00"). */
export function describeCron(expr: string): string {
  const parts = expr.trim().split(/\s+/);
  if (parts.length !== 5) return expr ? `custom: ${expr}` : 'manual only';
  const [min, hour, dom, mon, dow] = parts;
  const isNum = (v: string) => /^\d+$/.test(v);
  const at = isNum(min) && isNum(hour) ? `${pad2(Number(hour))}:${pad2(Number(min))}` : '';
  if (min.startsWith('*/') && hour === '*' && dom === '*' && mon === '*' && dow === '*') {
    return `every ${min.slice(2)} minutes`;
  }
  if (isNum(min) && hour === '*' && dom === '*' && mon === '*' && dow === '*') {
    return `every hour at minute ${Number(min)}`;
  }
  if (isNum(min) && hour.startsWith('*/') && dom === '*' && mon === '*' && dow === '*') {
    return `every ${hour.slice(2)} hours (minute ${Number(min)})`;
  }
  if (at && dom === '*' && mon === '*') {
    if (dow === '*') return `every day at ${at}`;
    if (dow === '1-5') return `weekdays at ${at}`;
    if (dow === '0,6' || dow === '6,0') return `weekends at ${at}`;
    const days = dow.split(',');
    if (days.every((d) => /^[0-7]$/.test(d))) {
      return `every ${days.map((d) => WEEKDAYS[Number(d) % 7]).join(', ')} at ${at}`;
    }
  }
  if (at && isNum(dom) && mon === '*' && dow === '*') return `monthly on day ${Number(dom)} at ${at}`;
  return `custom: ${expr}`;
}

function parseHHMM(v: string): number | null {
  const m = /^(\d{1,2}):(\d{2})$/.exec(v.trim());
  if (!m) return null;
  const h = Number(m[1]);
  const mi = Number(m[2]);
  if (h > 23 || mi > 59) return null;
  return h * 60 + mi;
}

/** 24-hour bar with the allowed scan window highlighted (handles windows over midnight). */
function WindowBar({ start, end, enabled }: { start: string; end: string; enabled: boolean }) {
  const s = parseHHMM(start);
  const e = parseHHMM(end);
  const valid = s !== null && e !== null && s !== e;
  const inWindow = (minute: number) => {
    if (!enabled) return true;
    if (!valid) return false;
    return s! < e! ? minute >= s! && minute < e! : minute >= s! || minute < e!;
  };
  const hours = s !== null && e !== null ? ((e - s + 1440) % 1440) / 60 : 0;
  return (
    <div className="space-y-1">
      <div className="flex h-3 w-full overflow-hidden border border-border">
        {Array.from({ length: 24 }, (_, h) => (
          <div
            key={h}
            className={cn('h-full flex-1 border-r border-background last:border-r-0', inWindow(h * 60 + 30) ? 'bg-emerald-500/70' : 'bg-muted')}
            title={`${pad2(h)}:00`}
          />
        ))}
      </div>
      <div className="flex justify-between font-mono text-[9px] text-muted-foreground">
        <span>00</span>
        <span>06</span>
        <span>12</span>
        <span>18</span>
        <span>24</span>
      </div>
      <p className="text-[11px] text-muted-foreground">
        {!enabled
          ? 'No window: the scan may run at any time of day.'
          : valid
            ? `Scans only ${start} to ${end} (${hours % 1 === 0 ? hours : hours.toFixed(1)} h a day). A run still going when the window closes pauses and resumes from its checkpoint when it opens again.`
            : 'Enter start and end as HH:MM.'}
      </p>
    </div>
  );
}

/** Port list as a few chips plus a "+N more" count, so long lists never push actions off-screen. */
function PortChips({ ports, max = 6 }: { ports: string; max?: number }) {
  const list = ports
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);
  if (list.length === 0) return <span className="text-muted-foreground">all default ports</span>;
  return (
    <div className="flex flex-wrap items-center gap-1" title={list.join(', ')}>
      {list.slice(0, max).map((p) => (
        <span key={p} className="border border-border bg-muted px-1 font-mono text-[10px] tabular-nums">
          {p}
        </span>
      ))}
      {list.length > max && <span className="text-[10px] text-muted-foreground">+{list.length - max} more</span>}
    </div>
  );
}

/** How the run was paced: configured vs effective rates, automatic backoffs, window pauses. */
function RateControlPanel({ scan, chunks }: { scan: ScanRun; chunks: ScanChunk[] }) {
  const t = scan.telemetry;
  const shares = chunks.map((c) => c.max_rate_pps || 0).filter((v) => v > 0);
  const workers = new Set(chunks.map((c) => c.worker).filter(Boolean)).size;
  if (!t && shares.length === 0) return null;
  const events = [
    ...(t?.throttles || []).map((x) => ({ at: x.at, kind: 'throttle' as const, x })),
    ...(t?.window_events || []).map((w) => ({ at: w.at, kind: 'window' as const, w })),
  ].sort((a, b) => a.at.localeCompare(b.at));
  return (
    <div className="space-y-2">
      <SectionTitle>Rate control</SectionTitle>
      <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-4">
        <RateFact label="Configured max">{t?.configured_pps ? `${formatNumber(t.configured_pps)} PPS` : 'n/a'}</RateFact>
        <RateFact label="nmap peak granted">
          {t?.nmap_peak_pps ? `${formatNumber(t.nmap_peak_pps)} PPS` : shares.length ? `${Math.max(...shares)} PPS per worker` : 'n/a'}
        </RateFact>
        <RateFact label="HTTP rate (start / end)">
          {t?.http_initial_rps ? `${t.http_initial_rps.toFixed(0)} / ${(t.http_rate_rps || 0).toFixed(0)} req/s` : t?.configured_http_rps ? `${t.configured_http_rps} req/s per host` : 'n/a'}
        </RateFact>
        <RateFact label="Workers">{workers || 'n/a'}</RateFact>
        <RateFact label="Automatic slowdowns">{t?.throttle_count ?? 0}</RateFact>
        <RateFact label="Timeouts">{formatNumber(t?.timeouts ?? 0)}</RateFact>
        <RateFact label="HTTP 429/503">{formatNumber(t?.http_429 ?? 0)}</RateFact>
        <RateFact label="TCP resets">{formatNumber(t?.rst ?? 0)}</RateFact>
      </div>
      {events.length > 0 ? (
        <ul className="max-h-40 space-y-0.5 overflow-y-auto font-mono text-[11px] text-muted-foreground">
          {events.map((e, i) => (
            <li key={i}>
              <span className="text-foreground/70">{formatDateTime(e.at)}</span>{' '}
              {e.kind === 'throttle' ? (
                <span className="text-amber-700 dark:text-amber-300">
                  slowed down: {throttleReasonLabel(e.x.reason)}
                  {e.x.host ? ` (${e.x.host})` : ''}, {rateChange(e.x.old_rate, e.x.new_rate)}
                </span>
              ) : e.w.kind === 'paused' ? (
                <span>
                  window closed, paused{e.w.next_open ? `; resumes ${formatDateTime(e.w.next_open)}` : ''}
                </span>
              ) : (
                <span>window opened, resumed from checkpoint</span>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-[11px] text-muted-foreground">
          No automatic slowdowns. The governor halves the rate on bursts of timeouts, HTTP 429/503 or TCP resets and
          speeds up again after a quiet period.
        </p>
      )}
    </div>
  );
}

function RateFact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col">
      <span className="text-[10px] tracking-wider text-muted-foreground uppercase">{label}</span>
      <span className="font-mono">{children}</span>
    </div>
  );
}
