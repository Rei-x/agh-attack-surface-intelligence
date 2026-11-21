import React, { useCallback, useEffect, useRef, useState } from 'react';
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
  RiStackLine,
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

type ScansTab = 'runs' | 'profiles' | 'scopes' | 'ingest' | 'agents';

const LOCAL_AGENT = '__local__';

const ALL = '__all__';


/**
 * Scan profile presets (SecureCodeBox-style scan types). They only prefill the form;
 * rate limits stay conservative (shared university network).
 */
const PROFILE_PRESETS = [
  {
    id: 'discovery',
    label: 'Szybki discovery',
    hint: 'Żywe hosty + top porty, bez HTTP',
    values: {
      description: 'Szybki discovery: top porty, bez fingerprintu HTTP',
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
    hint: 'Porty usług + fingerprint HTTP/TLS',
    values: {
      description: 'Standard: typowe usługi sieciowe + fingerprint HTTP/TLS',
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
    label: 'Pełny web',
    hint: 'Porty web + HTTP/TLS + bezpieczne ścieżki',
    values: {
      description: 'Pełny web: porty HTTP(S), fingerprint HTTP/TLS i bezpieczne ścieżki z sygnatur',
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

  // Profile creator
  const [profileForm, setProfileForm] = useState({
    name: '',
    description: '',
    targetsText: '172.28.0.0/24',
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
  });

  // Coverage Ledger selected scan & metadata editor
  const [expandedScanId, setExpandedScanId] = useState<string | null>(null);
  const [scanDetail, setScanDetail] = useState<ScanRun | null>(null);
  const [editingScanId, setEditingScanId] = useState<string | null>(null);
  const [editScanName, setEditScanName] = useState('');
  const [editScanNotes, setEditScanNotes] = useState('');

  // Manual Ingest Form
  const [manualForm, setManualForm] = useState({
    scan_name: 'Wpis ręczny analityka',
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
      toast.error('Błąd ładowania', (err as Error).message);
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
      // background refresh — ignore
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
      toast.error('Błąd estymacji', (err as Error).message);
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
      toast.success('Dodano cel');
      loadAll();
    } catch (err) {
      toast.error('Błąd dodawania celu', (err as Error).message);
    }
  };

  const handleAddExclusion = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newExclusion.trim()) return;
    try {
      await api.createExclusion({
        value: newExclusion.trim(),
        reason: newExclusionReason.trim() || 'Wykluczenie CBI AGH',
      });
      setNewExclusion('');
      setNewExclusionReason('');
      toast.success('Dodano wykluczenie');
      loadAll();
    } catch (err) {
      toast.error('Błąd dodawania wykluczenia', (err as Error).message);
    }
  };

  const handleCreateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!profileForm.name.trim()) return;
    try {
      await api.createProfile({
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
      });
      setProfileForm((p) => ({ ...p, name: '', description: '' }));
      toast.success('Utworzono profil');
      loadAll();
    } catch (err) {
      toast.error('Błąd tworzenia profilu', (err as Error).message);
    }
  };

  const handleStartProfileScan = async (profile: ScanProfile) => {
    try {
      const run = await api.runProfile(profile.id);
      toast.success('Uruchomiono skan', run.name);
      setActiveTab('runs');
      loadAll();
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        toast.error('Profil już ma aktywny przebieg', 'Poczekaj na koniec bieżącego skanu albo go zatrzymaj.');
      } else {
        toast.error('Błąd uruchomienia skanu', (err as Error).message);
      }
    }
  };

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
      toast.error('Błąd Coverage Ledger', (err as Error).message);
    }
  };

  const handleSaveScanMeta = async (scanId: string) => {
    try {
      await api.updateScan(scanId, { name: editScanName, notes: editScanNotes });
      toast.success('Zapisano');
      setEditingScanId(null);
      loadAll();
    } catch (err) {
      toast.error('Błąd zapisu', (err as Error).message);
    }
  };

  const handleScanControl = async (scanId: string, action: 'pause' | 'resume' | 'stop' | 'delete') => {
    try {
      if (action === 'pause') await api.pauseScan(scanId);
      else if (action === 'resume') await api.resumeScan(scanId);
      else if (action === 'stop') await api.stopScan(scanId);
      else if (action === 'delete') {
        if (!window.confirm('Usunąć przebieg skanu?')) return;
        await api.deleteScan(scanId);
      }
      toast.success('Wykonano');
      loadAll();
    } catch (err) {
      toast.error('Błąd akcji', (err as Error).message);
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
        scan_name: manualForm.scan_name || 'Formularz ręczny',
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

      toast.success('Dodano host', manualForm.ip);
      setManualForm((m) => ({ ...m, ip: '', hostname: '', http_title: '', notes: '' }));
      loadAll();
    } catch (err) {
      toast.error('Błąd wpisu ręcznego', (err as Error).message);
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
      toast.success('Zaimportowano', importFile.name);
      setImportFile(null);
      setImportPreview('');
      setImportScanName('');
      loadAll();
    } catch (err) {
      toast.error('Błąd importu', (err as Error).message);
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
      .catch((err) => toast.error('Błąd eksportu', (err as Error).message));

  return (
    <div className="space-y-6">
      <PageHeader
        title="Skaner"
        meta={`${scans.length} przebiegów · ${profiles.length} profili`}
        actions={
          canRunScans && profiles.length > 0 ? (
            <>
              <SimpleSelect
                value={launchProfile?.id ?? ''}
                onValueChange={setLaunchProfileId}
                options={profiles.map((p) => ({ value: p.id, label: p.name }))}
                placeholder="Profil"
                size="sm"
                className="w-56"
              />
              <Button
                size="sm"
                disabled={!launchProfile}
                onClick={() => launchProfile && handleStartProfileScan(launchProfile)}
              >
                <RiPlayLine data-icon="inline-start" />
                Uruchom skan
              </Button>
            </>
          ) : undefined
        }
      />

      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as ScansTab)}>
        <TabsList variant="line">
          <TabsTrigger value="runs">Skany ({scans.length})</TabsTrigger>
          <TabsTrigger value="profiles">Profile ({profiles.length})</TabsTrigger>
          <TabsTrigger value="scopes">Zakresy</TabsTrigger>
          <TabsTrigger value="ingest">Import / Eksport</TabsTrigger>
          <TabsTrigger value="agents">Agenci ({agents.length})</TabsTrigger>
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
                    <TableHead>Nazwa</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="w-40">Chunki</TableHead>
                    <TableHead className="text-right">IP</TableHead>
                    <TableHead className="text-right">Hosty</TableHead>
                    <TableHead className="text-right">Usługi</TableHead>
                    <TableHead className="text-right">Zmiany</TableHead>
                    <TableHead>Start</TableHead>
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
                          <TableCell className="max-w-[320px]">
                            <button
                              type="button"
                              onClick={() => handleToggleScanDetail(scan.id)}
                              className="flex min-w-0 items-center gap-1.5 text-left"
                            >
                              {isExpanded ? (
                                <RiArrowDownSLine className="size-4 shrink-0 text-muted-foreground" />
                              ) : (
                                <RiArrowRightSLine className="size-4 shrink-0 text-muted-foreground" />
                              )}
                              <span className="truncate text-sm font-medium">{scan.name}</span>
                              <Pill tone="neutral">{scan.run_type}</Pill>
                            </button>
                            {scan.notes && (
                              <div className="mt-1 truncate pl-5.5 text-xs text-muted-foreground">
                                {scan.notes}
                              </div>
                            )}
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
                          <TableCell className="text-right font-mono text-xs">
                            {scan.scanned_ips}/{scan.total_ips}
                          </TableCell>
                          <TableCell className="text-right font-mono text-xs">
                            {scan.active_hosts}
                          </TableCell>
                          <TableCell className="text-right font-mono text-xs">
                            {scan.services_found}
                          </TableCell>
                          <TableCell className="text-right font-mono text-xs">
                            {scan.changes_detected}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">
                            {formatDateTime(scan.started_at)}
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center justify-end gap-0.5">
                              <Button
                                variant="ghost"
                                size="icon-xs"
                                aria-label="Coverage Ledger"
                                title="Coverage Ledger"
                                onClick={() => handleToggleScanDetail(scan.id)}
                              >
                                <RiStackLine />
                              </Button>
                              {canWriteScans && (
                                <Button
                                  variant="ghost"
                                  size="icon-xs"
                                  aria-label="Edytuj"
                                  title="Edytuj"
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
                                  aria-label="Usuń"
                                  title="Usuń"
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
                            <TableCell colSpan={9} className="whitespace-normal">
                              <div className="flex flex-col items-end gap-4 px-5.5 pb-2 sm:flex-row">
                                <Field label="Nazwa" className="w-full sm:flex-1">
                                  <Input
                                    value={editScanName}
                                    onChange={(e) => setEditScanName(e.target.value)}
                                  />
                                </Field>
                                <Field label="Notatki" className="w-full sm:flex-[2]">
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
                                    Anuluj
                                  </Button>
                                  <Button size="sm" onClick={() => handleSaveScanMeta(scan.id)}>
                                    <RiSaveLine data-icon="inline-start" /> Zapisz
                                  </Button>
                                </div>
                              </div>
                            </TableCell>
                          </TableRow>
                        )}

                        {/* Coverage Ledger chunk grid */}
                        {isExpanded && (
                          <TableRow className="bg-muted/30 hover:bg-muted/30">
                            <TableCell colSpan={9} className="whitespace-normal">
                              <div className="space-y-3 px-5.5 pb-2">
                                <SectionTitle>Coverage Ledger · {chunks.length}</SectionTitle>

                                {chunks.length === 0 ? (
                                  <Empty className="py-4">Brak chunków</Empty>
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
                                  />
                                )}
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
          <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
            <Card size="sm" className={cn('py-0', canWriteScans ? 'xl:col-span-7' : 'xl:col-span-12')}>
              {loading ? (
                <PeckLoader />
              ) : profiles.length === 0 ? (
                <Empty>Brak profili</Empty>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Profil</TableHead>
                      <TableHead>Limity</TableHead>
                      <TableHead>Harmonogram</TableHead>
                      <TableHead className="text-right" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {profiles.map((p) => (
                      <TableRow key={p.id}>
                        <TableCell className="max-w-[280px] whitespace-normal">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-sm font-medium">{p.name}</span>
                            {p.agent_id && (
                              <Pill
                                tone={agents.find((a) => a.id === p.agent_id)?.status === 'online' ? 'violet' : 'warning'}
                                title="Skanowany przez zdalnego agenta"
                              >
                                agent: {agents.find((a) => a.id === p.agent_id)?.name ?? 'usunięty'}
                              </Pill>
                            )}
                            {p.window_enabled && (
                              <Pill tone="warning">
                                <RiTimeLine className="size-3" />
                                {p.window_start}–{p.window_end}
                              </Pill>
                            )}
                          </div>
                          <div className="mt-1 truncate font-mono text-[11px] text-muted-foreground">
                            {(p.targets || []).join(', ') || 'zakres globalny'}
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-[11px] text-muted-foreground">
                          <div>{p.allowed_ports}</div>
                          <div>
                            {p.max_rate_pps} PPS · HTTP {p.http_rps} RPS · K={p.missing_threshold} T=
                            {p.grace_period_hours}h
                          </div>
                        </TableCell>
                        <TableCell className="max-w-[240px] whitespace-normal font-mono text-[11px] text-muted-foreground">
                          <ScheduleCell schedule={p.schedule} cron={p.schedule_cron} />
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center justify-end gap-1">
                            {canRunScans && (
                              <Button
                                variant="outline"
                                size="xs"
                                onClick={() => handleStartProfileScan(p)}
                              >
                                <RiPlayLine data-icon="inline-start" />
                                Uruchom
                              </Button>
                            )}
                            {canDeleteScans && (
                              <Button
                                variant="ghost"
                                size="icon-xs"
                                aria-label="Usuń profil"
                                title="Usuń profil"
                                className="text-muted-foreground hover:text-destructive"
                                onClick={async () => {
                                  await api.deleteProfile(p.id);
                                  toast.success('Usunięto profil');
                                  loadAll();
                                }}
                              >
                                <RiDeleteBinLine />
                              </Button>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </Card>

            {canWriteScans && (
              <Card size="sm" className="xl:col-span-5">
                <form onSubmit={handleCreateProfile} className="flex flex-col gap-5">
                  <CardHeader>
                    <CardTitle className="text-sm">Nowy profil</CardTitle>
                  </CardHeader>
                  <CardContent className="grid grid-cols-1 gap-5 sm:grid-cols-2">
                    <Field label="Typ skanu (preset)" className="sm:col-span-2">
                      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                        {PROFILE_PRESETS.map((preset) => {
                          const active =
                            profileForm.allowed_ports === preset.values.allowed_ports &&
                            profileForm.enable_http_fingerprint ===
                              preset.values.enable_http_fingerprint;
                          return (
                            <button
                              key={preset.id}
                              type="button"
                              onClick={() => setProfileForm((p) => ({ ...p, ...preset.values }))}
                              className={cn(
                                'border px-3 py-2 text-left transition-colors hover:bg-muted/50',
                                active ? 'border-primary bg-primary/5' : 'border-border'
                              )}
                            >
                              <div className="text-xs font-semibold">{preset.label}</div>
                              <div className="text-[11px] text-muted-foreground">{preset.hint}</div>
                            </button>
                          );
                        })}
                      </div>
                    </Field>
                    <Field label="Nazwa" htmlFor="pf-name" className="sm:col-span-2">
                      <Input
                        id="pf-name"
                        required
                        value={profileForm.name}
                        onChange={(e) => setProfileForm((p) => ({ ...p, name: e.target.value }))}
                        placeholder="Skan nocny"
                      />
                    </Field>
                    <Field label="Cele" htmlFor="pf-targets" className="sm:col-span-2">
                      <Textarea
                        id="pf-targets"
                        rows={2}
                        value={profileForm.targetsText}
                        onChange={(e) =>
                          setProfileForm((p) => ({ ...p, targetsText: e.target.value }))
                        }
                        className="font-mono text-xs"
                      />
                    </Field>
                    <Field
                      label="Skanuje"
                      htmlFor="pf-agent"
                      className="sm:col-span-2"
                      hint="Zdalny agent skanuje z wnętrza swojej sieci; wyniki trafiają do tego samego potoku."
                    >
                      <SimpleSelect
                        id="pf-agent"
                        value={profileForm.agent_id}
                        onValueChange={(v) => setProfileForm((p) => ({ ...p, agent_id: v || LOCAL_AGENT }))}
                        options={[
                          { value: LOCAL_AGENT, label: 'Ten serwer (lokalnie)' },
                          ...agents
                            .filter((a) => !a.disabled)
                            .map((a) => ({
                              value: a.id,
                              label: `Agent: ${a.name}${a.site ? ` (${a.site})` : ''} · ${a.status}`,
                            })),
                        ]}
                      />
                    </Field>
                    <Field label="Porty" htmlFor="pf-ports" className="sm:col-span-2">
                      <Input
                        id="pf-ports"
                        value={profileForm.allowed_ports}
                        onChange={(e) =>
                          setProfileForm((p) => ({ ...p, allowed_ports: e.target.value }))
                        }
                        className="font-mono"
                      />
                    </Field>
                    <Field label="Max PPS" htmlFor="pf-pps">
                      <Input
                        id="pf-pps"
                        type="number"
                        value={profileForm.max_rate_pps}
                        onChange={(e) =>
                          setProfileForm((p) => ({ ...p, max_rate_pps: Number(e.target.value) }))
                        }
                        className="font-mono"
                      />
                    </Field>
                    <Field label="HTTP RPS" htmlFor="pf-rps">
                      <Input
                        id="pf-rps"
                        type="number"
                        value={profileForm.http_rps}
                        onChange={(e) =>
                          setProfileForm((p) => ({ ...p, http_rps: Number(e.target.value) }))
                        }
                        className="font-mono"
                      />
                    </Field>
                    <Field label="Harmonogram (cron, 5 pól)" htmlFor="pf-cron">
                      <Input
                        id="pf-cron"
                        value={profileForm.schedule_cron}
                        placeholder="np. 0 22 * * * (puste = tylko ręcznie)"
                        onChange={(e) =>
                          setProfileForm((p) => ({ ...p, schedule_cron: e.target.value }))
                        }
                        className="font-mono"
                      />
                    </Field>
                    <div className="flex items-center gap-3 sm:col-span-2">
                      <Switch
                        id="win_en"
                        checked={profileForm.window_enabled}
                        onCheckedChange={(checked) =>
                          setProfileForm((p) => ({ ...p, window_enabled: checked }))
                        }
                      />
                      <Label htmlFor="win_en" className="text-xs">
                        Okno czasowe (Auto Pause/Resume)
                      </Label>
                    </div>
                    <div className="flex items-center gap-3 sm:col-span-2">
                      <Switch
                        id="http_fp"
                        checked={profileForm.enable_http_fingerprint}
                        onCheckedChange={(checked) =>
                          setProfileForm((p) => ({ ...p, enable_http_fingerprint: checked }))
                        }
                      />
                      <Label htmlFor="http_fp" className="text-xs">
                        Fingerprint HTTP/TLS + bezpieczne ścieżki
                      </Label>
                    </div>
                    {profileForm.window_enabled && (
                      <>
                        <Field label="Start (HH:MM)" htmlFor="pf-ws">
                          <Input
                            id="pf-ws"
                            value={profileForm.window_start}
                            onChange={(e) =>
                              setProfileForm((p) => ({ ...p, window_start: e.target.value }))
                            }
                            className="font-mono"
                          />
                        </Field>
                        <Field label="Koniec (HH:MM)" htmlFor="pf-we">
                          <Input
                            id="pf-we"
                            value={profileForm.window_end}
                            onChange={(e) =>
                              setProfileForm((p) => ({ ...p, window_end: e.target.value }))
                            }
                            className="font-mono"
                          />
                        </Field>
                      </>
                    )}
                  </CardContent>
                  <CardFooter className="justify-end">
                    <Button type="submit" size="sm">
                      <RiSaveLine data-icon="inline-start" /> Zapisz profil
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
                <CardTitle className="text-sm">Cele · {targets.length}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {canWriteScans && (
                  <form onSubmit={handleAddTarget} className="flex items-end gap-3">
                    <Input
                      value={newTarget}
                      onChange={(e) => setNewTarget(e.target.value)}
                      placeholder="172.28.0.0/24 lub agh.edu.pl"
                      aria-label="Cel"
                      className="flex-1 font-mono"
                    />
                    <Input
                      value={newTargetLabel}
                      onChange={(e) => setNewTargetLabel(e.target.value)}
                      placeholder="Etykieta"
                      aria-label="Etykieta"
                      className="w-32"
                    />
                    <Button type="submit" size="sm">
                      <RiAddLine data-icon="inline-start" /> Dodaj
                    </Button>
                  </form>
                )}
                {targets.length === 0 ? (
                  <Empty className="py-6">Brak celów</Empty>
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
                            aria-label="Usuń cel"
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
                  Wykluczenia · {exclusions.length}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {canWriteScans && (
                  <form onSubmit={handleAddExclusion} className="flex items-end gap-3">
                    <Input
                      value={newExclusion}
                      onChange={(e) => setNewExclusion(e.target.value)}
                      placeholder="10.0.0.1/32"
                      aria-label="Wykluczenie"
                      className="flex-1 font-mono"
                    />
                    <Input
                      value={newExclusionReason}
                      onChange={(e) => setNewExclusionReason(e.target.value)}
                      placeholder="Powód"
                      aria-label="Powód"
                      className="w-40"
                    />
                    <Button type="submit" size="sm" variant="destructive">
                      <RiForbidLine data-icon="inline-start" /> Wyklucz
                    </Button>
                  </form>
                )}
                {exclusions.length === 0 ? (
                  <Empty className="py-6">Brak wykluczeń</Empty>
                ) : (
                  <div className="max-h-64 divide-y divide-border overflow-y-auto border-y border-border">
                    {exclusions.map((ex) => (
                      <div key={ex.id} className="flex items-center justify-between gap-2 py-2 text-xs">
                        <div className="flex min-w-0 items-center gap-2">
                          <Pill tone="danger">{ex.value}</Pill>
                          {ex.reason && (
                            <span className="truncate text-muted-foreground">{ex.reason}</span>
                          )}
                        </div>
                        {canDeleteScans && (
                          <Button
                            variant="ghost"
                            size="icon-xs"
                            aria-label="Usuń wykluczenie"
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
                Estymator
              </CardTitle>
            </CardHeader>
            <CardContent className="grid grid-cols-1 gap-5 lg:grid-cols-12">
              <Field label="Zakresy" htmlFor="est-targets" className="lg:col-span-4">
                <Textarea
                  id="est-targets"
                  rows={3}
                  value={estTargets}
                  onChange={(e) => setEstTargets(e.target.value)}
                  className="font-mono text-xs"
                />
              </Field>
              <Field label="Wykluczenia" htmlFor="est-excl" className="lg:col-span-3">
                <Textarea
                  id="est-excl"
                  rows={3}
                  value={estExclusions}
                  onChange={(e) => setEstExclusions(e.target.value)}
                  className="font-mono text-xs"
                />
              </Field>
              <div className="grid grid-cols-2 gap-5 sm:grid-cols-3 lg:col-span-5">
                <Field label="Porty" htmlFor="est-ports" className="col-span-2 sm:col-span-3">
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
                <Field label="Okno od" htmlFor="est-ws">
                  <Input
                    id="est-ws"
                    value={estWindowStart}
                    onChange={(e) => setEstWindowStart(e.target.value)}
                    className="font-mono"
                  />
                </Field>
                <Field label="Okno do" htmlFor="est-we">
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
              <Button size="sm" disabled={estimating} onClick={handleEstimate}>
                <RiCalculatorLine data-icon="inline-start" />
                {estimating ? 'Liczenie…' : 'Oblicz'}
              </Button>
            </CardFooter>
          </Card>

          {estimate && (
            <StatStrip>
              <Stat label="Wszystkie IP" value={formatNumber(estimate.total_ips)} />
              <Stat label="Wykluczone" value={formatNumber(estimate.excluded_ips)} tone="danger" />
              <Stat label="Efektywne" value={formatNumber(estimate.effective_ips)} />
              <Stat
                label="Chunk / liczba"
                value={`${estimate.recommended_chunk_size} / ${estimate.chunk_count}`}
              />
              <Stat label="ETA" value={formatDurationSeconds(estimate.estimated_seconds)} />
              <Stat
                label="Okno"
                tone={estimate.fits_in_window ? 'success' : 'warning'}
                value={
                  <span className="text-sm">
                    {estimate.fits_in_window
                      ? 'Mieści się'
                      : `Pause/Resume · ${estimate.estimated_windows || 2} okna`}
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
                  <CardTitle className="text-sm">Wpis ręczny</CardTitle>
                </CardHeader>
                {!canImport ? (
                  <CardContent>
                    <Notice tone="warning">
                      Wymagane uprawnienie <Code>import:write</Code>
                    </Notice>
                  </CardContent>
                ) : (
                  <>
                    <CardContent className="grid grid-cols-1 gap-5 sm:grid-cols-3">
                      <Field label="Nazwa przebiegu" htmlFor="m-name" className="sm:col-span-2">
                        <Input
                          id="m-name"
                          value={manualForm.scan_name}
                          onChange={(e) => setManualForm((m) => ({ ...m, scan_name: e.target.value }))}
                        />
                      </Field>
                      <Field label="Środowisko">
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
                      <Field label="Tagi" htmlFor="m-tags">
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
                      <Field label="Produkt" htmlFor="m-product">
                        <Input
                          id="m-product"
                          value={manualForm.product}
                          onChange={(e) => setManualForm((m) => ({ ...m, product: e.target.value }))}
                        />
                      </Field>
                      <Field label="Wersja" htmlFor="m-version">
                        <Input
                          id="m-version"
                          value={manualForm.version}
                          onChange={(e) => setManualForm((m) => ({ ...m, version: e.target.value }))}
                          className="font-mono"
                        />
                      </Field>
                      <Field label="Tytuł HTTP" htmlFor="m-title" className="sm:col-span-2">
                        <Input
                          id="m-title"
                          value={manualForm.http_title}
                          onChange={(e) => setManualForm((m) => ({ ...m, http_title: e.target.value }))}
                          placeholder="Staging Admin Console"
                        />
                      </Field>
                      <Field label="Kod HTTP" htmlFor="m-code">
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
                      <Field label="Nagłówki" htmlFor="m-headers" className="sm:col-span-3">
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
                      <Field label="Notatki" htmlFor="m-notes" className="sm:col-span-3">
                        <Input
                          id="m-notes"
                          value={manualForm.notes}
                          onChange={(e) => setManualForm((m) => ({ ...m, notes: e.target.value }))}
                        />
                      </Field>
                    </CardContent>
                    <CardFooter className="justify-end">
                      <Button type="submit" size="sm" disabled={submittingManual}>
                        <RiCheckLine data-icon="inline-start" />
                        {submittingManual ? 'Przetwarzanie…' : 'Dodaj'}
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
                    <CardTitle className="text-sm">Import CSV / JSON</CardTitle>
                  </CardHeader>
                  {!canImport ? (
                    <CardContent>
                      <Notice tone="warning">
                        Wymagane uprawnienie <Code>import:write</Code>
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
                            {importFile ? importFile.name : 'Upuść plik .csv / .json / nmap .xml (-oX)'}
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
                          <Field label="Nazwa importu" htmlFor="imp-name">
                            <Input
                              id="imp-name"
                              value={importScanName}
                              onChange={(e) => setImportScanName(e.target.value)}
                              placeholder="opcjonalnie"
                            />
                          </Field>
                        </div>

                        {importPreview && (
                          <div className="border border-border bg-muted/40 p-3">
                            <div className="mb-1.5 text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
                              Podgląd · {importFile?.name}
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
                          {importing ? 'Importowanie…' : 'Importuj'}
                        </Button>
                      </CardFooter>
                    </>
                  )}
                </form>
              </Card>

              {/* Export */}
              <Card size="sm">
                <CardHeader>
                  <CardTitle className="text-sm">Eksport</CardTitle>
                </CardHeader>
                <CardContent className="grid grid-cols-1 gap-5 sm:grid-cols-3">
                  <Field label="Skan">
                    <SimpleSelect
                      value={exportScanId || ALL}
                      onValueChange={(v) => setExportScanId(v === ALL ? '' : v)}
                      options={[
                        { value: ALL, label: 'Wszystkie' },
                        ...scans.map((s) => ({ value: s.id, label: s.name })),
                      ]}
                    />
                  </Field>
                  <Field label="Stan">
                    <SimpleSelect
                      value={exportState || ALL}
                      onValueChange={(v) => setExportState(v === ALL ? '' : v)}
                      options={[
                        { value: ALL, label: 'Wszystkie' },
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
                      placeholder="dowolny"
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
                        title="Jeden URL na linię: httpx, nuclei, gowitness"
                        onClick={() => runExport('urls')}
                      >
                        <RiDownload2Line data-icon="inline-start" /> URL-e
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        title="NDJSON w Elastic Common Schema: ELK / Splunk"
                        onClick={() => runExport('ecs')}
                      >
                        <RiDownload2Line data-icon="inline-start" /> ECS (ELK)
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        title="findings.json w formacie OWASP secureCodeBox (Host / Open Port + TLS/SSH)"
                        onClick={() => runExport('scb')}
                      >
                        <RiDownload2Line data-icon="inline-start" /> secureCodeBox
                      </Button>
                    </>
                  ) : (
                    <Notice tone="neutral" className="w-full">
                      Wymagane uprawnienie <Code>export:read</Code>
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

/** Recurring schedule summary: cron, next run (window-adjusted), last run, last skip reason. */
function ScheduleCell({ schedule, cron }: { schedule?: ProfileSchedule; cron?: string }) {
  if (!cron && !schedule?.cron) return <span>tylko ręcznie</span>;
  if (schedule?.cron_error) {
    return <span className="text-rose-500">błędny cron: {schedule.cron_error}</span>;
  }
  return (
    <div className="space-y-0.5">
      <div className="text-foreground">{schedule?.cron || cron}</div>
      {schedule?.next_run_at && (
        <div>
          następny: {formatDateTime(schedule.next_run_at)}
          {schedule.deferred_by_window && (
            <Pill tone="warning" className="ml-1">
              po otwarciu okna
            </Pill>
          )}
          {schedule.pending_catch_up && (
            <Pill tone="violet" className="ml-1">
              zaległy
            </Pill>
          )}
        </div>
      )}
      {schedule?.active_run && (
        <div className="text-amber-600 dark:text-amber-300">
          aktywny: {schedule.active_run.status} — kolejny slot zostanie pominięty
        </div>
      )}
      {schedule?.last_run && (
        <div>
          ostatni: {formatDateTime(schedule.last_run.started_at)} · {schedule.last_run.status}
        </div>
      )}
      {schedule?.last_skip_reason && (
        <div className="truncate" title={schedule.last_skip_reason}>
          pominięto: {schedule.last_skip_reason}
        </div>
      )}
    </div>
  );
}
