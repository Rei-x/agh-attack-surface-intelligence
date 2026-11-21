import React, { useCallback, useEffect, useState } from 'react';
import {
  Calculator,
  CheckCircle2,
  Clock,
  Download,
  Edit3,
  FileUp,
  Layers,
  Pause,
  Play,
  Plus,
  Radar,
  Save,
  ShieldBan,
  Square,
  Trash2,
  Upload,
} from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import { PERMISSIONS } from '../lib/permissions';
import {
  formatDateTime,
  formatDurationSeconds,
  formatNumber,
  scanStatusMeta,
} from '../lib/format';
import type {
  ScanChunk,
  ScanProfile,
  ScanRun,
  Target,
  TargetEstimate,
  TargetExclusion,
} from '../types/api';

export function ScansPage() {
  const { can } = useAuth();
  const toast = useToast();

  const [activeTab, setActiveTab] = useState<'profiles' | 'runs' | 'ingest'>('profiles');
  const [targets, setTargets] = useState<Target[]>([]);
  const [exclusions, setExclusions] = useState<TargetExclusion[]>([]);
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [scans, setScans] = useState<ScanRun[]>([]);
  const [loading, setLoading] = useState(true);

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
  const [estConcurrency, setEstConcurrency] = useState(32);
  const [estWindowStart, setEstWindowStart] = useState('22:00');
  const [estWindowEnd, setEstWindowEnd] = useState('06:00');
  const [estimate, setEstimate] = useState<TargetEstimate | null>(null);
  const [estimating, setEstimating] = useState(false);

  // Profile creator
  const [profileForm, setProfileForm] = useState({
    name: '',
    description: '',
    targetsText: '172.28.0.0/24',
    allowed_ports: '22,80,443,8080,8443',
    max_rate_pps: 300,
    http_rps: 20,
    concurrency: 16,
    chunk_target_sec: 30,
    window_enabled: false,
    window_start: '22:00',
    window_end: '06:00',
    timezone: 'Europe/Warsaw',
    missing_threshold: 2,
    grace_period_hours: 24,
    retry_unstable_count: 2,
    enable_http_fingerprint: true,
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
  const [importFormat, setImportFormat] = useState<'csv' | 'json'>('csv');
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
    } catch (err) {
      toast.error('Błąd pobierania danych skanera', (err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

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
      toast.error('Błąd estymacji zakresu', (err as Error).message);
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
      toast.success('Dodano cel skanowania');
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
      toast.success('Dodano wykluczenie (Scope Deny Gate)');
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
        missing_threshold: profileForm.missing_threshold,
        grace_period_hours: profileForm.grace_period_hours,
        retry_unstable_count: profileForm.retry_unstable_count,
        enable_http_fingerprint: profileForm.enable_http_fingerprint,
        enabled: true,
      });
      setProfileForm((p) => ({ ...p, name: '', description: '' }));
      toast.success('Utworzono profil skanowania');
      loadAll();
    } catch (err) {
      toast.error('Błąd tworzenia profilu', (err as Error).message);
    }
  };

  const handleStartProfileScan = async (profile: ScanProfile) => {
    try {
      const run = await api.startScan({
        profile_id: profile.id,
        name: `${profile.name} — ${new Date().toLocaleTimeString('pl-PL')}`,
      });
      toast.success('Uruchomiono skan', `Przebieg "${run.name}" jest w toku.`);
      setActiveTab('runs');
      loadAll();
    } catch (err) {
      toast.error('Nie udało się uruchomić skanu', (err as Error).message);
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
      toast.error('Błąd pobierania Coverage Ledger', (err as Error).message);
    }
  };

  const handleSaveScanMeta = async (scanId: string) => {
    try {
      await api.updateScan(scanId, { name: editScanName, notes: editScanNotes });
      toast.success('Zaktualizowano metadane skanu');
      setEditingScanId(null);
      loadAll();
    } catch (err) {
      toast.error('Błąd zapisu metadanych skanu', (err as Error).message);
    }
  };

  const handleScanControl = async (scanId: string, action: 'pause' | 'resume' | 'stop' | 'delete') => {
    try {
      if (action === 'pause') await api.pauseScan(scanId);
      else if (action === 'resume') await api.resumeScan(scanId);
      else if (action === 'stop') await api.stopScan(scanId);
      else if (action === 'delete') {
        if (!window.confirm('Usunąć wybrany przebieg skanu?')) return;
        await api.deleteScan(scanId);
      }
      toast.success('Wykonano akcję na skanie');
      loadAll();
    } catch (err) {
      toast.error('Błąd akcji na skanie', (err as Error).message);
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

      toast.success(
        'Dodano obserwację przez zunifikowany pipeline',
        `Host ${manualForm.ip} przeszedł detekcję sygnatur, scoring, diff i szyfrowanie at rest.`
      );
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
    if (file.name.toLowerCase().endsWith('.json')) setImportFormat('json');
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
      toast.success(
        'Zaimportowano plik przez zunifikowany pipeline',
        `Plik "${importFile.name}" został przeanalizowany i zaszyfrowany.`
      );
      setImportFile(null);
      setImportPreview('');
      setImportScanName('');
      loadAll();
    } catch (err) {
      toast.error('Błąd importu pliku', (err as Error).message);
    } finally {
      setImporting(false);
    }
  };

  const chunkColor = (status: string) => {
    switch (status) {
      case 'DONE':
        return 'bg-emerald-500/25 border-emerald-500/50 text-emerald-300';
      case 'RUNNING':
        return 'bg-cyan-500/25 border-cyan-400 text-cyan-200 animate-pulse';
      case 'PAUSED':
        return 'bg-amber-500/25 border-amber-500/50 text-amber-300';
      case 'FAILED':
        return 'bg-rose-500/25 border-rose-500/50 text-rose-300';
      default:
        return 'bg-bg-elevated border-border-subtle text-text-muted';
    }
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-text-primary flex items-center gap-2">
            <Radar className="h-5 w-5 text-cyan-400" />
            Skaner, Okna Czasowe, Coverage Ledger i Import/Eksport
          </h1>
          <p className="text-xs text-text-muted mt-0.5">
            Adaptacyjny chunking dla sieci 10 000–65 536+ IP, twarde okna czasowe i zunifikowany
            pipeline ingestu
          </p>
        </div>

        <div className="inline-flex rounded-lg border border-border-subtle bg-bg-card p-0.5">
          {[
            { id: 'profiles', label: 'Profile, Zakres & Estymator' },
            { id: 'runs', label: `Przebiegi & Coverage Ledger (${scans.length})` },
            { id: 'ingest', label: 'Import / Wpis Ręczny / Eksport' },
          ].map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                activeTab === tab.id
                  ? 'bg-cyan-500/15 text-cyan-400'
                  : 'text-text-muted hover:text-text-primary'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* TAB 1: PROFILES, SCOPE & TARGET ESTIMATOR */}
      {activeTab === 'profiles' && (
        <div className="space-y-5">
          {/* Live Target Estimator */}
          <div className="rounded-xl border border-cyan-500/30 bg-bg-card p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
                  <Calculator className="h-4 w-4 text-cyan-400" />
                  Estymator Zakresu i Okna Czasowego (Target Estimator)
                </h2>
                <p className="text-xs text-text-muted">
                  Oblicz dokładną liczbę IP po wykluczeniach, rozmiar chunka, ETA oraz dopasowanie
                  do okna czasowego (np. 22:00–06:00)
                </p>
              </div>
              <button
                type="button"
                disabled={estimating}
                onClick={handleEstimate}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-50"
              >
                <Calculator className="h-3.5 w-3.5" />
                {estimating ? 'Obliczanie...' : 'Oblicz estymację'}
              </button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
              <div className="lg:col-span-4">
                <label className="block text-xs text-text-muted mb-1">
                  Zakresy (IP, CIDR /16+, zakres a-b, domeny)
                </label>
                <textarea
                  rows={3}
                  value={estTargets}
                  onChange={(e) => setEstTargets(e.target.value)}
                  className="w-full rounded-lg border border-border-subtle bg-bg-elevated p-2.5 font-mono text-xs text-text-primary"
                />
              </div>
              <div className="lg:col-span-3">
                <label className="block text-xs text-text-muted mb-1">
                  Wykluczenia (Scope Deny Gate)
                </label>
                <textarea
                  rows={3}
                  value={estExclusions}
                  onChange={(e) => setEstExclusions(e.target.value)}
                  className="w-full rounded-lg border border-border-subtle bg-bg-elevated p-2.5 font-mono text-xs text-text-primary"
                />
              </div>
              <div className="lg:col-span-5 grid grid-cols-2 sm:grid-cols-3 gap-2.5 text-xs">
                <div className="col-span-2 sm:col-span-3">
                  <label className="block text-text-muted mb-1">Dozwolone porty</label>
                  <input
                    type="text"
                    value={estPorts}
                    onChange={(e) => setEstPorts(e.target.value)}
                    className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1.5 font-mono text-text-primary"
                  />
                </div>
                <div>
                  <label className="block text-text-muted mb-1">Max PPS</label>
                  <input
                    type="number"
                    value={estRate}
                    onChange={(e) => setEstRate(Number(e.target.value))}
                    className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1.5 font-mono text-text-primary"
                  />
                </div>
                <div>
                  <label className="block text-text-muted mb-1">Okno od</label>
                  <input
                    type="text"
                    value={estWindowStart}
                    onChange={(e) => setEstWindowStart(e.target.value)}
                    className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1.5 font-mono text-text-primary"
                  />
                </div>
                <div>
                  <label className="block text-text-muted mb-1">Okno do</label>
                  <input
                    type="text"
                    value={estWindowEnd}
                    onChange={(e) => setEstWindowEnd(e.target.value)}
                    className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1.5 font-mono text-text-primary"
                  />
                </div>
              </div>
            </div>

            {estimate && (
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 pt-2 border-t border-border-subtle">
                <div className="rounded-lg bg-bg-elevated p-3 border border-border-subtle">
                  <div className="text-[11px] text-text-muted">Wszystkie IP</div>
                  <div className="text-lg font-bold font-mono text-text-primary">
                    {formatNumber(estimate.total_ips)}
                  </div>
                </div>
                <div className="rounded-lg bg-bg-elevated p-3 border border-border-subtle">
                  <div className="text-[11px] text-text-muted">Wykluczone IP</div>
                  <div className="text-lg font-bold font-mono text-rose-400">
                    {formatNumber(estimate.excluded_ips)}
                  </div>
                </div>
                <div className="rounded-lg bg-bg-elevated p-3 border border-border-subtle">
                  <div className="text-[11px] text-text-muted">Efektywne IP</div>
                  <div className="text-lg font-bold font-mono text-cyan-400">
                    {formatNumber(estimate.effective_ips)}
                  </div>
                </div>
                <div className="rounded-lg bg-bg-elevated p-3 border border-border-subtle">
                  <div className="text-[11px] text-text-muted">Chunk Size / Liczba</div>
                  <div className="text-lg font-bold font-mono text-text-primary">
                    {estimate.recommended_chunk_size} / {estimate.chunk_count}
                  </div>
                </div>
                <div className="rounded-lg bg-bg-elevated p-3 border border-border-subtle">
                  <div className="text-[11px] text-text-muted">Szacowane ETA</div>
                  <div className="text-lg font-bold font-mono text-text-primary">
                    {formatDurationSeconds(estimate.estimated_seconds)}
                  </div>
                </div>
                <div
                  className={`rounded-lg p-3 border ${
                    estimate.fits_in_window
                      ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                      : 'bg-amber-500/15 border-amber-500/40 text-amber-300'
                  }`}
                >
                  <div className="text-[11px] opacity-80">Okno czasowe</div>
                  <div className="text-xs font-bold mt-1">
                    {estimate.fits_in_window
                      ? 'Mieści się w 1 oknie'
                      : `Auto Pause/Resume (${estimate.estimated_windows || 2} okna)`}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Scan Profiles List + Creator */}
          <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
            <div className="xl:col-span-7 rounded-xl border border-border-subtle bg-bg-card p-5 space-y-3">
              <h2 className="text-sm font-semibold text-text-primary">
                Profile Skanowania ({profiles.length})
              </h2>
              {loading ? (
                <div className="py-6 text-center text-xs text-text-muted">Ładowanie...</div>
              ) : profiles.length === 0 ? (
                <div className="py-6 text-center text-xs text-text-muted">
                  Brak zapisanych profili skanowania.
                </div>
              ) : (
                <div className="space-y-3">
                  {profiles.map((p) => (
                    <div
                      key={p.id}
                      className="rounded-lg border border-border-subtle bg-bg-elevated/70 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                    >
                      <div className="min-w-0 space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-semibold text-sm text-text-primary">{p.name}</span>
                          {p.window_enabled && (
                            <span className="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/35">
                              <Clock className="h-3 w-3" /> {p.window_start}–{p.window_end} ({p.timezone})
                            </span>
                          )}
                        </div>
                        <div className="font-mono text-[11px] text-cyan-400">
                          Cele: {(p.targets || []).join(', ') || 'ze skali globalnej'}
                        </div>
                        <div className="text-[11px] text-text-muted font-mono">
                          Porty: {p.allowed_ports} · {p.max_rate_pps} PPS · HTTP {p.http_rps} RPS ·
                          histereza K={p.missing_threshold}, T={p.grace_period_hours}h
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        {canRunScans && (
                          <button
                            type="button"
                            onClick={() => handleStartProfileScan(p)}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white"
                          >
                            <Play className="h-3.5 w-3.5" />
                            Uruchom skan
                          </button>
                        )}
                        {canDeleteScans && (
                          <button
                            type="button"
                            onClick={async () => {
                              await api.deleteProfile(p.id);
                              toast.success('Usunięto profil');
                              loadAll();
                            }}
                            className="p-1.5 rounded-lg text-text-muted hover:text-rose-400 hover:bg-rose-500/10"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* New Profile Form */}
            {canWriteScans && (
              <form
                onSubmit={handleCreateProfile}
                className="xl:col-span-5 rounded-xl border border-border-subtle bg-bg-card p-5 space-y-3"
              >
                <h2 className="text-sm font-semibold text-text-primary flex items-center gap-1.5">
                  <Plus className="h-4 w-4 text-cyan-400" />
                  Nowy Profil Skanowania
                </h2>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div className="sm:col-span-2">
                    <label className="block text-text-muted mb-1">Nazwa profilu</label>
                    <input
                      type="text"
                      required
                      value={profileForm.name}
                      onChange={(e) => setProfileForm((p) => ({ ...p, name: e.target.value }))}
                      placeholder="np. Skan Nocny Kampus AGH"
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 text-text-primary"
                    />
                  </div>
                  <div className="sm:col-span-2">
                    <label className="block text-text-muted mb-1">Cele (IP / CIDR / domeny)</label>
                    <textarea
                      rows={2}
                      value={profileForm.targetsText}
                      onChange={(e) =>
                        setProfileForm((p) => ({ ...p, targetsText: e.target.value }))
                      }
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated p-2 font-mono text-text-primary"
                    />
                  </div>
                  <div className="sm:col-span-2">
                    <label className="block text-text-muted mb-1">Dozwolone porty</label>
                    <input
                      type="text"
                      value={profileForm.allowed_ports}
                      onChange={(e) =>
                        setProfileForm((p) => ({ ...p, allowed_ports: e.target.value }))
                      }
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-text-primary"
                    />
                  </div>
                  <div>
                    <label className="block text-text-muted mb-1">Max Rate (PPS)</label>
                    <input
                      type="number"
                      value={profileForm.max_rate_pps}
                      onChange={(e) =>
                        setProfileForm((p) => ({ ...p, max_rate_pps: Number(e.target.value) }))
                      }
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-text-primary"
                    />
                  </div>
                  <div>
                    <label className="block text-text-muted mb-1">HTTP RPS</label>
                    <input
                      type="number"
                      value={profileForm.http_rps}
                      onChange={(e) =>
                        setProfileForm((p) => ({ ...p, http_rps: Number(e.target.value) }))
                      }
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-text-primary"
                    />
                  </div>
                  <div className="sm:col-span-2 flex items-center gap-2 pt-1">
                    <input
                      type="checkbox"
                      id="win_en"
                      checked={profileForm.window_enabled}
                      onChange={(e) =>
                        setProfileForm((p) => ({ ...p, window_enabled: e.target.checked }))
                      }
                      className="accent-amber-500"
                    />
                    <label htmlFor="win_en" className="text-text-secondary font-medium">
                      Wymuszaj twarde okno czasowe (Auto Pause/Resume)
                    </label>
                  </div>
                  {profileForm.window_enabled && (
                    <>
                      <div>
                        <label className="block text-text-muted mb-1">Start okna (HH:MM)</label>
                        <input
                          type="text"
                          value={profileForm.window_start}
                          onChange={(e) =>
                            setProfileForm((p) => ({ ...p, window_start: e.target.value }))
                          }
                          className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-text-primary"
                        />
                      </div>
                      <div>
                        <label className="block text-text-muted mb-1">Koniec okna (HH:MM)</label>
                        <input
                          type="text"
                          value={profileForm.window_end}
                          onChange={(e) =>
                            setProfileForm((p) => ({ ...p, window_end: e.target.value }))
                          }
                          className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-text-primary"
                        />
                      </div>
                    </>
                  )}
                </div>
                <button
                  type="submit"
                  className="w-full inline-flex items-center justify-center gap-1.5 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white"
                >
                  <Save className="h-3.5 w-3.5" /> Zapisz profil skanowania
                </button>
              </form>
            )}
          </div>

          {/* Scope Targets & Hard Exclusions */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <div className="rounded-xl border border-border-subtle bg-bg-card p-5 space-y-3">
              <h3 className="text-sm font-semibold text-text-primary">
                Zakres Globalny (Targets: {targets.length})
              </h3>
              {canWriteScans && (
                <form onSubmit={handleAddTarget} className="flex gap-2">
                  <input
                    type="text"
                    value={newTarget}
                    onChange={(e) => setNewTarget(e.target.value)}
                    placeholder="np. 172.28.0.0/24 lub agh.edu.pl"
                    className="flex-1 rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-xs text-text-primary"
                  />
                  <input
                    type="text"
                    value={newTargetLabel}
                    onChange={(e) => setNewTargetLabel(e.target.value)}
                    placeholder="Etykieta"
                    className="w-32 rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 text-xs text-text-primary"
                  />
                  <button
                    type="submit"
                    className="px-3 py-1.5 rounded-lg text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white"
                  >
                    Dodaj
                  </button>
                </form>
              )}
              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                {targets.map((t) => (
                  <div
                    key={t.id}
                    className="flex items-center justify-between px-3 py-2 rounded-lg bg-bg-elevated border border-border-subtle text-xs"
                  >
                    <div>
                      <span className="font-mono font-semibold text-text-primary">{t.value}</span>
                      {t.label && <span className="text-text-muted ml-2">({t.label})</span>}
                    </div>
                    {canDeleteScans && (
                      <button
                        type="button"
                        onClick={async () => {
                          await api.deleteTarget(t.id);
                          loadAll();
                        }}
                        className="text-text-muted hover:text-rose-400"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-xl border border-border-subtle bg-bg-card p-5 space-y-3">
              <h3 className="text-sm font-semibold text-rose-400 flex items-center gap-1.5">
                <ShieldBan className="h-4 w-4" />
                Lista Wykluczeń — Scope / Deny Gate ({exclusions.length})
              </h3>
              {canWriteScans && (
                <form onSubmit={handleAddExclusion} className="flex gap-2">
                  <input
                    type="text"
                    value={newExclusion}
                    onChange={(e) => setNewExclusion(e.target.value)}
                    placeholder="np. 10.0.0.1/32"
                    className="flex-1 rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-xs text-text-primary"
                  />
                  <input
                    type="text"
                    value={newExclusionReason}
                    onChange={(e) => setNewExclusionReason(e.target.value)}
                    placeholder="Powód wykluczenia"
                    className="w-40 rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 text-xs text-text-primary"
                  />
                  <button
                    type="submit"
                    className="px-3 py-1.5 rounded-lg text-xs font-medium bg-rose-600 hover:bg-rose-500 text-white"
                  >
                    Wyklucz
                  </button>
                </form>
              )}
              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                {exclusions.map((ex) => (
                  <div
                    key={ex.id}
                    className="flex items-center justify-between px-3 py-2 rounded-lg bg-rose-500/5 border border-rose-500/25 text-xs"
                  >
                    <div>
                      <span className="font-mono font-semibold text-rose-300">{ex.value}</span>
                      {ex.reason && <span className="text-text-muted ml-2">— {ex.reason}</span>}
                    </div>
                    {canDeleteScans && (
                      <button
                        type="button"
                        onClick={async () => {
                          await api.deleteExclusion(ex.id);
                          loadAll();
                        }}
                        className="text-text-muted hover:text-rose-400"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: SCAN RUNS & COVERAGE LEDGER */}
      {activeTab === 'runs' && (
        <div className="space-y-3">
          {scans.length === 0 ? (
            <div className="rounded-xl border border-border-subtle bg-bg-card p-10 text-center text-sm text-text-muted">
              Brak przebiegów skanów.
            </div>
          ) : (
            scans.map((scan) => {
              const meta = scanStatusMeta(scan.status);
              const isExpanded = expandedScanId === scan.id;
              const isEditing = editingScanId === scan.id;
              const chunks: ScanChunk[] = isExpanded ? scanDetail?.chunks || scan.chunks || [] : [];
              const pct =
                scan.total_chunks > 0
                  ? Math.round((scan.completed_chunks / scan.total_chunks) * 100)
                  : scan.status === 'COMPLETED'
                    ? 100
                    : 0;

              return (
                <div
                  key={scan.id}
                  className="rounded-xl border border-border-subtle bg-bg-card overflow-hidden"
                >
                  <div className="p-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                    <div
                      className="min-w-0 flex-1 cursor-pointer"
                      onClick={() => handleToggleScanDetail(scan.id)}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-semibold text-text-primary">{scan.name}</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-bg-elevated border border-border-subtle text-text-secondary">
                          {scan.run_type}
                        </span>
                        <span className={`text-[11px] font-mono px-2 py-0.5 rounded border ${meta.badge}`}>
                          {meta.label}
                        </span>
                      </div>
                      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted mt-1.5 font-mono">
                        <span>IP: {scan.scanned_ips}/{scan.total_ips}</span>
                        <span>Chunki: {scan.completed_chunks}/{scan.total_chunks || 1} ({pct}%)</span>
                        <span>Hosty: {scan.active_hosts}</span>
                        <span>Usługi: {scan.services_found}</span>
                        <span>Zmiany: {scan.changes_detected}</span>
                        <span>Start: {formatDateTime(scan.started_at)}</span>
                      </div>
                      {scan.notes && (
                        <p className="text-xs text-text-secondary mt-1 italic">Notatka: {scan.notes}</p>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-1.5 shrink-0">
                      <button
                        type="button"
                        onClick={() => handleToggleScanDetail(scan.id)}
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs border border-border-subtle bg-bg-elevated hover:bg-bg-hover text-text-secondary"
                      >
                        <Layers className="h-3.5 w-3.5 text-cyan-400" />
                        Coverage Ledger
                      </button>

                      {canWriteScans && (
                        <button
                          type="button"
                          onClick={() => {
                            setEditingScanId(isEditing ? null : scan.id);
                            setEditScanName(scan.name);
                            setEditScanNotes(scan.notes || '');
                          }}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs border border-border-subtle bg-bg-elevated hover:bg-bg-hover text-text-secondary"
                          title="Edytuj nazwę/notatki (działa w każdym stanie skanu)"
                        >
                          <Edit3 className="h-3.5 w-3.5" />
                          Edytuj
                        </button>
                      )}

                      {canRunScans && scan.status === 'RUNNING' && (
                        <button
                          type="button"
                          onClick={() => handleScanControl(scan.id, 'pause')}
                          className="p-1.5 rounded-lg bg-amber-500/15 text-amber-300 border border-amber-500/35"
                          title="Pause"
                        >
                          <Pause className="h-3.5 w-3.5" />
                        </button>
                      )}
                      {canRunScans &&
                        (scan.status === 'PAUSED_USER' || scan.status === 'PAUSED_WINDOW') && (
                          <button
                            type="button"
                            onClick={() => handleScanControl(scan.id, 'resume')}
                            className="p-1.5 rounded-lg bg-emerald-500/15 text-emerald-300 border border-emerald-500/35"
                            title="Resume"
                          >
                            <Play className="h-3.5 w-3.5" />
                          </button>
                        )}
                      {canRunScans &&
                        (scan.status === 'RUNNING' ||
                          scan.status === 'PAUSED_USER' ||
                          scan.status === 'PAUSED_WINDOW') && (
                          <button
                            type="button"
                            onClick={() => handleScanControl(scan.id, 'stop')}
                            className="p-1.5 rounded-lg bg-rose-500/15 text-rose-300 border border-rose-500/35"
                            title="Stop"
                          >
                            <Square className="h-3.5 w-3.5" />
                          </button>
                        )}
                      {canDeleteScans && (
                        <button
                          type="button"
                          onClick={() => handleScanControl(scan.id, 'delete')}
                          className="p-1.5 rounded-lg text-text-muted hover:text-rose-400 hover:bg-rose-500/10"
                          title="Usuń skan"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Inline Scan Metadata Editor (always works regardless of status!) */}
                  {isEditing && canWriteScans && (
                    <div className="border-t border-border-subtle bg-bg-elevated/60 p-4 flex flex-col sm:flex-row gap-3 items-end">
                      <div className="flex-1 w-full">
                        <label className="block text-[11px] text-text-muted mb-1">Nazwa skanu</label>
                        <input
                          type="text"
                          value={editScanName}
                          onChange={(e) => setEditScanName(e.target.value)}
                          className="w-full rounded-lg border border-border-subtle bg-bg-card px-3 py-1.5 text-xs text-text-primary"
                        />
                      </div>
                      <div className="flex-[2] w-full">
                        <label className="block text-[11px] text-text-muted mb-1">
                          Notatki operacyjne (edytowalne w dowolnym stanie skanu)
                        </label>
                        <input
                          type="text"
                          value={editScanNotes}
                          onChange={(e) => setEditScanNotes(e.target.value)}
                          className="w-full rounded-lg border border-border-subtle bg-bg-card px-3 py-1.5 text-xs text-text-primary"
                        />
                      </div>
                      <button
                        type="button"
                        onClick={() => handleSaveScanMeta(scan.id)}
                        className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shrink-0"
                      >
                        <Save className="h-3.5 w-3.5" /> Zapisz
                      </button>
                    </div>
                  )}

                  {/* Coverage Ledger Visual Chunk Grid */}
                  {isExpanded && (
                    <div className="border-t border-border-subtle bg-bg-primary/50 p-4 space-y-3">
                      <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                        <span className="font-semibold text-text-primary">
                          Coverage Ledger — Siatka Chunków ({chunks.length})
                        </span>
                        <div className="flex items-center gap-3 text-[11px] font-mono">
                          <span className="text-emerald-400">■ DONE</span>
                          <span className="text-cyan-400">■ RUNNING</span>
                          <span className="text-amber-400">■ PAUSED</span>
                          <span className="text-text-muted">■ PENDING</span>
                          <span className="text-rose-400">■ FAILED</span>
                        </div>
                      </div>

                      {chunks.length === 0 ? (
                        <p className="text-xs text-text-muted">
                          Brak indywidualnych chunków dla tego przebiegu (np. import ręczny/CSV).
                        </p>
                      ) : (
                        <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-6 lg:grid-cols-8 gap-2">
                          {chunks.map((ch) => (
                            <div
                              key={ch.id || ch.chunk_index}
                              className={`rounded-lg border p-2 text-[11px] font-mono ${chunkColor(
                                ch.status
                              )}`}
                              title={ch.error || `Chunk #${ch.chunk_index + 1}: ${ch.ip_count} IP`}
                            >
                              <div className="flex items-center justify-between font-bold">
                                <span>#{ch.chunk_index + 1}</span>
                                <span className="text-[9px]">{ch.status}</span>
                              </div>
                              <div className="text-[10px] opacity-80 mt-0.5">
                                {ch.ip_count} IP · {ch.active_hosts}H/{ch.services_found}S
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      )}

      {/* TAB 3: UNIFIED INGEST & EXPORT */}
      {activeTab === 'ingest' && (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
          {/* Manual Form */}
          <form
            onSubmit={handleManualSubmit}
            className="xl:col-span-7 rounded-xl border border-border-subtle bg-bg-card p-5 space-y-4"
          >
            <div>
              <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
                <Plus className="h-4 w-4 text-cyan-400" />
                Formularz Ręczny (Zunifikowany Pipeline)
              </h2>
              <p className="text-xs text-text-muted mt-0.5">
                Tworzy pełnoprawny <span className="font-mono">scan_run(MANUAL)</span> i przepuszcza
                dane przez silnik sygnatur, scoring, diff oraz szyfrowanie AES-256-GCM.
              </p>
            </div>

            {!canImport ? (
              <div className="rounded-lg border border-amber-500/35 bg-amber-500/10 p-4 text-xs text-amber-300">
                Brak uprawnienia <span className="font-mono">import:write</span>. Przełącz rolę na
                Operator lub Administracja, aby dodawać dane ręcznie.
              </div>
            ) : (
              <>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                  <div className="sm:col-span-2">
                    <label className="block text-text-muted mb-1">Nazwa przebiegu</label>
                    <input
                      type="text"
                      value={manualForm.scan_name}
                      onChange={(e) => setManualForm((m) => ({ ...m, scan_name: e.target.value }))}
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 text-text-primary"
                    />
                  </div>
                  <div>
                    <label className="block text-text-muted mb-1">Środowisko</label>
                    <select
                      value={manualForm.environment}
                      onChange={(e) => setManualForm((m) => ({ ...m, environment: e.target.value }))}
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 text-text-primary"
                    >
                      <option value="prod">prod</option>
                      <option value="staging">staging</option>
                      <option value="dev">dev</option>
                      <option value="test">test</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-text-muted mb-1">Adres IP *</label>
                    <input
                      type="text"
                      required
                      value={manualForm.ip}
                      onChange={(e) => setManualForm((m) => ({ ...m, ip: e.target.value }))}
                      placeholder="172.28.0.55"
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-text-primary"
                    />
                  </div>
                  <div>
                    <label className="block text-text-muted mb-1">Hostname / Domena</label>
                    <input
                      type="text"
                      value={manualForm.hostname}
                      onChange={(e) => setManualForm((m) => ({ ...m, hostname: e.target.value }))}
                      placeholder="admin-dev.agh.edu.pl"
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-text-primary"
                    />
                  </div>
                  <div>
                    <label className="block text-text-muted mb-1">Tagi</label>
                    <input
                      type="text"
                      value={manualForm.tags}
                      onChange={(e) => setManualForm((m) => ({ ...m, tags: e.target.value }))}
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 text-text-primary"
                    />
                  </div>
                  <div>
                    <label className="block text-text-muted mb-1">Port</label>
                    <input
                      type="number"
                      value={manualForm.port}
                      onChange={(e) => setManualForm((m) => ({ ...m, port: Number(e.target.value) }))}
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-text-primary"
                    />
                  </div>
                  <div>
                    <label className="block text-text-muted mb-1">Usługa / Produkt</label>
                    <input
                      type="text"
                      value={manualForm.product}
                      onChange={(e) => setManualForm((m) => ({ ...m, product: e.target.value }))}
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 text-text-primary"
                    />
                  </div>
                  <div>
                    <label className="block text-text-muted mb-1">Wersja</label>
                    <input
                      type="text"
                      value={manualForm.version}
                      onChange={(e) => setManualForm((m) => ({ ...m, version: e.target.value }))}
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-text-primary"
                    />
                  </div>
                  <div className="sm:col-span-2">
                    <label className="block text-text-muted mb-1">Tytuł HTTP</label>
                    <input
                      type="text"
                      value={manualForm.http_title}
                      onChange={(e) => setManualForm((m) => ({ ...m, http_title: e.target.value }))}
                      placeholder="np. Staging Admin Console"
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 text-text-primary"
                    />
                  </div>
                  <div>
                    <label className="block text-text-muted mb-1">Kod HTTP</label>
                    <input
                      type="number"
                      value={manualForm.status_code}
                      onChange={(e) =>
                        setManualForm((m) => ({ ...m, status_code: Number(e.target.value) }))
                      }
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-text-primary"
                    />
                  </div>
                  <div className="sm:col-span-3">
                    <label className="block text-text-muted mb-1">Nagłówki HTTP (Klucz: Wartość)</label>
                    <textarea
                      rows={2}
                      value={manualForm.headers_text}
                      onChange={(e) => setManualForm((m) => ({ ...m, headers_text: e.target.value }))}
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated p-2 font-mono text-text-primary"
                    />
                  </div>
                  <div className="sm:col-span-3">
                    <label className="block text-text-muted mb-1">Ciasteczka Set-Cookie (1 na linię)</label>
                    <input
                      type="text"
                      value={manualForm.cookies_text}
                      onChange={(e) => setManualForm((m) => ({ ...m, cookies_text: e.target.value }))}
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-text-primary"
                    />
                  </div>
                  <div className="sm:col-span-3">
                    <label className="block text-text-muted mb-1">Notatki</label>
                    <input
                      type="text"
                      value={manualForm.notes}
                      onChange={(e) => setManualForm((m) => ({ ...m, notes: e.target.value }))}
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 text-text-primary"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={submittingManual}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-50"
                >
                  <CheckCircle2 className="h-4 w-4" />
                  {submittingManual ? 'Przetwarzanie...' : 'Dodaj i przetwórz w pipeline'}
                </button>
              </>
            )}
          </form>

          {/* Right: File Import + Export */}
          <div className="xl:col-span-5 space-y-5">
            {/* Import CSV / JSON */}
            <form
              onSubmit={handleImportSubmit}
              className="rounded-xl border border-border-subtle bg-bg-card p-5 space-y-3"
            >
              <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
                <FileUp className="h-4 w-4 text-cyan-400" />
                Import z pliku CSV / JSON
              </h2>

              {!canImport ? (
                <p className="text-xs text-amber-300">Wymagane uprawnienie import:write.</p>
              ) : (
                <>
                  <div
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={(e) => {
                      e.preventDefault();
                      handleFileChange(e.dataTransfer.files?.[0] || null);
                    }}
                    className="rounded-xl border-2 border-dashed border-border-strong bg-bg-elevated/50 p-5 text-center space-y-2"
                  >
                    <Upload className="h-6 w-6 text-cyan-400 mx-auto" />
                    <p className="text-xs text-text-secondary">
                      Przeciągnij plik <span className="font-mono">.csv</span> lub{' '}
                      <span className="font-mono">.json</span> tutaj albo wybierz z dysku
                    </p>
                    <input
                      type="file"
                      accept=".csv,.json,text/csv,application/json"
                      onChange={(e) => handleFileChange(e.target.files?.[0] || null)}
                      className="text-xs text-text-muted file:mr-2 file:py-1 file:px-3 file:rounded-md file:border-0 file:bg-cyan-500/15 file:text-cyan-300 hover:file:bg-cyan-500/25"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <label className="block text-text-muted mb-1">Format</label>
                      <select
                        value={importFormat}
                        onChange={(e) => setImportFormat(e.target.value as 'csv' | 'json')}
                        className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1.5 text-text-primary"
                      >
                        <option value="csv">CSV</option>
                        <option value="json">JSON</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-text-muted mb-1">Nazwa importu</label>
                      <input
                        type="text"
                        value={importScanName}
                        onChange={(e) => setImportScanName(e.target.value)}
                        placeholder="opcjonalnie"
                        className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1.5 text-text-primary"
                      />
                    </div>
                  </div>

                  {importPreview && (
                    <div className="rounded-lg border border-border-subtle bg-bg-primary/70 p-2.5">
                      <div className="text-[10px] font-mono uppercase text-text-muted mb-1">
                        Podgląd pliku ({importFile?.name})
                      </div>
                      <pre className="text-[11px] font-mono text-text-secondary overflow-x-auto max-h-36">
                        {importPreview}
                      </pre>
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={!importFile || importing}
                    className="w-full inline-flex items-center justify-center gap-2 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-50"
                  >
                    <FileUp className="h-3.5 w-3.5" />
                    {importing ? 'Importowanie...' : 'Zaimportuj i przeanalizuj'}
                  </button>
                </>
              )}
            </form>

            {/* Export Panel */}
            <div className="rounded-xl border border-border-subtle bg-bg-card p-5 space-y-3">
              <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
                <Download className="h-4 w-4 text-emerald-400" />
                Eksport Danych (CSV / JSON)
              </h2>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                <select
                  value={exportScanId}
                  onChange={(e) => setExportScanId(e.target.value)}
                  className="rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1.5 text-text-primary"
                >
                  <option value="">Wszystkie skany</option>
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </select>
                <select
                  value={exportState}
                  onChange={(e) => setExportState(e.target.value)}
                  className="rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1.5 text-text-primary"
                >
                  <option value="">Wszystkie stany</option>
                  <option value="ACTIVE">ACTIVE</option>
                  <option value="INTERMITTENT">INTERMITTENT</option>
                  <option value="MISSING">MISSING</option>
                </select>
                <input
                  type="text"
                  value={exportTag}
                  onChange={(e) => setExportTag(e.target.value)}
                  placeholder="Filtr tagu..."
                  className="rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1.5 text-text-primary"
                />
              </div>

              {canExport ? (
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() =>
                      api.exportData({
                        format: 'csv',
                        scan_id: exportScanId || undefined,
                        state: exportState || undefined,
                        tag: exportTag || undefined,
                      })
                    }
                    className="flex-1 inline-flex items-center justify-center gap-1.5 py-2 rounded-lg text-xs font-semibold border border-border-subtle bg-bg-elevated hover:bg-bg-hover text-text-primary"
                  >
                    <Download className="h-3.5 w-3.5 text-emerald-400" /> Pobierz CSV
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      api.exportData({
                        format: 'json',
                        scan_id: exportScanId || undefined,
                        state: exportState || undefined,
                        tag: exportTag || undefined,
                      })
                    }
                    className="flex-1 inline-flex items-center justify-center gap-1.5 py-2 rounded-lg text-xs font-semibold border border-border-subtle bg-bg-elevated hover:bg-bg-hover text-text-primary"
                  >
                    <Download className="h-3.5 w-3.5 text-cyan-400" /> Pobierz JSON
                  </button>
                </div>
              ) : (
                <p className="text-xs text-text-muted">Brak uprawnienia export:read.</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
