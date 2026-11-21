import React, { useCallback, useEffect, useState } from 'react';
import {
  CheckCircle2,
  ExternalLink,
  FileText,
  KeyRound,
  Lock,
  Plus,
  RefreshCw,
  RotateCw,
  Save,
  Send,
  Settings,
  Shield,
  Trash2,
  UserPlus,
  Users,
} from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import {
  ALL_PERMISSIONS_META,
  getRoleBadgeClasses,
  PERMISSIONS,
} from '../lib/permissions';
import { formatDateTime } from '../lib/format';
import type {
  AuditLog,
  CryptoStatusResponse,
  DefectDojoConfig,
  DefectDojoExport,
  Role,
  ScanRun,
  Service,
  User,
} from '../types/api';

type AdminTab = 'defectdojo' | 'rbac' | 'crypto' | 'audit';

export function AdminPage() {
  const { can } = useAuth();
  const toast = useToast();

  const canDD = can(PERMISSIONS.DEFECTDOJO_PUSH) || can(PERMISSIONS.ADMIN_SETTINGS);
  const canRBAC = can(PERMISSIONS.ADMIN_ROLES) || can(PERMISSIONS.ADMIN_USERS);
  const canCrypto = can(PERMISSIONS.ADMIN_SETTINGS);
  const canAudit = can(PERMISSIONS.ADMIN_AUDIT);

  const defaultTab: AdminTab = canDD
    ? 'defectdojo'
    : canRBAC
      ? 'rbac'
      : canCrypto
        ? 'crypto'
        : 'audit';

  const [activeTab, setActiveTab] = useState<AdminTab>(defaultTab);

  // DefectDojo state
  const [ddConfig, setDdConfig] = useState<DefectDojoConfig>({
    url: 'http://lab-defectdojo-mock:8000',
    api_token: '',
    product_id: 1,
    engagement_id: 1,
    verify_tls: false,
    auto_push_nmap: false,
  });
  const [ddHistory, setDdHistory] = useState<DefectDojoExport[]>([]);
  const [scans, setScans] = useState<ScanRun[]>([]);
  const [services, setServices] = useState<Service[]>([]);
  const [selectedScanForNmap, setSelectedScanForNmap] = useState('');
  const [selectedServiceIds, setSelectedServiceIds] = useState<string[]>([]);
  const [ddSeverity, setDdSeverity] = useState('High');
  const [ddBusy, setDdBusy] = useState(false);

  // RBAC state
  const [roles, setRoles] = useState<Role[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [selectedRoleId, setSelectedRoleId] = useState<string | null>(null);
  const [roleForm, setRoleForm] = useState({
    slug: '',
    name: '',
    description: '',
    permissions: [] as string[],
  });
  const [newUserForm, setNewUserForm] = useState({
    username: '',
    email: '',
    password: '',
    role_slug: 'analyst',
  });

  // Crypto state
  const [cryptoStatus, setCryptoStatus] = useState<CryptoStatusResponse | null>(null);
  const [rotatingKey, setRotatingKey] = useState(false);

  // Audit state
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [auditStatusFilter, setAuditStatusFilter] = useState('');

  const loadDefectDojo = useCallback(async () => {
    try {
      const [cfg, hist, sc, svcs] = await Promise.allSettled([
        api.getDefectDojoConfig(),
        api.listDefectDojoHistory(),
        api.listScans(),
        api.listServices({ min_score: 20 }),
      ]);
      if (cfg.status === 'fulfilled' && cfg.value) {
        setDdConfig((prev) => ({ ...prev, ...cfg.value, api_token: '' }));
      }
      if (hist.status === 'fulfilled') setDdHistory(hist.value);
      if (sc.status === 'fulfilled') {
        setScans(sc.value);
        const withXml = sc.value.find((s) => s.has_raw_nmap_xml) || sc.value[0];
        if (withXml) setSelectedScanForNmap(withXml.id);
      }
      if (svcs.status === 'fulfilled') setServices(svcs.value);
    } catch {
      // ignore
    }
  }, []);

  const loadRBAC = useCallback(async () => {
    try {
      const [r, u] = await Promise.allSettled([api.listRoles(), api.listUsers()]);
      if (r.status === 'fulfilled') setRoles(r.value);
      if (u.status === 'fulfilled') setUsers(u.value);
    } catch {
      // ignore
    }
  }, []);

  const loadCrypto = useCallback(async () => {
    try {
      const status = await api.cryptoStatus();
      setCryptoStatus(status);
    } catch (err) {
      toast.error('Błąd statusu szyfrowania', (err as Error).message);
    }
  }, [toast]);

  const loadAudit = useCallback(async () => {
    try {
      const logs = await api.listAuditLogs({
        limit: 100,
        status: auditStatusFilter || undefined,
      });
      setAuditLogs(logs);
    } catch (err) {
      toast.error('Błąd dziennika audytowego', (err as Error).message);
    }
  }, [auditStatusFilter, toast]);

  useEffect(() => {
    if (activeTab === 'defectdojo' && canDD) loadDefectDojo();
    if (activeTab === 'rbac' && canRBAC) loadRBAC();
    if (activeTab === 'crypto' && canCrypto) loadCrypto();
    if (activeTab === 'audit' && canAudit) loadAudit();
  }, [activeTab, canDD, canRBAC, canCrypto, canAudit, loadDefectDojo, loadRBAC, loadCrypto, loadAudit]);

  // DefectDojo handlers
  const handleSaveDDConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    setDdBusy(true);
    try {
      const payload: Partial<DefectDojoConfig> = {
        url: ddConfig.url,
        product_id: Number(ddConfig.product_id),
        engagement_id: Number(ddConfig.engagement_id),
        verify_tls: ddConfig.verify_tls,
        auto_push_nmap: ddConfig.auto_push_nmap,
      };
      if (ddConfig.api_token?.trim()) payload.api_token = ddConfig.api_token.trim();
      await api.updateDefectDojoConfig(payload);
      toast.success('Zapisano konfigurację DefectDojo v2', 'Token API zaszyfrowany AES-256-GCM.');
      loadDefectDojo();
    } catch (err) {
      toast.error('Błąd zapisu konfiguracji DefectDojo', (err as Error).message);
    } finally {
      setDdBusy(false);
    }
  };

  const handleTestDD = async () => {
    setDdBusy(true);
    try {
      const res = await api.testDefectDojo();
      toast.success('Połączenie z DefectDojo v2 OK', JSON.stringify(res));
    } catch (err) {
      toast.error('Test połączenia DefectDojo nieudany', (err as Error).message);
    } finally {
      setDdBusy(false);
    }
  };

  const handlePushNmap = async () => {
    if (!selectedScanForNmap) return;
    setDdBusy(true);
    try {
      await api.pushDefectDojoNmap({
        scan_run_id: selectedScanForNmap,
        engagement_id: Number(ddConfig.engagement_id) || 1,
      });
      toast.success('Wysłano Nmap XML do DefectDojo v2', 'Import Nmap Scan zakończony.');
      loadDefectDojo();
    } catch (err) {
      toast.error('Błąd eksportu Nmap XML', (err as Error).message);
    } finally {
      setDdBusy(false);
    }
  };

  const handlePushFindings = async () => {
    if (selectedServiceIds.length === 0) {
      toast.warning('Wybierz co najmniej jedną usługę do eksportu');
      return;
    }
    setDdBusy(true);
    try {
      await api.pushDefectDojoFindings({
        service_ids: selectedServiceIds,
        engagement_id: Number(ddConfig.engagement_id) || 1,
        severity: ddSeverity,
      });
      toast.success(
        'Wysłano znaleziska do DefectDojo v2',
        `Wyeksportowano ${selectedServiceIds.length} znalezisk z dowodami.`
      );
      setSelectedServiceIds([]);
      loadDefectDojo();
    } catch (err) {
      toast.error('Błąd eksportu znalezisk', (err as Error).message);
    } finally {
      setDdBusy(false);
    }
  };

  // RBAC handlers
  const togglePermission = (slug: string) => {
    setRoleForm((prev) => ({
      ...prev,
      permissions: prev.permissions.includes(slug)
        ? prev.permissions.filter((p) => p !== slug)
        : [...prev.permissions, slug],
    }));
  };

  const handleSaveRole = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      if (selectedRoleId) {
        await api.updateRole(selectedRoleId, {
          name: roleForm.name,
          description: roleForm.description,
          permissions: roleForm.permissions,
        });
        toast.success('Zaktualizowano rolę RBAC', roleForm.name);
      } else {
        await api.createRole(roleForm);
        toast.success('Utworzono nową rolę RBAC', roleForm.name);
      }
      setSelectedRoleId(null);
      setRoleForm({ slug: '', name: '', description: '', permissions: [] });
      loadRBAC();
    } catch (err) {
      toast.error('Błąd zapisu roli', (err as Error).message);
    }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createUser({
        username: newUserForm.username.trim(),
        email: newUserForm.email.trim(),
        password: newUserForm.password,
        role_slug: newUserForm.role_slug,
        active: true,
      });
      toast.success('Utworzono użytkownika', newUserForm.username);
      setNewUserForm({ username: '', email: '', password: '', role_slug: 'analyst' });
      loadRBAC();
    } catch (err) {
      toast.error('Błąd tworzenia użytkownika', (err as Error).message);
    }
  };

  // Crypto Key Rotation
  const handleRotateKey = async () => {
    if (!window.confirm('Przeprowadzić rotację klucza DEK (AES-256-GCM re-encryption)?')) return;
    setRotatingKey(true);
    try {
      await api.rotateCryptoKey();
      toast.success(
        'Rotacja klucza DEK zakończona',
        'Wszystkie wrażliwe wiersze zostały ponownie zaszyfrowane nową wersją klucza.'
      );
      await loadCrypto();
    } catch (err) {
      toast.error('Błąd rotacji klucza DEK', (err as Error).message);
    } finally {
      setRotatingKey(false);
    }
  };

  const groupedPermissions = ALL_PERMISSIONS_META.reduce<
    Record<string, typeof ALL_PERMISSIONS_META>
  >((acc, item) => {
    if (!acc[item.group]) acc[item.group] = [];
    acc[item.group].push(item);
    return acc;
  }, {});

  const cryptoSamples =
    cryptoStatus?.samples && cryptoStatus.samples.length > 0
      ? cryptoStatus.samples
      : cryptoStatus?.sample
        ? [cryptoStatus.sample]
        : [];

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-text-primary flex items-center gap-2">
            <Settings className="h-5 w-5 text-cyan-400" />
            DefectDojo v2, Dynamiczny RBAC, Szyfrowanie i Audyt
          </h1>
          <p className="text-xs text-text-muted mt-0.5">
            Integracja z DefectDojo API v2, macierz uprawnień RBAC, dowód szyfrowania AES-256-GCM
            at rest oraz Audit Log
          </p>
        </div>

        <div className="inline-flex flex-wrap rounded-lg border border-border-subtle bg-bg-card p-0.5">
          {canDD && (
            <button
              type="button"
              onClick={() => setActiveTab('defectdojo')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium ${
                activeTab === 'defectdojo'
                  ? 'bg-cyan-500/15 text-cyan-400'
                  : 'text-text-muted hover:text-text-primary'
              }`}
            >
              DefectDojo v2
            </button>
          )}
          {canRBAC && (
            <button
              type="button"
              onClick={() => setActiveTab('rbac')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium ${
                activeTab === 'rbac'
                  ? 'bg-cyan-500/15 text-cyan-400'
                  : 'text-text-muted hover:text-text-primary'
              }`}
            >
              Dynamiczny RBAC
            </button>
          )}
          {canCrypto && (
            <button
              type="button"
              onClick={() => setActiveTab('crypto')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium ${
                activeTab === 'crypto'
                  ? 'bg-cyan-500/15 text-cyan-400'
                  : 'text-text-muted hover:text-text-primary'
              }`}
            >
              Encryption At Rest
            </button>
          )}
          {canAudit && (
            <button
              type="button"
              onClick={() => setActiveTab('audit')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium ${
                activeTab === 'audit'
                  ? 'bg-cyan-500/15 text-cyan-400'
                  : 'text-text-muted hover:text-text-primary'
              }`}
            >
              Audit Log
            </button>
          )}
        </div>
      </div>

      {/* TAB 1: DEFECTDOJO v2 */}
      {activeTab === 'defectdojo' && canDD && (
        <div className="space-y-5">
          <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
            {/* Configuration */}
            <form
              onSubmit={handleSaveDDConfig}
              className="xl:col-span-5 rounded-xl border border-border-subtle bg-bg-card p-5 space-y-3 text-xs"
            >
              <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
                <Shield className="h-4 w-4 text-cyan-400" />
                Konfiguracja DefectDojo API v2
              </h2>
              <div>
                <label className="block text-text-muted mb-1">DefectDojo Base URL</label>
                <input
                  type="text"
                  value={ddConfig.url}
                  onChange={(e) => setDdConfig((c) => ({ ...c, url: e.target.value }))}
                  placeholder="http://lab-defectdojo-mock:8000"
                  className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-text-primary"
                />
              </div>
              <div>
                <label className="block text-text-muted mb-1">
                  API v2 Token{' '}
                  {ddConfig.has_api_token && (
                    <span className="text-emerald-400">(zapisany i zaszyfrowany w DB)</span>
                  )}
                </label>
                <input
                  type="password"
                  value={ddConfig.api_token || ''}
                  onChange={(e) => setDdConfig((c) => ({ ...c, api_token: e.target.value }))}
                  placeholder={ddConfig.has_api_token ? '•••••••• (pozostaw puste aby zachować)' : 'Token API...'}
                  className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-text-primary"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-text-muted mb-1">Product ID</label>
                  <input
                    type="number"
                    value={ddConfig.product_id}
                    onChange={(e) =>
                      setDdConfig((c) => ({ ...c, product_id: Number(e.target.value) }))
                    }
                    className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-text-primary"
                  />
                </div>
                <div>
                  <label className="block text-text-muted mb-1">Engagement ID</label>
                  <input
                    type="number"
                    value={ddConfig.engagement_id}
                    onChange={(e) =>
                      setDdConfig((c) => ({ ...c, engagement_id: Number(e.target.value) }))
                    }
                    className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-text-primary"
                  />
                </div>
              </div>

              <div className="flex flex-wrap gap-4 pt-1">
                <label className="inline-flex items-center gap-1.5 text-text-secondary">
                  <input
                    type="checkbox"
                    checked={ddConfig.verify_tls}
                    onChange={(e) => setDdConfig((c) => ({ ...c, verify_tls: e.target.checked }))}
                    className="accent-cyan-500"
                  />
                  Weryfikuj TLS
                </label>
                <label className="inline-flex items-center gap-1.5 text-text-secondary">
                  <input
                    type="checkbox"
                    checked={ddConfig.auto_push_nmap}
                    onChange={(e) =>
                      setDdConfig((c) => ({ ...c, auto_push_nmap: e.target.checked }))
                    }
                    className="accent-cyan-500"
                  />
                  Auto-push Nmap XML po skanie
                </label>
              </div>

              <div className="flex gap-2 pt-2">
                {can(PERMISSIONS.ADMIN_SETTINGS) && (
                  <button
                    type="submit"
                    disabled={ddBusy}
                    className="flex-1 inline-flex items-center justify-center gap-1.5 py-2 rounded-lg font-semibold bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-50"
                  >
                    <Save className="h-3.5 w-3.5" /> Zapisz
                  </button>
                )}
                <button
                  type="button"
                  disabled={ddBusy}
                  onClick={handleTestDD}
                  className="flex-1 inline-flex items-center justify-center gap-1.5 py-2 rounded-lg font-medium border border-emerald-500/35 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-50"
                >
                  <CheckCircle2 className="h-3.5 w-3.5" /> Testuj połączenie
                </button>
              </div>
            </form>

            {/* Push Actions: Nmap XML & Selected Findings */}
            <div className="xl:col-span-7 space-y-4">
              <div className="rounded-xl border border-border-subtle bg-bg-card p-5 space-y-3">
                <h3 className="text-sm font-semibold text-text-primary">
                  Eksport Nmap XML Scan (<span className="font-mono text-xs">/api/v2/import-scan/</span>)
                </h3>
                <div className="flex flex-col sm:flex-row gap-2">
                  <select
                    value={selectedScanForNmap}
                    onChange={(e) => setSelectedScanForNmap(e.target.value)}
                    className="flex-1 rounded-lg border border-border-subtle bg-bg-elevated px-3 py-2 text-xs text-text-primary"
                  >
                    <option value="">Wybierz skan z Nmap XML...</option>
                    {scans.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.name} ({s.run_type}) {s.has_raw_nmap_xml ? '✓ Nmap XML' : ''}
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    disabled={ddBusy || !selectedScanForNmap || !can(PERMISSIONS.DEFECTDOJO_PUSH)}
                    onClick={handlePushNmap}
                    className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-50"
                  >
                    <Send className="h-3.5 w-3.5" /> Wyślij Nmap XML
                  </button>
                </div>
              </div>

              <div className="rounded-xl border border-border-subtle bg-bg-card p-5 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="text-sm font-semibold text-text-primary">
                    Selektywny Eksport Znalezisk (<span className="font-mono text-xs">/api/v2/findings/</span>)
                  </h3>
                  <div className="flex items-center gap-2 text-xs">
                    <select
                      value={ddSeverity}
                      onChange={(e) => setDdSeverity(e.target.value)}
                      className="rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1 text-text-primary"
                    >
                      <option value="Critical">Critical</option>
                      <option value="High">High</option>
                      <option value="Medium">Medium</option>
                      <option value="Low">Low</option>
                      <option value="Info">Info</option>
                    </select>
                    <button
                      type="button"
                      disabled={ddBusy || selectedServiceIds.length === 0 || !can(PERMISSIONS.DEFECTDOJO_PUSH)}
                      onClick={handlePushFindings}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-semibold bg-rose-600 hover:bg-rose-500 text-white disabled:opacity-50"
                    >
                      <Send className="h-3.5 w-3.5" /> Wyślij ({selectedServiceIds.length})
                    </button>
                  </div>
                </div>

                <div className="max-h-44 overflow-y-auto space-y-1.5">
                  {services.length === 0 ? (
                    <p className="text-xs text-text-muted py-4 text-center">
                      Brak usług o podwyższonym score do eksportu.
                    </p>
                  ) : (
                    services.slice(0, 20).map((svc) => {
                      const checked = selectedServiceIds.includes(svc.id);
                      return (
                        <label
                          key={svc.id}
                          className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg border border-border-subtle bg-bg-elevated/60 hover:bg-bg-hover cursor-pointer text-xs"
                        >
                          <div className="flex items-center gap-2 min-w-0">
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={() =>
                                setSelectedServiceIds((prev) =>
                                  checked ? prev.filter((id) => id !== svc.id) : [...prev, svc.id]
                                )
                              }
                              className="accent-cyan-500"
                            />
                            <span className="font-mono font-semibold text-text-primary">
                              {svc.host_ip}:{svc.port}
                            </span>
                            <span className="text-text-secondary truncate">
                              {svc.http?.title || svc.product || svc.service_name}
                            </span>
                          </div>
                          <span className="font-mono text-amber-400 shrink-0">
                            Score {svc.interestingness}
                          </span>
                        </label>
                      );
                    })
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Export History */}
          <div className="rounded-xl border border-border-subtle bg-bg-card overflow-hidden">
            <div className="p-4 border-b border-border-subtle flex items-center justify-between">
              <h3 className="text-sm font-semibold text-text-primary">
                Historia Eksportów do DefectDojo ({ddHistory.length})
              </h3>
              <button
                type="button"
                onClick={loadDefectDojo}
                className="text-xs text-cyan-400 hover:underline flex items-center gap-1"
              >
                <RefreshCw className="h-3.5 w-3.5" /> Odśwież
              </button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-bg-elevated text-text-muted uppercase text-[11px]">
                  <tr>
                    <th className="px-4 py-2.5">Typ</th>
                    <th className="px-4 py-2.5">Tytuł</th>
                    <th className="px-4 py-2.5">Status</th>
                    <th className="px-4 py-2.5">External ID / Link</th>
                    <th className="px-4 py-2.5">Użytkownik</th>
                    <th className="px-4 py-2.5">Data</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle/60">
                  {ddHistory.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-4 py-6 text-center text-text-muted">
                        Brak wykonanych eksportów.
                      </td>
                    </tr>
                  ) : (
                    ddHistory.map((ex) => (
                      <tr key={ex.id}>
                        <td className="px-4 py-2.5 font-mono text-cyan-400">{ex.export_type}</td>
                        <td className="px-4 py-2.5 text-text-primary">{ex.title}</td>
                        <td className="px-4 py-2.5">
                          <span
                            className={`px-2 py-0.5 rounded font-mono text-[10px] border ${
                              ex.status === 'success'
                                ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                                : 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                            }`}
                          >
                            {ex.status}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 font-mono">
                          {ex.external_url ? (
                            <a
                              href={ex.external_url}
                              target="_blank"
                              rel="noreferrer"
                              className="inline-flex items-center gap-1 text-cyan-400 hover:underline"
                            >
                              #{ex.external_id || 'link'} <ExternalLink className="h-3 w-3" />
                            </a>
                          ) : (
                            ex.external_id || ex.error_message || '—'
                          )}
                        </td>
                        <td className="px-4 py-2.5 text-text-secondary">{ex.exported_by}</td>
                        <td className="px-4 py-2.5 font-mono text-text-muted">
                          {formatDateTime(ex.created_at)}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: DYNAMIC RBAC */}
      {activeTab === 'rbac' && canRBAC && (
        <div className="space-y-5">
          {/* Roles & Permission Matrix */}
          <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
            <div className="xl:col-span-5 rounded-xl border border-border-subtle bg-bg-card p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
                  <KeyRound className="h-4 w-4 text-cyan-400" />
                  Role RBAC ({roles.length})
                </h2>
                <button
                  type="button"
                  onClick={() => {
                    setSelectedRoleId(null);
                    setRoleForm({ slug: '', name: '', description: '', permissions: ['dashboard:read'] });
                  }}
                  className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:underline"
                >
                  <Plus className="h-3.5 w-3.5" /> Nowa rola
                </button>
              </div>
              <div className="space-y-2">
                {roles.map((r) => (
                  <div
                    key={r.id}
                    onClick={() => {
                      setSelectedRoleId(r.id);
                      setRoleForm({
                        slug: r.slug,
                        name: r.name,
                        description: r.description,
                        permissions: r.permissions || [],
                      });
                    }}
                    className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                      selectedRoleId === r.id
                        ? 'border-cyan-500/50 bg-cyan-500/10'
                        : 'border-border-subtle bg-bg-elevated/60 hover:bg-bg-hover'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span
                        className={`text-xs font-semibold px-2 py-0.5 rounded border ${getRoleBadgeClasses(
                          r.slug
                        )}`}
                      >
                        {r.name}
                      </span>
                      <div className="flex items-center gap-1.5">
                        <span className="text-[11px] font-mono text-text-muted">
                          {r.permissions?.includes('*')
                            ? 'ALL (*)'
                            : `${r.permissions?.length || 0} perm`}
                        </span>
                        {!r.is_system && (
                          <button
                            type="button"
                            onClick={async (e) => {
                              e.stopPropagation();
                              await api.deleteRole(r.id);
                              toast.success('Usunięto rolę', r.name);
                              loadRBAC();
                            }}
                            className="text-text-muted hover:text-rose-400"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </div>
                    </div>
                    <p className="text-[11px] text-text-muted mt-1">{r.description}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Role Editor + Permission Checkboxes */}
            <form
              onSubmit={handleSaveRole}
              className="xl:col-span-7 rounded-xl border border-border-subtle bg-bg-card p-5 space-y-4 text-xs"
            >
              <h3 className="text-sm font-semibold text-text-primary">
                {selectedRoleId ? `Edycja roli: ${roleForm.name}` : 'Tworzenie Własnej Roli RBAC'}
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="block text-text-muted mb-1">Slug</label>
                  <input
                    type="text"
                    required
                    disabled={Boolean(selectedRoleId)}
                    value={roleForm.slug}
                    onChange={(e) => setRoleForm((f) => ({ ...f, slug: e.target.value }))}
                    placeholder="np. soc_auditor"
                    className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-text-primary disabled:opacity-60"
                  />
                </div>
                <div className="sm:col-span-2">
                  <label className="block text-text-muted mb-1">Nazwa wyświetlana</label>
                  <input
                    type="text"
                    required
                    value={roleForm.name}
                    onChange={(e) => setRoleForm((f) => ({ ...f, name: e.target.value }))}
                    placeholder="np. Audytor SOC CBI AGH"
                    className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 text-text-primary"
                  />
                </div>
                <div className="sm:col-span-3">
                  <label className="block text-text-muted mb-1">Opis</label>
                  <input
                    type="text"
                    value={roleForm.description}
                    onChange={(e) => setRoleForm((f) => ({ ...f, description: e.target.value }))}
                    className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 text-text-primary"
                  />
                </div>
              </div>

              <div className="space-y-3 max-h-72 overflow-y-auto pr-1">
                {Object.entries(groupedPermissions).map(([group, list]) => (
                  <div
                    key={group}
                    className="rounded-lg border border-border-subtle bg-bg-elevated/60 p-3"
                  >
                    <div className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400 mb-2">
                      {group}
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                      {list.map((p) => {
                        const hasAll = roleForm.permissions.includes('*');
                        const checked = hasAll || roleForm.permissions.includes(p.slug);
                        return (
                          <label
                            key={p.slug}
                            className="flex items-start gap-2 cursor-pointer text-[11px]"
                          >
                            <input
                              type="checkbox"
                              disabled={hasAll}
                              checked={checked}
                              onChange={() => togglePermission(p.slug)}
                              className="mt-0.5 accent-cyan-500"
                            />
                            <span>
                              <span className="font-mono text-text-primary block">{p.slug}</span>
                              <span className="text-text-muted">{p.label}</span>
                            </span>
                          </label>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>

              <button
                type="submit"
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg font-semibold bg-cyan-600 hover:bg-cyan-500 text-white"
              >
                <Save className="h-3.5 w-3.5" /> Zapisz rolę RBAC
              </button>
            </form>
          </div>

          {/* Users Management */}
          <div className="rounded-xl border border-border-subtle bg-bg-card p-5 space-y-4">
            <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
              <Users className="h-4 w-4 text-cyan-400" />
              Użytkownicy Systemu ({users.length})
            </h3>

            <form
              onSubmit={handleCreateUser}
              className="grid grid-cols-1 sm:grid-cols-5 gap-2.5 text-xs"
            >
              <input
                type="text"
                required
                value={newUserForm.username}
                onChange={(e) => setNewUserForm((u) => ({ ...u, username: e.target.value }))}
                placeholder="Nazwa użytkownika"
                className="rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 text-text-primary"
              />
              <input
                type="email"
                value={newUserForm.email}
                onChange={(e) => setNewUserForm((u) => ({ ...u, email: e.target.value }))}
                placeholder="email@agh.edu.pl"
                className="rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 text-text-primary"
              />
              <input
                type="password"
                required
                value={newUserForm.password}
                onChange={(e) => setNewUserForm((u) => ({ ...u, password: e.target.value }))}
                placeholder="Hasło"
                className="rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 text-text-primary"
              />
              <select
                value={newUserForm.role_slug}
                onChange={(e) => setNewUserForm((u) => ({ ...u, role_slug: e.target.value }))}
                className="rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 text-text-primary"
              >
                {roles.map((r) => (
                  <option key={r.id} value={r.slug}>
                    {r.name}
                  </option>
                ))}
              </select>
              <button
                type="submit"
                className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold py-1.5"
              >
                <UserPlus className="h-3.5 w-3.5" /> Dodaj
              </button>
            </form>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-bg-elevated text-text-muted uppercase text-[11px]">
                  <tr>
                    <th className="px-3 py-2">Użytkownik</th>
                    <th className="px-3 py-2">Email (encrypted at rest)</th>
                    <th className="px-3 py-2">Rola</th>
                    <th className="px-3 py-2">Status</th>
                    <th className="px-3 py-2 text-right">Akcje</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle/60">
                  {users.map((u) => (
                    <tr key={u.id}>
                      <td className="px-3 py-2 font-mono font-semibold text-text-primary">
                        {u.username}
                      </td>
                      <td className="px-3 py-2 text-text-secondary">{u.email || '—'}</td>
                      <td className="px-3 py-2">
                        <span
                          className={`px-2 py-0.5 rounded border text-[11px] ${getRoleBadgeClasses(
                            u.role_slug
                          )}`}
                        >
                          {u.role_name || u.role_slug}
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        <span className={u.active !== false ? 'text-emerald-400' : 'text-rose-400'}>
                          {u.active !== false ? 'Aktywny' : 'Wyłączony'}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-right">
                        <button
                          type="button"
                          onClick={async () => {
                            if (!window.confirm(`Usunąć użytkownika ${u.username}?`)) return;
                            await api.deleteUser(u.id);
                            toast.success('Usunięto użytkownika', u.username);
                            loadRBAC();
                          }}
                          className="text-text-muted hover:text-rose-400"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: ENCRYPTION AT REST PROOF PANEL */}
      {activeTab === 'crypto' && canCrypto && (
        <div className="space-y-5">
          <div className="rounded-xl border border-emerald-500/35 bg-bg-card p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="h-11 w-11 rounded-xl bg-emerald-500/15 border border-emerald-500/35 flex items-center justify-center text-emerald-400 shrink-0">
                <Lock className="h-5 w-5" />
              </div>
              <div>
                <h2 className="text-base font-bold text-text-primary flex items-center gap-2">
                  Encryption At Rest — Envelope Encryption (AES-256-GCM AEAD)
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/35">
                    AKTYWNE
                  </span>
                </h2>
                <p className="text-xs text-text-muted mt-1">
                  Wszystkie pola wrażliwe (IP, hosty, nagłówki HTTP, ciasteczka, certyfikaty TLS,
                  notatki, nadpisania, surowy Nmap XML, tokeny API) są szyfrowane z AAD (
                  <span className="font-mono">table:record_id:column</span>) i indeksowane przez
                  HMAC-SHA256 blind index.
                </p>
                <div className="flex flex-wrap gap-3 mt-2.5 text-xs font-mono">
                  <span className="text-text-secondary">
                    Aktywny DEK:{' '}
                    <strong className="text-cyan-400">
                      {cryptoStatus?.key_version || cryptoStatus?.active_kid || 'v1'}
                    </strong>
                  </span>
                  <span className="text-text-secondary">
                    Algorytm:{' '}
                    <strong className="text-emerald-400">
                      {cryptoStatus?.algorithm || 'AES-256-GCM + AAD'}
                    </strong>
                  </span>
                  {cryptoStatus?.rotated_at && (
                    <span className="text-text-muted">
                      Ostatnia rotacja: {formatDateTime(cryptoStatus.rotated_at)}
                    </span>
                  )}
                </div>
              </div>
            </div>

            <button
              type="button"
              disabled={rotatingKey}
              onClick={handleRotateKey}
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-semibold bg-amber-600 hover:bg-amber-500 text-white shrink-0 disabled:opacity-50"
            >
              <RotateCw className={`h-4 w-4 ${rotatingKey ? 'animate-spin' : ''}`} />
              {rotatingKey ? 'Rotacja DEK...' : 'Rotuj klucz DEK'}
            </button>
          </div>

          {/* Side-by-Side Raw DB Ciphertext vs Decrypted View */}
          <div className="rounded-xl border border-border-subtle bg-bg-card p-5 space-y-4">
            <h3 className="text-sm font-semibold text-text-primary">
              Dowód Szyfrowania w Bazie Danych (Raw DB Ciphertext vs Zdekryptowany Widok)
            </h3>

            {cryptoSamples.length === 0 ? (
              <p className="text-xs text-text-muted">
                Dodaj lub przeskanuj co najmniej jednego hosta, aby zobaczyć żywą próbkę szyfrogramu
                z bazy danych.
              </p>
            ) : (
              cryptoSamples.map((s, idx) => (
                <div
                  key={idx}
                  className="grid grid-cols-1 lg:grid-cols-2 gap-4 rounded-xl border border-border-subtle bg-bg-elevated/60 p-4"
                >
                  <div className="space-y-1.5">
                    <div className="text-[11px] font-mono uppercase tracking-wider text-amber-400 font-semibold">
                      Surowy wiersz w PostgreSQL ({s.table || 'hosts'}.{s.column || 'ip_enc'})
                    </div>
                    <div className="rounded-lg border border-amber-500/30 bg-bg-primary p-3 font-mono text-xs text-amber-300 break-all">
                      {s.raw_ciphertext || s.ciphertext || 'enc:v1:...'}
                    </div>
                    {s.aad && (
                      <div className="text-[11px] font-mono text-text-muted">AAD: {s.aad}</div>
                    )}
                    {s.blind_index && (
                      <div className="text-[11px] font-mono text-text-muted truncate">
                        Blind Index (HMAC-SHA256): {s.blind_index}
                      </div>
                    )}
                  </div>

                  <div className="space-y-1.5">
                    <div className="text-[11px] font-mono uppercase tracking-wider text-emerald-400 font-semibold">
                      Po autoryzowanej deszyfracji w pamięci (AegisASI API)
                    </div>
                    <div className="rounded-lg border border-emerald-500/30 bg-bg-primary p-3 font-mono text-xs text-emerald-300 break-all">
                      {s.decrypted_value || s.plaintext || '—'}
                    </div>
                    <div className="text-[11px] text-text-muted">
                      Klucz szyfrujący nigdy nie opuszcza warstwy Vault i nie jest eksponowany w API.
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 4: AUDIT LOG */}
      {activeTab === 'audit' && canAudit && (
        <div className="rounded-xl border border-border-subtle bg-bg-card overflow-hidden">
          <div className="p-4 border-b border-border-subtle flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
              <FileText className="h-4 w-4 text-cyan-400" />
              Dziennik Audytowy — Audit Log ({auditLogs.length})
            </h2>
            <div className="flex items-center gap-2">
              <select
                value={auditStatusFilter}
                onChange={(e) => setAuditStatusFilter(e.target.value)}
                className="rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1 text-xs text-text-primary"
              >
                <option value="">Wszystkie statusy</option>
                <option value="success">success</option>
                <option value="denied">denied (403)</option>
                <option value="error">error</option>
              </select>
              <button
                type="button"
                onClick={loadAudit}
                className="p-1.5 rounded-lg border border-border-subtle bg-bg-elevated hover:bg-bg-hover text-text-secondary"
              >
                <RefreshCw className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-bg-elevated text-text-muted uppercase text-[11px]">
                <tr>
                  <th className="px-4 py-2.5">Czas</th>
                  <th className="px-4 py-2.5">Użytkownik / Rola</th>
                  <th className="px-4 py-2.5">Akcja</th>
                  <th className="px-4 py-2.5">Zasób</th>
                  <th className="px-4 py-2.5">Status</th>
                  <th className="px-4 py-2.5">IP</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle/60">
                {auditLogs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-text-muted">
                      Brak wpisów audytowych.
                    </td>
                  </tr>
                ) : (
                  auditLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-bg-hover/40">
                      <td className="px-4 py-2.5 font-mono text-[11px] text-text-muted whitespace-nowrap">
                        {formatDateTime(log.created_at)}
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="font-mono font-semibold text-text-primary">
                          {log.username}
                        </span>
                        <span className="ml-1.5 text-[10px] font-mono text-text-muted">
                          ({log.role_slug})
                        </span>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-cyan-400">{log.action}</td>
                      <td className="px-4 py-2.5 font-mono text-text-secondary">
                        {log.resource}
                        {log.resource_id ? `/${log.resource_id.slice(0, 8)}` : ''}
                      </td>
                      <td className="px-4 py-2.5">
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                            log.status === 'success'
                              ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                              : log.status === 'denied'
                                ? 'bg-rose-500/15 text-rose-400 border-rose-500/35'
                                : 'bg-amber-500/15 text-amber-400 border-amber-500/35'
                          }`}
                        >
                          {log.status}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[11px] text-text-muted">
                        {log.ip_address || '—'}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
