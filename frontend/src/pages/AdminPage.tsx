import React, { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  RiAddLine,
  RiCheckboxCircleLine,
  RiDeleteBinLine,
  RiExternalLinkLine,
  RiFileList3Line,
  RiLockLine,
  RiLoopRightLine,
  RiRefreshLine,
  RiSave3Line,
  RiSendPlaneLine,
  RiUserAddLine,
} from '@remixicon/react';
import { api } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/context/ToastContext';
import { ALL_PERMISSIONS_META, getRoleBadgeClasses, PERMISSIONS } from '@/lib/permissions';
import { formatDateTime, type Tone } from '@/lib/format';
import { cn } from '@/lib/utils';
import type {
  AuditLog,
  CryptoStatusResponse,
  DefectDojoConfig,
  DefectDojoExport,
  DefectDojoStatus,
  Role,
  ScanRun,
  Service,
  User,
} from '@/types/api';
import { WebhookPanel } from '@/components/WebhookPanel';
import { DOJO_STATUS_CHANGED } from '@/components/DojoStatusChip';
import { Button } from '@/components/ui/button';
import { Card, CardAction, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
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
  CopyButton,
  Empty,
  Field,
  PageHeader,
  Pill,
  SectionTitle,
  SimpleSelect,
} from '@/components/common';

type AdminTab = 'defectdojo' | 'users' | 'rbac' | 'crypto' | 'audit' | 'alerts';

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];

const EXPORT_TYPE_LABEL: Record<string, string> = {
  nmap_xml: 'nmap XML',
  change_findings: 'Change findings',
  finding: 'Manual finding',
};

const AUDIT_RESOURCES: [RegExp, string][] = [
  [/^\/api\/v1\/auth\/login$/, 'Login'],
  [/^\/api\/v1\/profiles\/[^/]+\/run$/, 'Scan started from profile'],
  [/^\/api\/v1\/profiles/, 'Scan profile'],
  [/^\/api\/v1\/scans\/[^/]+\/stop$/, 'Scan stopped'],
  [/^\/api\/v1\/scans\/[^/]+\/pause$/, 'Scan paused'],
  [/^\/api\/v1\/scans\/[^/]+\/resume$/, 'Scan resumed'],
  [/^\/api\/v1\/scans/, 'Scan'],
  [/^\/api\/v1\/tag-rules/, 'Tag rules'],
  [/^\/api\/v1\/admin\/users/, 'User'],
  [/^\/api\/v1\/admin\/roles/, 'Role'],
  [/^\/api\/v1\/admin\/crypto/, 'Encryption key'],
  [/^\/api\/v1\/integrations\/defectdojo\/sync$/, 'DefectDojo sync started'],
  [/^\/api\/v1\/integrations\/defectdojo\/test$/, 'DefectDojo connection tested'],
  [/^\/api\/v1\/integrations\/defectdojo\/push-/, 'Manual DefectDojo push started'],
  [/^\/api\/v1\/integrations\/defectdojo\/login$/, 'DefectDojo login shown in the header'],
  [/^\/api\/v1\/integrations\/defectdojo/, 'DefectDojo integration'],
  [/^\/api\/v1\/integrations\/webhook/, 'Alert webhook'],
  [/^\/api\/v1\/agents/, 'Scanning agent'],
  [/^\/api\/v1\/(hosts|services)\/[^/]+\/overrides$/, 'Analyst override'],
  [/^\/api\/v1\/signatures/, 'Signature'],
  [/^\/api\/v1\/(targets|exclusions)/, 'Scope'],
  [/^\/api\/v1\/ingest/, 'Import'],
];

/** "POST /api/v1/profiles/<id>/run" -> "Scan started from profile". */
function auditActionLabel(log: AuditLog): string {
  const [method, path = ''] = log.action.split(' ');
  const hit = AUDIT_RESOURCES.find(([re]) => re.test(path));
  if (!hit) return log.action;
  const what = hit[1];
  if (what === 'Login') return log.status === 'success' ? 'Login' : 'Failed login';
  if (/started|stopped|paused|resumed|tested/.test(what)) return what;
  const verb = method === 'POST' ? 'created' : method === 'DELETE' ? 'deleted' : method === 'PUT' || method === 'PATCH' ? 'changed' : '';
  return verb ? `${what} ${verb}` : what;
}

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
      ? 'users'
      : canCrypto
        ? 'crypto'
        : 'audit';

  const [searchParams] = useSearchParams();
  const tabParam = searchParams.get('tab') as AdminTab | null;
  const [activeTab, setActiveTab] = useState<AdminTab>(
    tabParam && ['defectdojo', 'users', 'rbac', 'crypto', 'audit', 'alerts'].includes(tabParam) ? tabParam : defaultTab
  );

  const [ddConfig, setDdConfig] = useState<DefectDojoConfig>({
    url: 'http://lab-defectdojo-mock:8000',
    api_token: '',
    product_id: 1,
    engagement_id: 1,
    verify_tls: false,
    auto_push_nmap: false,
    auto_push_findings: true,
  });
  const [ddStatus, setDdStatus] = useState<DefectDojoStatus | null>(null);
  const [ddSyncing, setDdSyncing] = useState(false);
  const [ddHistory, setDdHistory] = useState<DefectDojoExport[]>([]);
  const [scans, setScans] = useState<ScanRun[]>([]);
  const [services, setServices] = useState<Service[]>([]);
  const [selectedScanForNmap, setSelectedScanForNmap] = useState('');
  const [selectedServiceIds, setSelectedServiceIds] = useState<string[]>([]);
  const [ddSeverity, setDdSeverity] = useState('High');
  const [ddBusy, setDdBusy] = useState(false);
  const [ddLogin, setDdLogin] = useState({ username: '', password: '' });
  const [ddLoginBusy, setDdLoginBusy] = useState(false);

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

  const [cryptoStatus, setCryptoStatus] = useState<CryptoStatusResponse | null>(null);
  const [rotatingKey, setRotatingKey] = useState(false);

  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [auditStatusFilter, setAuditStatusFilter] = useState('');

  const loadDefectDojo = useCallback(async () => {
    try {
      const [cfg, hist, sc, svcs, st] = await Promise.allSettled([
        api.getDefectDojoConfig(),
        api.listDefectDojoHistory(),
        api.listScans(),
        api.listServices({ min_score: 20 }),
        api.defectDojoStatus(),
      ]);
      if (st.status === 'fulfilled') {
        setDdStatus(st.value);
        setDdLogin(st.value.login ?? { username: '', password: '' });
      }
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
      toast.error('Could not load encryption status', (err as Error).message);
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
      toast.error('Could not load the audit log', (err as Error).message);
    }
  }, [auditStatusFilter, toast]);

  useEffect(() => {
    if (activeTab === 'defectdojo' && canDD) loadDefectDojo();
    if ((activeTab === 'rbac' || activeTab === 'users') && canRBAC) loadRBAC();
    if (activeTab === 'crypto' && canCrypto) loadCrypto();
    if (activeTab === 'audit' && canAudit) loadAudit();
  }, [activeTab, canDD, canRBAC, canCrypto, canAudit, loadDefectDojo, loadRBAC, loadCrypto, loadAudit]);

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
        auto_push_findings: ddConfig.auto_push_findings ?? true,
      };
      if (ddConfig.api_token?.trim()) payload.api_token = ddConfig.api_token.trim();
      await api.updateDefectDojoConfig(payload);
      toast.success('Saved', 'API token stored encrypted (AES-256-GCM)');
      window.dispatchEvent(new Event(DOJO_STATUS_CHANGED));
      loadDefectDojo();
    } catch (err) {
      toast.error('Save failed', (err as Error).message);
    } finally {
      setDdBusy(false);
    }
  };

  const handleSaveDDLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    const username = ddLogin.username.trim();
    if (!username || !ddLogin.password) {
      toast.warning('Enter both a username and a password');
      return;
    }
    setDdLoginBusy(true);
    try {
      await api.saveDefectDojoLogin({ username, password: ddLogin.password });
      toast.success('Login saved', 'The DefectDojo chip in the header now shows it');
      window.dispatchEvent(new Event(DOJO_STATUS_CHANGED));
      loadDefectDojo();
    } catch (err) {
      toast.error('Save failed', (err as Error).message);
    } finally {
      setDdLoginBusy(false);
    }
  };

  const handleClearDDLogin = async () => {
    setDdLoginBusy(true);
    try {
      await api.clearDefectDojoLogin();
      setDdLogin({ username: '', password: '' });
      toast.success('Login cleared', 'The DefectDojo chip no longer shows a login');
      window.dispatchEvent(new Event(DOJO_STATUS_CHANGED));
      loadDefectDojo();
    } catch (err) {
      toast.error('Clear failed', (err as Error).message);
    } finally {
      setDdLoginBusy(false);
    }
  };

  const handleTestDD = async () => {
    setDdBusy(true);
    try {
      const res = await api.testDefectDojo();
      toast.success('DefectDojo connection OK', String((res as Record<string, unknown>).message || ''));
    } catch (err) {
      toast.error('DefectDojo connection failed', (err as Error).message);
    } finally {
      setDdBusy(false);
    }
  };

  const handleSyncNow = async () => {
    setDdSyncing(true);
    try {
      await api.syncDefectDojoNow();
      toast.success('DefectDojo synced', 'Change findings of the whole inventory and triage decisions pushed');
      loadDefectDojo();
    } catch (err) {
      toast.error('DefectDojo sync failed', (err as Error).message);
    } finally {
      setDdSyncing(false);
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
      toast.success('nmap XML imported into DefectDojo');
      loadDefectDojo();
    } catch (err) {
      toast.error('nmap XML push failed', (err as Error).message);
    } finally {
      setDdBusy(false);
    }
  };

  const handlePushFindings = async () => {
    if (selectedServiceIds.length === 0) {
      toast.warning('Select at least one service');
      return;
    }
    setDdBusy(true);
    try {
      await api.pushDefectDojoFindings({
        service_ids: selectedServiceIds,
        engagement_id: Number(ddConfig.engagement_id) || 1,
        severity: ddSeverity,
      });
      toast.success('Findings sent', `${selectedServiceIds.length} service(s)`);
      setSelectedServiceIds([]);
      loadDefectDojo();
    } catch (err) {
      toast.error('Push failed', (err as Error).message);
    } finally {
      setDdBusy(false);
    }
  };

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
        toast.success('Role saved', roleForm.name);
      } else {
        await api.createRole(roleForm);
        toast.success('Role created', roleForm.name);
      }
      setSelectedRoleId(null);
      setRoleForm({ slug: '', name: '', description: '', permissions: [] });
      loadRBAC();
    } catch (err) {
      toast.error('Could not save the role', (err as Error).message);
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
      toast.success('User added', newUserForm.username);
      setNewUserForm({ username: '', email: '', password: '', role_slug: 'analyst' });
      loadRBAC();
    } catch (err) {
      toast.error('Could not create the user', (err as Error).message);
    }
  };

  const handleRotateKey = async () => {
    if (!window.confirm('Rotate the data encryption key? All encrypted fields are re-encrypted with the new key.')) return;
    setRotatingKey(true);
    try {
      await api.rotateCryptoKey();
      toast.success('Key rotated');
      await loadCrypto();
    } catch (err) {
      toast.error('Key rotation failed', (err as Error).message);
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

  const roleOptions = roles.map((r) => ({ value: r.slug, label: r.name }));

  const auditTone = (status: string): Tone =>
    status === 'success' ? 'success' : status === 'denied' ? 'danger' : 'warning';

  return (
    <div>
      <PageHeader title="Admin" />

      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as AdminTab)} className="gap-6">
        <TabsList variant="line" className="max-w-full flex-wrap">
          {canDD && <TabsTrigger value="defectdojo">DefectDojo</TabsTrigger>}
          {canRBAC && <TabsTrigger value="users">Users</TabsTrigger>}
          {canRBAC && <TabsTrigger value="rbac">Roles (RBAC)</TabsTrigger>}
          {canCrypto && <TabsTrigger value="crypto">Encryption</TabsTrigger>}
          {canCrypto && <TabsTrigger value="alerts">Alerts</TabsTrigger>}
          {canAudit && <TabsTrigger value="audit">Audit log</TabsTrigger>}
        </TabsList>

        {canDD && (
          <TabsContent value="defectdojo" className="space-y-6">
            <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
              <div className="space-y-6 xl:col-span-5">
                <Card size="sm" className="h-fit">
                  <form onSubmit={handleSaveDDConfig} className="flex flex-col gap-(--card-spacing)">
                    <CardHeader className="border-b">
                      <CardTitle className="text-sm">Connection (API v2)</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-5">
                      <Field label="Base URL" htmlFor="dd-url">
                        <Input
                          id="dd-url"
                          value={ddConfig.url}
                          onChange={(e) => setDdConfig((c) => ({ ...c, url: e.target.value }))}
                          placeholder="http://lab-defectdojo-mock:8000"
                          className="font-mono"
                        />
                      </Field>
                      <Field
                        label={
                          <span className="flex items-center gap-2">
                            API token
                            {ddConfig.has_api_token && (
                              <Pill tone="success">
                                <RiLockLine className="size-3" /> stored encrypted
                              </Pill>
                            )}
                          </span>
                        }
                        htmlFor="dd-token"
                      >
                        <Input
                          id="dd-token"
                          type="password"
                          value={ddConfig.api_token || ''}
                          onChange={(e) => setDdConfig((c) => ({ ...c, api_token: e.target.value }))}
                          placeholder={ddConfig.has_api_token ? '•••••••• (unchanged)' : 'Token'}
                          className="font-mono"
                        />
                      </Field>
                      <div className="grid grid-cols-2 gap-4">
                        <Field label="Product ID" htmlFor="dd-product">
                          <Input
                            id="dd-product"
                            type="number"
                            value={ddConfig.product_id}
                            onChange={(e) =>
                              setDdConfig((c) => ({ ...c, product_id: Number(e.target.value) }))
                            }
                            className="font-mono"
                          />
                        </Field>
                        <Field label="Engagement ID" htmlFor="dd-engagement">
                          <Input
                            id="dd-engagement"
                            type="number"
                            value={ddConfig.engagement_id}
                            onChange={(e) =>
                              setDdConfig((c) => ({ ...c, engagement_id: Number(e.target.value) }))
                            }
                            className="font-mono"
                          />
                        </Field>
                      </div>
                      <div className="space-y-3 pt-1">
                        <Label className="justify-between">
                          <span className="text-xs font-normal tracking-normal normal-case">
                            Verify TLS certificate
                          </span>
                          <Switch
                            checked={ddConfig.verify_tls}
                            onCheckedChange={(checked) =>
                              setDdConfig((c) => ({ ...c, verify_tls: checked }))
                            }
                          />
                        </Label>
                        <Label className="justify-between">
                          <span className="text-xs font-normal tracking-normal normal-case">
                            Push change findings after every completed run (and sync triage)
                          </span>
                          <Switch
                            checked={ddConfig.auto_push_findings ?? true}
                            onCheckedChange={(checked) =>
                              setDdConfig((c) => ({ ...c, auto_push_findings: checked }))
                            }
                          />
                        </Label>
                        <Label className="justify-between">
                          <span className="text-xs font-normal tracking-normal normal-case">
                            Push nmap XML after every completed run
                          </span>
                          <Switch
                            checked={ddConfig.auto_push_nmap}
                            onCheckedChange={(checked) =>
                              setDdConfig((c) => ({ ...c, auto_push_nmap: checked }))
                            }
                          />
                        </Label>
                      </div>
                    </CardContent>
                    <CardFooter className="justify-end gap-2 border-t">
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        disabled={ddBusy}
                        onClick={handleTestDD}
                      >
                        <RiCheckboxCircleLine /> Test
                      </Button>
                      {can(PERMISSIONS.ADMIN_SETTINGS) && (
                        <Button type="submit" size="sm" disabled={ddBusy}>
                          <RiSave3Line /> Save
                        </Button>
                      )}
                    </CardFooter>
                  </form>
                </Card>

                <Card size="sm" className="h-fit">
                  <form onSubmit={handleSaveDDLogin} autoComplete="off" className="flex flex-col gap-(--card-spacing)">
                    <CardHeader className="border-b">
                      <CardTitle className="text-sm">Login shown in the header</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4 text-xs">
                      <p className="text-muted-foreground">
                        Anyone signed in to Dzięcioł sees this login in the DefectDojo chip.
                      </p>
                      {ddStatus?.login ? (
                        <dl className="space-y-1.5">
                          {(
                            [
                              ['Username', ddStatus.login.username, false],
                              ['Password', ddStatus.login.password, true],
                            ] as const
                          ).map(([label, value, mono]) => (
                            <div key={label} className="flex items-center gap-2">
                              <dt className="w-20 shrink-0 text-[10px] tracking-wider text-muted-foreground uppercase">{label}</dt>
                              <dd className={cn('min-w-0 flex-1 truncate select-all', mono ? 'font-mono' : 'font-medium')}>{value}</dd>
                              <CopyButton text={value} label={`Copy ${label.toLowerCase()}`} />
                            </div>
                          ))}
                        </dl>
                      ) : (
                        <p>No login set. The chip shows the sync status and a link only.</p>
                      )}
                      {can(PERMISSIONS.ADMIN_SETTINGS) && (
                        <div className="grid grid-cols-2 gap-4">
                          <Field label="Username" htmlFor="dd-login-username">
                            <Input
                              id="dd-login-username"
                              value={ddLogin.username}
                              onChange={(e) => setDdLogin((l) => ({ ...l, username: e.target.value }))}
                              autoComplete="off"
                              data-1p-ignore
                              data-lpignore="true"
                              spellCheck={false}
                            />
                          </Field>
                          <Field label="Password" htmlFor="dd-login-password">
                            <Input
                              id="dd-login-password"
                              value={ddLogin.password}
                              onChange={(e) => setDdLogin((l) => ({ ...l, password: e.target.value }))}
                              autoComplete="off"
                              data-1p-ignore
                              data-lpignore="true"
                              spellCheck={false}
                              className="font-mono"
                            />
                          </Field>
                        </div>
                      )}
                    </CardContent>
                    {can(PERMISSIONS.ADMIN_SETTINGS) && (
                      <CardFooter className="justify-end gap-2 border-t">
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          disabled={ddLoginBusy || !ddStatus?.login}
                          onClick={handleClearDDLogin}
                        >
                          <RiDeleteBinLine /> Clear
                        </Button>
                        <Button type="submit" size="sm" disabled={ddLoginBusy}>
                          <RiSave3Line /> Save
                        </Button>
                      </CardFooter>
                    )}
                  </form>
                </Card>
              </div>

              <div className="space-y-6 xl:col-span-7">
                <Card size="sm">
                  <CardHeader className="border-b">
                    <CardTitle className="text-sm">Automatic sync</CardTitle>
                    <CardAction>
                      {can(PERMISSIONS.DEFECTDOJO_PUSH) && (
                        <Button type="button" variant="outline" size="sm" disabled={ddSyncing} onClick={handleSyncNow}>
                          <RiRefreshLine className={cn(ddSyncing && 'animate-spin')} /> Push now
                        </Button>
                      )}
                    </CardAction>
                  </CardHeader>
                  <CardContent className="space-y-3 text-xs">
                    <p className="text-muted-foreground">
                      After every completed run (local or agent) Dzięcioł reimports the run&apos;s nmap XML into
                      &quot;Dzięcioł Nmap: &lt;profile&gt;&quot; and the actionable change findings of the whole inventory
                      (risky exposures, admin panels, end-of-life versions, new services, gone hosts, with owner) into
                      one &quot;Dzięcioł changes&quot; test, so a host covered by several profiles gives one finding. Fixed
                      items are closed in DefectDojo. Analyst decisions are mirrored: false positive becomes false_p,
                      accepted risk becomes risk accepted with the reason and expiry as a note.
                    </p>
                    {ddStatus?.sync?.last_sync_at ? (
                      <dl className="grid grid-cols-2 gap-x-6 gap-y-1 sm:grid-cols-4">
                        <div>
                          <dt className="text-[10px] tracking-wider text-muted-foreground uppercase">Last sync</dt>
                          <dd className="font-mono">{formatDateTime(ddStatus.sync.last_sync_at)}</dd>
                        </div>
                        <div>
                          <dt className="text-[10px] tracking-wider text-muted-foreground uppercase">Result</dt>
                          <dd>
                            <Pill tone={ddStatus.sync.last_status === 'failed' ? 'danger' : 'success'}>
                              {ddStatus.sync.last_status || 'n/a'}
                            </Pill>
                          </dd>
                        </div>
                        <div>
                          <dt className="text-[10px] tracking-wider text-muted-foreground uppercase">Change findings</dt>
                          <dd className="font-mono">{ddStatus.sync.findings}</dd>
                        </div>
                        <div>
                          <dt className="text-[10px] tracking-wider text-muted-foreground uppercase">Triage updates</dt>
                          <dd className="font-mono">{ddStatus.sync.triage_synced}</dd>
                        </div>
                      </dl>
                    ) : (
                      <p>No automatic sync has run yet. It runs after the next completed scan, or use Push now.</p>
                    )}
                    {ddStatus?.sync?.last_error && <p className="text-rose-600 dark:text-rose-400">{ddStatus.sync.last_error}</p>}
                    <div className="flex flex-wrap gap-3">
                      {ddStatus?.sync?.test_url && (
                        <a href={ddStatus.sync.test_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 underline-offset-2 hover:underline">
                          Dzięcioł changes test{ddStatus.sync.test_id ? ` #${ddStatus.sync.test_id}` : ''} <RiExternalLinkLine className="size-3" />
                        </a>
                      )}
                      {ddStatus?.sync?.nmap_test_url && (
                        <a href={ddStatus.sync.nmap_test_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 underline-offset-2 hover:underline">
                          Last nmap test <RiExternalLinkLine className="size-3" />
                        </a>
                      )}
                      {ddStatus?.sync?.product_url && (
                        <a href={ddStatus.sync.product_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 underline-offset-2 hover:underline">
                          Product <RiExternalLinkLine className="size-3" />
                        </a>
                      )}
                    </div>
                    {ddStatus?.sync?.legacy_tests && ddStatus.sync.legacy_tests.length > 0 && (
                      <div className="space-y-1 border-t pt-3">
                        <p className="text-muted-foreground">
                          Superseded per-profile tests from an older version, closed so no finding is open twice. Analyst
                          notes and false positive / risk accepted states set in DefectDojo were copied to the change test.
                        </p>
                        <ul className="space-y-0.5">
                          {ddStatus.sync.legacy_tests.map((lt) => (
                            <li key={`${lt.test_id}-${lt.retired_at}`} className="flex flex-wrap items-center gap-x-2">
                              <a href={lt.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 underline-offset-2 hover:underline">
                                #{lt.test_id} {lt.title} <RiExternalLinkLine className="size-3" />
                              </a>
                              <span className="font-mono text-muted-foreground">
                                {lt.closed} closed, {lt.notes_carried} notes and {lt.triage_carried} decisions carried
                                {' · '}
                                {formatDateTime(lt.retired_at)}
                              </span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </CardContent>
                </Card>
                <Card size="sm">
                  <CardHeader>
                    <CardTitle className="text-sm">Manual push: nmap XML of a run</CardTitle>
                    <CardAction>
                      <Code>/api/v2/import-scan/</Code>
                    </CardAction>
                  </CardHeader>
                  <CardContent className="flex flex-col gap-3 sm:flex-row sm:items-end">
                    <Field label="Run" className="flex-1">
                      <SimpleSelect
                        value={selectedScanForNmap}
                        onValueChange={setSelectedScanForNmap}
                        placeholder="Select a run"
                        options={scans.map((s) => ({
                          value: s.id,
                          label: `${s.name} (${s.run_type})${s.has_raw_nmap_xml ? ' · XML ✓' : ''}`,
                        }))}
                      />
                    </Field>
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      disabled={ddBusy || !selectedScanForNmap || !can(PERMISSIONS.DEFECTDOJO_PUSH)}
                      onClick={handlePushNmap}
                    >
                      <RiSendPlaneLine /> Push nmap XML
                    </Button>
                  </CardContent>
                </Card>

                <Card size="sm">
                  <CardHeader className="border-b">
                    <CardTitle className="text-sm">Manual push: selected services</CardTitle>
                    <CardAction>
                      <Code>/api/v2/findings/</Code>
                    </CardAction>
                  </CardHeader>
                  <CardContent>
                    {services.length === 0 ? (
                      <Empty>No services with score ≥ 20</Empty>
                    ) : (
                      <div className="max-h-64 divide-y divide-border overflow-y-auto border border-border">
                        {services.slice(0, 20).map((svc) => {
                          const checked = selectedServiceIds.includes(svc.id);
                          return (
                            <label
                              key={svc.id}
                              className={cn(
                                'flex cursor-pointer items-center justify-between gap-3 px-3 py-2 text-xs hover:bg-muted/50',
                                checked && 'bg-muted'
                              )}
                            >
                              <div className="flex min-w-0 items-center gap-2.5">
                                <input
                                  type="checkbox"
                                  checked={checked}
                                  onChange={() =>
                                    setSelectedServiceIds((prev) =>
                                      checked ? prev.filter((id) => id !== svc.id) : [...prev, svc.id]
                                    )
                                  }
                                  className="size-3.5 accent-primary"
                                />
                                <span className="font-mono font-semibold">
                                  {svc.host_ip}:{svc.port}
                                </span>
                                <span className="truncate text-muted-foreground">
                                  {svc.http?.title || svc.product || svc.service_name}
                                </span>
                              </div>
                              <span className="shrink-0 font-mono text-muted-foreground tabular-nums">
                                {svc.interestingness}
                              </span>
                            </label>
                          );
                        })}
                      </div>
                    )}
                  </CardContent>
                  <CardFooter className="justify-end gap-2 border-t">
                    <SimpleSelect
                      size="sm"
                      value={ddSeverity}
                      onValueChange={setDdSeverity}
                      options={SEVERITIES.map((s) => ({ value: s, label: s }))}
                      className="w-32"
                    />
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      disabled={
                        ddBusy || selectedServiceIds.length === 0 || !can(PERMISSIONS.DEFECTDOJO_PUSH)
                      }
                      onClick={handlePushFindings}
                    >
                      <RiSendPlaneLine /> Push selected ({selectedServiceIds.length})
                    </Button>
                  </CardFooter>
                </Card>
              </div>
            </div>

            <Card size="sm" className="pb-0">
              <CardHeader>
                <CardTitle className="text-sm">Push history ({ddHistory.length})</CardTitle>
                <CardAction>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-xs"
                    aria-label="Refresh"
                    onClick={loadDefectDojo}
                  >
                    <RiRefreshLine />
                  </Button>
                </CardAction>
              </CardHeader>
              {ddHistory.length === 0 ? (
                <Empty>Nothing pushed yet</Empty>
              ) : (
                <Table className="text-xs">
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="pl-5">Type</TableHead>
                      <TableHead>Title</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>In DefectDojo</TableHead>
                      <TableHead>By</TableHead>
                      <TableHead className="pr-5">When</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {ddHistory.map((ex) => (
                      <TableRow key={ex.id}>
                        <TableCell className="pl-5">{EXPORT_TYPE_LABEL[ex.export_type] || ex.export_type}</TableCell>
                        <TableCell>{ex.title}</TableCell>
                        <TableCell>
                          <Pill tone={ex.status === 'success' ? 'success' : 'danger'}>{ex.status}</Pill>
                        </TableCell>
                        <TableCell className="font-mono">
                          {ex.external_url ? (
                            <a
                              href={ex.external_url}
                              target="_blank"
                              rel="noreferrer"
                              className="inline-flex items-center gap-1 text-foreground underline-offset-2 hover:underline"
                            >
                              {ex.export_type === 'finding' ? `finding #${ex.external_id || '?'}` : `test #${ex.external_id || '?'}`}{' '}
                              <RiExternalLinkLine className="size-3" />
                            </a>
                          ) : (
                            <span className="block max-w-[28rem] truncate text-muted-foreground" title={ex.error_message || ex.external_id}>
                              {ex.error_message || ex.external_id || 'n/a'}
                            </span>
                          )}
                        </TableCell>
                        <TableCell className="text-muted-foreground">{ex.exported_by}</TableCell>
                        <TableCell className="pr-5 font-mono text-muted-foreground">
                          {formatDateTime(ex.created_at)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </Card>
          </TabsContent>
        )}

        {canRBAC && (
          <TabsContent value="users" className="space-y-6">
            <Card size="sm">
              <CardHeader>
                <CardTitle className="text-sm">New user</CardTitle>
              </CardHeader>
              <CardContent>
                <form
                  onSubmit={handleCreateUser}
                  className="grid grid-cols-1 items-end gap-4 sm:grid-cols-2 lg:grid-cols-[1fr_1fr_1fr_1fr_auto]"
                >
                  <Field label="Login" htmlFor="nu-username">
                    <Input
                      id="nu-username"
                      required
                      value={newUserForm.username}
                      onChange={(e) => setNewUserForm((u) => ({ ...u, username: e.target.value }))}
                    />
                  </Field>
                  <Field label="Email" htmlFor="nu-email">
                    <Input
                      id="nu-email"
                      type="email"
                      value={newUserForm.email}
                      onChange={(e) => setNewUserForm((u) => ({ ...u, email: e.target.value }))}
                      placeholder="email@agh.edu.pl"
                    />
                  </Field>
                  <Field label="Password" htmlFor="nu-password">
                    <Input
                      id="nu-password"
                      type="password"
                      required
                      value={newUserForm.password}
                      onChange={(e) => setNewUserForm((u) => ({ ...u, password: e.target.value }))}
                    />
                  </Field>
                  <Field label="Role">
                    <SimpleSelect
                      value={newUserForm.role_slug}
                      onValueChange={(v) => setNewUserForm((u) => ({ ...u, role_slug: v }))}
                      options={roleOptions}
                    />
                  </Field>
                  <Button type="submit" size="sm">
                    <RiUserAddLine /> Add user
                  </Button>
                </form>
              </CardContent>
            </Card>

            <Card size="sm" className="pb-0">
              <CardHeader>
                <CardTitle className="text-sm">Users ({users.length})</CardTitle>
              </CardHeader>
              {users.length === 0 ? (
                <Empty>No users</Empty>
              ) : (
                <Table className="text-xs">
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="pl-5">User</TableHead>
                      <TableHead>
                        Email <span className="normal-case opacity-70">(encrypted)</span>
                      </TableHead>
                      <TableHead>Role</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="pr-5 text-right" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {users.map((u) => (
                      <TableRow key={u.id}>
                        <TableCell className="pl-5 font-mono font-semibold">{u.username}</TableCell>
                        <TableCell className="text-muted-foreground">{u.email || ''}</TableCell>
                        <TableCell>
                          <Pill className={getRoleBadgeClasses(u.role_slug)}>
                            {u.role_name || u.role_slug}
                          </Pill>
                        </TableCell>
                        <TableCell>
                          {u.active !== false ? (
                            <Pill tone="success" dot>
                              Active
                            </Pill>
                          ) : (
                            <Pill dot>Disabled</Pill>
                          )}
                        </TableCell>
                        <TableCell className="pr-5 text-right">
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon-xs"
                            aria-label={`Delete ${u.username}`}
                            className="text-muted-foreground hover:text-destructive"
                            onClick={async () => {
                              if (!window.confirm(`Delete user ${u.username}?`)) return;
                              await api.deleteUser(u.id);
                              toast.success('User deleted', u.username);
                              loadRBAC();
                            }}
                          >
                            <RiDeleteBinLine />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </Card>
          </TabsContent>
        )}

        {canRBAC && (
          <TabsContent value="rbac">
            <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
              <Card size="sm" className="h-fit pb-0 xl:col-span-4">
                <CardHeader>
                  <CardTitle className="text-sm">Role ({roles.length})</CardTitle>
                  <CardAction>
                    <Button
                      type="button"
                      variant="ghost"
                      size="xs"
                      onClick={() => {
                        setSelectedRoleId(null);
                        setRoleForm({
                          slug: '',
                          name: '',
                          description: '',
                          permissions: ['dashboard:read'],
                        });
                      }}
                    >
                      <RiAddLine /> New
                    </Button>
                  </CardAction>
                </CardHeader>
                <div className="divide-y divide-border border-t border-border">
                  {roles.length === 0 && <Empty>No roles</Empty>}
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
                      className={cn(
                        'cursor-pointer border-l-2 border-l-transparent px-5 py-3 transition-colors hover:bg-muted/50',
                        selectedRoleId === r.id && 'border-l-primary bg-muted'
                      )}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <Pill className={getRoleBadgeClasses(r.slug)}>{r.name}</Pill>
                        <div className="flex items-center gap-1">
                          <span className="font-mono text-[11px] text-muted-foreground">
                            {r.permissions?.includes('*')
                              ? 'ALL (*)'
                              : `${r.permissions?.length || 0} perm`}
                          </span>
                          {!r.is_system && (
                            <Button
                              type="button"
                              variant="ghost"
                              size="icon-xs"
                              aria-label={`Delete ${r.name}`}
                              className="text-muted-foreground hover:text-destructive"
                              onClick={async (e) => {
                                e.stopPropagation();
                                await api.deleteRole(r.id);
                                toast.success('Role deleted', r.name);
                                loadRBAC();
                              }}
                            >
                              <RiDeleteBinLine />
                            </Button>
                          )}
                        </div>
                      </div>
                      {r.description && (
                        <p className="mt-1.5 truncate text-[11px] text-muted-foreground">
                          {r.description}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </Card>

              <Card size="sm" className="xl:col-span-8">
                <form onSubmit={handleSaveRole} className="flex flex-col gap-(--card-spacing)">
                  <CardHeader className="border-b">
                    <CardTitle className="text-sm">
                      {selectedRoleId ? roleForm.name || 'Role' : 'New role'}
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <div className="grid grid-cols-1 gap-x-4 gap-y-5 sm:grid-cols-3">
                      <Field label="Slug" htmlFor="role-slug">
                        <Input
                          id="role-slug"
                          required
                          disabled={Boolean(selectedRoleId)}
                          value={roleForm.slug}
                          onChange={(e) => setRoleForm((f) => ({ ...f, slug: e.target.value }))}
                          placeholder="soc_auditor"
                          className="font-mono"
                        />
                      </Field>
                      <Field label="Name" htmlFor="role-name" className="sm:col-span-2">
                        <Input
                          id="role-name"
                          required
                          value={roleForm.name}
                          onChange={(e) => setRoleForm((f) => ({ ...f, name: e.target.value }))}
                          placeholder="SOC auditor"
                        />
                      </Field>
                      <Field label="Description" htmlFor="role-desc" className="sm:col-span-3">
                        <Input
                          id="role-desc"
                          value={roleForm.description}
                          onChange={(e) =>
                            setRoleForm((f) => ({ ...f, description: e.target.value }))
                          }
                        />
                      </Field>
                    </div>

                    <div className="space-y-2">
                      <SectionTitle>Permissions</SectionTitle>
                      <div className="max-h-[28rem] divide-y divide-border overflow-y-auto border border-border">
                        {Object.entries(groupedPermissions).map(([group, list]) => (
                          <div key={group} className="px-4 py-3">
                            <div className="mb-2 text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
                              {group}
                            </div>
                            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                              {list.map((p) => {
                                const hasAll = roleForm.permissions.includes('*');
                                const checked = hasAll || roleForm.permissions.includes(p.slug);
                                return (
                                  <label
                                    key={p.slug}
                                    className={cn(
                                      'flex cursor-pointer items-start gap-2 text-[11px]',
                                      hasAll && 'cursor-not-allowed opacity-70'
                                    )}
                                  >
                                    <input
                                      type="checkbox"
                                      disabled={hasAll}
                                      checked={checked}
                                      onChange={() => togglePermission(p.slug)}
                                      className="mt-0.5 size-3.5 accent-primary"
                                    />
                                    <span className="min-w-0">
                                      <span className="block font-mono">{p.slug}</span>
                                      <span className="text-muted-foreground">{p.label}</span>
                                    </span>
                                  </label>
                                );
                              })}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </CardContent>
                  <CardFooter className="justify-end border-t">
                    <Button type="submit" size="sm">
                      <RiSave3Line /> Save role
                    </Button>
                  </CardFooter>
                </form>
              </Card>
            </div>
          </TabsContent>
        )}

        {canCrypto && (
          <TabsContent value="alerts" className="space-y-6">
            <WebhookPanel />
          </TabsContent>
        )}

        {canCrypto && (
          <TabsContent value="crypto" className="space-y-6">
            <Card size="sm">
              <CardContent className="flex flex-col gap-5 md:flex-row md:items-center md:justify-between">
                <div className="flex items-start gap-4">
                  <div className="flex size-10 shrink-0 items-center justify-center border border-border bg-muted">
                    <RiLockLine className="size-4" />
                  </div>
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <h2 className="font-heading text-sm font-semibold tracking-wider uppercase">
                        Encryption at rest
                      </h2>
                      <Pill tone="success" dot>
                        Active
                      </Pill>
                    </div>
                    <dl className="flex flex-wrap gap-x-6 gap-y-1 text-xs">
                      <div className="flex gap-1.5">
                        <dt className="text-muted-foreground">DEK</dt>
                        <dd className="font-mono font-semibold">
                          {cryptoStatus?.key_version || cryptoStatus?.active_kid || 'v1'}
                        </dd>
                      </div>
                      <div className="flex gap-1.5">
                        <dt className="text-muted-foreground">Algorithm</dt>
                        <dd className="font-mono font-semibold">
                          {cryptoStatus?.algorithm || 'AES-256-GCM + AAD'}
                        </dd>
                      </div>
                      {cryptoStatus?.rotated_at && (
                        <div className="flex gap-1.5">
                          <dt className="text-muted-foreground">Rotated</dt>
                          <dd className="font-mono">{formatDateTime(cryptoStatus.rotated_at)}</dd>
                        </div>
                      )}
                    </dl>
                  </div>
                </div>

                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={rotatingKey}
                  onClick={handleRotateKey}
                >
                  <RiLoopRightLine className={cn(rotatingKey && 'animate-spin')} />
                  {rotatingKey ? 'Rotating…' : 'Rotate key'}
                </Button>
              </CardContent>
            </Card>

            <Card size="sm">
              <CardHeader>
                <CardTitle className="text-sm">Stored ciphertext vs what the API returns</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {cryptoSamples.length === 0 ? (
                  <div className="space-y-2 text-xs">
                    <p className="text-muted-foreground">
                      No record to sample yet (it appears after the first scan or import). These columns are encrypted
                      with {cryptoStatus?.algorithm || 'AES-256-GCM'}, each bound to its row by AAD:
                    </p>
                    <ul className="list-inside list-disc font-mono text-[11px]">
                      {(cryptoStatus?.encrypted_tables || []).map((t) => (
                        <li key={t}>{t}</li>
                      ))}
                    </ul>
                  </div>
                ) : (
                  cryptoSamples.map((s, idx) => (
                    <div
                      key={idx}
                      className="grid grid-cols-1 divide-y divide-border border border-border lg:grid-cols-2 lg:divide-x lg:divide-y-0"
                    >
                      <div className="min-w-0 space-y-2 p-4">
                        <SectionTitle>
                          Raw DB · {s.table || 'hosts'}.{s.column || 'ip_enc'}
                        </SectionTitle>
                        <div className="border border-border bg-muted/30 p-3 font-mono text-xs break-all">
                          {s.raw_ciphertext || s.ciphertext || 'enc:v1:...'}
                        </div>
                        {s.aad && (
                          <div className="font-mono text-[11px] text-muted-foreground">
                            AAD: {s.aad}
                          </div>
                        )}
                        {s.blind_index && (
                          <div className="truncate font-mono text-[11px] text-muted-foreground">
                            Blind index: {s.blind_index}
                          </div>
                        )}
                      </div>
                      <div className="min-w-0 space-y-2 p-4">
                        <SectionTitle
                          actions={
                            <Pill tone="success">
                              <RiCheckboxCircleLine className="size-3" /> decrypted
                            </Pill>
                          }
                        >
                          API
                        </SectionTitle>
                        <div className="border border-border bg-muted/30 p-3 font-mono text-xs break-all">
                          {s.decrypted_value || s.plaintext || 'n/a'}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>
          </TabsContent>
        )}

        {canAudit && (
          <TabsContent value="audit">
            <Card size="sm" className="pb-0">
              <CardHeader>
                <CardTitle className="text-sm">Audit log ({auditLogs.length})</CardTitle>
                <CardAction className="flex items-center gap-2">
                  <SimpleSelect
                    size="sm"
                    value={auditStatusFilter || 'all'}
                    onValueChange={(v) => setAuditStatusFilter(v === 'all' ? '' : v)}
                    options={[
                      { value: 'all', label: 'All' },
                      { value: 'success', label: 'success' },
                      { value: 'denied', label: 'denied (403)' },
                      { value: 'error', label: 'error' },
                    ]}
                    className="w-40"
                  />
                  <Button
                    type="button"
                    variant="outline"
                    size="icon-sm"
                    aria-label="Refresh"
                    onClick={loadAudit}
                  >
                    <RiRefreshLine />
                  </Button>
                </CardAction>
              </CardHeader>
              {auditLogs.length === 0 ? (
                <Empty icon={RiFileList3Line}>No entries</Empty>
              ) : (
                <Table className="text-xs">
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="pl-5">Time</TableHead>
                      <TableHead>User</TableHead>
                      <TableHead>Action</TableHead>
                      <TableHead>Resource</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="pr-5">IP</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {auditLogs.map((log) => (
                      <TableRow key={log.id}>
                        <TableCell className="pl-5 font-mono text-[11px] text-muted-foreground">
                          {formatDateTime(log.created_at)}
                        </TableCell>
                        <TableCell>
                          <span className="font-mono font-semibold">{log.username}</span>
                          <span className="ml-1.5 font-mono text-[10px] text-muted-foreground">
                            {log.role_slug}
                          </span>
                        </TableCell>
                        <TableCell>
                          <div>{auditActionLabel(log)}</div>
                          <div className="font-mono text-[10px] text-muted-foreground">{log.action}</div>
                        </TableCell>
                        <TableCell className="font-mono text-muted-foreground">
                          {log.resource}
                          {log.resource_id ? `/${log.resource_id.slice(0, 8)}` : ''}
                        </TableCell>
                        <TableCell>
                          <Pill tone={auditTone(log.status)}>{log.status}</Pill>
                        </TableCell>
                        <TableCell className="pr-5 font-mono text-[11px] text-muted-foreground">
                          {log.ip_address || ''}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </Card>
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
}
