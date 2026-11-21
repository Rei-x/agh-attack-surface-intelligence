import React, { useCallback, useEffect, useState } from 'react';
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
  Role,
  ScanRun,
  Service,
  User,
} from '@/types/api';
import { WebhookPanel } from '@/components/WebhookPanel';
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
  Empty,
  Field,
  PageHeader,
  Pill,
  SectionTitle,
  SimpleSelect,
} from '@/components/common';

type AdminTab = 'defectdojo' | 'users' | 'rbac' | 'crypto' | 'audit' | 'alerts';

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];

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
      toast.error('Błąd Audit Log', (err as Error).message);
    }
  }, [auditStatusFilter, toast]);

  useEffect(() => {
    if (activeTab === 'defectdojo' && canDD) loadDefectDojo();
    if ((activeTab === 'rbac' || activeTab === 'users') && canRBAC) loadRBAC();
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
      toast.success('Zapisano', 'Token zaszyfrowany AES-256-GCM');
      loadDefectDojo();
    } catch (err) {
      toast.error('Błąd zapisu', (err as Error).message);
    } finally {
      setDdBusy(false);
    }
  };

  const handleTestDD = async () => {
    setDdBusy(true);
    try {
      const res = await api.testDefectDojo();
      toast.success('DefectDojo: OK', JSON.stringify(res));
    } catch (err) {
      toast.error('DefectDojo: błąd', (err as Error).message);
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
      toast.success('Wysłano Nmap XML');
      loadDefectDojo();
    } catch (err) {
      toast.error('Błąd eksportu Nmap', (err as Error).message);
    } finally {
      setDdBusy(false);
    }
  };

  const handlePushFindings = async () => {
    if (selectedServiceIds.length === 0) {
      toast.warning('Wybierz usługi');
      return;
    }
    setDdBusy(true);
    try {
      await api.pushDefectDojoFindings({
        service_ids: selectedServiceIds,
        engagement_id: Number(ddConfig.engagement_id) || 1,
        severity: ddSeverity,
      });
      toast.success('Wysłano findings', `${selectedServiceIds.length} szt.`);
      setSelectedServiceIds([]);
      loadDefectDojo();
    } catch (err) {
      toast.error('Błąd eksportu', (err as Error).message);
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
        toast.success('Zapisano rolę', roleForm.name);
      } else {
        await api.createRole(roleForm);
        toast.success('Utworzono rolę', roleForm.name);
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
      toast.success('Dodano użytkownika', newUserForm.username);
      setNewUserForm({ username: '', email: '', password: '', role_slug: 'analyst' });
      loadRBAC();
    } catch (err) {
      toast.error('Błąd tworzenia', (err as Error).message);
    }
  };

  // Crypto Key Rotation
  const handleRotateKey = async () => {
    if (!window.confirm('Przeprowadzić rotację klucza DEK (AES-256-GCM re-encryption)?')) return;
    setRotatingKey(true);
    try {
      await api.rotateCryptoKey();
      toast.success('Rotacja DEK zakończona');
      await loadCrypto();
    } catch (err) {
      toast.error('Błąd rotacji DEK', (err as Error).message);
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
      <PageHeader title="Administracja" />

      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as AdminTab)} className="gap-6">
        <TabsList variant="line" className="max-w-full flex-wrap">
          {canDD && <TabsTrigger value="defectdojo">DefectDojo</TabsTrigger>}
          {canRBAC && <TabsTrigger value="users">Użytkownicy</TabsTrigger>}
          {canRBAC && <TabsTrigger value="rbac">Role (RBAC)</TabsTrigger>}
          {canCrypto && <TabsTrigger value="crypto">Szyfrowanie</TabsTrigger>}
          {canCrypto && <TabsTrigger value="alerts">Alerty</TabsTrigger>}
          {canAudit && <TabsTrigger value="audit">Audit Log</TabsTrigger>}
        </TabsList>

        {/* DEFECTDOJO */}
        {canDD && (
          <TabsContent value="defectdojo" className="space-y-6">
            <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
              <Card size="sm" className="h-fit xl:col-span-5">
                <form onSubmit={handleSaveDDConfig} className="flex flex-col gap-(--card-spacing)">
                  <CardHeader className="border-b">
                    <CardTitle className="text-sm">Konfiguracja API v2</CardTitle>
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
                          API Token
                          {ddConfig.has_api_token && (
                            <Pill tone="success">
                              <RiLockLine className="size-3" /> zaszyfrowany
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
                        placeholder={ddConfig.has_api_token ? '•••••••• (bez zmian)' : 'Token'}
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
                          Weryfikuj TLS
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
                          Auto-push Nmap XML po skanie
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
                        <RiSave3Line /> Zapisz
                      </Button>
                    )}
                  </CardFooter>
                </form>
              </Card>

              <div className="space-y-6 xl:col-span-7">
                <Card size="sm">
                  <CardHeader>
                    <CardTitle className="text-sm">Nmap XML</CardTitle>
                    <CardAction>
                      <Code>/api/v2/import-scan/</Code>
                    </CardAction>
                  </CardHeader>
                  <CardContent className="flex flex-col gap-3 sm:flex-row sm:items-end">
                    <Field label="Skan" className="flex-1">
                      <SimpleSelect
                        value={selectedScanForNmap}
                        onValueChange={setSelectedScanForNmap}
                        placeholder="Wybierz skan"
                        options={scans.map((s) => ({
                          value: s.id,
                          label: `${s.name} (${s.run_type})${s.has_raw_nmap_xml ? ' · XML ✓' : ''}`,
                        }))}
                      />
                    </Field>
                    <Button
                      type="button"
                      size="sm"
                      disabled={ddBusy || !selectedScanForNmap || !can(PERMISSIONS.DEFECTDOJO_PUSH)}
                      onClick={handlePushNmap}
                    >
                      <RiSendPlaneLine /> Wyślij
                    </Button>
                  </CardContent>
                </Card>

                <Card size="sm">
                  <CardHeader className="border-b">
                    <CardTitle className="text-sm">Findings</CardTitle>
                    <CardAction>
                      <Code>/api/v2/findings/</Code>
                    </CardAction>
                  </CardHeader>
                  <CardContent>
                    {services.length === 0 ? (
                      <Empty>Brak usług</Empty>
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
                      disabled={
                        ddBusy || selectedServiceIds.length === 0 || !can(PERMISSIONS.DEFECTDOJO_PUSH)
                      }
                      onClick={handlePushFindings}
                    >
                      <RiSendPlaneLine /> Wyślij ({selectedServiceIds.length})
                    </Button>
                  </CardFooter>
                </Card>
              </div>
            </div>

            <Card size="sm" className="pb-0">
              <CardHeader>
                <CardTitle className="text-sm">Historia ({ddHistory.length})</CardTitle>
                <CardAction>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-xs"
                    aria-label="Odśwież"
                    onClick={loadDefectDojo}
                  >
                    <RiRefreshLine />
                  </Button>
                </CardAction>
              </CardHeader>
              {ddHistory.length === 0 ? (
                <Empty>Brak eksportów</Empty>
              ) : (
                <Table className="text-xs">
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="pl-5">Typ</TableHead>
                      <TableHead>Tytuł</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>External ID</TableHead>
                      <TableHead>Użytkownik</TableHead>
                      <TableHead className="pr-5">Data</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {ddHistory.map((ex) => (
                      <TableRow key={ex.id}>
                        <TableCell className="pl-5 font-mono">{ex.export_type}</TableCell>
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
                              className="inline-flex items-center gap-1 text-primary hover:underline"
                            >
                              #{ex.external_id || 'link'} <RiExternalLinkLine className="size-3" />
                            </a>
                          ) : (
                            <span className="text-muted-foreground">
                              {ex.external_id || ex.error_message || '—'}
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

        {/* USERS */}
        {canRBAC && (
          <TabsContent value="users" className="space-y-6">
            <Card size="sm">
              <CardHeader>
                <CardTitle className="text-sm">Nowy użytkownik</CardTitle>
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
                  <Field label="Hasło" htmlFor="nu-password">
                    <Input
                      id="nu-password"
                      type="password"
                      required
                      value={newUserForm.password}
                      onChange={(e) => setNewUserForm((u) => ({ ...u, password: e.target.value }))}
                    />
                  </Field>
                  <Field label="Rola">
                    <SimpleSelect
                      value={newUserForm.role_slug}
                      onValueChange={(v) => setNewUserForm((u) => ({ ...u, role_slug: v }))}
                      options={roleOptions}
                    />
                  </Field>
                  <Button type="submit" size="sm">
                    <RiUserAddLine /> Dodaj
                  </Button>
                </form>
              </CardContent>
            </Card>

            <Card size="sm" className="pb-0">
              <CardHeader>
                <CardTitle className="text-sm">Użytkownicy ({users.length})</CardTitle>
              </CardHeader>
              {users.length === 0 ? (
                <Empty>Brak użytkowników</Empty>
              ) : (
                <Table className="text-xs">
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="pl-5">Użytkownik</TableHead>
                      <TableHead>
                        Email <span className="normal-case opacity-70">(encrypted)</span>
                      </TableHead>
                      <TableHead>Rola</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="pr-5 text-right" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {users.map((u) => (
                      <TableRow key={u.id}>
                        <TableCell className="pl-5 font-mono font-semibold">{u.username}</TableCell>
                        <TableCell className="text-muted-foreground">{u.email || '—'}</TableCell>
                        <TableCell>
                          <Pill className={getRoleBadgeClasses(u.role_slug)}>
                            {u.role_name || u.role_slug}
                          </Pill>
                        </TableCell>
                        <TableCell>
                          {u.active !== false ? (
                            <Pill tone="success" dot>
                              Aktywny
                            </Pill>
                          ) : (
                            <Pill dot>Wyłączony</Pill>
                          )}
                        </TableCell>
                        <TableCell className="pr-5 text-right">
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon-xs"
                            aria-label={`Usuń ${u.username}`}
                            className="text-muted-foreground hover:text-destructive"
                            onClick={async () => {
                              if (!window.confirm(`Usunąć użytkownika ${u.username}?`)) return;
                              await api.deleteUser(u.id);
                              toast.success('Usunięto', u.username);
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

        {/* ROLES (RBAC) */}
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
                      <RiAddLine /> Nowa
                    </Button>
                  </CardAction>
                </CardHeader>
                <div className="divide-y divide-border border-t border-border">
                  {roles.length === 0 && <Empty>Brak ról</Empty>}
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
                              aria-label={`Usuń ${r.name}`}
                              className="text-muted-foreground hover:text-destructive"
                              onClick={async (e) => {
                                e.stopPropagation();
                                await api.deleteRole(r.id);
                                toast.success('Usunięto rolę', r.name);
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
                      {selectedRoleId ? roleForm.name || 'Rola' : 'Nowa rola'}
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
                      <Field label="Nazwa" htmlFor="role-name" className="sm:col-span-2">
                        <Input
                          id="role-name"
                          required
                          value={roleForm.name}
                          onChange={(e) => setRoleForm((f) => ({ ...f, name: e.target.value }))}
                          placeholder="Audytor SOC"
                        />
                      </Field>
                      <Field label="Opis" htmlFor="role-desc" className="sm:col-span-3">
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
                      <SectionTitle>Uprawnienia</SectionTitle>
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
                      <RiSave3Line /> Zapisz rolę
                    </Button>
                  </CardFooter>
                </form>
              </Card>
            </div>
          </TabsContent>
        )}

        {/* ALERT WEBHOOK (admin:settings) */}
        {canCrypto && (
          <TabsContent value="alerts" className="space-y-6">
            <WebhookPanel />
          </TabsContent>
        )}

        {/* ENCRYPTION AT REST */}
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
                        Encryption At Rest
                      </h2>
                      <Pill tone="success" dot>
                        Aktywne
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
                        <dt className="text-muted-foreground">Algorytm</dt>
                        <dd className="font-mono font-semibold">
                          {cryptoStatus?.algorithm || 'AES-256-GCM + AAD'}
                        </dd>
                      </div>
                      {cryptoStatus?.rotated_at && (
                        <div className="flex gap-1.5">
                          <dt className="text-muted-foreground">Rotacja</dt>
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
                  {rotatingKey ? 'Rotacja…' : 'Rotuj DEK'}
                </Button>
              </CardContent>
            </Card>

            <Card size="sm">
              <CardHeader>
                <CardTitle className="text-sm">Ciphertext vs odszyfrowane</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {cryptoSamples.length === 0 ? (
                  <Empty icon={RiLockLine}>Brak próbek</Empty>
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
                              <RiCheckboxCircleLine className="size-3" /> odszyfrowane
                            </Pill>
                          }
                        >
                          API
                        </SectionTitle>
                        <div className="border border-border bg-muted/30 p-3 font-mono text-xs break-all">
                          {s.decrypted_value || s.plaintext || '—'}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>
          </TabsContent>
        )}

        {/* AUDIT LOG */}
        {canAudit && (
          <TabsContent value="audit">
            <Card size="sm" className="pb-0">
              <CardHeader>
                <CardTitle className="text-sm">Audit Log ({auditLogs.length})</CardTitle>
                <CardAction className="flex items-center gap-2">
                  <SimpleSelect
                    size="sm"
                    value={auditStatusFilter || 'all'}
                    onValueChange={(v) => setAuditStatusFilter(v === 'all' ? '' : v)}
                    options={[
                      { value: 'all', label: 'Wszystkie' },
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
                    aria-label="Odśwież"
                    onClick={loadAudit}
                  >
                    <RiRefreshLine />
                  </Button>
                </CardAction>
              </CardHeader>
              {auditLogs.length === 0 ? (
                <Empty icon={RiFileList3Line}>Brak wpisów</Empty>
              ) : (
                <Table className="text-xs">
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="pl-5">Czas</TableHead>
                      <TableHead>Użytkownik</TableHead>
                      <TableHead>Akcja</TableHead>
                      <TableHead>Zasób</TableHead>
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
                        <TableCell className="font-mono">{log.action}</TableCell>
                        <TableCell className="font-mono text-muted-foreground">
                          {log.resource}
                          {log.resource_id ? `/${log.resource_id.slice(0, 8)}` : ''}
                        </TableCell>
                        <TableCell>
                          <Pill tone={auditTone(log.status)}>{log.status}</Pill>
                        </TableCell>
                        <TableCell className="pr-5 font-mono text-[11px] text-muted-foreground">
                          {log.ip_address || '—'}
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
