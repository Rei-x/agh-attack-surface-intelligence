import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  RiAddLine,
  RiCheckboxCircleLine,
  RiCodeSSlashLine,
  RiDeleteBinLine,
  RiDownload2Line,
  RiErrorWarningLine,
  RiFlaskLine,
  RiPlayLine,
  RiSave3Line,
  RiSearchLine,
  RiShieldCheckLine,
  RiUploadCloud2Line,
} from '@remixicon/react';
import { api } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/context/ToastContext';
import { PERMISSIONS } from '@/lib/permissions';
import { cn } from '@/lib/utils';
import type {
  Signature,
  SignatureMatcher,
  SignatureTestResult,
  SignatureValidationResult,
} from '@/types/api';
import { Button } from '@/components/ui/button';
import { Card, CardAction, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
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
  Empty,
  Field,
  Notice,
  PageHeader,
  Pill,
  SectionTitle,
  SimpleSelect,
  type SelectOption,
} from '@/components/common';
import { PeckLoader } from '@/components/Woodpecker';

const EMPTY_SIG: Partial<Signature> = {
  name: '',
  description: '',
  category: 'custom',
  match_mode: 'any',
  confidence_weight: 0.75,
  interesting_points: 20,
  tags: ['custom'],
  enabled: true,
  matchers: [
    {
      type: 'header',
      key: 'Server',
      pattern: '',
      regex: false,
    },
  ],
};

const MATCHER_TYPES = [
  'header',
  'cookie',
  'favicon_mmh3',
  'favicon_sha256',
  'html_body',
  'footer_version',
  'safe_path',
  'tls_cert',
  'jarm',
  'banner',
  'port',
];

const CATEGORIES = [
  'cms',
  'framework',
  'server',
  'iot',
  'admin_panel',
  'staging',
  'interesting_header',
  'interesting_cookie',
  'custom',
];

/** Build select options from a list, keeping an unknown current value selectable. */
function toOptions(list: string[], current?: string): SelectOption[] {
  const values = current && !list.includes(current) ? [current, ...list] : list;
  return values.map((v) => ({ value: v, label: v }));
}

type SigTab = 'list' | 'editor' | 'playground';

export function SignaturesPage() {
  const { can } = useAuth();
  const toast = useToast();

  const [tab, setTab] = useState<SigTab>('list');

  const [signatures, setSignatures] = useState<Signature[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editorMode, setEditorMode] = useState<'visual' | 'json'>('visual');
  const [draft, setDraft] = useState<Partial<Signature>>(EMPTY_SIG);
  const [jsonText, setJsonText] = useState(JSON.stringify(EMPTY_SIG, null, 2));
  const [tagsText, setTagsText] = useState('custom');

  const [validation, setValidation] = useState<SignatureValidationResult | null>(null);
  const [validating, setValidating] = useState(false);
  const [testResult, setTestResult] = useState<SignatureTestResult | null>(null);
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);

  const canWrite = can(PERMISSIONS.SIGNATURES_WRITE);
  const canDelete = can(PERMISSIONS.SIGNATURES_DELETE);

  const loadSignatures = useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.listSignatures();
      setSignatures(list);
    } catch (err) {
      toast.error('Could not load signatures', (err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    loadSignatures();
  }, [loadSignatures]);

  const filteredSignatures = useMemo(() => {
    const q = search.trim().toLowerCase();
    return signatures.filter((s) => {
      if (categoryFilter && s.category !== categoryFilter) return false;
      if (
        q &&
        !s.name.toLowerCase().includes(q) &&
        !(s.description || '').toLowerCase().includes(q) &&
        !(s.tags || []).some((t) => t.toLowerCase().includes(q))
      ) {
        return false;
      }
      return true;
    });
  }, [signatures, search, categoryFilter]);

  const selectSignature = (sig: Signature) => {
    setSelectedId(sig.id);
    setDraft(sig);
    setTagsText((sig.tags || []).join(', '));
    setJsonText(JSON.stringify(sig, null, 2));
    setValidation(null);
    setTestResult(null);
  };

  const startNewSignature = () => {
    setSelectedId(null);
    const fresh: Partial<Signature> = {
      ...EMPTY_SIG,
      matchers: [{ type: 'header', key: 'X-Debug-Token', pattern: '', regex: false }],
    };
    setDraft(fresh);
    setTagsText('custom');
    setJsonText(JSON.stringify(fresh, null, 2));
    setValidation(null);
    setTestResult(null);
  };

  const getCurrentPayload = (): Partial<Signature> => {
    if (editorMode === 'json') {
      return JSON.parse(jsonText) as Partial<Signature>;
    }
    return {
      ...draft,
      tags: tagsText
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean),
    };
  };

  const switchEditorMode = (next: 'visual' | 'json') => {
    if (next === editorMode) return;
    if (next === 'json') {
      const current = getCurrentPayload();
      setJsonText(JSON.stringify(current, null, 2));
      setEditorMode('json');
    } else {
      try {
        const parsed = JSON.parse(jsonText) as Partial<Signature>;
        setDraft(parsed);
        setTagsText((parsed.tags || []).join(', '));
        setEditorMode('visual');
      } catch (err) {
        toast.error('Invalid JSON', (err as Error).message);
      }
    }
  };

  const handleValidate = async () => {
    setValidating(true);
    try {
      const payload = getCurrentPayload();
      const res = await api.validateSignature(payload);
      setValidation(res);
      if (res.valid) {
        toast.success('Signature is valid');
      } else {
        toast.warning('Signature rejected', res.reason || res.errors?.join('; '));
      }
    } catch (err) {
      toast.error('Validation failed', (err as Error).message);
    } finally {
      setValidating(false);
    }
  };

  const handleRetroactiveTest = async () => {
    setTesting(true);
    try {
      const payload = getCurrentPayload();
      const res = await api.testSignature(payload);
      setTestResult(res);
      toast.info('Test finished', `${res.matches?.length ?? res.total_matches ?? 0} matches`);
    } catch (err) {
      toast.error('Test failed', (err as Error).message);
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const payload = getCurrentPayload();
      if (!payload.name?.trim()) {
        toast.error('Enter a name');
        return;
      }
      if (selectedId) {
        const updated = await api.updateSignature(selectedId, payload);
        toast.success('Saved', updated.name);
      } else {
        const created = await api.createSignature(payload);
        setSelectedId(created.id);
        toast.success('Created', created.name);
      }
      await loadSignatures();
    } catch (err) {
      toast.error('Save failed', (err as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (sig: Signature) => {
    if (!window.confirm(`Delete signature "${sig.name}"?`)) return;
    try {
      await api.deleteSignature(sig.id);
      toast.success('Deleted', sig.name);
      if (selectedId === sig.id) startNewSignature();
      loadSignatures();
    } catch (err) {
      toast.error('Delete failed', (err as Error).message);
    }
  };

  const handleImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      await api.importSignatures(parsed);
      toast.success('Imported');
      loadSignatures();
    } catch (err) {
      toast.error('Import failed', (err as Error).message);
    } finally {
      e.target.value = '';
    }
  };

  const updateMatcher = (idx: number, patch: Partial<SignatureMatcher>) => {
    setDraft((prev) => {
      const list = [...(prev.matchers || [])];
      list[idx] = { ...list[idx], ...patch };
      return { ...prev, matchers: list };
    });
  };

  const addMatcher = () => {
    setDraft((prev) => ({
      ...prev,
      matchers: [...(prev.matchers || []), { type: 'html_body', pattern: '', regex: false }],
    }));
  };

  const removeMatcher = (idx: number) => {
    setDraft((prev) => ({
      ...prev,
      matchers: (prev.matchers || []).filter((_, i) => i !== idx),
    }));
  };

  const openSignature = (sig: Signature) => {
    selectSignature(sig);
    setTab('editor');
  };

  const openNew = () => {
    startNewSignature();
    setTab('editor');
  };

  const categoryOptions: SelectOption[] = [
    { value: 'all', label: `All (${signatures.length})` },
    ...CATEGORIES.map((c) => ({ value: c, label: c })),
  ];

  /** Shared signature editor (visual / JSON), rendered in the Editor and Playground tabs. */
  const editorCard = (
    <Card size="sm" className="min-w-0">
      <CardHeader className="border-b">
        <CardTitle className="flex min-w-0 items-center gap-2 text-sm">
          <span className="truncate">{selectedId ? draft.name || 'Signature' : 'New signature'}</span>
          {draft.is_builtin && <Pill title="Shipped with Dzięcioł; duplicate it to change it">Built-in</Pill>}
        </CardTitle>
        <CardAction>
          <div className="inline-flex border border-border">
            <Button
              type="button"
              size="xs"
              variant={editorMode === 'visual' ? 'secondary' : 'ghost'}
              onClick={() => switchEditorMode('visual')}
            >
              Form
            </Button>
            <Button
              type="button"
              size="xs"
              variant={editorMode === 'json' ? 'secondary' : 'ghost'}
              onClick={() => switchEditorMode('json')}
            >
              <RiCodeSSlashLine /> JSON
            </Button>
          </div>
        </CardAction>
      </CardHeader>

      <CardContent>
        {editorMode === 'visual' ? (
          <div className="space-y-6">
            <div className="grid grid-cols-1 gap-x-4 gap-y-5 sm:grid-cols-3">
              <Field label="Name *" htmlFor="sig-name" className="sm:col-span-2">
                <Input
                  id="sig-name"
                  value={draft.name || ''}
                  onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
                  placeholder="AGH Staging Debug Header"
                />
              </Field>
              <Field label="Category">
                <SimpleSelect
                  value={draft.category || 'custom'}
                  onValueChange={(v) => setDraft((d) => ({ ...d, category: v }))}
                  options={toOptions(CATEGORIES, draft.category)}
                />
              </Field>
              <Field label="Description" htmlFor="sig-desc" className="sm:col-span-3">
                <Input
                  id="sig-desc"
                  value={draft.description || ''}
                  onChange={(e) => setDraft((d) => ({ ...d, description: e.target.value }))}
                />
              </Field>
              <Field label="Match mode">
                <SimpleSelect
                  value={draft.match_mode || 'any'}
                  onValueChange={(v) => setDraft((d) => ({ ...d, match_mode: v }))}
                  options={[
                    { value: 'any', label: 'ANY' },
                    { value: 'all', label: 'ALL' },
                  ]}
                />
              </Field>
              <Field label="Evidence weight (0.1 to 0.98)" htmlFor="sig-weight">
                <Input
                  id="sig-weight"
                  type="number"
                  step={0.05}
                  min={0.1}
                  max={0.98}
                  value={draft.confidence_weight ?? 0.75}
                  onChange={(e) =>
                    setDraft((d) => ({ ...d, confidence_weight: Number(e.target.value) }))
                  }
                  className="font-mono"
                />
              </Field>
              <Field label="Risk points (added to the score)" htmlFor="sig-points">
                <Input
                  id="sig-points"
                  type="number"
                  min={0}
                  max={100}
                  value={draft.interesting_points ?? 20}
                  onChange={(e) =>
                    setDraft((d) => ({ ...d, interesting_points: Number(e.target.value) }))
                  }
                  className="font-mono"
                />
              </Field>
              <Field label="Tags" htmlFor="sig-tags" className="sm:col-span-3">
                <Input
                  id="sig-tags"
                  value={tagsText}
                  onChange={(e) => setTagsText(e.target.value)}
                  placeholder="tag1, tag2"
                />
              </Field>
            </div>

            <div className="space-y-2">
              <SectionTitle
                actions={
                  <Button type="button" variant="ghost" size="xs" onClick={addMatcher}>
                    <RiAddLine /> Matcher
                  </Button>
                }
              >
                Matchers ({draft.matchers?.length || 0})
              </SectionTitle>

              <div className="divide-y divide-border border border-border">
                {(draft.matchers || []).length === 0 && <Empty>No matchers</Empty>}
                {(draft.matchers || []).map((m, idx) => (
                  <div
                    key={idx}
                    className="grid grid-cols-1 items-center gap-2 px-3 py-2 sm:grid-cols-12"
                  >
                    <SimpleSelect
                      size="sm"
                      value={m.type}
                      onValueChange={(v) => updateMatcher(idx, { type: v })}
                      options={toOptions(MATCHER_TYPES, m.type)}
                      className="font-mono sm:col-span-3"
                    />
                    <Input
                      value={m.key || ''}
                      onChange={(e) => updateMatcher(idx, { key: e.target.value })}
                      placeholder="Key"
                      className="h-9 font-mono text-xs sm:col-span-3"
                    />
                    <Input
                      value={m.pattern}
                      onChange={(e) => updateMatcher(idx, { pattern: e.target.value })}
                      placeholder="Pattern / regex"
                      className="h-9 font-mono text-xs sm:col-span-4"
                    />
                    <label className="flex items-center gap-1.5 text-[10px] font-semibold tracking-widest text-muted-foreground uppercase sm:col-span-1">
                      <input
                        type="checkbox"
                        checked={m.regex}
                        onChange={(e) => updateMatcher(idx, { regex: e.target.checked })}
                        className="size-3.5 accent-primary"
                      />
                      Rx
                    </label>
                    <div className="flex justify-end sm:col-span-1">
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon-xs"
                        aria-label="Delete matcher"
                        onClick={() => removeMatcher(idx)}
                        className="text-muted-foreground hover:text-destructive"
                      >
                        <RiDeleteBinLine />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <Textarea
            rows={22}
            value={jsonText}
            onChange={(e) => setJsonText(e.target.value)}
            spellCheck={false}
            className="field-sizing-fixed min-h-[28rem] resize-y border border-border bg-muted/30 p-3 font-mono text-xs md:text-xs"
          />
        )}
      </CardContent>

      {(canWrite || (selectedId && !draft.is_builtin && canDelete)) && (
        <CardFooter className="justify-end gap-2 border-t">
          {selectedId && !draft.is_builtin && canDelete && (
            <Button
              type="button"
              variant="destructive"
              size="sm"
              onClick={() => handleDelete(draft as Signature)}
            >
              <RiDeleteBinLine /> Delete
            </Button>
          )}
          {canWrite && (
            <Button type="button" size="sm" disabled={saving} onClick={handleSave}>
              <RiSave3Line />
              {saving ? 'Saving…' : 'Save'}
            </Button>
          )}
        </CardFooter>
      )}
    </Card>
  );

  return (
    <div>
      <PageHeader
        title="Signatures"
        meta={`${signatures.length}`}
        actions={
          <>
            {canWrite && (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  render={<label />}
                  nativeButton={false}
                  className="cursor-pointer"
                >
                  <RiUploadCloud2Line /> Import
                  <input type="file" accept=".json" onChange={handleImportFile} className="hidden" />
                </Button>
              </>
            )}
            <Button type="button" variant="outline" size="sm" onClick={() => api.exportSignatures()}>
              <RiDownload2Line /> Export
            </Button>
            {canWrite && (
              <Button type="button" size="sm" onClick={openNew}>
                <RiAddLine /> New signature
              </Button>
            )}
          </>
        }
      />

      <Tabs value={tab} onValueChange={(v) => setTab(v as SigTab)} className="gap-6">
        <TabsList variant="line">
          <TabsTrigger value="list">Signatures</TabsTrigger>
          <TabsTrigger value="editor">Editor / validator</TabsTrigger>
          <TabsTrigger value="playground">Playground</TabsTrigger>
        </TabsList>

        <TabsContent value="list">
          <Card size="sm" className="py-0">
            <div className="flex flex-col gap-3 border-b border-border px-5 py-3 sm:flex-row sm:items-center">
              <div className="relative flex-1">
                <RiSearchLine className="pointer-events-none absolute top-1/2 left-0 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search…"
                  className="pl-6"
                />
              </div>
              <SimpleSelect
                value={categoryFilter || 'all'}
                onValueChange={(v) => setCategoryFilter(v === 'all' ? '' : v)}
                options={categoryOptions}
                className="sm:w-56"
              />
            </div>

            {loading ? (
              <PeckLoader />
            ) : filteredSignatures.length === 0 ? (
              <Empty icon={RiSearchLine}>No results</Empty>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="pl-5">Name</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead className="text-right" title="Evidence weight in the Noisy-OR confidence (0.1 to 0.98)">Evidence weight</TableHead>
                    <TableHead className="pr-5 text-right" title="Points added to the risk score when it matches">Risk points</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredSignatures.map((sig) => {
                    const active = selectedId === sig.id;
                    return (
                      <TableRow
                        key={sig.id}
                        onClick={() => openSignature(sig)}
                        className={cn('cursor-pointer', active && 'bg-muted')}
                      >
                        <TableCell className="max-w-[28rem] pl-5">
                          <div className="truncate text-xs font-semibold">{sig.name}</div>
                          {sig.description && (
                            <div className="truncate text-[11px] text-muted-foreground">
                              {sig.description}
                            </div>
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {sig.category}
                        </TableCell>
                        <TableCell>
                          {sig.is_builtin ? <Pill>Built-in</Pill> : <Pill tone="violet">Custom</Pill>}
                        </TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums">
                          {sig.confidence_weight}
                        </TableCell>
                        <TableCell className="pr-5 text-right font-mono text-xs tabular-nums">
                          +{sig.interesting_points}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </Card>
        </TabsContent>

        <TabsContent value="editor">
          <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
            <div className="xl:col-span-8">{editorCard}</div>

            <Card size="sm" className="h-fit xl:col-span-4">
              <CardHeader className="border-b">
                <CardTitle className="text-sm">Validator</CardTitle>
                <CardAction>
                  <Button
                    type="button"
                    variant="outline"
                    size="xs"
                    disabled={validating}
                    onClick={handleValidate}
                  >
                    <RiShieldCheckLine />
                    {validating ? 'Checking…' : 'Validate'}
                  </Button>
                </CardAction>
              </CardHeader>
              <CardContent>
                {!validation ? (
                  <Empty icon={RiShieldCheckLine}>Not validated yet</Empty>
                ) : (
                  <Notice
                    tone={validation.valid ? 'success' : 'danger'}
                    icon={validation.valid ? RiCheckboxCircleLine : RiErrorWarningLine}
                  >
                    <div className="font-semibold">
                      {validation.valid ? 'Safe (read-only checks only)' : 'Policy violation'}
                    </div>
                    {validation.reason && <p className="mt-1">{validation.reason}</p>}
                    {(validation.errors?.length || 0) > 0 && (
                      <ul className="mt-1 list-disc space-y-0.5 pl-4">
                        {validation.errors!.map((er, i) => (
                          <li key={i}>{er}</li>
                        ))}
                      </ul>
                    )}
                  </Notice>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="playground">
          <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
            {editorCard}

            <Card size="sm" className="h-fit min-w-0">
              <CardHeader className="border-b">
                <CardTitle className="flex items-center gap-2 text-sm">
                  Retroactive test
                  {testResult && (
                    <Pill tone={(testResult.matches?.length || 0) > 0 ? 'warning' : 'neutral'}>
                      {testResult.matches?.length || 0}
                    </Pill>
                  )}
                </CardTitle>
                <CardAction>
                  <Button type="button" size="xs" disabled={testing} onClick={handleRetroactiveTest}>
                    <RiPlayLine />
                    {testing ? 'Testing…' : 'Run test'}
                  </Button>
                </CardAction>
              </CardHeader>
              <CardContent className="space-y-3">
                {testResult?.tested_services !== undefined && (
                  <div className="text-xs text-muted-foreground">
                    Checked {testResult.tested_services} services
                  </div>
                )}
                {!testResult ? (
                  <Empty icon={RiFlaskLine}>Run the test against the current inventory</Empty>
                ) : (testResult.matches?.length || 0) === 0 ? (
                  <Empty>No matches</Empty>
                ) : (
                  <div className="max-h-[32rem] overflow-y-auto border border-border">
                    <Table>
                      <TableHeader>
                        <TableRow className="hover:bg-transparent">
                          <TableHead>Service</TableHead>
                          <TableHead>Title</TableHead>
                          <TableHead>Version</TableHead>
                          <TableHead className="text-right">Conf.</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {testResult.matches.map((m, idx) => (
                          <TableRow key={idx}>
                            <TableCell className="font-mono text-xs font-semibold">
                              {m.host_ip}:{m.port}
                            </TableCell>
                            <TableCell className="max-w-[14rem] truncate text-xs">
                              {m.http_title || ''}
                            </TableCell>
                            <TableCell>
                              {m.version ? <Pill tone="success">v{m.version}</Pill> : null}
                            </TableCell>
                            <TableCell className="text-right font-mono text-xs tabular-nums">
                              {m.confidence !== undefined ? `${m.confidence}%` : ''}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
