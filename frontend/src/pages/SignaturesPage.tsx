import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  CheckCircle2,
  Code2,
  Download,
  FlaskConical,
  Plus,
  Save,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  Upload,
} from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import { PERMISSIONS } from '../lib/permissions';
import type {
  Signature,
  SignatureMatcher,
  SignatureTestResult,
  SignatureValidationResult,
} from '../types/api';

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

export function SignaturesPage() {
  const { can } = useAuth();
  const toast = useToast();

  const [signatures, setSignatures] = useState<Signature[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');

  // Editor state
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editorMode, setEditorMode] = useState<'visual' | 'json'>('visual');
  const [draft, setDraft] = useState<Partial<Signature>>(EMPTY_SIG);
  const [jsonText, setJsonText] = useState(JSON.stringify(EMPTY_SIG, null, 2));
  const [tagsText, setTagsText] = useState('custom');

  // Validator & Retroactive Playground state
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
      toast.error('Błąd pobierania sygnatur', (err as Error).message);
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
        toast.error('Niepoprawny JSON', (err as Error).message);
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
        toast.success('Walidacja bezpieczeństwa: OK', 'Sygnatura jest bezpieczna (Read-Only).');
      } else {
        toast.warning('Odrzucono przez Safety Validator', res.reason || res.errors?.join('; '));
      }
    } catch (err) {
      toast.error('Błąd walidacji sygnatury', (err as Error).message);
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
      toast.info(
        'Test retroaktywny zakończony',
        `Dopasowania: ${res.matches?.length ?? res.total_matches ?? 0} usług.`
      );
    } catch (err) {
      toast.error('Błąd testu retroaktywnego', (err as Error).message);
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const payload = getCurrentPayload();
      if (!payload.name?.trim()) {
        toast.error('Podaj nazwę sygnatury');
        return;
      }
      if (selectedId) {
        const updated = await api.updateSignature(selectedId, payload);
        toast.success('Zaktualizowano sygnaturę', updated.name);
      } else {
        const created = await api.createSignature(payload);
        setSelectedId(created.id);
        toast.success('Utworzono nową sygnaturę', created.name);
      }
      await loadSignatures();
    } catch (err) {
      toast.error('Błąd zapisu sygnatury', (err as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (sig: Signature) => {
    if (!window.confirm(`Usunąć sygnaturę "${sig.name}"?`)) return;
    try {
      await api.deleteSignature(sig.id);
      toast.success('Usunięto sygnaturę', sig.name);
      if (selectedId === sig.id) startNewSignature();
      loadSignatures();
    } catch (err) {
      toast.error('Nie udało się usunąć sygnatury', (err as Error).message);
    }
  };

  const handleImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      await api.importSignatures(parsed);
      toast.success('Zaimportowano sygnatury z JSON');
      loadSignatures();
    } catch (err) {
      toast.error('Błąd importu sygnatur', (err as Error).message);
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

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-text-primary flex items-center gap-2">
            <Sparkles className="h-5 w-5 text-cyan-400" />
            Signature Studio & Playground Retroaktywny
          </h1>
          <p className="text-xs text-text-muted mt-0.5">
            Wbudowane i własne sygnatury detekcji z Safety Validatorem (GET/HEAD only) i
            natychmiastowym testem na zapisanych obserwacjach
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {canWrite && (
            <>
              <button
                type="button"
                onClick={startNewSignature}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white"
              >
                <Plus className="h-3.5 w-3.5" /> Nowa sygnatura
              </button>
              <label className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-border-subtle bg-bg-card hover:bg-bg-hover text-text-secondary cursor-pointer">
                <Upload className="h-3.5 w-3.5" /> Import JSON
                <input type="file" accept=".json" onChange={handleImportFile} className="hidden" />
              </label>
            </>
          )}
          <button
            type="button"
            onClick={() => api.exportSignatures()}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-border-subtle bg-bg-card hover:bg-bg-hover text-text-secondary"
          >
            <Download className="h-3.5 w-3.5" /> Eksport JSON
          </button>
        </div>
      </div>

      {/* Main Split View */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        {/* Left: Signatures List */}
        <div className="xl:col-span-4 rounded-xl border border-border-subtle bg-bg-card flex flex-col max-h-[760px]">
          <div className="p-3.5 border-b border-border-subtle space-y-2">
            <div className="relative">
              <Search className="h-3.5 w-3.5 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Szukaj sygnatury..."
                className="w-full rounded-lg border border-border-subtle bg-bg-elevated pl-8 pr-3 py-1.5 text-xs text-text-primary"
              />
            </div>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1.5 text-xs text-text-primary"
            >
              <option value="">Wszystkie kategorie ({signatures.length})</option>
              {CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>

          <div className="flex-1 overflow-y-auto divide-y divide-border-subtle/60">
            {loading ? (
              <div className="p-6 text-center text-xs text-text-muted">Ładowanie sygnatur...</div>
            ) : filteredSignatures.length === 0 ? (
              <div className="p-6 text-center text-xs text-text-muted">Brak pasujących sygnatur.</div>
            ) : (
              filteredSignatures.map((sig) => {
                const active = selectedId === sig.id;
                return (
                  <div
                    key={sig.id}
                    onClick={() => selectSignature(sig)}
                    className={`p-3 cursor-pointer transition-colors ${
                      active ? 'bg-cyan-500/10 border-l-2 border-l-cyan-400' : 'hover:bg-bg-hover/60'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-semibold text-text-primary truncate">
                        {sig.name}
                      </span>
                      <div className="flex items-center gap-1 shrink-0">
                        {sig.is_builtin ? (
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-bg-elevated text-text-muted border border-border-subtle">
                            builtin
                          </span>
                        ) : (
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-300 border border-violet-500/30">
                            custom
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center justify-between text-[11px] text-text-muted mt-1">
                      <span className="font-mono">{sig.category}</span>
                      <span className="font-mono">
                        w={sig.confidence_weight} · +{sig.interesting_points}pkt
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right: Builder / JSON Editor + Validator + Retroactive Test */}
        <div className="xl:col-span-8 space-y-4">
          <div className="rounded-xl border border-border-subtle bg-bg-card p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-semibold text-text-primary">
                  {selectedId ? `Edycja: ${draft.name || ''}` : 'Nowa Sygnatura Detekcji'}
                </h2>
                {draft.is_builtin && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-bg-elevated text-text-muted border border-border-subtle">
                    Wbudowana
                  </span>
                )}
              </div>

              <div className="inline-flex rounded-lg border border-border-subtle bg-bg-elevated p-0.5">
                <button
                  type="button"
                  onClick={() => switchEditorMode('visual')}
                  className={`px-3 py-1 rounded text-xs font-medium ${
                    editorMode === 'visual'
                      ? 'bg-cyan-500/15 text-cyan-400'
                      : 'text-text-muted hover:text-text-primary'
                  }`}
                >
                  Kreator wizualny
                </button>
                <button
                  type="button"
                  onClick={() => switchEditorMode('json')}
                  className={`inline-flex items-center gap-1 px-3 py-1 rounded text-xs font-medium ${
                    editorMode === 'json'
                      ? 'bg-cyan-500/15 text-cyan-400'
                      : 'text-text-muted hover:text-text-primary'
                  }`}
                >
                  <Code2 className="h-3.5 w-3.5" /> Edytor JSON
                </button>
              </div>
            </div>

            {editorMode === 'visual' ? (
              <div className="space-y-4 text-xs">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="sm:col-span-2">
                    <label className="block text-text-muted mb-1">Nazwa sygnatury *</label>
                    <input
                      type="text"
                      value={draft.name || ''}
                      onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
                      placeholder="np. AGH Internal Staging Debug Header"
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 text-text-primary"
                    />
                  </div>
                  <div>
                    <label className="block text-text-muted mb-1">Kategoria</label>
                    <select
                      value={draft.category || 'custom'}
                      onChange={(e) => setDraft((d) => ({ ...d, category: e.target.value }))}
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1.5 text-text-primary"
                    >
                      {CATEGORIES.map((c) => (
                        <option key={c} value={c}>
                          {c}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="sm:col-span-3">
                    <label className="block text-text-muted mb-1">Opis</label>
                    <input
                      type="text"
                      value={draft.description || ''}
                      onChange={(e) => setDraft((d) => ({ ...d, description: e.target.value }))}
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 text-text-primary"
                    />
                  </div>
                  <div>
                    <label className="block text-text-muted mb-1">Tryb dopasowania</label>
                    <select
                      value={draft.match_mode || 'any'}
                      onChange={(e) => setDraft((d) => ({ ...d, match_mode: e.target.value }))}
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1.5 text-text-primary"
                    >
                      <option value="any">ANY (dowolny matcher)</option>
                      <option value="all">ALL (wszystkie matchery)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-text-muted mb-1">
                      Confidence Weight (0.1–0.98)
                    </label>
                    <input
                      type="number"
                      step={0.05}
                      min={0.1}
                      max={0.98}
                      value={draft.confidence_weight ?? 0.75}
                      onChange={(e) =>
                        setDraft((d) => ({ ...d, confidence_weight: Number(e.target.value) }))
                      }
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-text-primary"
                    />
                  </div>
                  <div>
                    <label className="block text-text-muted mb-1">Punkty Interestingness</label>
                    <input
                      type="number"
                      min={0}
                      max={100}
                      value={draft.interesting_points ?? 20}
                      onChange={(e) =>
                        setDraft((d) => ({ ...d, interesting_points: Number(e.target.value) }))
                      }
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-text-primary"
                    />
                  </div>
                  <div className="sm:col-span-3">
                    <label className="block text-text-muted mb-1">Tagi (po przecinku)</label>
                    <input
                      type="text"
                      value={tagsText}
                      onChange={(e) => setTagsText(e.target.value)}
                      className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 text-text-primary"
                    />
                  </div>
                </div>

                {/* Matchers Builder */}
                <div className="space-y-2 pt-2 border-t border-border-subtle">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-text-secondary">
                      Reguły dopasowania — Matchers ({draft.matchers?.length || 0})
                    </span>
                    <button
                      type="button"
                      onClick={addMatcher}
                      className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:underline"
                    >
                      <Plus className="h-3.5 w-3.5" /> Dodaj matcher
                    </button>
                  </div>

                  {(draft.matchers || []).map((m, idx) => (
                    <div
                      key={idx}
                      className="grid grid-cols-1 sm:grid-cols-12 gap-2 items-center rounded-lg border border-border-subtle bg-bg-elevated/70 p-2.5"
                    >
                      <select
                        value={m.type}
                        onChange={(e) => updateMatcher(idx, { type: e.target.value })}
                        className="sm:col-span-3 rounded border border-border-subtle bg-bg-card px-2 py-1.5 font-mono text-text-primary"
                      >
                        {MATCHER_TYPES.map((t) => (
                          <option key={t} value={t}>
                            {t}
                          </option>
                        ))}
                      </select>
                      <input
                        type="text"
                        value={m.key || ''}
                        onChange={(e) => updateMatcher(idx, { key: e.target.value })}
                        placeholder="Klucz (np. Server)"
                        className="sm:col-span-3 rounded border border-border-subtle bg-bg-card px-2 py-1.5 font-mono text-text-primary"
                      />
                      <input
                        type="text"
                        value={m.pattern}
                        onChange={(e) => updateMatcher(idx, { pattern: e.target.value })}
                        placeholder="Wzorzec / Regex..."
                        className="sm:col-span-4 rounded border border-border-subtle bg-bg-card px-2 py-1.5 font-mono text-text-primary"
                      />
                      <label className="sm:col-span-1 flex items-center gap-1 text-[11px] text-text-muted">
                        <input
                          type="checkbox"
                          checked={m.regex}
                          onChange={(e) => updateMatcher(idx, { regex: e.target.checked })}
                          className="accent-cyan-500"
                        />
                        Rx
                      </label>
                      <button
                        type="button"
                        onClick={() => removeMatcher(idx)}
                        className="sm:col-span-1 text-text-muted hover:text-rose-400 flex justify-end"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <textarea
                rows={16}
                value={jsonText}
                onChange={(e) => setJsonText(e.target.value)}
                className="w-full rounded-lg border border-border-subtle bg-bg-primary p-3 font-mono text-xs text-cyan-200 focus:outline-none focus:border-cyan-500"
              />
            )}

            {/* Action Bar */}
            <div className="flex flex-wrap items-center justify-between gap-2 pt-3 border-t border-border-subtle">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={validating}
                  onClick={handleValidate}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-emerald-500/35 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-50"
                >
                  <ShieldCheck className="h-3.5 w-3.5" />
                  {validating ? 'Sprawdzanie...' : 'Waliduj bezpieczeństwo'}
                </button>
                <button
                  type="button"
                  disabled={testing}
                  onClick={handleRetroactiveTest}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-amber-500/35 bg-amber-500/10 text-amber-300 hover:bg-amber-500/20 disabled:opacity-50"
                >
                  <FlaskConical className="h-3.5 w-3.5" />
                  {testing ? 'Testowanie...' : 'Testuj na zapisanych danych'}
                </button>
              </div>

              <div className="flex items-center gap-2">
                {selectedId && !draft.is_builtin && canDelete && (
                  <button
                    type="button"
                    onClick={() => handleDelete(draft as Signature)}
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-rose-500/15 text-rose-300 border border-rose-500/35 hover:bg-rose-500/25"
                  >
                    <Trash2 className="h-3.5 w-3.5" /> Usuń
                  </button>
                )}
                {canWrite && (
                  <button
                    type="button"
                    disabled={saving}
                    onClick={handleSave}
                    className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-50"
                  >
                    <Save className="h-3.5 w-3.5" />
                    {saving ? 'Zapisywanie...' : 'Zapisz sygnaturę'}
                  </button>
                )}
              </div>
            </div>

            {/* Safety Validation Banner */}
            {validation && (
              <div
                className={`rounded-lg border p-3 text-xs flex items-start gap-2.5 ${
                  validation.valid
                    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
                    : 'border-rose-500/40 bg-rose-500/10 text-rose-300'
                }`}
              >
                {validation.valid ? (
                  <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" />
                ) : (
                  <ShieldAlert className="h-4 w-4 shrink-0 mt-0.5" />
                )}
                <div>
                  <div className="font-semibold">
                    {validation.valid
                      ? 'Safety Validator: Sygnatura bezpieczna (Read-Only, brak metod mutujących/logowania)'
                      : 'Safety Validator: Wykryto naruszenie polityki bezpieczeństwa!'}
                  </div>
                  {validation.reason && <p className="mt-0.5">{validation.reason}</p>}
                  {(validation.errors?.length || 0) > 0 && (
                    <ul className="list-disc pl-4 mt-1 space-y-0.5">
                      {validation.errors!.map((er, i) => (
                        <li key={i}>{er}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Retroactive Playground Results */}
          {testResult && (
            <div className="rounded-xl border border-amber-500/35 bg-bg-card p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-amber-300 flex items-center gap-2">
                  <FlaskConical className="h-4 w-4" />
                  Wyniki Playgroundu Retroaktywnego ({testResult.matches?.length || 0} dopasowań)
                </h3>
                {testResult.tested_services !== undefined && (
                  <span className="text-xs font-mono text-text-muted">
                    Przeszukano {testResult.tested_services} zapisanych usług
                  </span>
                )}
              </div>

              {(testResult.matches?.length || 0) === 0 ? (
                <p className="text-xs text-text-muted py-4 text-center">
                  Żadna z zapisanych usług nie pasuje do tej definicji sygnatury.
                </p>
              ) : (
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {testResult.matches.map((m, idx) => (
                    <div
                      key={idx}
                      className="rounded-lg border border-border-subtle bg-bg-elevated p-3 flex flex-wrap items-center justify-between gap-2 text-xs"
                    >
                      <div>
                        <span className="font-mono font-bold text-cyan-400">
                          {m.host_ip}:{m.port}
                        </span>
                        {m.http_title && (
                          <span className="text-text-primary ml-2">{m.http_title}</span>
                        )}
                        {m.version && (
                          <span className="ml-2 font-mono text-[11px] px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300">
                            v{m.version}
                          </span>
                        )}
                      </div>
                      {m.confidence !== undefined && (
                        <span className="font-mono text-xs text-amber-300 font-semibold">
                          Confidence: {m.confidence}%
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
