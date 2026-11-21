import { useEffect, useRef, useState } from 'react';
import { ApiError, getStoredToken } from './api';
import type { Service } from '../types/api';

/** One stored screenshot of a service (ids are opaque blob ids). */
export interface ScreenshotEntry {
  id: string;
  thumb: string;
  width: number;
  height: number;
  bytes: number;
  phash: string;
  url: string;
  title?: string;
  first_seen: string;
  captured_at: string;
  scan_run_id?: string;
}

export interface ScreenshotKey {
  ip: string;
  port: number;
  protocol: string;
}

export type GalleryKind = 'admin' | 'iot' | 'default' | 'eol';

export interface GalleryItem {
  host_id: string;
  host_ip: string;
  hostname?: string;
  owner?: string;
  service: Service;
  shot: ScreenshotEntry;
  versions: number;
  key: ScreenshotKey;
  kinds?: GalleryKind[];
}

export interface ScreenshotStatus {
  available: boolean;
  detail: string;
  store: boolean;
}

export interface GalleryResponse {
  items: GalleryItem[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
  counts: Partial<Record<GalleryKind | 'all', number>>;
  status: ScreenshotStatus;
}

export interface HostScreenshots {
  host_id: string;
  services: Array<{ key: ScreenshotKey; entries: ScreenshotEntry[] }>;
  status: ScreenshotStatus;
}

async function authedFetch(path: string, signal?: AbortSignal): Promise<Response> {
  const headers = new Headers();
  const token = getStoredToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const res = await fetch(path, { headers, signal });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.error) msg = body.error;
    } catch {
      // not JSON
    }
    throw new ApiError(res.status, msg);
  }
  return res;
}

export async function listScreenshots(params: {
  q?: string;
  kind?: GalleryKind | '';
  page?: number;
  limit?: number;
}): Promise<GalleryResponse> {
  const sp = new URLSearchParams();
  if (params.q) sp.set('q', params.q);
  if (params.kind) sp.set('kind', params.kind);
  if (params.page) sp.set('page', String(params.page));
  if (params.limit) sp.set('limit', String(params.limit));
  const res = await authedFetch(`/api/v1/screenshots?${sp.toString()}`);
  return res.json();
}

const hostCache = new Map<string, Promise<HostScreenshots>>();

/** Screenshots of every service of one host (cached briefly per host for the drawer). */
export function hostScreenshots(hostId: string): Promise<HostScreenshots> {
  let p = hostCache.get(hostId);
  if (!p) {
    p = authedFetch(`/api/v1/hosts/${encodeURIComponent(hostId)}/screenshots`).then((r) => r.json());
    hostCache.set(hostId, p);
    p.catch(() => hostCache.delete(hostId));
    window.setTimeout(() => hostCache.delete(hostId), 30_000);
  }
  return p;
}

/**
 * Images need the bearer token, so <img src> cannot load them directly. They are fetched
 * once and kept as blob: URLs (content-addressed ids never change, so the cache is safe).
 */
const blobCache = new Map<string, Promise<string>>();
const BLOB_CACHE_MAX = 400;

export function screenshotBlobURL(id: string): Promise<string> {
  let p = blobCache.get(id);
  if (!p) {
    p = authedFetch(`/api/v1/screenshots/${id}`)
      .then((r) => r.blob())
      .then((b) => URL.createObjectURL(b));
    p.catch(() => blobCache.delete(id));
    blobCache.set(id, p);
    if (blobCache.size > BLOB_CACHE_MAX) {
      const oldest = blobCache.keys().next().value as string;
      const old = blobCache.get(oldest);
      blobCache.delete(oldest);
      old?.then((u) => URL.revokeObjectURL(u)).catch(() => undefined);
    }
  }
  return p;
}

/**
 * Lazily resolves an image id to a blob URL once the element scrolls near the viewport.
 * Returns [ref to attach, url or null, failed].
 */
export function useScreenshotImage<T extends Element>(id: string | undefined, lazy = true) {
  const ref = useRef<T | null>(null);
  const [visible, setVisible] = useState(!lazy);
  const [url, setUrl] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!lazy || visible) return;
    const el = ref.current;
    if (!el || typeof IntersectionObserver === 'undefined') {
      setVisible(true);
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setVisible(true);
          io.disconnect();
        }
      },
      { rootMargin: '300px' }
    );
    io.observe(el);
    // Hidden or throttled tabs may never deliver observer callbacks: check geometry once.
    const t = window.setTimeout(() => {
      const r = el.getBoundingClientRect();
      if (r.top < window.innerHeight + 300 && r.bottom > -300) setVisible(true);
    }, 1200);
    return () => {
      io.disconnect();
      window.clearTimeout(t);
    };
  }, [lazy, visible]);

  useEffect(() => {
    if (!id || !visible) return;
    let alive = true;
    setFailed(false);
    screenshotBlobURL(id)
      .then((u) => alive && setUrl(u))
      .catch(() => alive && setFailed(true));
    return () => {
      alive = false;
    };
  }, [id, visible]);

  return [ref, url, failed] as const;
}
