import React, { createContext, useCallback, useContext, useState } from 'react';
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from 'lucide-react';

type ToastKind = 'success' | 'error' | 'warning' | 'info';

interface ToastItem {
  id: string;
  kind: ToastKind;
  title: string;
  detail?: string;
}

interface ToastContextValue {
  toast: {
    success: (title: string, detail?: string) => void;
    error: (title: string, detail?: string) => void;
    warning: (title: string, detail?: string) => void;
    info: (title: string, detail?: string) => void;
  };
}

const ToastContext = createContext<ToastContextValue>({
  toast: {
    success: () => {},
    error: () => {},
    warning: () => {},
    info: () => {},
  },
});

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);

  const push = useCallback((kind: ToastKind, title: string, detail?: string) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    setItems((prev) => [...prev.slice(-4), { id, kind, title, detail }]);
    window.setTimeout(() => {
      setItems((prev) => prev.filter((item) => item.id !== id));
    }, 5200);
  }, []);

  const dismiss = (id: string) => setItems((prev) => prev.filter((i) => i.id !== id));

  const value: ToastContextValue = {
    toast: {
      success: (t, d) => push('success', t, d),
      error: (t, d) => push('error', t, d),
      warning: (t, d) => push('warning', t, d),
      info: (t, d) => push('info', t, d),
    },
  };

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="fixed bottom-4 right-4 z-[90] flex flex-col gap-2 max-w-md w-full pointer-events-none px-4 sm:px-0">
        {items.map((item) => {
          const styles =
            item.kind === 'success'
              ? 'border-emerald-500/40 bg-bg-card/95 text-emerald-300'
              : item.kind === 'error'
                ? 'border-rose-500/40 bg-bg-card/95 text-rose-300'
                : item.kind === 'warning'
                  ? 'border-amber-500/40 bg-bg-card/95 text-amber-300'
                  : 'border-cyan-500/40 bg-bg-card/95 text-cyan-300';
          const Icon =
            item.kind === 'success'
              ? CheckCircle2
              : item.kind === 'error'
                ? XCircle
                : item.kind === 'warning'
                  ? AlertTriangle
                  : Info;

          return (
            <div
              key={item.id}
              className={`pointer-events-auto flex items-start gap-3 rounded-lg border px-4 py-3 shadow-xl backdrop-blur-md ${styles}`}
            >
              <Icon className="h-4 w-4 mt-0.5 shrink-0" />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-text-primary">{item.title}</p>
                {item.detail && (
                  <p className="text-xs text-text-muted mt-0.5 break-words">{item.detail}</p>
                )}
              </div>
              <button
                type="button"
                onClick={() => dismiss(item.id)}
                className="text-text-muted hover:text-text-primary"
                aria-label="Zamknij"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext).toast;
}
