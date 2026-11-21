import React, { createContext, useCallback, useContext, useState } from 'react';
import {
  RiAlertLine as AlertTriangle,
  RiCheckboxCircleLine as CheckCircle2,
  RiCloseCircleLine as XCircle,
  RiCloseLine,
  RiInformationLine as Info,
} from '@remixicon/react';

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
      <div className="pointer-events-none fixed right-4 bottom-4 z-[90] flex w-full max-w-sm flex-col gap-2 px-4 sm:px-0">
        {items.map((item) => {
          const styles =
            item.kind === 'success'
              ? 'text-emerald-600 dark:text-emerald-400'
              : item.kind === 'error'
                ? 'text-rose-600 dark:text-rose-400'
                : item.kind === 'warning'
                  ? 'text-amber-600 dark:text-amber-400'
                  : 'text-sky-600 dark:text-sky-400';
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
              className={`pointer-events-auto flex items-start gap-3 border bg-popover px-4 py-3 shadow-md ${styles}`}
            >
              <Icon className="mt-0.5 size-4 shrink-0" />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-foreground">{item.title}</p>
                {item.detail && (
                  <p className="mt-0.5 text-xs break-words text-muted-foreground">{item.detail}</p>
                )}
              </div>
              <button
                type="button"
                onClick={() => dismiss(item.id)}
                className="text-muted-foreground hover:text-foreground"
                aria-label="Zamknij"
              >
                <RiCloseLine className="size-4" />
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
