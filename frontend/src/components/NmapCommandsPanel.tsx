import { useMemo, useState } from 'react';
import { RiCheckLine, RiDownload2Line, RiFileCopyLine, RiTerminalBoxLine } from '@remixicon/react';
import { api } from '@/lib/api';
import { useToast } from '@/context/ToastContext';
import { Button } from '@/components/ui/button';
import { SectionTitle } from '@/components/common';
import type { ScanChunk, ScanRun } from '@/types/api';

/**
 * Exact nmap command lines executed for a run (per chunk), copyable as a shell script,
 * plus a download of the run's merged raw nmap XML (-oX) for DefectDojo / Metasploit / etc.
 */
export function NmapCommandsPanel({ scan, chunks }: { scan: ScanRun; chunks: ScanChunk[] }) {
  const toast = useToast();
  const [copied, setCopied] = useState(false);
  const [downloading, setDownloading] = useState(false);

  const commands = useMemo(
    () =>
      [...chunks]
        .sort((a, b) => a.chunk_index - b.chunk_index)
        .flatMap((c) => c.nmap_commands || []),
    [chunks]
  );

  if (commands.length === 0 && !scan.has_raw_nmap_xml) return null;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(commands.join('\n') + '\n');
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.error('Nie udało się skopiować', 'Schowek niedostępny w tej przeglądarce');
    }
  };

  const download = async () => {
    setDownloading(true);
    try {
      await api.downloadScanNmapXml(scan.id);
    } catch (err) {
      toast.error('Błąd pobierania', (err as Error).message);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="space-y-2">
      <SectionTitle
        actions={
          <div className="flex gap-2">
            {commands.length > 0 && (
              <Button variant="outline" size="xs" onClick={copy}>
                {copied ? (
                  <RiCheckLine data-icon="inline-start" />
                ) : (
                  <RiFileCopyLine data-icon="inline-start" />
                )}
                {copied ? 'Skopiowano' : 'Kopiuj'}
              </Button>
            )}
            {scan.has_raw_nmap_xml && (
              <Button variant="outline" size="xs" disabled={downloading} onClick={download}>
                <RiDownload2Line data-icon="inline-start" />
                Pobierz nmap XML
              </Button>
            )}
          </div>
        }
      >
        <span className="inline-flex items-center gap-1.5">
          <RiTerminalBoxLine className="size-3.5" />
          Polecenia nmap · {commands.length}
        </span>
      </SectionTitle>
      {commands.length > 0 ? (
        <pre className="max-h-48 overflow-auto rounded-md bg-muted/50 p-2 font-mono text-[11px] leading-relaxed whitespace-pre-wrap break-all text-muted-foreground">
          {commands.map((cmd, i) => (
            <div key={i}>
              <span className="select-none text-foreground/60">$ </span>
              {cmd}
            </div>
          ))}
        </pre>
      ) : (
        <p className="text-xs text-muted-foreground">
          Wyniki zaimportowane z nmap XML. Oryginalny plik można pobrać powyżej.
        </p>
      )}
    </div>
  );
}
