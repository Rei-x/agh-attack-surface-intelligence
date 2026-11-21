import { useMemo, useState } from 'react';
import { RiCheckLine, RiDownload2Line, RiFileCopyLine, RiTerminalBoxLine } from '@remixicon/react';
import { api } from '@/lib/api';
import { useToast } from '@/context/ToastContext';
import { Button } from '@/components/ui/button';
import { SectionTitle } from '@/components/common';
import type { ScanChunk, ScanRun } from '@/types/api';
import { collapseCommands } from '@/lib/scanTelemetry';

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
  // A re-probe retry runs the identical command again: show it once with the count.
  const lines = useMemo(() => collapseCommands(commands), [commands]);

  if (commands.length === 0 && !scan.has_raw_nmap_xml) return null;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(commands.join('\n') + '\n');
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.error('Could not copy', 'Clipboard is not available in this browser');
    }
  };

  const download = async () => {
    setDownloading(true);
    try {
      await api.downloadScanNmapXml(scan.id);
    } catch (err) {
      toast.error('Download failed', (err as Error).message);
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
                {copied ? 'Copied' : 'Copy'}
              </Button>
            )}
            {scan.has_raw_nmap_xml && (
              <Button variant="outline" size="xs" disabled={downloading} onClick={download}>
                <RiDownload2Line data-icon="inline-start" />
                Download nmap XML
              </Button>
            )}
          </div>
        }
      >
        <span className="inline-flex items-center gap-1.5">
          <RiTerminalBoxLine className="size-3.5" />
          nmap commands · {lines.length}
        </span>
      </SectionTitle>
      {commands.length > 0 ? (
        <pre className="max-h-48 overflow-auto rounded-md bg-muted/50 p-2 font-mono text-[11px] leading-relaxed whitespace-pre-wrap break-all text-muted-foreground">
          {lines.map((l, i) => (
            <div key={i}>
              <span className="select-none text-foreground/60">$ </span>
              {l.cmd}
              {l.times > 1 && (
                <span className="ml-2 select-none text-foreground/70">({l.times} attempts, re-probe retry)</span>
              )}
            </div>
          ))}
        </pre>
      ) : (
        <p className="text-xs text-muted-foreground">
          Results were imported from nmap XML. The original file can be downloaded above.
        </p>
      )}
    </div>
  );
}
