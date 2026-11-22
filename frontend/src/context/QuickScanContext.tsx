import { createContext, useContext } from 'react';

/** Opens the Quick scan dialog owned by the Layout (header button and Scans page). */
export const QuickScanContext = createContext<() => void>(() => {});

export function useOpenQuickScan() {
  return useContext(QuickScanContext);
}
