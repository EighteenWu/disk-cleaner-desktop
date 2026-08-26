import type { CoverageGap, InventoryQueryItem, ScanCoverageStatus } from "./types";

export function mergeInventoryItems(
  current: InventoryQueryItem[],
  incoming: InventoryQueryItem[],
  append: boolean
): InventoryQueryItem[] {
  if (!append) {
    return incoming;
  }
  const seen = new Set(current.map((item) => item.entryId));
  return [...current, ...incoming.filter((item) => !seen.has(item.entryId))];
}

export function isIncompleteCoverage(status: ScanCoverageStatus): boolean {
  return status !== "complete" && status !== "notStarted";
}

export function occupancyPercent(allocatedBytes: number, totalBytes: number): number {
  if (totalBytes <= 0 || allocatedBytes <= 0) {
    return 0;
  }

  return Math.min(100, Math.max(2, Math.round((allocatedBytes / totalBytes) * 100)));
}

export function mergeActionableGaps(gaps: CoverageGap[]): CoverageGap[] {
  const merged = new Map<string, CoverageGap>();

  for (const gap of gaps) {
    if (gap.reason === "reparseNotFollowed" || gap.reason === "identityFallback") {
      continue;
    }

    const key = `${gap.volumeId}:${gap.reason}`;
    const current = merged.get(key);
    if (current) {
      current.count += gap.count;
    } else {
      merged.set(key, { ...gap });
    }
  }

  return Array.from(merged.values());
}
