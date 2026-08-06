import type { InventoryQueryItem, ScanCoverageStatus } from "./types";

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
