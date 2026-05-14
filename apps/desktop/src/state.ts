import type {
  CleanupCandidate,
  CleanupPlan,
  CleanupReport,
  DeleteStrategy,
  RiskFilter,
  RiskLevel,
  ScanStatus,
  VolumeInfo
} from "./types";

export type ScanControlAction = "start" | "pause" | "resume" | "rescan";

export interface ScanControlState {
  action: ScanControlAction;
  label: string;
}

export interface VisibleWindow {
  startIndex: number;
  endIndex: number;
  topPadding: number;
  bottomPadding: number;
}

export interface CleanupBatch {
  candidates: CleanupCandidate[];
  selectedIds: string[];
}

export function formatBytes(bytes: number): string {
  if (bytes >= 1024 ** 3) {
    return `${trim(bytes / 1024 ** 3)} GB`;
  }

  if (bytes >= 1024 ** 2) {
    return `${trim(bytes / 1024 ** 2)} MB`;
  }

  return `${bytes} B`;
}

export function riskLabel(riskLevel: RiskLevel): string {
  switch (riskLevel) {
    case "safeRecommended":
      return "推荐";
    case "cautiousRecommended":
      return "谨慎";
    case "reviewRequired":
      return "危险";
    case "blocked":
      return "不可清理";
  }
}

export function riskClass(riskLevel: RiskLevel): string {
  switch (riskLevel) {
    case "safeRecommended":
      return "safe";
    case "cautiousRecommended":
      return "warn";
    case "reviewRequired":
      return "danger";
    case "blocked":
      return "danger";
  }
}

export function cleanupStatusLabel(candidate: CleanupCandidate): string {
  if (candidate.category === "大文件") {
    return "仅分析";
  }

  if (candidate.reason.includes("暂不支持")) {
    return "暂不支持";
  }

  if (candidate.riskLevel === "blocked" || candidate.deleteStrategy === "skip") {
    return "禁止清理";
  }

  if (candidate.selected && candidate.defaultSelected) {
    return "默认清理";
  }

  if (candidate.riskLevel === "safeRecommended") {
    return "推荐";
  }

  if (candidate.riskLevel === "cautiousRecommended") {
    return "谨慎";
  }

  return "危险";
}

export function cleanupStatusClass(candidate: CleanupCandidate): string {
  const label = cleanupStatusLabel(candidate);

  if (label === "默认清理" || label === "推荐") {
    return "safe";
  }

  if (label === "谨慎") {
    return "warn";
  }

  if (label === "仅分析") {
    return "info";
  }

  return "danger";
}

export function isCleanupSelectable(candidate: CleanupCandidate): boolean {
  return candidate.riskLevel !== "blocked" && candidate.deleteStrategy !== "skip";
}

export function scanControlForStatus(scanStatus: ScanStatus): ScanControlState {
  switch (scanStatus) {
    case "scanning":
      return { action: "pause", label: "暂停" };
    case "paused":
      return { action: "resume", label: "继续" };
    case "complete":
    case "failed":
      return { action: "rescan", label: "重新扫描" };
    case "idle":
      return { action: "start", label: "开始扫描" };
  }
}

export function visibleWindowForList(
  itemCount: number,
  scrollTop: number,
  viewportHeight: number,
  rowHeight: number,
  overscan: number
): VisibleWindow {
  if (itemCount <= 0 || rowHeight <= 0 || viewportHeight <= 0) {
    return { startIndex: 0, endIndex: 0, topPadding: 0, bottomPadding: 0 };
  }

  const safeScrollTop = Math.max(0, scrollTop);
  const safeOverscan = Math.max(0, overscan);
  const firstVisible = Math.floor(safeScrollTop / rowHeight);
  const visibleCount = Math.ceil(viewportHeight / rowHeight);
  const startIndex = Math.max(0, firstVisible - safeOverscan);
  const endIndex = Math.min(itemCount, firstVisible + visibleCount + safeOverscan);

  return {
    startIndex,
    endIndex,
    topPadding: startIndex * rowHeight,
    bottomPadding: Math.max(0, itemCount - endIndex) * rowHeight
  };
}

export function canOpenChildren(candidate: CleanupCandidate): boolean {
  return candidate.objectType === "directory";
}

export function filterCandidates(
  candidates: CleanupCandidate[],
  query: string,
  filter: RiskFilter,
  selectedCategories?: ReadonlySet<string>
): CleanupCandidate[] {
  const normalizedQuery = query.trim().toLocaleLowerCase();

  return candidates.filter((candidate) => {
    if (selectedCategories && !selectedCategories.has(candidate.category)) {
      return false;
    }

    const matchesFilter =
      filter === "all" ||
      (filter === "recommended" && candidate.riskLevel === "safeRecommended") ||
      (filter === "caution" && candidate.riskLevel === "cautiousRecommended") ||
      (filter === "dangerous" &&
        (candidate.riskLevel === "reviewRequired" ||
          candidate.riskLevel === "blocked" ||
          candidate.deleteStrategy === "skip"));

    if (!matchesFilter) {
      return false;
    }

    if (!normalizedQuery) {
      return true;
    }

    return [
      candidate.displayName,
      candidate.path,
      candidate.category,
      candidate.reason,
      candidate.source.label,
      candidate.source.kind,
      candidate.source.evidence
    ]
      .join(" ")
      .toLocaleLowerCase()
      .includes(normalizedQuery);
  });
}

export function selectedCandidateCategories(candidates: CleanupCandidate[]): Set<string> {
  return new Set(
    candidates
      .filter((candidate) => candidate.selected && isCleanupSelectable(candidate))
      .map((candidate) => candidate.category)
  );
}

export function selectedVolumeIds(volumes: VolumeInfo[]): Set<string> {
  return new Set(volumes.filter((volume) => volume.selected).map((volume) => volume.id));
}

export function scopeCandidatesToVolumes(
  candidates: CleanupCandidate[],
  selectedVolumes: Set<string>
): CleanupCandidate[] {
  if (selectedVolumes.size === 0) {
    return [];
  }

  return candidates.filter((candidate) => selectedVolumes.has(candidate.volumeId));
}

export function toggleCandidate(candidates: CleanupCandidate[], candidateId: string): CleanupCandidate[] {
  return candidates.map((candidate) => {
    if (candidate.id !== candidateId || !isCleanupSelectable(candidate)) {
      return candidate;
    }

    return {
      ...candidate,
      selected: !candidate.selected
    };
  });
}

export function setCandidateSelection(
  candidates: CleanupCandidate[],
  candidateIds: string[],
  selected: boolean
): CleanupCandidate[] {
  const lookup = new Set(candidateIds);

  return candidates.map((candidate) => {
    if (!lookup.has(candidate.id) || !isCleanupSelectable(candidate)) {
      return candidate;
    }

    return {
      ...candidate,
      selected
    };
  });
}

export function selectedCandidateIds(candidates: CleanupCandidate[]): string[] {
  return candidates
    .filter((candidate) => candidate.selected && isCleanupSelectable(candidate))
    .map((candidate) => candidate.id);
}

export function cleanupPreviewSummary(
  candidates: CleanupCandidate[],
  deleteStrategy: Exclude<DeleteStrategy, "skip">
): CleanupPlan {
  return candidates.reduce<CleanupPlan>(
    (plan, candidate) => {
      if (!candidate.selected) {
        return plan;
      }

      if (!isCleanupSelectable(candidate)) {
        plan.skippedLockedCount += 1;
        return plan;
      }

      plan.selectedCount += 1;
      plan.estimatedReclaimBytes += candidate.sizeBytes;
      return plan;
    },
    {
      selectedCount: 0,
      skippedLockedCount: 0,
      estimatedReclaimBytes: 0,
      deleteStrategy,
      warnings: ["清理前会重新校验对象状态，目录会展开为具体子项执行。"]
    }
  );
}

export function allCleanableSelected(candidates: CleanupCandidate[]): boolean {
  const cleanable = candidates.filter(isCleanupSelectable);

  return cleanable.length > 0 && cleanable.every((candidate) => candidate.selected);
}

export function removeCandidates(
  candidates: CleanupCandidate[],
  candidateIds: string[],
  candidatePaths: string[] = []
): CleanupCandidate[] {
  const lookup = new Set(candidateIds);
  const removedPaths = candidatePaths.map(normalizeCandidatePath).filter(Boolean);

  return candidates.filter((candidate) => {
    if (lookup.has(candidate.id) || (candidate.parentId !== null && lookup.has(candidate.parentId))) {
      return false;
    }

    const candidatePath = normalizeCandidatePath(candidate.path);

    return !removedPaths.some(
      (removedPath) => candidatePath === removedPath || candidatePath.startsWith(`${removedPath}/`)
    );
  });
}

function normalizeCandidatePath(path: string): string {
  return path.replace(/\\/g, "/").replace(/\/+$/, "").toLocaleLowerCase();
}

export function cleanupBatches(
  candidates: CleanupCandidate[],
  selectedIds: string[],
  batchSize: number
): CleanupBatch[] {
  const selectedLookup = new Set(selectedIds);
  const selectedCandidates = candidates.filter(
    (candidate) => selectedLookup.has(candidate.id) && isCleanupSelectable(candidate)
  );
  const safeBatchSize = Math.max(1, Math.floor(batchSize));
  const batches: CleanupBatch[] = [];

  for (let startIndex = 0; startIndex < selectedCandidates.length; startIndex += safeBatchSize) {
    const batchCandidates = selectedCandidates.slice(startIndex, startIndex + safeBatchSize);
    batches.push({
      candidates: batchCandidates,
      selectedIds: batchCandidates.map((candidate) => candidate.id)
    });
  }

  return batches;
}

export function mergeCleanupReports(reports: CleanupReport[]): CleanupReport {
  return reports.reduce<CleanupReport>(
    (mergedReport, report) => ({
      requestedCount: mergedReport.requestedCount + report.requestedCount,
      cleanedCount: mergedReport.cleanedCount + report.cleanedCount,
      skippedLockedCount: mergedReport.skippedLockedCount + report.skippedLockedCount,
      failedCount: mergedReport.failedCount + report.failedCount,
      cancelled: mergedReport.cancelled || report.cancelled,
      reclaimedBytes: mergedReport.reclaimedBytes + report.reclaimedBytes,
      cleanedIds: [...mergedReport.cleanedIds, ...report.cleanedIds],
      skippedIds: [...mergedReport.skippedIds, ...report.skippedIds],
      failedIds: [...mergedReport.failedIds, ...report.failedIds],
      deleteStrategy: "moveToRecycleBin",
      warnings: [...mergedReport.warnings, ...report.warnings],
      itemResults: [...mergedReport.itemResults, ...report.itemResults]
    }),
    {
      requestedCount: 0,
      cleanedCount: 0,
      skippedLockedCount: 0,
      failedCount: 0,
      cancelled: false,
      reclaimedBytes: 0,
      cleanedIds: [],
      skippedIds: [],
      failedIds: [],
      deleteStrategy: "moveToRecycleBin",
      warnings: [],
      itemResults: []
    }
  );
}

export function toggleVolume(volumes: VolumeInfo[], volumeId: string): VolumeInfo[] {
  return volumes.map((volume) => {
    if (volume.id !== volumeId) {
      return volume;
    }

    return {
      ...volume,
      selected: !volume.selected
    };
  });
}

export function mergeRefreshedVolumes(
  currentVolumes: VolumeInfo[],
  refreshedVolumes: VolumeInfo[]
): VolumeInfo[] {
  const selectionById = new Map(currentVolumes.map((volume) => [volume.id, volume.selected]));

  return refreshedVolumes.map((volume) => ({
    ...volume,
    selected: selectionById.get(volume.id) ?? volume.selected
  }));
}

export function selectedSummary(candidates: CleanupCandidate[]): {
  selectedCount: number;
  selectedBytes: number;
  lockedCount: number;
} {
  return candidates.reduce(
    (summary, candidate) => {
      if (!isCleanupSelectable(candidate)) {
        summary.lockedCount += 1;
      }

      if (candidate.selected && isCleanupSelectable(candidate)) {
        summary.selectedCount += 1;
        summary.selectedBytes += candidate.sizeBytes;
      }

      return summary;
    },
    { selectedCount: 0, selectedBytes: 0, lockedCount: 0 }
  );
}

function trim(value: number): string {
  return Number.isInteger(value) ? value.toFixed(0) : value.toFixed(value >= 10 ? 1 : 2);
}
