import { isCleanupSelectable, setCandidateSelection } from "./state";
import type { CleanupCandidate, RiskLevel, SourceKind } from "./types";

/**
 * Candidates are grouped by `SourceKind` rather than by the rule `category`
 * string. Categories come from rule YAML as free-form text ("浏览器缓存"),
 * so they cannot be localized and drift with every subscription import.
 * `SourceKind` is a closed enum shared with the Rust side, which makes it both
 * translatable and stable.
 *
 * The product reason for grouping at all: a first-time user recognizes
 * "browsers" and "games", not "chrome-cache" or a rule id.
 */

export type GroupSelection = "none" | "partial" | "all";

export interface CandidateGroup {
  kind: SourceKind;
  candidates: CleanupCandidate[];
  /** Bytes across every candidate, including ones that cannot be selected. */
  totalBytes: number;
  selectedBytes: number;
  selectableCount: number;
  selectedCount: number;
  blockedCount: number;
  selection: GroupSelection;
  /** Worst risk in the group, so the UI can warn before expanding. */
  maxRisk: RiskLevel;
}

/**
 * Display order, safest and most recognizable first. Anything unknown sinks to
 * the bottom because it is the least actionable for a non-expert user.
 */
export const GROUP_ORDER: readonly SourceKind[] = [
  "browser",
  "windows",
  "installedApp",
  "storeApp",
  "game",
  "devTool",
  "project",
  "unknown"
];

const RISK_SEVERITY: Record<RiskLevel, number> = {
  safeRecommended: 0,
  cautiousRecommended: 1,
  reviewRequired: 2,
  blocked: 3
};

export function buildCandidateGroups(candidates: CleanupCandidate[]): CandidateGroup[] {
  const buckets = new Map<SourceKind, CleanupCandidate[]>();

  for (const candidate of candidates) {
    const kind = candidate.source.kind;
    const bucket = buckets.get(kind);

    if (bucket) {
      bucket.push(candidate);
    } else {
      buckets.set(kind, [candidate]);
    }
  }

  return GROUP_ORDER.filter((kind) => buckets.has(kind)).map((kind) =>
    summarizeGroup(kind, buckets.get(kind) ?? [])
  );
}

function summarizeGroup(kind: SourceKind, candidates: CleanupCandidate[]): CandidateGroup {
  let totalBytes = 0;
  let selectedBytes = 0;
  let selectableCount = 0;
  let selectedCount = 0;
  let blockedCount = 0;
  let maxRisk: RiskLevel = "safeRecommended";

  for (const candidate of candidates) {
    totalBytes += candidate.sizeBytes;

    if (RISK_SEVERITY[candidate.riskLevel] > RISK_SEVERITY[maxRisk]) {
      maxRisk = candidate.riskLevel;
    }

    if (isCleanupSelectable(candidate)) {
      selectableCount += 1;

      if (candidate.selected) {
        selectedCount += 1;
        selectedBytes += candidate.sizeBytes;
      }
    } else {
      blockedCount += 1;
    }
  }

  return {
    kind,
    candidates,
    totalBytes,
    selectedBytes,
    selectableCount,
    selectedCount,
    blockedCount,
    selection: selectionStateFor(selectableCount, selectedCount),
    maxRisk
  };
}

function selectionStateFor(selectableCount: number, selectedCount: number): GroupSelection {
  if (selectableCount === 0 || selectedCount === 0) {
    return "none";
  }

  return selectedCount === selectableCount ? "all" : "partial";
}

/**
 * Selecting a whole group is the one-click path that keeps the operation chain
 * short: pick a group, confirm, clean.
 */
export function setGroupSelection(
  candidates: CleanupCandidate[],
  kind: SourceKind,
  selected: boolean
): CleanupCandidate[] {
  const ids = candidates
    .filter((candidate) => candidate.source.kind === kind && isCleanupSelectable(candidate))
    .map((candidate) => candidate.id);

  return ids.length === 0 ? candidates : setCandidateSelection(candidates, ids, selected);
}

/**
 * The default one-click selection: safe recommended items that also opted
 * into default selection. Recycle bin can be recommended yet stay unchecked.
 */
export function applyRecommendedSelection(candidates: CleanupCandidate[]): CleanupCandidate[] {
  const recommendedIds: string[] = [];
  const otherIds: string[] = [];

  for (const candidate of candidates) {
    if (!isCleanupSelectable(candidate)) {
      continue;
    }

    if (candidate.riskLevel === "safeRecommended" && candidate.defaultSelected) {
      recommendedIds.push(candidate.id);
    } else {
      otherIds.push(candidate.id);
    }
  }

  const cleared = setCandidateSelection(candidates, otherIds, false);

  return setCandidateSelection(cleared, recommendedIds, true);
}

export function groupsSelectedSummary(groups: CandidateGroup[]): {
  selectedCount: number;
  selectedBytes: number;
} {
  return groups.reduce(
    (accumulator, group) => ({
      selectedCount: accumulator.selectedCount + group.selectedCount,
      selectedBytes: accumulator.selectedBytes + group.selectedBytes
    }),
    { selectedCount: 0, selectedBytes: 0 }
  );
}