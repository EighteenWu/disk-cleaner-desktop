import { describe, expect, it } from "vitest";
import { mockSnapshot } from "./mockData";
import {
  allCleanableSelected,
  canOpenChildren,
  cleanupBatches,
  cleanupPreviewSummary,
  cleanupStatusLabel,
  filterCandidates,
  mergeRefreshedVolumes,
  mergeCleanupReports,
  removeCandidates,
  scopeCandidatesToVolumes,
  selectedCandidateCategories,
  selectedSummary,
  selectedCandidateIds,
  selectedVolumeIds,
  setCandidateSelection,
  toggleCandidate,
  toggleVolume,
  visibleWindowForList
} from "./state";

describe("candidate state", () => {
  it("does not toggle blocked candidates", () => {
    const toggled = toggleCandidate(mockSnapshot.candidates, "app-session-db");
    const blocked = toggled.find((candidate) => candidate.id === "app-session-db");

    expect(blocked?.selected).toBe(false);
  });

  it("summarizes only selected non-blocked candidates", () => {
    const summary = selectedSummary(mockSnapshot.candidates);

    expect(summary.selectedCount).toBe(2);
    expect(summary.lockedCount).toBe(1);
    expect(summary.selectedBytes).toBeGreaterThan(0);
  });

  it("filters recommended candidates", () => {
    const recommended = filterCandidates(mockSnapshot.candidates, "", "recommended");

    expect(recommended).toHaveLength(2);
    expect(recommended.every((candidate) => candidate.riskLevel === "safeRecommended")).toBe(true);
  });

  it("filters by path or category query", () => {
    const result = filterCandidates(mockSnapshot.candidates, "roaming", "all");

    expect(result.map((candidate) => candidate.id)).toEqual(["app-session-db"]);
  });

  it("filters table candidates to selected categories", () => {
    const categories = selectedCandidateCategories(mockSnapshot.candidates);
    const result = filterCandidates(mockSnapshot.candidates, "", "all", categories);

    expect(Array.from(categories).sort()).toEqual(["安装残留", "浏览器缓存"]);
    expect(result.map((candidate) => candidate.id)).toEqual(["chrome-cache", "installer-rollback"]);
  });

  it("selects all cleanable candidates without selecting blocked items", () => {
    const ids = mockSnapshot.candidates.map((candidate) => candidate.id);
    const selected = setCandidateSelection(mockSnapshot.candidates, ids, true);

    expect(selectedCandidateIds(selected)).not.toContain("app-session-db");
    expect(allCleanableSelected(selected)).toBe(true);
  });

  it("selects only candidates in the current filtered result set", () => {
    const candidates = mockSnapshot.candidates.map((candidate) => ({
      ...candidate,
      selected: candidate.id === "video-editor-cache"
    }));
    const visible = filterCandidates(candidates, "chrome", "all");
    const selected = setCandidateSelection(
      candidates,
      visible.map((candidate) => candidate.id),
      true
    );

    expect(selectedCandidateIds(selected)).toContain("chrome-cache");
    expect(selected.find((candidate) => candidate.id === "video-editor-cache")?.selected).toBe(true);
  });

  it("summarizes cleanup preview without backend round trips", () => {
    const candidates = mockSnapshot.candidates.map((candidate) =>
      candidate.id === "app-session-db" ? { ...candidate, selected: true } : candidate
    );
    const plan = cleanupPreviewSummary(candidates, "permanentDelete");

    expect(plan.deleteStrategy).toBe("permanentDelete");
    expect(plan.selectedCount).toBe(2);
    expect(plan.skippedLockedCount).toBe(1);
    expect(plan.estimatedReclaimBytes).toBe(selectedSummary(mockSnapshot.candidates).selectedBytes);
  });

  it("removes cleaned candidates from the current result set", () => {
    const next = removeCandidates(mockSnapshot.candidates, ["chrome-cache", "installer-rollback"]);

    expect(next.map((candidate) => candidate.id)).not.toContain("chrome-cache");
    expect(next).toHaveLength(mockSnapshot.candidates.length - 2);
  });

  it("removes candidates under cleaned paths from the current result set", () => {
    const chromeCache = mockSnapshot.candidates[0];
    const childCandidate = {
      ...chromeCache,
      id: "chrome-cache-entry",
      parentId: chromeCache.id,
      displayName: "data_1",
      path: `${chromeCache.path}\\data_1`,
      objectType: "file" as const,
      childrenCount: 0
    };
    const next = removeCandidates([...mockSnapshot.candidates, childCandidate], [chromeCache.id], [chromeCache.path]);

    expect(next.map((candidate) => candidate.id)).not.toContain(chromeCache.id);
    expect(next.map((candidate) => candidate.id)).not.toContain(childCandidate.id);
  });

  it("splits selected cleanup candidates into stable batches", () => {
    const batches = cleanupBatches(
      mockSnapshot.candidates,
      ["chrome-cache", "installer-rollback", "video-editor-cache"],
      2
    );

    expect(batches).toHaveLength(2);
    expect(batches[0].selectedIds).toEqual(["chrome-cache", "installer-rollback"]);
    expect(batches[1].selectedIds).toEqual(["video-editor-cache"]);
  });

  it("merges batched cleanup reports into one result", () => {
    const report = mergeCleanupReports([
      {
        requestedCount: 2,
        cleanedCount: 1,
        skippedLockedCount: 1,
        failedCount: 0,
        cancelled: false,
        reclaimedBytes: 100,
        cleanedIds: ["chrome-cache"],
        skippedIds: ["app-session-db"],
        failedIds: [],
        deleteStrategy: "moveToRecycleBin",
        warnings: ["跳过锁定项"],
        itemResults: [
          {
            id: "chrome-cache",
            displayName: "Chrome Cache",
            path: "C:\\cache",
            source: mockSnapshot.candidates[0].source,
            status: "cleaned",
            reclaimedBytes: 100,
            reason: "已清理"
          }
        ]
      },
      {
        requestedCount: 1,
        cleanedCount: 0,
        skippedLockedCount: 0,
        failedCount: 1,
        cancelled: false,
        reclaimedBytes: 0,
        cleanedIds: [],
        skippedIds: [],
        failedIds: ["installer-rollback"],
        deleteStrategy: "moveToRecycleBin",
        warnings: ["删除失败"],
        itemResults: [
          {
            id: "installer-rollback",
            displayName: "installer_unpack_rollback",
            path: "C:\\temp",
            source: mockSnapshot.candidates[1].source,
            status: "failed",
            reclaimedBytes: 0,
            reason: "删除失败"
          }
        ]
      }
    ]);

    expect(report.requestedCount).toBe(3);
    expect(report.cleanedIds).toEqual(["chrome-cache"]);
    expect(report.failedIds).toEqual(["installer-rollback"]);
    expect(report.warnings).toEqual(["跳过锁定项", "删除失败"]);
    expect(report.itemResults.map((item) => item.id)).toEqual(["chrome-cache", "installer-rollback"]);
  });

  it("labels cleanability and directory drilldown support", () => {
    const chromeCache = mockSnapshot.candidates.find((candidate) => candidate.id === "chrome-cache");
    const blockedSession = mockSnapshot.candidates.find((candidate) => candidate.id === "app-session-db");

    expect(chromeCache ? cleanupStatusLabel(chromeCache) : "").toBe("默认清理");
    expect(chromeCache ? canOpenChildren(chromeCache) : false).toBe(true);
    expect(blockedSession ? cleanupStatusLabel(blockedSession) : "").toBe("禁止清理");
    expect(blockedSession ? canOpenChildren(blockedSession) : true).toBe(false);
  });

  it("filters by backend-provided source labels", () => {
    const result = filterCandidates(mockSnapshot.candidates, "Google Chrome", "all");

    expect(result.map((candidate) => candidate.id)).toEqual(["chrome-cache"]);
  });
});

describe("virtual result window", () => {
  it("returns a padded window around the visible rows", () => {
    expect(visibleWindowForList(2_000, 680, 340, 68, 4)).toEqual({
      startIndex: 6,
      endIndex: 19,
      topPadding: 408,
      bottomPadding: 134_708
    });
  });

  it("handles empty lists without padding", () => {
    expect(visibleWindowForList(0, 500, 340, 68, 4)).toEqual({
      startIndex: 0,
      endIndex: 0,
      topPadding: 0,
      bottomPadding: 0
    });
  });
});

describe("volume state", () => {
  it("toggles drive selection", () => {
    const toggled = toggleVolume(mockSnapshot.volumes, "E");
    const drive = toggled.find((volume) => volume.id === "E");

    expect(drive?.selected).toBe(true);
  });

  it("keeps drive selection when refreshing volume metadata", () => {
    const current = toggleVolume(mockSnapshot.volumes, "E");
    const refreshed = mockSnapshot.volumes.map((volume) => ({
      ...volume,
      availableBytes: volume.availableBytes + 1024,
      selected: false
    }));

    const merged = mergeRefreshedVolumes(current, refreshed);

    expect(merged.map((volume) => [volume.id, volume.selected])).toEqual([
      ["C", true],
      ["D", true],
      ["E", true]
    ]);
    expect(merged[0].availableBytes).toBe(mockSnapshot.volumes[0].availableBytes + 1024);
  });

  it("scopes candidates to selected drives", () => {
    const volumes = toggleVolume(mockSnapshot.volumes, "D");
    const scoped = scopeCandidatesToVolumes(mockSnapshot.candidates, selectedVolumeIds(volumes));

    expect(scoped.map((candidate) => candidate.volumeId)).toEqual(["C", "C", "C"]);
    expect(scoped.some((candidate) => candidate.id === "video-editor-cache")).toBe(false);
  });
});
