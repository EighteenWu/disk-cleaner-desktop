import { describe, expect, it } from "vitest";
import {
  applyRecommendedSelection,
  buildCandidateGroups,
  GROUP_ORDER,
  groupsSelectedSummary,
  setGroupSelection
} from "./groups";
import type { CleanupCandidate, RiskLevel, SourceKind } from "./types";

function candidate(
  id: string,
  kind: SourceKind,
  overrides: Partial<CleanupCandidate> = {}
): CleanupCandidate {
  return {
    id,
    parentId: null,
    displayName: id,
    path: `C:\\${id}`,
    volumeId: "C",
    objectType: "directory",
    category: "cache",
    sizeBytes: 1024,
    childrenCount: 0,
    riskLevel: "safeRecommended",
    defaultSelected: true,
    selected: false,
    deleteStrategy: "moveToRecycleBin",
    reason: "test",
    confidence: 90,
    source: { label: id, kind, confidence: 90, evidence: "test" },
    cleanupPolicy: { ruleId: null, method: "contents", keepDays: 0, excludePatterns: [] },
    ...overrides
  };
}

describe("buildCandidateGroups", () => {
  it("groups candidates by source kind", () => {
    const groups = buildCandidateGroups([
      candidate("a", "browser"),
      candidate("b", "browser"),
      candidate("c", "game")
    ]);

    expect(groups.map((group) => group.kind)).toEqual(["browser", "game"]);
    expect(groups[0].candidates).toHaveLength(2);
  });

  it("keeps the declared display order regardless of input order", () => {
    const groups = buildCandidateGroups([
      candidate("a", "unknown"),
      candidate("b", "devTool"),
      candidate("c", "browser")
    ]);

    expect(groups.map((group) => group.kind)).toEqual(["browser", "devTool", "unknown"]);
  });

  it("omits kinds with no candidates", () => {
    const groups = buildCandidateGroups([candidate("a", "windows")]);

    expect(groups).toHaveLength(1);
    expect(GROUP_ORDER.length).toBeGreaterThan(1);
  });

  it("sums total bytes across selectable and blocked candidates", () => {
    const groups = buildCandidateGroups([
      candidate("a", "browser", { sizeBytes: 100, selected: true }),
      candidate("b", "browser", { sizeBytes: 400, riskLevel: "blocked" })
    ]);

    expect(groups[0].totalBytes).toBe(500);
    expect(groups[0].selectedBytes).toBe(100);
    expect(groups[0].blockedCount).toBe(1);
    expect(groups[0].selectableCount).toBe(1);
  });

  it("does not count blocked candidates as selectable", () => {
    const groups = buildCandidateGroups([
      candidate("a", "windows", { riskLevel: "blocked", selected: true })
    ]);

    expect(groups[0].selectableCount).toBe(0);
    expect(groups[0].selectedCount).toBe(0);
    expect(groups[0].selection).toBe("none");
  });

  it("does not count skip-strategy candidates as selectable", () => {
    const groups = buildCandidateGroups([
      candidate("a", "windows", { deleteStrategy: "skip", selected: true })
    ]);

    expect(groups[0].selectableCount).toBe(0);
    expect(groups[0].selection).toBe("none");
  });

  it("reports partial selection when only some selectable candidates are on", () => {
    const groups = buildCandidateGroups([
      candidate("a", "browser", { selected: true }),
      candidate("b", "browser", { selected: false })
    ]);

    expect(groups[0].selection).toBe("partial");
  });

  it("reports full selection when every selectable candidate is on", () => {
    const groups = buildCandidateGroups([
      candidate("a", "browser", { selected: true }),
      candidate("b", "browser", { selected: true, riskLevel: "blocked" })
    ]);

    expect(groups[0].selection).toBe("all");
  });

  it("tracks the worst risk level in the group", () => {
    const groups = buildCandidateGroups([
      candidate("a", "browser", { riskLevel: "safeRecommended" }),
      candidate("b", "browser", { riskLevel: "reviewRequired" }),
      candidate("c", "browser", { riskLevel: "cautiousRecommended" })
    ]);

    expect(groups[0].maxRisk).toBe<RiskLevel>("reviewRequired");
  });
});

describe("setGroupSelection", () => {
  it("selects every selectable candidate in the group", () => {
    const candidates = [candidate("a", "browser"), candidate("b", "browser"), candidate("c", "game")];
    const next = setGroupSelection(candidates, "browser", true);

    expect(next.filter((item) => item.selected).map((item) => item.id)).toEqual(["a", "b"]);
  });

  it("leaves other groups untouched", () => {
    const candidates = [candidate("a", "browser"), candidate("c", "game", { selected: true })];
    const next = setGroupSelection(candidates, "browser", true);

    expect(next.find((item) => item.id === "c")?.selected).toBe(true);
  });

  it("never selects blocked candidates", () => {
    const candidates = [candidate("a", "browser", { riskLevel: "blocked" })];
    const next = setGroupSelection(candidates, "browser", true);

    expect(next[0].selected).toBe(false);
  });

  it("clears selection when asked to deselect", () => {
    const candidates = [candidate("a", "browser", { selected: true })];
    const next = setGroupSelection(candidates, "browser", false);

    expect(next[0].selected).toBe(false);
  });

  it("returns the same array when the group has nothing selectable", () => {
    const candidates = [candidate("a", "browser", { riskLevel: "blocked" })];

    expect(setGroupSelection(candidates, "game", true)).toBe(candidates);
  });
});

describe("applyRecommendedSelection", () => {
  it("selects only safe candidates", () => {
    const candidates = [
      candidate("safe", "browser", { riskLevel: "safeRecommended" }),
      candidate("caution", "browser", { riskLevel: "cautiousRecommended" }),
      candidate("review", "windows", { riskLevel: "reviewRequired" })
    ];
    const next = applyRecommendedSelection(candidates);

    expect(next.filter((item) => item.selected).map((item) => item.id)).toEqual(["safe"]);
  });

  it("clears previously selected risky candidates", () => {
    const candidates = [
      candidate("review", "windows", { riskLevel: "reviewRequired", selected: true })
    ];

    expect(applyRecommendedSelection(candidates)[0].selected).toBe(false);
  });

  it("keeps blocked candidates unselected", () => {
    const candidates = [candidate("blocked", "windows", { riskLevel: "blocked" })];

    expect(applyRecommendedSelection(candidates)[0].selected).toBe(false);
  });
});

describe("groupsSelectedSummary", () => {
  it("adds up selected counts and bytes across groups", () => {
    const groups = buildCandidateGroups([
      candidate("a", "browser", { sizeBytes: 100, selected: true }),
      candidate("b", "game", { sizeBytes: 250, selected: true }),
      candidate("c", "game", { sizeBytes: 999 })
    ]);

    expect(groupsSelectedSummary(groups)).toEqual({ selectedCount: 2, selectedBytes: 350 });
  });

  it("returns zeros for an empty group list", () => {
    expect(groupsSelectedSummary([])).toEqual({ selectedCount: 0, selectedBytes: 0 });
  });
});