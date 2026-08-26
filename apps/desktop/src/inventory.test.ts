import { describe, expect, it } from "vitest";
import { isIncompleteCoverage, mergeActionableGaps, mergeInventoryItems, occupancyPercent } from "./inventory";
import type { InventoryQueryItem } from "./types";

describe("inventory paging", () => {
  it("appends stable pages without duplicating cursor overlap", () => {
    expect(mergeInventoryItems([item("1")], [item("1"), item("2")], true).map((value) => value.entryId)).toEqual([
      "1",
      "2"
    ]);
  });

  it("replaces results for a new search and treats partial as incomplete", () => {
    expect(mergeInventoryItems([item("1")], [item("2")], false).map((value) => value.entryId)).toEqual(["2"]);
    expect(isIncompleteCoverage("partial")).toBe(true);
    expect(isIncompleteCoverage("complete")).toBe(false);
  });

  it("merges actionable coverage gaps and hides expected reparse/identity noise", () => {
    expect(
      mergeActionableGaps([
        { volumeId: "C", reason: "reparseNotFollowed", count: 12 },
        { volumeId: "C", reason: "accessDenied", count: 2 },
        { volumeId: "C", reason: "accessDenied", count: 3 },
        { volumeId: "D", reason: "backendFallback", count: 1 }
      ])
    ).toEqual([
      { volumeId: "C", reason: "accessDenied", count: 5 },
      { volumeId: "D", reason: "backendFallback", count: 1 }
    ]);
  });

  it("keeps occupancy bars honest when totals are missing", () => {
    expect(occupancyPercent(40, 100)).toBe(40);
    expect(occupancyPercent(0, 100)).toBe(0);
    expect(occupancyPercent(10, 0)).toBe(0);
  });
});

function item(entryId: string): InventoryQueryItem {
  return {
    entryId,
    parentEntryId: null,
    volumeId: "C",
    name: entryId,
    path: `C:\\${entryId}`,
    objectType: "file",
    logicalBytes: 1,
    allocatedBytes: 1,
    disposition: "blocked",
    allocationOwner: true,
    hasChildren: false
  };
}
