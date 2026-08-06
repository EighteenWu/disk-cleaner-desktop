import { describe, expect, it } from "vitest";
import { isIncompleteCoverage, mergeInventoryItems } from "./inventory";
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
